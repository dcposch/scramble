/** @jsx React.DOM */

//
// SCRAMBLE.IO
// Secure email for everyone
// by DC and Jaekwon - http://dcpos.ch/, https://github.com/jaekwon
//


//
// CONSTANTS
// See https://tools.ietf.org/html/rfc4880
//

var NUM_WORKERS = 1;

var BOX_PAGE_SIZE = 20;

var REGEX_TOKEN = /^[a-z0-9][a-z0-9][a-z0-9]+$/;
var REGEX_EMAIL = /^([A-Z0-9._%+-=]+)@([A-Z0-9.-]+\.[A-Z]{2,4})$/i;
var REGEX_BODY = /^Subject: (.*)(?:\r?\n)+([\s\S]*)$/i;
var REGEX_CONTACT_NAME = /^[^@]*$/i;

var SCRYPT_PARAMS = {
    N:16384, // difficulty=2^14, recommended range 2^14 to 2^20
    r:8,     // recommended values
    p:1
};

var DEFAULT_SIGNATURE = "\n\n--\n"+
    "Sent with https://scramble.io";

var CONTACTS_VERSION = 1;


// If we get responses from all but n notaries for a given address,
// and the responses all agree, we accept the public key.
// 
// This allow individual notary operators to have brief downtime 
// (eg upgrading their server) without breaking Scramble, without
// significantly impacting security.
//
// (To MITM a user, an adversary would have to commandeer (n-x)
//  notaries and then take down the remaining x notaries.)
var MAX_MISSING_NOTARIES = 1;


//
// SESSION VARIABLES
//
// sessionStorage["token"] is the username
// sessionStorage["emailAddress"] is <token>@<host>
// sessionStorage["passHash"] is the auth key
// sessionStorage["passHashOld"] is for backwards compatibility
// sessionStorage["/publickeys/notary"] is the cached /publickeys/notary response
// sessionStorage["hostPrefix"] is the request prefix, like "https://scramble.io", for chrome
//
// These are never seen by the server, and never go in cookies or localStorage
// sessionStorage["passKey"] is AES128 key derived from passphrase, used to encrypt to private key
// sessionStorage["publicKeyArmored"] is the PGP public key, ascii armored
// sessionStorage["privateKeyArmored"] is the plaintext private key, ascii armored
//



//
// VIEW VARIABLES
// These are even more transient than session variables.
// They go away if you hit Refresh.
//

var viewState = {};

// current box (e.g. inbox, sent, archive)
viewState.box = null;
// Returns the last email
viewState.getLastEmail = function() {
    if (!this.emails) {
        return null;
    }
    return this.emails[this.emails.length-1];
};
// Returns the last email from another user.
viewState.getLastEmailFromAnother = function() {
    if (!this.emails) {
        return null;
    }
    for (var i=this.emails.length-1; 0 <= i; i--) {
        var email = this.emails[i];
        if (trimToLower(email.from) != sessionStorage["emailAddress"]) {
            return email;
        }
    }
    // just return the last email even from self.
    return this.getLastEmail();
};
viewState.clearEmails = function() {
    this.box = null;
    this.emails = null;
};

viewState.contacts = null; // plaintext address book
viewState.notaries = null; // notaries that client trusts.



//
// IN-MEMORY CACHE
// Don't decrypt the same email twice.
// Don't resolve the same email address -> public key twice.
//

// Maps email addresses to OpenPGP public key objects
var cache = {};
cache.keyMap = {}; // email address -> notarized public key
cache.emailCache = {};
cache.plaintextCache = {}; // cache key -> plaintext


//
// DEPENDENCIES
//

var Api = require("./scramble-api");

var React = require("react");
var Login = require("./Login");
var CreateAccount = require("./CreateAccount");

var Router = require("director").Router;
var routes = {
    "/": main,
    "/inbox": showInbox,
    "/inbox/:msg": showInbox 
};
var router = Router(routes);
router.init();
function showInbox(){
    console.log("ShowInbox");
}


//
// LOAD THE SITE
// Called on load: $(main)
//

window.main = main;
function main() {
    console.log("Hello World");

    // initialize browser crypto
    if (!window.crypto.getRandomValues) {
        alert("Sorry, your browser doesn't support cryptography.\n"+
            "You'll need a recent version of Chrome, Firefox, or Safari.\n\n"+
            "The Tor Browser Bundle unfortunately ships an old version of FF :(\n"+
            "To use Scramble thru Tor, we recommend using Chrome in Incognito mode "+
            "through the SOCKS proxy which the Tor Browser Bundle / Vidalia provides.");
        return;
    }
    startPgpDecryptWorkers(NUM_WORKERS);
    startPgpWorkerWatcher();

    // initialize the ui
    initHandlebars();
    initMomentJS();
    initAjaxAuth();
    bindKeyboardShortcuts();

    // are we logged in?
    if (!isLoggedIn()) {
        console.log("Please log in.");
        showLogin();
    } else {
        console.log("Auth tokens already present, logging in.");
        login();
    }
}

function login(failureCb){
    Api.getAccount().done(function(data){
        // (first load after login)
        sessionStorage["emailAddress"] = data.EmailAddress;
        sessionStorage["pubHash"] = data.PublicHash;
        sessionStorage["publicKeyArmored"] = data.PublicKey;
        sessionStorage["privateKeyArmored"] = decryptPrivateKey(data.CipherPrivateKey);
        
        workerSendAll({
            "type":"set-key",
            "privateKey": sessionStorage["privateKeyArmored"]
        });
        loadDecryptAndShowBox("inbox");
    }).fail(function(xhr){
        clearCredentials(); 
        if(failureCb){
            failureCb(xhr.responseText);
        } else {
            alert("Login failed. Please refresh and try again.");
        }
    });
}

function decryptPrivateKey(cipherPrivateKeyHex){
    var cipherPrivateKey = hex2bin(cipherPrivateKeyHex);

    var privateKeyArmored = passphraseDecrypt(cipherPrivateKey);
    if (!privateKeyArmored) {
        alert("Can't decrypt our own private key. Please refresh and try again.");
    }
    return privateKeyArmored;
}

// Asynchronously decrypts (and optionally verifies) a PGP message
//
// Requires:
// * unique cache key
// * ASCII-armored ciphertext
// * (optional) ASCII-armored public key for signature verification or null
// * a callback cb(plaintext)
function cachedDecryptPgp(id, armoredText, publicKeyArmored, cb){
    var plain = cache.plaintextCache[id];
    if (typeof(plain) !== "undefined"){
        cb(plain);
    } else if (pendingJobs[id]){
        pendingJobs[id].callbacks.push(cb);
        console.log("Warning: skipping job, already in progress: "+id);
    } else {
        console.log("Decrypting "+id);
        var job = {
            "type":"decrypt-verify",
            "id":id,
            "armoredText":armoredText,
            "publicKeyArmored":publicKeyArmored,
            "randomBase64":randomBase64(65000) //+armoredText.length*2)
        };
        workerSubmitJob(job, function(msg){
            cache.plaintextCache[msg.id] = msg.plaintext;
            cb(msg.plaintext, msg.error);
        });
    }
}


//
// KEYBOARD SHORTCUTS
//

var keyMap = {
    "j":showNextItem,
    "k":showPrevItem,
    "g":{
        "c":showContacts,
        "i":function(){loadDecryptAndShowBox("inbox");},
        "s":function(){loadDecryptAndShowBox("sent");},
        "a":function(){loadDecryptAndShowBox("archive");}
    },
    "c":showCompose,
    "r":function(){emailReply(viewState.getLastEmailFromAnother());},
    "a":function(){emailReplyAll(viewState.getLastEmail());},
    "f":function(){emailForward(viewState.getLastEmail());},
    "y":function(){threadMove(viewState.getLastEmail(), "archive");},
    "d":function(){threadMove(viewState.getLastEmail(), "trash");},
};

function bindKeyboardShortcuts() {
    var currentKeyMap = keyMap;
    $(document).keydown(function(e) {
        // no keyboard shortcuts while the user is typing
        var target = e.target;
        var tag = target.tagName.toLowerCase();
        if (tag=="textarea" ||
            (tag=="input" && target.type=="text") ||
            (tag=="input" && target.type=="email") ||
            (tag=="input" && target.type=="password")) {
            return;
        }
        // don't interpret "Ctrl C" as "c" and accidentally go to Compose, etc
        if(e.shiftKey || e.ctrlKey || e.altKey){
            return;
        }

        var code = e.which || e.charCode;
        var mapping = currentKeyMap[code] || 
                      currentKeyMap[String.fromCharCode(code).toLowerCase()];
        if (!mapping) {
            // unrecognized keyboard shortcut
            currentKeyMap = keyMap;
        } else if (typeof(mapping)=="function") {
            // valid keyboard shortcut
            mapping();
            currentKeyMap = keyMap;
        } else {
            // pressed one key in a combination, wait for the next key
            currentKeyMap = mapping;
        }
    });
}



//
// TABS & PAGE STRUCTURE
//

function bindTabEvents() {
    // Navigate to Inbox, Sent, or Archive
    $(".js-tab-inbox").click(function(e) {
        loadDecryptAndShowBox("inbox");
    });
    $(".js-tab-sent").click(function(e) {
        loadDecryptAndShowBox("sent");
    });
    $(".js-tab-archive").click(function(e) {
        loadDecryptAndShowBox("archive");
    });

    // Navigate to Compose
    $(".js-tab-compose").click(function(e) {
        showCompose();
    });

    // Navigate to Contacts
    $(".js-tab-contacts").click(function(e) {
        showContacts();
    });

    // Log out: click a link, deletes sessionStorage and refreshes the page
    $("#link-logout").click(function(e) {
        if (keepUnsavedWork()) {
            e.preventDefault();
            return;
        }
        clearCredentials();
    });
}

function setSelectedTab(tab) {
    $(".js-tab").removeClass("active");
    tab.addClass("active");
}

function showStatus(msg, cssClass) {
    if(!cssClass) {
        cssClass = "text-success";
    }
    $("#statusBar")
        .text(msg)
        .attr("class", cssClass)
        .show()
        .delay(1000)
        .fadeOut("slow");
}



//
// MODAL DIALOGS
//

function showModal(modal) {
    React.renderComponent(modal,
        document.getElementById("modal"));
}

function closeModal() {
    $(".modal").remove();
    $(".modal-bg").remove();
}



//
// LOGIN 
//

function clearCredentials() {
    sessionStorage.clear();
}

function showLogin() {
    // not logged in. reset session state.
    clearCredentials();

    // show the login ui
    React.renderComponent((<Login 
            onLogin={handleLogin} 
            onCreateAccount={showCreateAccountModal} 
         />), 
        document.getElementById("wrapper"));
}

function handleLogin(username, password) {
    setAuthTokens(username, password);
    login(function(err){
        // TODO: reactify
        $(".error-signin").text(err);
    });
}


function bindLoginEvents() {
    $("#enterButton").click(function() {
        var token = $("#token").val();
        var pass = $("#pass").val();
    });

    var keys = null;
    $("#generateButton").click(showCreateAccountModal);
}

function setAuthTokens(token, pass) {
    // two hashes of (token, pass)
    // ...one encrypts the private key. the server must never see it.
    // save for this session only, never in a cookie or localStorage
    sessionStorage["passKey"] = computeAesKey(token, pass);
    sessionStorage["passKeyOld"] = computeAesKeyOld(token, pass);

    // ...the other one authenticates us. the server sees it.
    sessionStorage["token"] = token;
    sessionStorage["passHash"] = computeAuth(token, pass);
    sessionStorage["passHashOld"] = computeAuthOld(token, pass);
}

function isLoggedIn() {
    return Boolean(sessionStorage["token"] && sessionStorage["passKey"]);
}


//
// LOGIN - "CREATE ACCOUNT" MODAL
//

function showCreateAccountModal() {
    var createModal = (<CreateAccount onCreateAccount={createAccount}/>);
    showModal(createModal);

    // Asynchronously generate PGP keys
    var job = {
        "id": "gen",
        "type": "generate-key-pair",
        "randomBase64": randomBase64(1000)
    };
    workerSubmitJob(job, function(response){
        var keys = {};
        keys.publicKeyArmored = response.publicKeyArmored;
        keys.privateKeyArmored = response.privateKeyArmored;
        sessionStorage["pubHash"] = computePublicHash(keys.publicKeyArmored);

        createModal.setProps({"keys":keys});
    });
}

// Attempts to creates a new account, given a freshly generated key pair.
// Reads token and passphrase. Validates that the token is unique, 
// and the passphrase strong enough.
// Posts the token, a hash of the passphrase, public key, and 
// encrypted private key to the server.
function createAccount(token, pass, secondaryEmail, keys) {
    // validate
    var err = validateToken(token);
    if(err) return alert(err);
    err = validateNewPassword(pass);
    if(err) return alert(err);
    err = validateOptionalEmail(secondaryEmail);
    if(err) return alert(err);

    // two passphrase hashes, one for login and one to encrypt the private key
    // the server knows only the login hash, and must not know the private key
    var aesKey = computeAesKey(token, pass);
    var passHash = computeAuth(token, pass);

    sessionStorage["token"] = token;
    sessionStorage["passHash"] = passHash;
    // save for this session only, never in a cookie or localStorage
    sessionStorage["passKey"] = aesKey;
    sessionStorage["privateKeyArmored"] = keys.privateKeyArmored;

    // encrypt the private key with the user's passphrase
    var cipherPrivateKey = passphraseEncrypt(keys.privateKeyArmored);

    // send it
    var data = {
        token:token,
        secondaryEmail:secondaryEmail,
        passHash:passHash,
        publicKey:keys.publicKeyArmored,
        cipherPrivateKey:bin2hex(cipherPrivateKey)
    };
    Api.postAccount(data).done(function() {
        //TODO: verify that what we load matches what we just generated
        login();
    }).fail(function(xhr) {
        alert(xhr.responseText);
    });
}

function validateToken(token) {
    if (token.match(REGEX_TOKEN)) {
        return null;
    } else {
        return "User must be at least three characters long.\n" +
              "Lowercase letters and numbers only, please.";
    }
}

function validateNewPassword(pass) {
    if (pass.length < 10) {
        return "Your passphrase is too short.\n" + 
               "An ordinary password is not strong enough here.\n" +
               "For help, see http://xkcd.com/936/";
    }
    return null;
}

function validateOptionalEmail(email){
    if (email && !email.match(REGEX_EMAIL)) {
        return email+" is not a valid email address";
    }
    return null;
}


//
// BOX
//

function bindBoxEvents() {
    // Click on an email to open it
    $("#box .js-item").click(function(e) {
        showEmail($(e.currentTarget));
    });
    // Click on a pagination link
    $("#box .box-pagination a").click(function(e) {
        var box = $(this).data("box");
        var page = $(this).data("page");
        loadDecryptAndShowBox(box, page);
        return false;
    });
}

function loadDecryptAndShowBox(box, page) {
    if (keepUnsavedWork()) { return; }
    box = box || "inbox";
    page = page || 1;
    console.log("Loading, decrypting and showing "+box+", page "+page);
    Api.getBox(box, page, BOX_PAGE_SIZE).done(function(boxSummary){
        console.log("Decrypting and showing "+box);
        showEncryptedBox(boxSummary, box);
        startDecryptingBox(boxSummary);
    }).fail(function(xhr) {
        alert(xhr.responseText || "Could not reach the server, try again");
    });
}

// Shows a box (eg inbox or sent) immediately,
// even though the contents have not yet been decrypted
function showEncryptedBox(boxSummary, box) {
    var data = {
        token:        sessionStorage["token"],
        box:          box,
        emailAddress: boxSummary.EmailAddress,
        pubHash:      boxSummary.PublicHash,
        offset:       boxSummary.Offset,
        limit:        boxSummary.Limit,
        total:        boxSummary.Total,
        page:         Math.floor(boxSummary.Offset / boxSummary.Limit)+1,
        totalPages:   Math.ceil(boxSummary.Total / boxSummary.Limit),
        emailHeaders: boxSummary.EmailHeaders.map(createEmailViewModel)
    };
    var pages = [];
    for (var i=0; i<data.totalPages; i++) {
        pages.push({page:i+1});
    }
    data.pages = pages;
    $("#wrapper").html(render("page-template", data));
    bindTabEvents();
    setSelectedTab($(".js-tab-"+box));
    $("#box").html(render("box-template", data));
    bindBoxEvents();
    viewState.box = box;
}

// Asynchronously decrypts a box (eg inbox and sent). Uses Web Workers.
function startDecryptingBox(boxSummary, box) {
    getContacts(function() {
        // Start decrypting the subjects
        boxSummary.EmailHeaders.forEach(decryptSubject);
        // Start prefetching and decrypting the bodies
        boxSummary.EmailHeaders.forEach(prefetchAndDecryptThread);
    });
}

function decryptSubject(h) {
    cachedDecryptPgp(h.ThreadID+" subject", h.CipherSubject, null, function(subject){
        if (subject === null) {
            subject = "(Decryption failed)";
        } else if (trim(subject)==="") {
            subject = "(No subject)";
        }
        var hexMsgID = bin2hex(h.MessageID);
        $("#subject-"+hexMsgID).removeClass("still-decrypting").text(subject);
        $("#subject-header-"+hexMsgID).removeClass("still-decrypting").text(subject);
    });
}

function prefetchAndDecryptThread(h){
    cachedLoadThread({msgID:h.MessageID, threadID:h.ThreadID}, function(emails) {
        console.log("Prefetched thread, # emails: "+emails.length);
        decryptEmailThread(emails); 
    });
}

function showNextItem() {
    var item;
    if ($(".js-item.active").length === 0) {
        item = $(".js-item").first();
    } else {
        item = $(".js-item.active").next();
    }
    if (item.length > 0) {
        showEmailOrContact(item);
    }
}

function showPrevItem() {
    var item;
    if ($(".js-item.active").length === 0) {
        item = $(".js-item").last();
    } else {
        item = $(".js-item.active").prev();
    }
    if (item.length > 0) {
        showEmailOrContact(item);
    }
}

function showEmailOrContact(item) {
    if (item.hasClass("js-box-item")) {
        showEmail(item);
    } else if(item.hasClass("js-contact-item")) {
        showContact(item);
    } else {
        console.warn(["Unrecognized item", item]);
    }
}



//
// SINGLE EMAIL
//

// Binds events for all emails in the current thread.
function bindEmailEvents() {
    // This is a helper that gets the relevant email data
    //  by finding the enclosed div.js-email
    var withEmail = function(cb) {
        return function() {
            var emailDiv = $(this).closest(".js-email");
            cb(emailDiv.data("email"));
        };
    };

    $(".js-email-control .js-reply-button").click(withEmail(emailReply));
    $(".js-email-control .js-reply-all-button").click(withEmail(emailReplyAll));
    $(".js-email-control .js-forward-button").click(withEmail(emailForward));
    $(".email .js-enter-add-contact-button").click(addContact);

    var withLastEmail = function(cb) {
        return function() {
            cb(viewState.getLastEmail());
        };
    };
    var withLastEmailFromAnother = function(cb) {
        return function() {
            cb(viewState.getLastEmailFromAnother());
        };
    };

    $(".js-thread-control .js-reply-button").click(withLastEmailFromAnother(emailReply));
    $(".js-thread-control .js-reply-all-button").click(withLastEmail(emailReplyAll));
    $(".js-thread-control .js-forward-button").click(withLastEmail(emailForward));
    $(".js-thread-control .js-archive-button").click(withLastEmail(function(email){
        threadMove(email, "archive");
    }));
    $(".js-thread-control .js-move-to-inbox-button").click(withLastEmail(function(email){
        threadMove(email, "inbox");
    }));
    $(".js-thread-control .js-delete-button").click(withLastEmail(function(email){
        threadMove(email, "trash");
    }));

    $(".js-show-orig").click(toggleShowOriginal);
}

function toggleShowOriginal(e){
    var elem = e.currentTarget;
    var panel = $(elem).closest(".panel");
    if($(elem).hasClass("js-show-orig")){
        $(elem).removeClass("js-show-orig").addClass("js-hide-orig");
        $(elem).text("Show Decrypted");
        panel.find(".email-body").hide();
        panel.find(".encrypted-body").show();
    } else {
        $(elem).removeClass("js-hide-orig").addClass("js-show-orig");
        $(elem).text("Show Original");
        panel.find(".email-body").show();
        panel.find(".encrypted-body").hide();
    }
}

// plaintextBody is of the form:
// ```
// Subject: <subject line>
//
// <body lines...>
// ```
//
// Returns {subject:<subject line>, body:<body...>, ok:<boolean>}
function parseBody(plaintextBody) {
    var parts = REGEX_BODY.exec(plaintextBody);
    if (parts === null) {
        // for legacy emails
        return {subject:"(Unknown subject)", body:plaintextBody, ok:false};
    } else {
        return {subject:parts[1], body:parts[2], ok:true};
    }
}

function addContact() {
    var addr = $(this).data("addr");
    var name = prompt("Contact name for "+addr);
    if (!name) {
        return;
    }
    lookupPublicKeys([addr], function(keyMap) {
        var error =   keyMap[addr].error;
        var pubHash = keyMap[addr].pubHash;
        if (error) {
            alert(error);
            return;
        }
        var contacts = addContacts(
            viewState.contacts,
            {name:name, address:addr, pubHash:pubHash}
        );
        trySaveContacts(contacts, function() {
            showStatus("Contact saved");
        });
    });
}


/**
    Takes an email, selects its js-item, shows the entire thread.
    For convenience, you can pass in the li.js-item jquery element,
     which has the relevant .data() attributes.

    arg should either be $(<box item>) or an email ID object:  
    {
        msgID (id of the selected email)
        threadID (thread id of the selected email)
    }
*/
function showEmail(arg) {
    if (keepUnsavedWork()) { return; }

    var emailID;
    if(!arg){
        return;
    } else if (arg instanceof jQuery) {
        if (arg.length === 0) {
            return;
        }
        emailID = {
            msgID:     arg.data("msgId"),
            threadID:  arg.data("threadId"),
        };
    } else {
        emailID = arg;
    }

    $("#content").empty();
    $(".js-item.active").removeClass("active");
    $(".js-item[data-thread-id='"+emailID.threadID+"']").addClass("active");

    cachedLoadThread(emailID, function(emails) {
        // Construct view modls
        viewState.emails = emails;

        // Construct thread element, show placeholders.
        showEmailThread(emails);
        // Reply, Fwd buttons, etc
        bindEmailEvents();
        // Start decoding. Actual messages appear when this is done.
        decryptEmailThread(emails, function() {
            emails.forEach(function(email) {
                $("#body-"+bin2hex(email.msgID)+".still-decrypting")
                    .removeClass("still-decrypting")
                    .html(email.htmlBody);
            });
        });
    });
}

function decryptEmailThread(emails, cb){
    // Asynchronously verify+decrypt
    var fromAddrs = emails.map("from").map(trimToLower).unique();
    lookupPublicKeys(fromAddrs, function(keyMap, newResolutions) {
        // First, save new pubHashes to contacts so future lookups are faster.
        if (newResolutions.length > 0) {
            trySaveContacts(addContacts(viewState.contacts, newResolutions));
        }

        // Start decrypt+verify on the web workers
        var numDecrypted = 0, numToDecrypt = emails.length;
        emails.forEach(function(email){
            decryptAndVerifyEmail(email, keyMap, function(){
                numDecrypted++;
                if(numDecrypted == numToDecrypt && cb){
                    cb();
                }
            });
        });
    });
}

function cachedLoadThread(emailID, cb){
    if(cache.emailCache.hasOwnProperty(emailID.threadID)){
        // NOTE: we may want to use params.box in the future.
        cb(cache.emailCache[emailID.threadID]);
    } else {
        Api.getThread(emailID).done(function(emailDatas){
            var emails = emailDatas.map(createEmailViewModel);
            cache.emailCache[emailID.threadID] = emails;
            cb(emails);
        }).fail(function(){
            console.log("Could not fetch "+JSON.stringify(emailID));
        });
    }
}

// Decrypts an email. Checks the signature, if there is one.
// Sets email.plainSubject and .plainBody.
function decryptAndVerifyEmail(email, keyMap, cb) {
    var from = email.from;
    var fromKey = keyMap[from].pubKeyArmor;
    if (!fromKey) {
        // TODO: color code to show that the email is unverified
        console.log("No key found for "+from+". This email is unverifiable "+
            "regardless of whether it has a signature.");
    }
    cachedDecryptPgp(email.msgID+" body", email.cipherBody, fromKey, function(plain){
        var parsedBody = parseBody(plain);
        email.plainSubject = parsedBody.subject;
        email.plainBody = parsedBody.body;
        if (!parsedBody.ok) {
            email.plainSubject = "(Encrypted message)";
            email.plainBody = plain;
        }
        if (email.plainBody) {
            email.htmlBody = createHyperlinks(email.plainBody);
        } else {
            email.htmlBody = "<div class='text-danger'>Decryption failed</div>";
        }
        cb(email);
    });
}

function createEmailViewModel(data) {
    // Parse From, To, etc
    var fromAddress = namedAddrFromAddress(data.From);
    var toAddresses = data.To==="" ? [] : 
        data.To.split(",").map(namedAddrFromAddress);

    // The model for rendering the email template
    return {
        msgID:         data.MessageID,
        ancestorIDs:   data.AncestorIDs,
        threadID:      data.ThreadID,
        unixTime:      data.UnixTime,
        time:          new Date(data.UnixTime*1000),
        prettyTime:    moment(data.UnixTime*1000).calendar(), 
        from:          trimToLower(data.From),
        fromAddress:   fromAddress,
        to:            trimToLower(data.To),
        toAddresses:   toAddresses,
        hexMsgID:      bin2hex(data.MessageID),
        isRead:        data.IsRead,
        cipherSubject: data.CipherSubject,
        cipherBody:    data.CipherBody,
        // following are decrypted asynchronously
        plainSubject:  undefined,
        plainBody:     undefined,
        htmlBody:      undefined
    };
}

function showEmailThread(emails) {
    // Mark as read
    // (any more recent emails on the same thread will not be marked)
    markAsRead(emails, true);
    
    // Render HTML
    var tid = emails[emails.length-1].threadID;
    var subj = cache.plaintextCache[tid+" subject"];
    var thread = {
        threadID:    tid,
        hexThreadID: bin2hex(tid),
        subject:     subj==="" ? "(No subject)" : subj,
        box:         viewState.box,
    };
    var elThread = $(render("thread-template", thread)).data("thread", thread);
    for (var i=0; i<emails.length; i++) {
        var email = emails[i];
        email._box = viewState.box; // used to determine which buttons to show
        var elEmail = $(render("email-template", email)).data("email", email);
        elThread.find("#thread-emails").append(elEmail);
    }

    $("#content").empty().append(elThread);
}

function markAsRead(emails, isRead){
	var msgID = emails[emails.length-1].msgID;
	var hexMsgID = emails[emails.length-1].hexMsgID;

	// Update the view models
	var changed = false;
	for(var i = 0; i < emails.length; i++){
		changed |= (emails[i].isRead != isRead);
		emails[i].isRead = isRead;
	}
	
	// Update the view
	$("#box-item-"+hexMsgID)
		.addClass("js-read")
		.removeClass("js-unread");
	
	// Persist the read/unread status
    Api.emailMarkAsRead(msgID, isRead).done(function() {
        // Marked as read
    }).fail(function(xhr) {
        console.log("Marking thread for "+msgID+" as "+
        	(isRead?"read":"unread")+" failed: "+xhr.responseText);
    });
}

// Turns URLS into links in the plaintext.
// Returns safe, escaped HTML
function createHyperlinks(text) {
    var exp = /(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig;
    var match, rawPart, safePart;
    var safeParts = [], lastIx = 0;
    while((match = exp.exec(text)) !== null){
        rawPart = text.substr(lastIx, match.index-lastIx);
        safePart = Handlebars.Utils.escapeExpression(rawPart);
        safeParts.push(safePart);

        var rawUrl = match[0];
        var safeLink = "<a href='"+rawUrl+"' target='_blank'>"+rawUrl+"</a>";
        safeParts.push(safeLink);

        lastIx = match.index+match[0].length;
    }
    rawPart = text.substr(lastIx);
    safePart = Handlebars.Utils.escapeExpression(rawPart);
    safeParts.push(safePart);

    return safeParts.join("");
}

function emailReply(email) {
    if (!email) return;
    var replyTo = email.fromAddress.name || email.fromAddress.address;
    showComposeInline(email, replyTo, email.plainSubject, undefined);
}

function emailReplyAll(email) {
    if (!email) return;

    var allRecipientsExceptMe = email.toAddresses
        .concat([email.fromAddress])
        .filter(function(addr) {
            // don't reply to our self
            return addr.address != sessionStorage["emailAddress"];
        });
    if (allRecipientsExceptMe.length === 0) {
        // replying to myself...
        allRecipientsExceptMe = [namedAddrFromAddress(email.from)];
    }

    var replyTo = allRecipientsExceptMe.map(function(addr) {
        return addr.name || addr.address;
    }).join(",");
    showComposeInline(email, replyTo, email.plainSubject, undefined);
}

function emailForward(email) {
    if (!email) return;
    showComposeInline(email, "", email.plainSubject, email.plainBody);
}

// Moves all emails in box for thread up to email.unixTime.
// That way, server doesn't move new emails that the user hasn't seen.
function threadMove(email, box) {
    if (!email) return;
    if (keepUnsavedWork()) return;
    // Do nothing if already moved.
    if (email._movedToBox == box) {
        return;
    }
    // Confirm if deleting
    if (box == "trash") {
		if (!confirm("Are you sure you want to delete this thread?")) return;
    }
    // Disable buttons while moving
    email._movedToBox = box;
    var elEmail = getEmailElement(email.msgID);
    if(!elEmail){
        // Already moved/archived/deleted, nothing to do
        return;
    }
    var elThread = elEmail.closest("#thread");
	elThread.find(".js-thread-control button").prop("disabled", true);
    
    // Send request
    Api.emailMoveToBox(email.msgID, box).done(function() {
        $("#thread").remove();
        showNextThread();
        showStatus("Moved to "+box);
    }).fail(function(xhr) {
        alert("Move to "+box+" failed: "+xhr.responseText);
    });
}

function getEmailElement(msgID) {
    var elEmail = $(".js-email[data-msg-id='"+msgID+"']");
    if (elEmail.length != 1) {
        console.log("Failed to find exactly 1 email element with msgID:"+msgID);
        return;
    }
    return elEmail;
}

function showNextThread() {
    var newSelection = $(".js-box-item.active").next();
    if (newSelection.length === 0) {
        newSelection = $(".js-box-item.active").prev();
    }
    $(".js-box-item.active").remove();
    showEmail(newSelection);
}



//
// COMPOSE
//

// cb: function(emailData), emailData has plaintext components including
//  msgID, threadID, ancestorIDs, subject, to, body...
function bindComposeEvents(elCompose, cb) {
    elCompose.find(".js-send-button").on('click', function() {
        $(this).prop("disabled", true);

        // generate 160-bit (20 byte) message id
        // secure random generator, so it will be unique
        var msgID = bin2hex(randomBytes(20))+"@"+window.location.hostname;
        var threadID    = elCompose.find("[name='threadID']").val() || msgID;
        var ancestorIDs = elCompose.find("[name='ancestorIDs']").val() || "";
        var subject     = elCompose.find("[name='subject']").val();
        var to          = elCompose.find("[name='to']").val();
        var body        = elCompose.find("[name='body']").val();
        sendEmail(msgID, threadID, ancestorIDs, to, subject, body, function() {
            elCompose.find("[data-default]").removeAttr("data-default");
            cb({
                msgID:       msgID,
                threadID:    threadID,
                ancestorIDs: ancestorIDs,
                subject:     subject,
                to:          to,
                body:        body,
            });
        }, function(error) {
            if(error) {
                alert(error);
            }
            elCompose.find(".js-send-button").prop("disabled", false);
        });
    });
}

function showCompose(to, subject, body) {
    if (keepUnsavedWork()) { return; }
    if (body === undefined) {
        body = DEFAULT_SIGNATURE;
    }

    // Clean up
    var data = {token: sessionStorage["token"]};
    $("#wrapper").html(render("compose-page-template", data));
    bindTabEvents();
    viewState.clearEmails();

    // Go to Compose tab
    setSelectedTab($(".js-tab-compose"));

    showComposeStandalone(to, subject, body);
}

// Shows the standalone compose screen--
// in other words, not part of an existing email thread
function showComposeStandalone(to, subject, body){
    var elCompose = $(render("compose-template", {
        to:          to,
        subject:     subject,
        body:        body,
    }));
    $("#content").empty().append(elCompose);
    bindComposeEvents(elCompose, function(emailData) {
        showStatus("Sent");
        showComposeStandalone();
    });
}

function showComposeInline(email, to, subject, body) {
    var elEmail = $("#thread-emails");
    var bodyDefault;
    if (body !== undefined) {
        if (keepUnsavedWork()) { return; }
        bodyDefault = body;
    } else {
        var elBodyTextarea = elEmail.find(".email-compose textarea[name='body']");
        if (elBodyTextarea.length > 0 && trim(elBodyTextarea.val()) != trim(elBodyTextarea.data("default"))) {
            // User has written something.
            // Try to keep whatever body already exists (for this email)
            body = elBodyTextarea.val() || DEFAULT_SIGNATURE;
            bodyDefault = elBodyTextarea.data("default") || body;
        } else {
            bodyDefault = body = DEFAULT_SIGNATURE;
        }
    }
    var newAncestorIDs = email.ancestorIDs ?
        email.ancestorIDs+" <"+email.msgID+">" :
        "<"+email.msgID+">";
    var elCompose = $(render("compose-template", {
        inline:      true,
        threadID:    email.threadID,
        ancestorIDs: newAncestorIDs,
        to:          to,
        subject:     subject,
        body:        body,
        bodyDefault: bodyDefault,
    }));
    elEmail.find(".email-compose").last().empty().append(elCompose);

    // Focus the Compose box
    setTimeout(function(){elCompose.find("textarea[name=body]").focus();}, 200);

    // Bind events (eg Send button)
    bindComposeEvents(elCompose, function(emailData) {
        showStatus("Sent");
        showEmail(emailData);
    });

}

function keepUnsavedWork() {
    var keepUnsaved = false;
    $("input[data-default], textarea[data-default]").each(function() {
        var el = $(this);
        if (trim(el.val()) != trim(el.data("default"))) {
            if(!confirm("Email has not been sent, continue?")) {
                keepUnsaved = true;
            }
        }
    });
    return keepUnsaved;
}

function sendEmail(msgID, threadID, ancestorIDs, to, subject, body, cb, failCb) {
    // validate email addresses
    var toAddresses = to.split(",").map(trimToLower).filter(Boolean);
    if (toAddresses.length === 0) {
        return failCb("Enter an email address to send to");
    }

    // lookup nicks from contacts
    var errors = [];
    for (var i=0; i<toAddresses.length; i++) {
        var addr = toAddresses[i];
        if (!addr.match(REGEX_EMAIL)) {
            if (addr.match(REGEX_CONTACT_NAME)) {
                var contactAddr = contactAddressFromName(addr);
                if (contactAddr) {
                    toAddresses[i] = contactAddr;
                } else {
                    errors.push("Unknown contact name "+addr);
                    continue;
                }
            } else {
                errors.push("Invalid email address "+addr);
                continue;
            }
        }
    }
    if (errors.length > 0) {
        return failCb("Error:\n"+errors.join("\n"));
    }

    // find a public key for each recipient
    var pubKeys = {}; // {toAddress: <pubKey>}
    lookupPublicKeys(toAddresses, function(keyMap, newResolutions) {
        // Save new addresses to contacts
        if (newResolutions.length > 0) {
            trySaveContacts(addContacts(viewState.contacts, newResolutions));
        }

        // Verify all recipient public keys from keyMap
        var missingKeys = [];
        toAddresses.forEach(function(toAddr){
            var result = keyMap[toAddr];
            pubKeys[toAddr] = result.pubKey || "";
        });

        // If errors, abort.
        if (errors.length > 0) {
            return failCb("Error:\n"+errors.join("\n"));
        }

        sendEmailEncryptedIfPossible(msgID, threadID, ancestorIDs, pubKeys, subject, body, cb, failCb);
    });

    return false;
}

// Send an email, encryyted if psossibie.
// If we don't have pub keys for all recipients, warn the uesr
// and confirm if they want to send the message unencrypted
function sendEmailEncryptedIfPossible(msgID, threadID, ancestorIDs, pubKeysByAddr, subject, body, cb, failCb){
    var addrs = Object.keys(pubKeysByAddr);
    var missingKeys = addrs.filter(function(addr){
        return pubKeysByAddr[addr] === "";
    });

    if (missingKeys.length > 0) {
        if (confirm("Could not find public keys for: "+missingKeys.join(", ")+
            " \nSend unencrypted to all recipients?")) {
            var to = Object.keys(pubKeysByAddr).join(",");
            sendEmailUnencrypted(msgID, threadID, ancestorIDs, to, subject, body, cb, failCb);
        } else {
            failCb();
        }
    } else {
        sendEmailEncrypted(msgID, threadID, ancestorIDs, pubKeysByAddr, subject, body, cb, failCb);
    }
}

/**
    Looks up the public keys for the given addresses, locally or via server.
    First it looks in the contacts list.
    For unknown addresses query the server.
    The server will dispatch to notaries & fetch the public keys as necessary.
    This function verifies the response by computing the hash, etc.

    cb: function(keyMap, newResolutions),

        keyMap => {
            <address>: {

                // For scramble addresses:
                pubHash:     <pubHash>,
                pubKeyArmor: <pubKeyArmor>,
                pubKey:      <pubKey>,

                // For non-scramble addresses:
                pubHash:     undefined,
                pubKeyArmor: undefined,
                pubKey:      undefined,
                
                // For addresses that couldn't be resolved:
                error:       <error string>
            },...
        }

        # Newly resolved contacts, verified by notaries.
        # Caller might want to save them.
        # Note: pubHash may be undefined for non-scramble addresses.
        newResolutions => [{address, pubHash}, ...]

*/
function lookupPublicKeys(addresses, cb) {
    // first, try the cache
    var addrsForLookup = [];
    addresses.forEach(function(addr){
        var contact = getContact(addr);
        if(contact && contact.publicKeyArmored){
            keyMap[addr] = parsePublicKey(contact.publicKeyArmored, addr);
        } else if(cache.keyMap.hasOwnProperty(addr)){
            keyMap[addr] = cache.keyMap[addr];
        } else {
            addrsForLookup.push(addr);
        }
    });

    // all cached? great!
    if(addrsForLookup.length === 0){
        return cb(keyMap, []);
    }

    // not cached? do a notary lookup
    lookupPublicKeysFromNotaries(addresses, function(keyMap, newResolutions){
        for(var addr in keyMap){
            cache.keyMap[addr] = keyMap[addr];
        }

        cb(keyMap, newResolutions);
    });
}

function lookupPublicKeysFromNotaries(addresses, cb) {

    var keyMap = {};         // {<address>: {pubHash, pubKeyArmor, pubKey || error}
    var newResolutions = []; // [{address,pubHash}]

    var needResolution = []; // addresses that need to be notarized
    var needPubKey = []; // addresses for which we need pubkeys
    var knownHashes = {};   // {<address>: <pubHash>}

    addresses.forEach(function(addr){
        var contact = getContact(addr);
        if (contact) {
            if (contact.pubHash) {
                needPubKey.push(addr);
                knownHashes[addr] = contact.pubHash;
            } else {
                knownHashes[addr] = undefined;
                cache.keyMap[addr] = keyMap[addr] = {
                    pubHash:     undefined,
                    pubKeyArmor: undefined,
                    pubKey:      undefined,
                };
            }
        } else {
            needResolution.push(addr);
            needPubKey.push(addr);
        }
    });

    // Nothing to look up
    if (needResolution.length === 0 && needPubKey.length === 0) {
        return cb(keyMap, newResolutions);
    }

    loadNotaries(function(notaryKeys) {
        var notaries = Object.keys(notaryKeys);

        Api.postNotaryQuery(needResolution, needPubKey, notaries).done(function(data) {

            var nameResolution = data.nameResolution;
            var publicKeys =     data.publicKeys;

            // verify notary responses
            if (needResolution.length > 0) {
                var res = verifyNotaryResponses(notaryKeys, needResolution, nameResolution);
                // TODO improve error handling
                if (res.errors.length > 0) {
                    alert(res.errors.join("\n\n"));
                    return; // halt, do not call cb.
                }
                if (res.warnings.length > 0) {
                    alert(res.warnings.join("\n\n"));
                }
                for (var a in res.pubHashes) {
                    knownHashes[a] = res.pubHashes[a];
                }
            }

            // de-armor keys and set pubHash on the results,
            // and verify against knownHashes.
            for(var addr in publicKeys) {
                var result = publicKeys[addr];
                if (result.status == "ERROR" || result.status == "NO_SUCH_USER") {
                    keyMap[addr] = {error:result.error};
                    continue;
                } else if (result.status == "OK") {
                    var pubKeyArmor = result.pubKey;
                    var pubKeyObj = parsePublicKey(result.pubKey, addr, knownHashes[addr]);
                    if(pubKeyObj.error){
                        alert(pubKeyObj.error);
                        return; // halt, do not call cb.
                    }
                    if (needResolution.indexOf(addr) != -1) {
                        newResolutions.push({address:addr, pubHash:knownHashes[addr]});
                    }
                    keyMap[addr] = pubKeyObj;
                } else if (result.status == "NOT_SCRAMBLE") {
                    newResolutions.push({address:addr, pubHash: undefined});
                    keyMap[addr] = {
                        pubKey:      undefined,
                        pubKeyArmor: undefined,
                        pubHash:     undefined,
                    };
                }
            }

            // ensure that we have results for all the query addresses.
            for (var i=0; i<addresses.length; i++) {
                var address = addresses[i];
                if (keyMap[address] === null) {
                    console.log("Missing lookup result for "+address+". "+
                                "Bad server impl?");
                    keyMap[address] = {error:"ERROR: Missing lookup result"};
                }
            }

            cb(keyMap, newResolutions);
        }).fail(function(xhr){
            console.log("Notary request failed: "+xhr.responseText);
        });
    });
}

// Takes PGP-armored public key and email address (needed for error messages).
// Optionally takes an expected hash--if provided, verifies that 
// pubHash(pubKeyArmor) == expectedHash
//
// Returns {pubKey:..., pubKeyArmor:..., pubHash:..., error:...}
function parsePublicKey(pubKeyArmor, addr, expectedHash){
    var computedHash = computePublicHash(pubKeyArmor);
    if (typeof(expectedHash)!=="undefined" && expectedHash != computedHash){
        return {error:"SECURITY WARNING! We received an incorrect key for "+addr};
    }
    var pka;
    try {
        pka  = openpgp.key.readArmored(pubKeyArmor).keys[0];
    } catch(e){
        return {error:"Couldn't parse PGP public key for "+addr+". Please make sure it's a valid PGP armored public key."};
    }
    // return {error:"Incorrect number of public keys in armor for address "+addr};
    return {
        pubKey:      pka,
        pubKeyArmor: pubKeyArmor,
        pubHash:     computedHash,
    };
}

// addrPubKeys: {toAddress: <pubKey>}
function sendEmailEncrypted(msgID, threadID, ancestorIDs, addrPubKeys, subject, body, cb, failCb) {
    // Get the private key so we can sign the encrypted message
    var privateKey = getPrivateKey();
    // Get the public key so we can also read it in the sent box
    //var publicKey = getPublicKey();

    // Encrypt message for all recipients in `addrPubKeys`
    var pubKeys = Object.values(addrPubKeys);
    //pubKeys.push(publicKey[0]);
    pubKeys = pubKeys.unique(function(pubKey) { return pubKey.getKeyIds()[0]; });
    
    // Embed the subject into the body for verification
    var cipherSubject = openpgp.signAndEncryptMessage(pubKeys, privateKey, subject);
    var subjectAndBody = "Subject: "+subject+"\n\n"+body;
    var cipherBody = openpgp.signAndEncryptMessage(pubKeys, privateKey, subjectAndBody);

    // Send our message
    var data = {
        msgID:         msgID,
        threadID:      threadID,
        ancestorIDs:   ancestorIDs,
        to:            Object.keys(addrPubKeys).join(","),
        cipherSubject: cipherSubject,
        cipherBody:    cipherBody
    };
    sendEmailPost(data, cb, failCb);
}

function sendEmailUnencrypted(msgID, threadID, ancestorIDs, to, subject, body, cb, failCb) {
    // Send our message unencrypted to all recipients
    var data = {
        msgID:         msgID,
        threadID:      threadID,
        ancestorIDs:   ancestorIDs,
        to:            to,
        subject:       subject,
        body:          body
    };
    sendEmailPost(data, cb, failCb);
}

function sendEmailPost(data, cb, failCb) {
    Api.emailSend(data).done(function() {
        // HACK, clear cached thread.
        // Alternatively, we could just create a new email model object client-side
        // and just inject it into the cache.
        delete cache.emailCache[data.threadID];
        cb();
    }).fail(function(xhr) {
        failCb("Sending failed:\n"+xhr.responseText);
    });
}



//
// CONTACTS
//

function showContacts() {
    if (keepUnsavedWork()) { return; }
    loadAndDecryptContacts(function(contacts) {
        // clean up 
        viewState.clearEmails();
        var data = {token: sessionStorage["token"]};
        $("#wrapper").html(render("page-template", data));
        bindTabEvents();

        // go to Contacts
        setSelectedTab($(".js-tab-contacts"));

        // create view models
        var contactViewModels = contacts.map(createContactViewModel);
        var me = getContactByAddress(contactViewModels, sessionStorage["emailAddress"]);
        me.name = "Me";

        // sort contacts list. "me" first, then others by email
        contactViewModels.sort(function(a,b){
            if (a == b){
                return 0;
            } else if (a == me){
                return -1;
            } else if (b == me){
                return 1;
            } else if(a.address < b.address){
                return -1;
            } else if(a.address > b.address){
                return 1;
            } else{
                return 0;
            }
        });

        // render contacts list in the sidebar
        var model = {
            "contacts": contactViewModels,
            "hasContacts": contactViewModels.length > 1 // contacts other than self
        };
        $(".box").html(render("contacts-list-template", model));

        // render the user's own info as the content
        bindContactsEvents();
        showContact($(".js-item").first());
    });
}

// Takes a contact object. Returns a new object with the same fields
// and some additional fields:
//
// Contact fields           {"name", "address", "pubHash", "pubKeyArmored",
// ...additional fields:     "hasKey":true/false, 
//                           "myName":"dcposch"
//                          }
//
// (Remember that we save encrypt(JSON.stringify([{contact object}, ...]))
function createContactViewModel(c){
    return {
        "name":c.name,
        "address":c.address,
        "pubHash":c.pubHash,
        "publicKeyArmored":c.publicKeyArmored,
        "hasKey":!!(c.pubHash || c.publicKeyArmored)
    };
}

function bindContactsEvents() {
    $(".js-item").click(function(e){
        showContact($(e.currentTarget));
    });
    $(".js-add-contact").click(function(e){
        var address = trim($("#contact-add-email").val());
        if (address === "") {
            alert("Enter an email address first");
            return;
        } else if (getContact(address) !== null){
            alert(address + " already exists");
            return;
        }
        $("#contact-add-email").val("");

        // TODO: save
        var contact = {"address":address};
        viewState.contacts.push(contact);
        var elem = $(render("contact-template", contact));
        $(".js-items").append(elem);
        showContact(elem, true);
    });
}

// Takes a contacts list item. The first argument should be a 1-element JQuery array.
// The editMode argument should be true or false.
// Selects the item. Shows the contact detail.
function showContact(elem, editMode) {
    // Get the contact
    var address = elem.data("address");
    var contact = getContact(address); 
    if (contact === null){
        // Should never happen
        alert("Could not find contact "+address);
        return;
    }

    // Select the item
    $(".js-item.active").removeClass("active");
    elem.addClass("active");

    // Show the detail
    viewState.contact = contact;
    if (contact.address == sessionStorage["emailAddress"]) {
        showSelfDetails(contact);
    } else if(editMode) {
        showContactEditDetails();
    } else {
        showContactDetails();
    }
}

// Displays a special detail view for the "contact"
// corresponding to the logged in user.
// 
// This page lets the user see his own public+private keys.
function showSelfDetails(contact){
    var model = createContactViewModel(contact);
    model.publicKeyArmored = sessionStorage["publicKeyArmored"];
    model.privateKeyArmored = sessionStorage["privateKeyArmored"];
    model.name = sessionStorage["token"];
    $("#content").html(render("contact-self-template", model));
    bindContactDetails();
}

// Displays the detail view for the currently selected
// contact (viewState.contacts).
function showContactDetails(){
    loadContactPublicKey(viewState.contact, function(publicKeyArmored){
        var model = createContactViewModel(viewState.contact);
        model.publicKeyArmored = publicKeyArmored;
        $("#content").html(render("contact-detail-template", model));
        bindContactDetails();
    });
}

// If contact has a public key set directly, calls cb(pubKeyArmored)
// If contact is a Scramble contact, looks up pubKey, then calls cb(pubKeyArmored)
// Otherwise, if no key is available, calls cb(null)
function loadContactPublicKey(contact, cb){
    if(contact.publicKeyArmored){
        cb(contact.publicKeyArmored);
    } else if(!contact.pubHash){
        cb(null);
    } else {
        lookupPublicKeys([contact.address], function(keyMap) {
            cb(keyMap[contact.address].pubKeyArmor);
        });
    }
}

function bindContactDetails(){
    $(".js-edit-contact").click(showContactEditDetails);
    $(".js-delete-contact").click(function(){
        if(!confirm("Are you sure you want to delete "+viewState.contact.address+"?")){
            return;
        }
        var newContacts = viewState.contacts.filter(function(c){
            return c != viewState.contact;
        });
        trySaveContacts(newContacts, function() {
            showStatus("Contact deleted");
            showContacts();
        });
    });
}

function showContactEditDetails(){
    loadContactPublicKey(viewState.contact, function(publicKeyArmored){
        var model = createContactViewModel(viewState.contact);
        model.publicKeyArmored = publicKeyArmored;
        $("#content").html(render("edit-contact-template", model));
        bindContactEditDetails();
    });
}


function bindContactEditDetails(){
    $(".js-save-contact").click(function(){
        var name = trim($(".js-name").val());
        var address = trimToLower($(".js-address").val());
        if (address === "") {
            alert("Enter an email address first");
            return;
        } else if (getContact(address) !== null &&
                   getContact(address) !== viewState.contact){
            alert(address + " already exists");
            return;
        }
        viewState.contact.name = name;
        viewState.contact.address = address;
        // For Scramble contacts--which have a notarized pubHash--
        // the public key is not editable
        if(!viewState.contact.pubHash){
            var pubKey = trim($(".js-public-key").val());
            if(pubKey !== ""){
                // Make sure this is a valid PGP key
                var pubKeyObj = parsePublicKey(pubKey, address);
                if (pubKeyObj.error){
                    alert(pubKeyObj.error);
                    return;
                }
            }
            viewState.contact.publicKeyArmored = pubKey;
        }

        trySaveContacts(viewState.contacts, function() {
            showStatus("Contacts saved");
            showContacts();
        });
    });
    $(".js-cancel-contact").click(showContactDetails);
    $(".js-keybase-lookup").click(function(){
        var guessUser = viewState.contact.address.split("@")[0];

        var modal = $("#modal-keybase");
        modal.find(".js-keybase-user").val(guessUser);
        modal.find(".js-keybase-proof").hide();
        modal.find(".js-keybase-buttons").hide();
        modal.modal("show");
        updateKeybaseUser();
    });
    $(".js-keybase-submit").click(function(){
        var pubKey = $(".js-keybase-public-key").text();
        $(".js-public-key").val(pubKey);
        $("#modal-keybase").modal('hide');
    });

    $("#modal-keybase .js-keybase-user").keyup(updateKeybaseUser);
}

var xhrKeybase;
function updateKeybaseUser(){
    if(xhrKeybase) {
        xhrKeybase.abort();
        xhrKeybase = null;
    }
    var user = $("#modal-keybase .js-keybase-user").val();
    xhrKeybase = keybaseLookup(user, function(key){
        var link = $("<a />").prop("href", "https://keybase.io/"+user).text("Verify "+user+" on Keybase");
        var key = $("<div class='js-keybase-public-key contact-key'>").text(key.bundle);
        var proof = $("<div />").append(link).append(key);
        $("#modal-keybase .js-keybase-error").hide();
        $("#modal-keybase .js-keybase-proof").html(proof).show();
        $("#modal-keybase .js-keybase-buttons").show();
        xhrKeybase = null;
    }, function(error){
        $("#modal-keybase .js-keybase-error").text(error).show();
        $("#modal-keybase .js-keybase-proof").hide();
        $("#modal-keybase .js-keybase-buttons").hide();
        xhrKeybase = null;
    });
}

// Returns {contacts || errors}
//     contacts => [{name?,address,pubHash},..]
//     errors   => [<error>,...}
function validateContacts(contacts) {

    if (!(contacts instanceof Array)) {
        throw "Invalid input to validateContacts";
    }

    var errors = [];
    var lnames = {};         // unique by lowercased name
    var addresses = {};      // unique by address
    var cleanContacts = [];

    for (var i = 0; i < contacts.length; i++) {
        var contact = contacts[i];
        var name = contact.name ? trim(contact.name) : undefined;
        var lname = name ? name.toLowerCase() : undefined;
        var address = trimToLower(contact.address);
        var addressMatch = address.match(REGEX_EMAIL);
        var pubHash = contact.pubHash ? trimToLower(contact.pubHash) : undefined;
        var pubKey = contact.publicKeyArmored;

        if (name && !name.match(REGEX_CONTACT_NAME)) {
            errors.push("Invalid contact name: "+name);
        }

        if (address === "") {
            errors.push("No email address for name: "+name);
        } else if (!addressMatch) {
            errors.push("Invalid email address: "+address);
        }

        if (addresses[address]) {
            errors.push("Duplicate email address: "+address);
        } else {
            addresses[address] = true;
        }

        if (lname) {
            if (lnames[lname]) {
                errors.push("Duplicate name: "+lname);
            } else {
                lnames[lname] = true;
            }
        }

        var cleanContact = {
            address:address
        };
        if(name){ cleanContact.name = name; }
        if(pubHash){ cleanContact.pubHash = pubHash; }
        if(pubKey){ cleanContact.publicKeyArmored = pubKey; }
        cleanContacts.push(cleanContact);
    }

    return {contacts:cleanContacts, errors:errors};
}

function trySaveContacts(contacts, done) {

    var contactsErr = validateContacts(contacts);

    // if there are mistakes, tell the user and bail
    if (contactsErr.errors.length > 0) {
        alert(contactsErr.errors.join("\n"));
        return;
    } 

    // set viewState.contacts now, before posting.
    // this prevents race conditions.
    viewState.contacts = contacts;

    // encrypt it
    var jsonContacts = JSON.stringify({
        version:  CONTACTS_VERSION,
        contacts: contacts,
    });
    var cipherContacts = passphraseEncrypt(jsonContacts);
    if (!cipherContacts) return;

    // send it to the server
    Apis.putContacts(bin2hex(cipherContacts))
        .done(done)
        .fail(function(xhr) {
            alert("Saving contacts failed: "+xhr.responseText);
        });
}

// contacts: an array of existing contacts, e.g. viewState.contacts
// newContacts: new contacts (or a single contact) to merge into contacts
//   where contact is of the form {name, address, pubHash},
//   name and pubHash are optional.
// Returns new array of contacts
function addContacts(contacts, newContacts) {
    // convenience
    if (! (newContacts instanceof Array)) {
        newContacts = [newContacts];
    }

    // create a new array, don't modify the old one.
    var allContacts = contacts.map(function(c){
        return {name:c.name, pubHash:c.pubHash, address:c.address};
    });
    // defensively delete reference to original contacts.
    contacts = null;

    // add each of [newContacts] to [allContacts]
    newContacts.forEach(function(newContact){
        var name = newContact.name;
        var address = newContact.address;
        var pubHash = newContact.pubHash;
        if (!address) {
            throw "addContacts() new contacts require address";
        }

        // If address is already in contacts, just set the name.
        // Otherwise, create a new one
        var existing = getContactByAddress(allContacts, address);
        if (existing) {
            if(name) {
                existing.name = name;
            }
        } else {
            var c = {
                name:    name ? trim(name) : undefined,
                address: trimToLower(address),
                pubHash: pubHash ? trimToLower(pubHash) : undefined,
            };
            allContacts.push(c);
        }
    });

    return allContacts;
}

function getContactByAddress(allContacts, address){
    if (address === null){
        return null;
    }
    address = trimToLower(address);
    for (var i=0; i<allContacts.length; i++) {
        if (allContacts[i].address === address) {
            return allContacts[i];
        }
    }
    return null;
}

function getContact(address) {
    if (viewState.contacts === null) {
        return null;
    }
    return getContactByAddress(viewState.contacts, address);
}

function contactNameFromAddress(address) {
    var contact = getContact(address);
    if (contact) {
        return contact.name;
    }
    return null;
}

function contactAddressFromName(name) {
    if (viewState.contacts === null) {
        return null;
    }
    name = trimToLower(name);
    for (var i = 0; i < viewState.contacts.length; i++) {
        var contact = viewState.contacts[i];
        if (contact.name && contact.name.toLowerCase() === name) {
            return contact.address;
        }
    }
    return null;
}

function isContactNameTaken(name){
    return contactAddressFromName(name) !== null;
}

function namedAddrFromAddress(address) {
    var addr = trimToLower(address);
    return {
        address: addr,
        name: contactNameFromAddress(addr)
    };
}

function getContacts(fn) {
    if (viewState.contacts) {
        fn(viewState.contacts);
    } else {
        loadAndDecryptContacts(fn);
    }
}

function loadAndDecryptContacts(fn) {
    if (!sessionStorage["passKey"]) {
        alert("Missing passphrase. Please log out and back in.");
        return;
    }

    Api.getContacts().done(function(cipherContactsHex) {
        var cipherContacts = hex2bin(cipherContactsHex);
        var jsonContacts = passphraseDecrypt(cipherContacts);
        if (!jsonContacts) {
            return;
        }
        var parsed = JSON.parse(jsonContacts);
        if (parsed.version === undefined) {
            migrateContactsReverseLookup(parsed, function(contacts) {
                viewState.contacts = contacts;
                fn(viewState.contacts);
            });
        } else if (parsed.version == CONTACTS_VERSION) {
            viewState.contacts = parsed.contacts;
            fn(viewState.contacts);
        }
    }, "text").fail(function(xhr) {
        if (xhr.status == 404) {
            viewState.contacts = [{
                name: "me",
                address: getUserEmail(),
                pubHash: sessionStorage["pubHash"],
            }];
            fn(viewState.contacts);
        } else {
            alert("Failed to retrieve our own encrypted contacts: "+xhr.responseText);
        }
    });
}

// If contacts is legacy version (where address is <pubHash>@<host> format
//  and pubHash key is missing) then convert it via reverse lookup.
function migrateContactsReverseLookup(contacts, fn) {
    var lookup = [];
    var pubHashToName = {};
    for (var i=0; i<contacts.length; i++) {
        var contact = contacts[i];
        if (contact.pubHash === undefined) {
            var pubHash = contact.address.split("@")[0];
            if (pubHash.length != 16 && pubHash.length != 40) {
                alert("Error: expected legacy contacts list to have hash address: "+contact.address);
                return;
            }
            lookup.push(pubHash);
            pubHashToName[pubHash] = contact.name;
        } else {
            if (lookup.length > 0) {
                alert("Error: expected legacy contact format but found one with pubHash already");
                return;
            }
        }
    }
    if (lookup.length > 0) {
        Api.getPubHashToAddress(lookup).done(function(pubHashToAddress) {
            var addresses = [], hashesDeleted = [];
            for (var hash in pubHashToAddress) {
                if (pubHashToAddress[hash]==="") {
                    console.log("Warning: deleting nonexistent legacy contact "+hash+"@scramble.io");
                    hashesDeleted.push(hash);
                } else {
                    addresses.push(pubHashToAddress[hash]);
                }
            }

            // we have pubHash -> address.
            // now let's resolve these addresses.
            lookupPublicKeys(addresses, function(keyMap) {
                var newContacts = [];
                for (var address in keyMap) {
                    var pubHash = keyMap[address].pubHash;
                    newContacts.push({name:pubHashToName[pubHash], pubHash:pubHash, address:address});
                }
                var hashesFound = newContacts.map("pubHash");
                var remaining = lookup.subtract(hashesFound).subtract(hashesDeleted);
                if (remaining.length > 0) {
                    alert("Error: contacts migration failed for address(es): "+remaining.join(","));
                    return;
                }
                trySaveContacts(newContacts, function() {
                    fn(newContacts);
                });
            });
        }, "json");
    } else {
        fn(contacts); // nothing to upgrade
    }
}



//
// NOTARY
//

function verifyNotaryResponses(notaryKeys, addresses, notaryResults) {

    var notaries = Object.keys(notaryKeys);
    var pubHashes = {}; // {<address>:<pubHash>}
    var notarized = {}; // {<address>:[<notary1@host>,...]}
    var warnings = [];
    var errors = [];

    for (var notary in notaryKeys) {
        var notaryPublicKey = notaryKeys[notary];
        var notaryRes = notaryResults[notary];
        if (notaryRes.error) {
            // This may be ok if there were enough notaries that succeeded.
            warnings.push("Notary "+notary+" failed: "+notaryRes.error);
            continue;
        }
        // Check the signature & check for agreement.
        for (var address in notaryRes.result) {
            var addressRes = notaryRes.result[address];
            addressRes.address = address;
            if (addresses.indexOf(address) == -1) {
                // This is strange, notary responded with a spurious address.
                // Handle with care.
                errors.push("Unsolicited notary response from "+notary+" for "+address);
                continue;
            }
            if (!verifyNotarySignature(addressRes, notaryPublicKey)) {
                // This is a serious error in terms of security.
                // Handle with care.
                errors.push("Invalid notary response from "+notary+" for "+address);
                continue;
            }
            if (notarized[address]) {
                if (pubHashes[address] != addressRes.pubHash) {
                    // This is another serious error in terms of security.
                    // There is disagreement about name resolution.
                    // Handle with care.
                    errors.push("Notary conflict for "+address);
                    continue;
                }
                notarized[address].push(notary);
            } else {
                notarized[address] = [notary];
                pubHashes[address] = addressRes.pubHash;
            }
        }
    }

    // For now, make sure that all notaries were successful.
    // In the future we'll be more flexible with occasional errors,
    //  especially when we have more notaries serving.
    var missingNotaries = [], missingAddresses = [];
    addresses.forEach(function(address){
        var missingNotariesForAddress = notaries.filter(function(notary){
            return !notarized[address] || notarized[address].indexOf(notary) < 0;
        });
        if(missingNotariesForAddress.length > MAX_MISSING_NOTARIES){
            missingAddresses.push(address);
        } else if (missingNotariesForAddress.length > 0) {
            // this address is *NOT* available from at least one notary, or
            // at least one notary server is down
            console.log("Warning: did NOT get a public key for "+address+
                " from: "+missingNotariesForAddress.join(",")+". " +
                "However, we got enough responses to proceed.");
        }
        addAllToSet(missingNotariesForAddress, missingNotaries);
    });
    if(missingAddresses.length > 0){
        // for at least one address, we did not get enough notary responses to proceed
        errors.push("Couldn't get a trusted public key for "+missingAddresses.join(", ")+". "+
            "The following notaries haven't signed: "+missingNotaries.join(", "));
    }
    return {warnings:warnings, errors:errors, pubHashes:pubHashes};
}

// Load list of notaries.
// cb: function(notaries), notaries: {<host>:<publicKey>, ...}
function loadNotaries(cb) {
    if (viewState.notaries) {
        cb(viewState.notaries);
    } else if (sessionStorage["/publickeys/notary"]) {
        var data = JSON.parse(sessionStorage["/publickeys/notary"]);
        var notaries = parseNotaries(data.notaries);
        cb(notaries);
    } else {
        Api.getNotaries().done(function(data) {
            var notaries = parseNotaries(data.notaries);
            if (!notaries) {
                alert("Failed to retrieve default notaries from server!");
                return;
            }
            sessionStorage["/publickeys/notary"] = JSON.stringify(data);
            cb(notaries);
        });
    }
}

// notaries: {<notaryName>:<pubKeyArmor>}
// returns {<notaryName>:<pubKey>}
function parseNotaries(notaries) {
    var parsed = {};
    for (var host in notaries) {
        var pubKey = notaries[host];
        parsed[host] = openpgp.key.readArmored(pubKey);
    }
    return parsed;
}

// Ensure that notaryRes is properly signed with notaryPublicKey.
// notaryRes: {address,pubHash,timestamp,signature}
// returns true or false
function verifyNotarySignature(notaryRes, notaryPublicKey) {
    var toSign = notaryRes.address+"="+(notaryRes.pubHash||"")+"@"+notaryRes.timestamp;
    var sig = openpgp.message.readArmored(notaryRes.signature);
    return sig[0].signature.verify(toSign, {obj:notaryPublicKey[0]});
}



//
// CRYPTO
//

// Uses a key derivation function to create an AES-128 key
// Returns 128-bit binary
var scrypt = scrypt_module_factory();
function computeAesKey(token, pass) {
    var salt = "2"+token;
    return hex2bin(computeScrypt(pass, salt, 16)); // 16 bytes = 128 bits
}

// Backcompat only: uses SHA1 to create a AES-128 key (binary)
// Returns 128-bit binary
function computeAesKeyOld(token, pass) {
    var sha1 = openpgp.crypto.hash.sha1("2"+token+pass);
    return sha1.substring(0, 16); // 16 bytes = 128 bits
}

// Uses a key derivation function to compute the user's auth token
// Returns 160-bit hex
function computeAuth(token, pass) {
    var salt = "1"+token;
    return computeScrypt(pass, salt, 20); // 20 bytes = 160 bits
}

function computeScrypt(pass, salt, nbytes) {
    var param = SCRYPT_PARAMS;
    var hash = scrypt.crypto_scrypt(
            scrypt.encode_utf8(pass), 
            scrypt.encode_utf8(salt), 
            param.N, param.r, param.p, // difficulty
            nbytes
        );
    return scrypt.to_hex(hash);
}

// Backcompat only: old SHA1 auth token
// Returns 160-bit hex
function computeAuthOld(token, pass) {
    return bin2hex(openpgp.crypto.hash.sha1("1"+token+pass));
}

// Symmetric encryption using a key derived from the user's passphrase
// The user must be logged in: the key must be in sessionStorage
function passphraseEncrypt(plainText) {
    if (!sessionStorage["passKey"] || sessionStorage["passKey"] == "undefined") {
        alert("Missing passphrase. Please log out and back in.");
        return null;
    }
    var prefixRandom = openpgp.crypto.getPrefixRandom("aes128");
    plainText = openpgp.util.encode_utf8(plainText);
    return openpgp.crypto.cfb.encrypt(
        prefixRandom, 
        "aes128", 
        plainText,
        sessionStorage["passKey"]);
}

// Symmetric decryption using a key derived from the user's passphrase
// The user must be logged in: the key must be in sessionStorage
function passphraseDecrypt(cipherText) {
    if (!sessionStorage["passKey"] || sessionStorage["passKey"] == "undefined") {
        alert("Missing passphrase. Please log out and back in.");
        return null;
    }
    var plain;
    try {
        plain = openpgp.crypto.cfb.decrypt(
            "aes128", 
            sessionStorage["passKey"], 
            cipherText);
    } catch(e) {
        // Backcompat: people with old accounts had weaker key derivation
        plain = openpgp.crypto.cfb.decrypt(
            "aes128", 
            sessionStorage["passKeyOld"], 
            cipherText);
        console.log("Warning: old account, used backcompat AES key");
    }
    return openpgp.util.decode_utf8(plain);
}

// Returns the first 80 bits of a SHA1 hash, encoded with a 5-bit ASCII encoding
// Returns a 16-byte string, eg "tnysbtbxsf356hiy"
// This is the same algorithm and format Onion URLS use
function computePublicHash(str) {
    // SHA1 hash
    var sha1Hex = bin2hex(openpgp.crypto.hash.sha1(str));

    // extract the first 80 bits as a string of "1" and "0"
    var sha1Bits = [];
    // 20 hex characters = 80 bits
    for (var i = 0; i < 20; i++) {
        var hexDigit = parseInt(sha1Hex[i], 16);
        for (var j = 0; j < 4; j++) {
            sha1Bits[i*4+3-j] = ((hexDigit%2) == 1);
            hexDigit = Math.floor(hexDigit/2);
        }
    }
    
    // encode in base-32: letters a-z, digits 2-7
    var hash = "";
    // 16 5-bit chars = 80 bits
    var ccA = "a".charCodeAt(0);
    var cc2 = "2".charCodeAt(0);
    for (var k = 0; k < 16; k++) {
        var digit =
            sha1Bits[k*5]*16 + 
            sha1Bits[k*5+1]*8 + 
            sha1Bits[k*5+2]*4 + 
            sha1Bits[k*5+3]*2 + 
            sha1Bits[k*5+4];
        if (digit < 26) {
            hash += String.fromCharCode(ccA+digit);
        } else {
            hash += String.fromCharCode(cc2+digit-26);
        }
    }
    return hash;
}

function getPrivateKey() {
    var armor = sessionStorage["privateKeyArmored"];
    return openpgp.key.readArmored(armor).keys[0];
}


//
// UTILITY
//

// Adds all members of the first list to the second, avoiding duplicates.
function addAllToSet(arrA, arrB){
    for(var i = 0; i < arrA.length; i++){
        if(arrB.indexOf(arrA[i]) == -1){
            arrB.push(arrA[i]);
        }
    }
}

// Renders a Handlebars template, reading from a <script> tag. Returns HTML.
var templates = {};
function render(templateID, data) {
    if (!templates) {
        alert("Missing template "+templateID);
        return "";
    }
    return templates[templateID](data);
}

function initHandlebars() {
    // Usage: {{formatDate myDate format="MMM YY"}} for "Aug 2013"
    Handlebars.registerHelper('formatDate', function(context, block) {
        var str = block.hash.format || "YYYY-MM-DD";
        return moment(context).format(str);
    });

    // Usage: {{ifCond something '==' other}}
    Handlebars.registerHelper('ifCond', function (v1, operator, v2, options) {
        switch (operator) {
            case '==':
                return (v1 == v2) ? options.fn(this) : options.inverse(this);
            case '===':
                return (v1 === v2) ? options.fn(this) : options.inverse(this);
            case '<':
                return (v1 < v2) ? options.fn(this) : options.inverse(this);
            case '<=':
                return (v1 <= v2) ? options.fn(this) : options.inverse(this);
            case '>':
                return (v1 > v2) ? options.fn(this) : options.inverse(this);
            case '>=':
                return (v1 >= v2) ? options.fn(this) : options.inverse(this);
            default:
                return options.inverse(this);
        }
    });

    // Read and compile all Handlebars templates and partials
    $("script").each(function() {
        var source = this.textContent;
        if (!this.id) {
            return;
        } else if (this.id.endsWith("-template")) {
            templates[this.id] = Handlebars.compile(source);
        } else if (this.id.endsWith("-partial")) {
            Handlebars.registerPartial(this.id, source);
        }
    });
}

// The Scramble email address of the currently logged-in user
function getUserEmail() {
    return sessionStorage["token"]+"@"+window.location.hostname;
}

function randomBase64(n){
    var randomBuf = new Uint8Array(n);
    window.crypto.getRandomValues(randomBuf);
    return btoa(String.fromCharCode.apply(null, randomBuf));
}
function randomBytes(n){
    var randBuf = new Uint8Array(n);
    window.crypto.getRandomValues(randBuf);
    return String.fromCharCode.apply(null, randBuf);
}
function bin2hex(str) {
    return openpgp.util.hexstrdump(str);
}
function hex2bin(str) {
    return openpgp.util.hex2bin(str);
}
function trim(str) {
    return str.replace(/^\s+|\s+$/g,'');
}
function trimToLower(str) {
    return trim(str).toLowerCase();
}

function initAjaxAuth() {
    // Adds cookie-like headers for every request...
    $.ajaxSetup({
        // http://stackoverflow.com/questions/7686827/how-can-i-add-a-custom-http-header-to-ajax-request-with-js-or-jquery
        beforeSend: function(xhr) {
            xhr.setRequestHeader('x-scramble-token', sessionStorage["token"]);
            xhr.setRequestHeader('x-scramble-passHash', sessionStorage["passHash"]);
            xhr.setRequestHeader('x-scramble-passHashOld', sessionStorage["passHashOld"]);
        }
    });
}

function initMomentJS() {
    moment.lang('en', {
        calendar : {
            sameDay : '[Today] LT',
            lastDay : '[Yesterday]',
            lastWeek: 'll',
            sameElse: 'll',
            nextDay : 'll',
            nextWeek: 'll'
        }
    });
}
