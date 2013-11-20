//
// SCRAMBLE.IO
// Secure email for everyone
// by DC - http://dcpos.ch/
//



//
// CONSTANTS
// See https://tools.ietf.org/html/rfc4880
//

var KEY_TYPE_RSA = 1;
var KEY_SIZE = 2048;

var ALGO_SHA1 = 2;
var ALGO_AES128 = 7;

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

var HOST_PREFIX = sessionStorage["hostPrefix"] || ''; // for chrome extension

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
// sessionStorage["privateKeyArmored"] is the plaintext private key, PGP ascii armored
//
// For convenience, we also have
// sessionStorage["pubHash"] +"@scramble.io" is the email of the logged-in user
// sessionStorage["publicKeyArmored"] is the extracted public key of the privateKey.
//   -> This is used for encrypting to self. The hash may or may not be equal to pubHash.
//



//
// VIEW VARIABLES
// These are even more transient than session variables.
// They go away if you hit Refresh.
//

var viewState = {};

// current box (e.g. inbox, sent, archive)
viewState.box = null;

// all emails in the current thread.
// [{
//     From,
//     To,
//     CipherBody,
//     ...,
//     viewModel?: { # only exists if decrypted.
//         from,
//         to,...
//     }
// },...]
viewState.emails = null;
// Returns the last email
viewState.getLastEmail = function() {
    return this.emails == null ? null : this.emails[this.emails.length-1].viewModel;
}
// Returns the last email from another user.
viewState.getLastEmailFromAnother = function() {
    if (!this.emails) {
        return null;
    }
    for (var i=this.emails.length-1; 0 <= i; i--) {
        var email = this.emails[i];
        if (!email.viewModel) {
            continue;
        }
        if (email.from != sessionStorage["emailAddress"]) {
            return email.viewModel;
        }
    }
    // just return the last email even from self.
    return this.getLastEmail();
}
viewState.clearEmails = function() {
    this.box = null;
    this.emails = null;
}

viewState.contacts = null; // plaintext address book, must *always* be good data.
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
cache.plaintextCache = {}; 



//
// LOAD THE SITE
// Called on load: $(main)
//

function main() {
    console.log("Hello World");

    // initialize browser crypto
    if (!initPGP()) {
        alert("Sorry, your browser doesn't support cryptography.\n"+
            "You'll need a recent version of Chrome, Firefox, or Safari.\n\n"+
            "The Tor Browser Bundle unfortunately ships an old version of FF :(\n"+
            "To use Scramble thru Tor, we recommend using Chrome in Incognito mode "+
            "through the SOCKS proxy which the Tor Browser Bundle / Vidalia provides.");
        return;
    }

    // initialize the ui
    initHandlebars();
    initAjaxAuth();
    bindKeyboardShortcuts();

    // are we logged in?
    if (!isLoggedIn()) {
        console.log("Please log in.");
        displayLogin();
    } else {
        console.log("Already logged in.");
        loadDecryptAndDisplayBox();
    }
}



//
// KEYBOARD SHORTCUTS
//

var keyMap = {
    "j":readNextEmail,
    "k":readPrevEmail,
    "g":{
        "c":displayCompose,
        "i":function(){loadDecryptAndDisplayBox("inbox")},
        "s":function(){loadDecryptAndDisplayBox("sent")},
        "a":function(){loadDecryptAndDisplayBox("archive")}
    },
    "r":function(){emailReply(viewState.getLastEmailFromAnother())},
    "a":function(){emailReplyAll(viewState.getLastEmail())},
    "f":function(){emailForward(viewState.getLastEmail())},
    "y":function(){emailMove(viewState.getLastEmail(), "archive", true)},
    "d":function(){emailMove(viewState.getLastEmail(), "trash", true)},
    27:closeModal // esc key
};

function bindKeyboardShortcuts() {
    var currentKeyMap = keyMap;
    $(document).keyup(function(e) {
        // no keyboard shortcuts while the user is typing
        var tag = e.target.tagName.toLowerCase();
        if (tag=="textarea" ||
            (tag=="input" && e.target.type=="text") ||
            (tag=="input" && e.target.type=="password")) {
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
    })
}



//
// SIDEBAR
//

function bindSidebarEvents() {
    // Navigate to Inbox, Sent, or Archive
    $("#tab-inbox").click(function(e) {
        loadDecryptAndDisplayBox("inbox");
    });
    $("#tab-sent").click(function(e) {
        loadDecryptAndDisplayBox("sent");
    });
    $("#tab-archive").click(function(e) {
        loadDecryptAndDisplayBox("archive");
    });

    // Navigate to Compose
    $("#tab-compose").click(function(e) {
        displayCompose();
    });

    // Navigate to Contacts
    $("#tab-contacts").click(function(e) {
        displayContacts();
    });

    // Log out: click a link, deletes sessionStorage and refreshes the page
    $("#link-logout").click(function(e) {
        if (keepUnsavedWork()) {
            e.preventDefault();
            return;
        }
        clearCredentials();
    });

    // Explain keyboard shortcuts
    $("#link-kb-shortcuts").click(function() {
        showModal("kb-shortcuts-template");
    });
}

function setSelectedTab(tab) {
    $("#sidebar .tab").removeClass("selected");
    tab.addClass("selected");
}

function displayStatus(msg) {
    $("#statusBar")
        .text(msg)
        .show()
        .delay(1000)
        .fadeOut("slow");
}



//
// MODAL DIALOGS
//

function showModal(templateName) {
    var modalHtml = render(templateName);
    $("#wrapper").append(modalHtml);
    $(".link-close-modal").click(closeModal);
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
    sessionStorage["hostPrefix"] = HOST_PREFIX;
}

function displayLogin() {
    // not logged in. reset session state.
    clearCredentials();

    // show the login ui
    $("#wrapper").html(render("login-template"));
    bindLoginEvents();
}

function bindLoginEvents() {
    $("#enterButton").click(function() {
        var token = $("#token").val();
        var pass = $("#pass").val();
        login(token, pass);
        loadDecryptAndDisplayBox('inbox');
    });

    var keys = null;
    $("#generateButton").click(displayCreateAccountModal);
}

function login(token, pass) {
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

function displayCreateAccountModal() {
    showModal("create-account-template");

    var keys;
    var cb;

    // defer the slow part, so that the modal actually appears
    setTimeout(function() {
        // create a new mailbox. this takes a few seconds...
        keys = openpgp.generate_key_pair(KEY_TYPE_RSA, KEY_SIZE, "");
        sessionStorage["pubHash"] = computePublicHash(keys.publicKeyArmored);

        // Change "Generating..." to "Done", explain what's going on to the user
        $("#spinner").css("display", "none");
        $("#createForm").css("display", "block");

        // call cb, the user had already pressed the create button
        if (cb) { cb() }
    }, 100)

    $("#createButton").click(function() {
        if (keys) {
            createAccount(keys);
        } else {
            cb = function() { createAccount(keys) };
        }
    });
}

// Attempts to creates a new account, given a freshly generated key pair.
// Reads token and passphrase. Validates that the token is unique, 
// and the passphrase strong enough.
// Posts the token, a hash of the passphrase, public key, and 
// encrypted private key to the server.
function createAccount(keys) {
    var token = validateToken();
    if (token == null) return false;
    var pass = validateNewPassword();
    if (pass == null) return false;
    var secondaryEmail = trim($("#secondaryEmail").val());
    
    if (secondaryEmail && !secondaryEmail.match(REGEX_EMAIL)) {
        alert(secondaryEmail+" is not a valid email address");
        return
    }

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
    $.post(HOST_PREFIX+"/user/", data, function() {
        $.get(HOST_PREFIX+"/box/inbox",
            { offset: 0, limit: BOX_PAGE_SIZE },
            function(inbox) {
                decryptAndDisplayBox(inbox);
            }, 'json').fail(function() {
                alert("Try refreshing the page, then logging in.");
            }
        )
    }).fail(function(xhr) {
        alert(xhr.responseText);
    });
    
    return true;
}

function validateToken() {
    var token = $("#createToken").val();
    if (token.match(REGEX_TOKEN)) {
        return token;
    } else {
        alert("User must be at least three characters long.\n"
            + "Lowercase letters and numbers only, please.");
        return null;
    }
}

function validateNewPassword() {
    var pass1 = $("#createPass").val();
    var pass2 = $("#confirmPass").val();
    if (pass1 != pass2) {
        alert("Passphrases must match");
        return null;
    }
    if (pass1.length < 10) {
        alert("Your passphrase is too short.\n" + 
              "An ordinary password is not strong enough here.\n" +
              "For help, see http://xkcd.com/936/");
        return null;
    }
    return pass1;
}



//
// BOX
//

function bindBoxEvents(box) {
    // Click on an email to open it
    $("#"+box+" .box-items>li").click(function(e) {
        displayEmail($(e.target));
    });
    // Click on a pagination link
    $("#"+box+" .box-pagination a").click(function(e) {
        var box = $(this).data("box");
        var page = $(this).data("page");
        loadDecryptAndDisplayBox(box, page);
        return false;
    });
}

function loadDecryptAndDisplayBox(box, page) {
    if (keepUnsavedWork()) { return; }
    box = box || "inbox";
    page = page || 1;
    console.log("Loading, decrypting and displaying "+box+", page "+page);
    $.get(HOST_PREFIX+"/box/"+encodeURI(box),
        { offset: (page-1)*BOX_PAGE_SIZE, limit: BOX_PAGE_SIZE },
        function(summary) {
            decryptAndDisplayBox(summary, box);
        }, 'json').fail(function(xhr) {
            alert(xhr.responseText || "Could not reach the server, try again");
        }
    );
}

function decryptAndDisplayBox(boxSummary, box) {
    box = box || "inbox";
    sessionStorage["pubHash"] = boxSummary.PublicHash;
    sessionStorage["emailAddress"] = boxSummary.EmailAddress;

    console.log("Decrypting and displaying "+box);
    getPrivateKey(function(privateKey) {
        getContacts(function() {
            decryptSubjects(boxSummary.EmailHeaders, privateKey);
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
                emailHeaders: boxSummary.EmailHeaders,
            };
            var pages = [];
            for (var i=0; i<data.totalPages; i++) {
                pages.push({page:i+1})
            };
            data.pages = pages;
            $("#wrapper").html(render("page-template", data));
            bindSidebarEvents();
            setSelectedTab($("#tab-"+box));
            $("#"+box).html(render("box-template", data));
            bindBoxEvents(box);
            viewState.box = box;
        });
    });
}

function decryptSubjects(headers, privateKey) {
    for (var i = 0; i < headers.length; i++) {
        var h = headers[i];
        h.Subject = cachedDecodePgp(h.MessageID+" subject", h.CipherSubject, privateKey);
        if (h.Subject == null) {
            h.Subject = "(Decryption failed)";
        } else if (trim(h.Subject)=="") {
            h.Subject = "(No subject)";
        }
    }
}

function readNextEmail() {
    var msg;
    if ($(".current").length == 0) {
        msg = $("li").first();
    } else {
        msg = $(".current").next();
    }
    if (msg.length > 0) {
        displayEmail(msg);
    }
}

function readPrevEmail() {
    var msg = $(".current").prev();
    if (msg.length > 0) {
        displayEmail(msg);
    }
}



//
// SINGLE EMAIL
//

// Binds events for all emails in the current thread.
function bindEmailEvents() {
    // This is a helper that gets the relevant email data
    //  by finding the enclosed div.email
    var withEmail = function(cb) {
        return function() {
            var emailDiv = $(this).closest(".email");
            cb(emailDiv.data("email"));
        };
    };

    $(".emailControl .replyButton").click(withEmail(emailReply));
    $(".emailControl .replyAllButton").click(withEmail(emailReplyAll));
    $(".emailControl .forwardButton").click(withEmail(emailForward));
    $(".emailControl .archiveButton").click(withEmail(function(email){emailMove(email, "archive", false)}));
    $(".emailControl .moveToInboxButton").click(withEmail(function(email){emailMove(email, "inbox", false)}));
    $(".emailControl .deleteButton").click(withEmail(function(email){emailMove(email, "trash", false)}));
    $(".email .enterAddContactButton").click(addContact);

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

    $(".threadControl .replyButton").click(withLastEmailFromAnother(emailReply));
    $(".threadControl .replyAllButton").click(withLastEmail(emailReplyAll));
    $(".threadControl .forwardButton").click(withLastEmail(emailForward));
    $(".threadControl .archiveButton").click(withLastEmail(function(email){emailMove(email, "archive", true)}));
    $(".threadControl .moveToInboxButton").click(withLastEmail(function(email){emailMove(email, "inbox", true)}));
    $(".threadControl .deleteButton").click(withLastEmail(function(email){emailMove(email, "trash", true)}));
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
            displayStatus("Contact saved");
        });
    });
}


/**
    Takes an email, selects its box-item, shows the entire thread.
    For convenience, you can pass in the li.box-item jquery element,
     which has the relevant .data() attributes.

    emailHeader => {
        msgID (id of the selected email)
        threadID (thread id of the selected email)
    }

    Also uses viewState.box to determine current box.
*/
function displayEmail(emailHeader) {
    if (keepUnsavedWork()) { return; }

    if (emailHeader instanceof jQuery) {
        if (emailHeader.length == 0) {
            return;
        }
        emailHeader = {
            msgID:     emailHeader.data("msgId"),
            threadID:  emailHeader.data("threadId"),
        };
    } else if (!emailHeader) {
        return;
    }

    var msgID    = emailHeader.msgID;
    var threadID = emailHeader.threadID;

    $("#content").empty();
    $("li.box-item.current").removeClass("current");
    $("li.box-item[data-thread-id='"+threadID+"']").addClass("current");

    var params = {
        msgID: msgID,
        threadID: threadID,
        box: viewState.box // not used now, but maybe used in the future.
    };
    cachedLoadEmail(params, function(emailDatas) {
        viewState.emails = emailDatas; // for keyboard shortcuts & thread control
        showCurrentThread();
    });
}

function showCurrentThread(){
    var currentThread = viewState.emails;

    getPrivateKey(function(privateKey) {
        var fromAddrs = currentThread.map("From").map(trimToLower).unique();
        lookupPublicKeys(fromAddrs, function(keyMap, newResolutions) {
            // First, save new pubHashes to contacts so future lookups are faster.
            if (newResolutions.length > 0) {
                trySaveContacts(addContacts(viewState.contacts, newResolutions));
            }

            // Construct array of email objects.
            // Also sets the view model on viewState.emails
            var emails = currentThread.map(function(emailData) {
                decryptAndVerifyEmail(emailData, privateKey, keyMap);
                var model = createEmailViewModel(emailData);
                emailData.viewModel = model;
                return model;
            });

            // Construct thread element, insert emails
            showEmailThread(emails);

            // Update view state
            bindEmailEvents();
        })
    });
}

function cachedLoadEmail(params, cb){
    if(cache.emailCache.hasOwnProperty(params.msgID)){
        // NOTE: we may want to use params.box in the future.
        cb(cache.emailCache[params.msgID]);
    } else {
        $.get(HOST_PREFIX+"/email/", params, function(emailData) {
            cache.emailCache[params.msgID] = emailData;
            cb(emailData);
        }, "json");
    }
}

// Decrypts an email. Checks the signature, if there is one.
// Expects data.CipherBody, sets data.plaintextBody
function decryptAndVerifyEmail(data, privateKey, keyMap) {
    var from = trimToLower(data.From);
    var fromKey = keyMap[from].pubKey;
    if (!fromKey) {
        // TODO: color code to show that the email is unverified
        console.log("No key found for "+from+". This email is unverifiable "+
            "regardless of whether it has a signature.");
    }
    data.plaintextBody = cachedDecodePgp(data.MessageID+" body", data.CipherBody, privateKey, fromKey);
}

function createEmailViewModel(data) {
    // Parse From, To, etc
    var fromAddress = namedAddrFromAddress(data.From);
    var toAddresses = data.To=="" ? [] : 
        data.To.split(",").map(namedAddrFromAddress);

    // Parse Body
    var parsedBody = parseBody(data.plaintextBody);

    // The model for rendering the email template
    return {
        msgID:       data.MessageID,
        ancestorIDs: data.AncestorIDs,
        threadID:    data.ThreadID,
        time:        new Date(data.UnixTime*1000),
        unixTime:    data.UnixTime,
        from:        trimToLower(data.From),
        fromAddress: fromAddress,
        to:          trimToLower(data.To),
        toAddresses: toAddresses,
        subject:     parsedBody.subject,
        htmlBody:    createHyperlinks(parsedBody.body),
        plainBody:   parsedBody.body,
    };
}

function showEmailThread(emails) {
    var thread = {
        threadID:    emails[emails.length-1].threadID,
        subject:     emails[emails.length-1].subject || "(No subject)",
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

// Turns URLS into links in the plaintext.
// Returns HTML
function createHyperlinks(text) {
    var exp = /(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig;
    var match;
    var safeParts = [], lastIx = 0;
    while((match = exp.exec(text)) !== null){
        var rawPart = text.substr(lastIx, match.index-lastIx);
        var safePart = Handlebars.Utils.escapeExpression(rawPart);
        safeParts.push(safePart);

        var rawUrl = match[0];
        var safeLink = "<a href='"+rawUrl+"' target='_blank'>"+rawUrl+"</a>";
        safeParts.push(safeLink);

        lastIx = match.index+match[0].length;
    }
    var rawPart = text.substr(lastIx);
    var safePart = Handlebars.Utils.escapeExpression(rawPart);
    safeParts.push(safePart);

    return safeParts.join("");
}

function emailReply(email) {
    if (!email) return;
    var replyTo = email.fromAddress.name || email.fromAddress.address;
    displayComposeInline(email, replyTo, email.subject, undefined);
}

function emailReplyAll(email) {
    if (!email) return;
    var allRecipientsExceptMe = email.toAddresses
        .concat([email.fromAddress])
        .filter(function(addr) {
            // email starts with our pubHash -> don't reply to our self
            return addr.address != sessionStorage["emailAddress"];
        });
    if (allRecipientsExceptMe.length == 0) {
        // replying to myself...
        allRecipientsExceptMe = [namedAddrFromAddress(email.from)];
    }

    var replyTo = allRecipientsExceptMe.map(function(addr) {
        return addr.name || addr.address;
    }).join(",");
    displayComposeInline(email, replyTo, email.subject, undefined);
}

function emailForward(email) {
    if (!email) return;
    displayComposeInline(email, "", email.subject, email.plainBody);
}

// email: the email object
// moveThread: if true, moves all emails in box for thread up to email.unixTime.
//  (that way, server doesn't move new emails that the user hasn't seen)
function emailMove(email, box, moveThread) {
    if (keepUnsavedWork()) { return; }
    // Do nothing if already moved.
    if (email._movedThread || (email._moved && !moveThread)) {
        return;
    }
    // Confirm if deleting
    if (box == "trash") {
        if (moveThread) {
            if (!confirm("Are you sure you want to delete this thread?")) return;
        } else {
            if (!confirm("Are you sure you want to delete this email?")) return;
        }
    }
    // Disable buttons while moving
    email._moved = true;
    email._movedThread = moveThread;
    var elEmail = getEmailElement(email.msgID);
    var elThread = elEmail.closest("#thread");
    if (moveThread) {
        elThread.find(".threadControl button").prop("disabled", true);
    } else {
        elEmail.find(".emailControl button").prop("disabled", true);
    }
    // Send request
    var params = {
        box: box,
        moveThread: (moveThread || false)
    };
    $.ajax({
        url: HOST_PREFIX+'/email/'+encodeURI(email.msgID),
        type: 'PUT',
        data: params,
    }).done(function() {
        if (moveThread) {
            $("#thread").remove();
            showNextThread();
        } else {
            removeEmailFromThread(email);
        }
        displayStatus("Moved to "+box);
    }).fail(function(xhr) {
        alert("Move to "+box+" failed: "+xhr.responseText);
    });
}

function getEmailElement(msgID) {
    var elEmail = $(".email[data-msg-id='"+msgID+"']");
    if (elEmail.length != 1) {
        console.log("Failed to find exactly 1 email element with msgID:"+msgID);
        return;
    }
    return elEmail;
}

// Remove the email from the thread.
// If thread is empty, show the next thread.
function removeEmailFromThread(email) {
    var elEmail = getEmailElement(email.msgID);
    var elThread = elEmail.closest("#thread");
    elEmail.remove();
    // If this thread has no emails left, then show the next thread.
    if (elThread.find("#thread-emails .email").length == 0) {
        showNextThread();
    }
}

function showNextThread() {
    var newSelection = $(".box .current").next();
    if (newSelection.length == 0) {
        newSelection = $(".box .current").prev();
    }
    $(".box .current").remove();
    displayEmail(newSelection);
}



//
// COMPOSE
//

// cb: function(emailData), emailData has plaintext components including
//  msgID, threadID, ancestorIDs, subject, to, body...
function bindComposeEvents(elCompose, cb) {
    elCompose.find(".sendButton").click(function() {
        $(this).prop("disabled", true);
        // generate 160-bit (20 byte) message id
        // secure random generator, so it will be unique
        var msgID = bin2hex(openpgp_crypto_getRandomBytes(20))+"@"+window.location.hostname;
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
            alert(error);
            elCompose.find(".sendButton").prop("disabled", false);
        });
    });
}

function displayCompose(to, subject, body) {
    if (keepUnsavedWork()) { return; }
    if (body === undefined) {
        body = DEFAULT_SIGNATURE;
    }
    $(".box").html("");
    viewState.clearEmails();
    setSelectedTab($("#tab-compose"));
    var elCompose = $(render("compose-template", {
        to:          to,
        subject:     subject,
        body:        body,
        bodyDefault: body,
    }));
    $("#content").empty().append(elCompose);
    bindComposeEvents(elCompose, function(emailData) {
        displayStatus("Sent");
        displayCompose();
    });
}

function displayComposeInline(email, to, subject, body) {
    var elEmail = getEmailElement(email.msgID);
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
    elEmail.find(".email-compose").empty().append(elCompose);

    // Scroll down to the Compose box
    var y = $(elCompose).position().top;
    $("#thread-emails").scrollTop(y);

    // Bind events (eg Send button)
    bindComposeEvents(elCompose, function(emailData) {
        displayStatus("Sent");
        displayEmail(emailData);
    });

}

function keepUnsavedWork() {
    var keepUnsaved = false;
    $("input[data-default], textarea[data-default]").each(function() {
        var el = $(this);
        if (trim(el.val()) != trim(el.data("default"))) {
            if(!confirm(el.data("displayName")+" is not saved, continue?")) {
                keepUnsaved = true;
            }
        }
    });
    return keepUnsaved;
}

function sendEmail(msgID, threadID, ancestorIDs, to, subject, body, cb, failCb) {
    // validate email addresses
    var toAddresses = to.split(",").map(trimToLower).filter(Boolean);
    if (toAddresses.length == 0) {
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
        })

        // If errors, abort.
        if (errors.length > 0) {
            return failCb("Error:\n"+errors.join("\n"));
        }

        sendEmailEncryptedIfPossible(msgID, threadID, ancestorIDs, pubKeys, subject, body, cb, failCb);
    })

    return false;
}

// Send an email, encryyted if psossibie.
// If we don't have pub keys for all recipients, warn the uesr
// and confirm if they want to send the message unencrypted
function sendEmailEncryptedIfPossible(msgID, threadID, ancestorIDs, pubKeysByAddr, subject, body, cb, failCb){
    var addrs = Object.keys(pubKeysByAddr);
    var missingKeys = addrs.filter(function(addr){
        return pubKeysByAddr[addr] == "";
    });

    if (missingKeys.length > 0) {
        if (confirm("Could not find public keys for: "+missingKeys.join(", ")
            +" \nSend unencrypted to all recipients?")) {
            var to = Object.keys(pubKeysByAddr).join(",")
            sendEmailUnencrypted(msgID, threadID, ancestorIDs, to, subject, body, cb, failCb);
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
        if(cache.keyMap.hasOwnProperty(addr)){
            keyMap[addr] = cache.keyMap[addr];
        } else {
            addrsForLookup.push(addr);
        }
    });

    // all cached? great!
    if(addrsForLookup.length == 0){
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

    loadNotaries(function(notaryKeys) {

        var needResolution = []; // addresses that need to be notarized
        var needPubKey = []; // addresses for which we need pubkeys
        var notaries = Object.keys(notaryKeys);
        var knownHashes = {};   // {<address>: <pubHash>}

        for (var i=0; i<addresses.length; i++) {
            var addr = addresses[i];
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
        }

        // Nothing to look up
        if (needResolution.length == 0 && needPubKey.length == 0) {
            return cb(keyMap, newResolutions);
        }

        var params = {
            needResolution: needResolution.join(","),
            needPubKey:    needPubKey.join(","),
            notaries:      notaries.join(","),
        };
        $.post(HOST_PREFIX+"/publickeys/query", params, function(data) {

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
                    // continue
                }
                for (var addr in res.pubHashes) {
                    knownHashes[addr] = res.pubHashes[addr];
                }
            }

            // de-armor keys and set pubHash on the results,
            // and verify against knownHashes.
            for (var addr in publicKeys) {
                var result = publicKeys[addr];
                if (result.status == "ERROR" || result.status == "NO_SUCH_USER") {
                    keyMap[addr] = {error:result.error};
                    continue;
                } else if (result.status == "OK") {
                    var pubKeyArmor = result.pubKey;
                    // check pubKeyArmor against knownHashes.
                    var computedHash = computePublicHash(pubKeyArmor);
                    if (computedHash != knownHashes[addr]) {
                        // this is a serious error. security breach?
                        var error = "SECURITY WARNING! We received an incorrect key for "+addr;
                        console.log(error, computedHash, knownHashes[addr]);
                        alert(error);
                        return; // halt, do not call cb.
                    }
                    if (needResolution.indexOf(addr) != -1) {
                        newResolutions.push({address:addr, pubHash:computedHash});
                    }
                    // parse publicKey
                    var pka = openpgp.read_publicKey(pubKeyArmor);
                    if (pka.length == 1) {
                        keyMap[addr] = {
                            pubKey:      pka[0],
                            pubKeyArmor: pubKeyArmor,
                            pubHash:     computedHash,
                        };
                    } else {
                        alert("Incorrect number of publicKeys in armor for address "+addr);
                        return; // halt, do not call cb.
                    }
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
                var addr = addresses[i];
                if (keyMap[addr] == null) {
                    console.log("Missing lookup result for "+addr+". Bad server impl?");
                    keyMap[addr] = {error:"ERROR: Missing lookup result"};
                }
            }

            cb(keyMap, newResolutions);
        }, "json");
    });
}

// addrPubKeys: {toAddress: <pubKey>}
function sendEmailEncrypted(msgID, threadID, ancestorIDs, addrPubKeys, subject, body, cb, failCb) {
    // Get the private key so we can sign the encrypted message
    getPrivateKey(function(privateKey) {
        // Get the public key so we can also read it in the sent box
        getPublicKey(function(publicKey) {

            // Encrypt message for all recipients in `addrPubKeys`
            var pubKeys = Object.values(addrPubKeys);
            pubKeys.push(publicKey[0]);
            pubKeys = pubKeys.unique(function(pubKey) { return pubKey.getKeyId() });
            
            var cipherSubject = openpgp.write_signed_and_encrypted_message(privateKey[0], pubKeys, subject);
            // Embed the subject into the body for verification
            var subjectAndBody = "Subject: "+subject+"\n\n"+body;
            var cipherBody = openpgp.write_signed_and_encrypted_message(privateKey[0], pubKeys, subjectAndBody);

            // send our message
            var data = {
                msgID:         msgID,
                threadID:      threadID,
                ancestorIDs:   ancestorIDs,
                to:            Object.keys(addrPubKeys).join(","),
                cipherSubject: cipherSubject,
                cipherBody:    cipherBody
            };
            sendEmailPost(data, cb, failCb);
        });
    });
}

function sendEmailUnencrypted(msgID, threadID, ancestorIDs, to, subject, body, cb, failCb) {
    // send our message
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
    $.post(HOST_PREFIX+"/email/", data, function() {
        cb();
    }).fail(function(xhr) {
        failCb("Sending failed:\n"+xhr.responseText);
    });
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
    if (parts == null) {
        // for legacy emails
        return {subject:"(Unknown subject)", body:plaintextBody, ok:false};
    } else {
        return {subject:parts[1], body:parts[2], ok:true};
    }
}



//
// CONTACTS
//

function displayContacts() {
    if (keepUnsavedWork()) { return; }
    loadAndDecryptContacts(function(contacts) {
        // clean up 
        $(".box").html("");
        viewState.clearEmails();
        setSelectedTab($("#tab-contacts"));

        // render compose form into #content
        var html = render("contacts-template", contacts);
        $("#content").html(html);
        bindContactsEvents();
    });
}

function bindContactsEvents() {
    $(".contacts li .deleteButton").click(deleteRow);
    $(".addContactButton").click(newRow);
    $(".saveContactsButton").click(function() {
        var rows = $(".contacts li");
        var contacts = [];
        var needResolution = {}; // need to find pubhash before saving
                                // {address: name}
        for (var i = 0; i < rows.length; i++) {
            var name = trim($(rows[i]).find(".name").val());
            var address = trim($(rows[i]).find(".address").val());
            var contact = getContact(address);
            if (!address) {
                continue;
            } else if (!contact) {
                needResolution[address] = name;
                continue;
            }
            contacts.push({name:name, address:address, pubHash:contact.pubHash});
        }

        contactsErr = validateContacts(contacts);
        if (contactsErr.errors.length > 0) {
            alert(contactsErr.errors.join("\n"));
            return;
        }

        lookupPublicKeys(Object.keys(needResolution), function(keyMap) {
            for (var address in needResolution) {
                if (keyMap[address].error) {
                    alert("Error resolving email address "+address+":\n"+keyMap[address].error);
                    return;
                }
                contacts.push({
                    name:    needResolution[address],
                    address: address,
                    pubHash: keyMap[address].pubHash,
                });
            }
            trySaveContacts(contacts, function() {
                displayStatus("Contacts saved");
                displayContacts();
            });
        });
    });
}
function newRow() {
    var row = $(render("new-contact-template"));
    row.find(".deleteButton").click(deleteRow);
    $(".contacts ul").append(row);
}
function deleteRow(e) {
    $(e.target).parent().remove();
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
    var contactsClean = [];

    for (var i = 0; i < contacts.length; i++) {
        var contact = contacts[i];
        var name = contact.name ? trim(contact.name) : undefined;
        var lname = name ? name.toLowerCase() : undefined;
        var address = trimToLower(contact.address);
        var addressMatch = address.match(REGEX_EMAIL);
        var pubHash = contact.pubHash ? trimToLower(contact.pubHash) : undefined;

        if (name && !name.match(REGEX_CONTACT_NAME)) {
            errors.push("Invalid contact name: "+name);
        }

        if (address == "") {
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

        var contact = {address:address};
        if (name)    { contact.name = name; }
        if (pubHash) { contact.pubHash = pubHash; }
        contactsClean.push(contact);
    }

    return {contacts:contactsClean, errors:errors};
}

function trySaveContacts(contacts, done) {

    var contactsErr = validateContacts(contacts);

    // if there are mistakes, tell the user and bail
    if (contactsErr.errors.length > 0) {
        alert(contactsErr.errors.join("\n"));
        return;
    } 

    // sort the contacts book
    contacts = contactsErr.contacts.sortBy(function(contact) {
        if (contact.name) {
            return contact.name;
        } else {
            // '~' is a high ord character.
            return "~"+contact.address;
        }
    })

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
    $.post(HOST_PREFIX+"/user/me/contacts", bin2hex(cipherContacts), "text")
        .done(done)
        .fail(function(xhr) {
            alert("Saving contacts failed: "+xhr.responseText)
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
    var allContacts = [];
    for (var i=0; i<contacts.length; i++) {
        var c = contacts[i];
        allContacts.push({name:c.name, pubHash:c.pubHash, address:c.address});
    }
    // defensively delete reference to original contacts.
    contacts = null;

    EACH_NEW_CONTACT:
    for (var i=0; i<newContacts.length; i++) {
        var newContact = newContacts[i];

        var name = newContact.name;
        var address = newContact.address;
        var pubHash = newContact.pubHash;

        if (!address) {
            throw "addContacts() new contacts require address";
        }

        // if address is already in contacts, just set the name.
        if (name) {
            for (var i=0; i<allContacts.length; i++) {
                if (allContacts[i].address == address) {
                    allContacts[i].name = name;
                    continue EACH_NEW_CONTACT;
                }
            }
        }

        // otherwise, add new contact
        var newContact = {
            name:    name ? trim(name) : undefined,
            address: trimToLower(address),
            pubHash: pubHash ? trimToLower(pubHash) : undefined,
        };

        allContacts.push(newContact);
    }

    return allContacts;
}

function getContact(address) {
    if (viewState.contacts == null) {
        return null;
    }
    address = trimToLower(address);
    for (var i = 0; i < viewState.contacts.length; i++) {
        var contact = viewState.contacts[i];
        if (contact.address==address) {
            return contact;
        }
    }
    return null;
}

function contactNameFromAddress(address) {
    var contact = getContact(address);
    if (contact) {
        return contact.name;
    }
    return null;
}

function contactAddressFromName(name) {
    if (viewState.contacts == null) {
        return null;
    }
    name = trimToLower(name);
    for (var i = 0; i < viewState.contacts.length; i++) {
        var contact = viewState.contacts[i];
        if (contact.name && contact.name.toLowerCase() == name) {
            return contact.address;
        }
    }
    return null;
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

    $.get(HOST_PREFIX+"/user/me/contacts", function(cipherContactsHex) {
        var cipherContacts = hex2bin(cipherContactsHex);
        var jsonContacts = passphraseDecrypt(cipherContacts);
        if (!jsonContacts) {
            return;
        }
        var parsed = JSON.parse(jsonContacts);
        if (parsed.version == undefined) {
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
        if (contact.pubHash == undefined) {
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
        var params = {pubHashes:lookup.join(",")};
        $.post(HOST_PREFIX+"/publickeys/reverse", params, function(pubHashToAddress) {
            var addresses = [], hashesDeleted = [];
            for (var hash in pubHashToAddress) {
                if (pubHashToAddress[hash]=="") {
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
                var hashesFound = newContacts.map("pubHash")
                var remaining = lookup.subtract(hashesFound).subtract(hashesDeleted);
                if (remaining.length > 0) {
                    alert("Error: contacts migration failed for address(es): "+remaining.join(","));
                    return;
                }
                trySaveContacts(newContacts, function() {
                    fn(newContacts);
                });
            })
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
    for (var i=0; i<addresses.length; i++) {
        var address = addresses[i];
        var missingNotariesForAddress = notaries.filter(function(notary){
            return !notarized[address] || notarized[address].indexOf(notary) < 0;
        });
        if(missingNotariesForAddress.length > MAX_MISSING_NOTARIES){
            missingAddresses.push(address);
        } else {
            // this address is *NOT* available from at least one notary, or
            // at least one notary server is down
            console.log("Warning: did NOT get a public key for "+address+
                " from: "+missingNotariesForAddress.join(",")+". " +
                "However, we got enough responses to proceed.");
        }
        addAllToSet(missingNotariesForAddress, missingNotaries);
    }
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
        $.getJSON(HOST_PREFIX+"/publickeys/notary", function(data) {
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
        parsed[host] = openpgp.read_publicKey(pubKey);
    }
    return parsed;
}

// Ensure that notaryRes is properly signed with notaryPublicKey.
// notaryRes: {address,pubHash,timestamp,signature}
// returns true or false
function verifyNotarySignature(notaryRes, notaryPublicKey) {
    var toSign = notaryRes.address+"="+(notaryRes.pubHash||"")+"@"+notaryRes.timestamp;
    var sig = openpgp.read_message(notaryRes.signature);
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
    var sha1 = new jsSHA("2"+token+pass, "ASCII").getHash("SHA-1", "ASCII");
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
    return new jsSHA("1"+token+pass, "ASCII").getHash("SHA-1", "HEX");
}

// Symmetric encryption using a key derived from the user's passphrase
// The user must be logged in: the key must be in sessionStorage
function passphraseEncrypt(plainText) {
    if (!sessionStorage["passKey"] || sessionStorage["passKey"] == "undefined") {
        alert("Missing passphrase. Please log out and back in.");
        return null;
    }
    var prefixRandom = openpgp_crypto_getPrefixRandom(ALGO_AES128);
    plainText = util.encode_utf8(plainText);
    return openpgp_crypto_symmetricEncrypt(
        prefixRandom, 
        ALGO_AES128, 
        sessionStorage["passKey"], 
        plainText);
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
        plain = openpgp_crypto_symmetricDecrypt(
            ALGO_AES128, 
            sessionStorage["passKey"], 
            cipherText);
    } catch(e) {
        // Backcompat: people with old accounts had weaker key derivation
        plain = openpgp_crypto_symmetricDecrypt(
            ALGO_AES128, 
            sessionStorage["passKeyOld"], 
            cipherText);
        console.log("Warning: old account, used backcompat AES key");
    }
    plain = util.decode_utf8(plain);
    return plain;
}

// Returns the first 80 bits of a SHA1 hash, encoded with a 5-bit ASCII encoding
// Returns a 16-byte string, eg "tnysbtbxsf356hiy"
// This is the same algorithm and format Onion URLS use
function computePublicHash(str) {
    // SHA1 hash
    var sha1Hex = new jsSHA(str, "ASCII").getHash("SHA-1", "HEX");

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
    for (var i = 0; i < 16; i++) {
        var digit =
            sha1Bits[i*5]*16 + 
            sha1Bits[i*5+1]*8 + 
            sha1Bits[i*5+2]*4 + 
            sha1Bits[i*5+3]*2 + 
            sha1Bits[i*5+4];
        if (digit < 26) {
            hash += String.fromCharCode(ccA+digit);
        } else {
            hash += String.fromCharCode(cc2+digit-26);
        }
    }
    return hash;
}

function getPrivateKey(fn) {
    if (sessionStorage["privateKeyArmored"]) {
        var privateKey = openpgp.read_privateKey(sessionStorage["privateKeyArmored"]);
        fn(privateKey);
        return;
    }

    $.get(HOST_PREFIX+"/user/me/key", function(cipherPrivateKeyHex) {
        var cipherPrivateKey = hex2bin(cipherPrivateKeyHex);
        var privateKeyArmored = passphraseDecrypt(cipherPrivateKey);
        if (!privateKeyArmored) return;
        sessionStorage["privateKeyArmored"] = privateKeyArmored;
        var privateKey = openpgp.read_privateKey(privateKeyArmored);
        console.log("Got private key");
        fn(privateKey);
    }, "text").fail(function(xhr) {
        alert("Failed to retrieve our own encrypted private key: "+xhr.responseText);
        return;
    })
}

function getPublicKey(fn) {
    if (sessionStorage["publicKeyArmored"]) {
        var publicKey = openpgp.read_publicKey(sessionStorage["publicKeyArmored"]);
        fn(publicKey);
        return;
    }

    getPrivateKey(function(privateKey) {
        var publicKey = openpgp.read_publicKey(privateKey[0].extractPublicKey());
        fn(publicKey);
        return;
    })
}

function cachedDecodePgp(cacheKey, armoredText, privateKey, publicKey){
    var plain = cache.plaintextCache[cacheKey];
    if (typeof(plain) === "undefined"){
        plain = tryDecodePgp(armoredText, privateKey, publicKey);
        cache.plaintextCache[cacheKey] = plain;
    }
    return plain;
}

// Decrypts a PGP message destined for our user, given their private key
// If publicKey exists, it is used to verify the sender's signature.
// This is a slow operation (60ms)
function tryDecodePgp(armoredText, privateKey, publicKey) {
    try {
        return decodePgp(armoredText, privateKey, publicKey);
    } catch (err) {
        console.log("Decryption failed:", [err, err.stack]);
        return "(Decryption failed)";
    }
}

function decodePgp(armoredText, privateKey, publicKey) {
    var msgs = openpgp.read_message(armoredText);
    if (msgs.length != 1) {
        alert("Warning. Expected 1 PGP message, found "+msgs.length);
    }
    var msg = msgs[0];
    var sessionKey = null;
    for (var i=0; i<msg.sessionKeys.length; i++) {
        if (msg.sessionKeys[i].keyId.bytes == privateKey[0].getKeyId()) {
            sessionKey = msg.sessionKeys[i];
            break;
        }
    }
    if (sessionKey == null) {
        alert("Warning. Matching PGP session key not found");
    }
    if (privateKey.length != 1) {
        alert("Warning. Expected 1 PGP private key, found "+privateKey.length);
    }
    var keymat = { key: privateKey[0], keymaterial: privateKey[0].privateKeyPacket};
    if (!keymat.keymaterial.decryptSecretMPIs("")) {
        alert("Error. The private key is passphrase protected.");
    }
    var text;
    if (publicKey) {
        var res = msg.decryptAndVerifySignature(keymat, sessionKey, [{obj:publicKey}]);
        if (res.length == 0) {
            console.log("Warning: this email is unsigned");
            text = msg.decryptWithoutVerification(keymat, sessionKey)[0];
        } else if (!res[0].signatureValid) {
            // old messages will pop this error modal.
            alert("Error. The signature is invalid!");
        } else {
            // valid signature, hooray
            text = res[0].text;
        }
    } else {
        var text = msg.decryptWithoutVerification(keymat, sessionKey)[0];
    }

    // HACK:
    // openpgp.js will only call util.decode_utf8 if the filehint is 'u',
    //  while golang's openpgp library only encodes to 't'.
    // For now, let's just always call util.decode_utf8.
    //  this will cause util.decode_utf8 to get double called for messages
    //  from openpgp.js, which will most likely do nothing.
    text = util.decode_utf8(text);
    return text;
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

function initPGP() {
  if (window.crypto.getRandomValues) {
    openpgp.init();
    return true;
  } else {
    alert("Sorry, you'll need a modern browser to use Scramble.\n"+
          "Use Chrome >= 11, Safari >= 3.1 or Firefox >= 21");
    return false;
  }   
}

// openpgp really wants this function.
function showMessages(msg) {
    var err = $("<div />").html(msg).text();
    console.log("OpenPGP.js - "+err);
    if (err.toLowerCase().startsWith("error")) {
        throw err;
    }
}

// Renders a Handlebars template, reading from a <script> tag. Returns HTML.
var templates = {};
function render(templateID, data) {
    if (!templates) {
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

// Appends an element to an array, if it's not already in the array
function addIfNotContains(elems, newElem) {
    if (elems.indexOf(newElem) < 0) {
        elems.push(newElem);
    }
}

function bin2hex(str) {
    return util.hexstrdump(str);
}
function hex2bin(str) {
    return util.hex2bin(str);
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

function setHostPrefix(hostPrefix) {
    HOST_PREFIX = hostPrefix;
    sessionStorage["hostPrefix"] = hostPrefix;
}
