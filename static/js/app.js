//
// SCRAMBLE.IO
// Secure email for everyone
// by DC - http://dcpos.ch/
//



//
// CONSTANTS
// See https://tools.ietf.org/html/rfc4880
//

var KEY_TYPE_RSA = 1
var KEY_SIZE = 2048

var ALGO_SHA1 = 2
var ALGO_AES128 = 7

var BOX_PAGE_SIZE = 20

var REGEX_TOKEN = /^[a-z0-9][a-z0-9][a-z0-9]+$/
var REGEX_EMAIL = /^([A-Z0-9._%+-]+)@([A-Z0-9.-]+\.[A-Z]{2,4})$/i
var REGEX_BODY = /^Subject: (.*)(?:\r?\n)+([\s\S]*)$/i
var REGEX_CONTACT_NAME = /^[^@]*$/i

var SCRYPT_PARAMS = {
    N:16384, // difficulty=2^14, recommended range 2^14 to 2^20
    r:8,     // recommended values
    p:1
}

var DEFAULT_SIGNATURE = "\n\n--\n"+
    "Encrypted with https://scramble.io";

var CONTACTS_VERSION = 1;


//
// SESSION VARIABLES
//
// sessionStorage["token"] is the username
// sessionStorage["emailAddress"] is <token>@<host>
// sessionStorage["passHash"] is the auth key
// sessionStorage["passHashOld"] is for backwards compatibility
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

var viewState = {}
viewState.emails = null // all emails in the current thread
viewState.getLastEmail = function(){
    return this.emails == null ? null : this.emails[this.emails.length-1];
}
viewState.contacts = null // plaintext address book, must *always* be good data.



//
// LOAD THE SITE
// Called on load: $(main)
//

function main(){
    console.log("Hello World")
    if(!initPGP()) return
    bindKeyboardShortcuts()

    // are we logged in?
    if(!sessionStorage["token"] || !sessionStorage["passKey"]) {
        console.log("Please log in.");
        displayLogin()
    } else {
        console.log("Already logged in.");
        loadDecryptAndDisplayBox()
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
    "r":function(){emailReply(viewState.getLastEmail())},
    "a":function(){emailReplyAll(viewState.getLastEmail())},
    "f":function(){emailForward(viewState.getLastEmail())},
    "y":function(){emailMove(viewState.getLastEmail(), "archive", true)},
    "d":function(){emailMove(viewState.getLastEmail(), "trash", true)},
    27:closeModal // esc key
}

function bindKeyboardShortcuts() {
    var currentKeyMap = keyMap
    $(document).keyup(function(e){
        // no keyboard shortcuts while the user is typing
        var tag = e.target.tagName.toLowerCase()
        if(tag=="textarea" ||
            (tag=="input" && e.target.type=="text") ||
            (tag=="input" && e.target.type=="password")){
            return
        }

        var code = e.which || e.charCode
        var mapping = currentKeyMap[code] || 
                      currentKeyMap[String.fromCharCode(code).toLowerCase()]
        if(!mapping){
            // unrecognized keyboard shortcut
            currentKeyMap = keyMap
        } else if (typeof(mapping)=="function"){
            // valid keyboard shortcut
            mapping()
            currentKeyMap = keyMap
        } else {
            // pressed one key in a combination, wait for the next key
            currentKeyMap = mapping
        }
    })
}



//
// SIDEBAR
//

function bindSidebarEvents() {
    // Navigate to Inbox, Sent, or Archive
    $("#tab-inbox").click(function(e){
        loadDecryptAndDisplayBox("inbox")
    })
    $("#tab-sent").click(function(e){
        loadDecryptAndDisplayBox("sent")
    })
    $("#tab-archive").click(function(e){
        loadDecryptAndDisplayBox("archive")
    })

    // Navigate to Compose
    $("#tab-compose").click(function(e){
        displayCompose()
    })

    // Navigate to Contacts
    $("#tab-contacts").click(function(e){
        displayContacts()
    })

    // Log out: click a link, deletes sessionStorage and refreshes the page
    $("#link-logout").click(function(){
        sessionStorage.clear()
    })

    // Explain keyboard shortcuts
    $("#link-kb-shortcuts").click(function(){
        showModal("kb-shortcuts-template")
    })
}

function setSelectedTab(tab) {
    $("#sidebar .tab").removeClass("selected")
    tab.addClass("selected")
}

function displayStatus(msg){
    $("#statusBar")
        .text(msg)
        .show()
        .delay(1000)
        .fadeOut("slow")
}



//
// MODAL DIALOGS
//

function showModal(templateName){
    var modalHtml = render(templateName)
    $("#wrapper").append(modalHtml)
    $(".link-close-modal").click(closeModal)
}

function closeModal(){
    $(".modal").remove()
    $(".modal-bg").remove()
}



//
// LOGIN 
//

function displayLogin(){
    // not logged in. reset session state.
    sessionStorage.clear()

    // show the login ui
    $("#wrapper").html(render("login-template"))
    bindLoginEvents()
}

function bindLoginEvents() {
    $("#enterButton").click(function(){
        var token = $("#token").val()
        var pass = $("#pass").val()
        login(token, pass)
    })

    var keys = null
    $("#generateButton").click(displayCreateAccountModal)
}

function login(token, pass){
    // two hashes of (token, pass)
    // ...one encrypts the private key. the server must never see it.
    // save for this session only, never in a cookie or localStorage
    sessionStorage["passKey"] = computeAesKey(token, pass)
    sessionStorage["passKeyOld"] = computeAesKeyOld(token, pass)

    // ...the other one authenticates us. the server sees it.
    sessionStorage["token"] = token
    sessionStorage["passHash"] = computeAuth(token, pass)
    sessionStorage["passHashOld"] = computeAuthOld(token, pass)

    // try fetching the inbox
    $.get("/box/inbox",
        { offset: 0, limit: BOX_PAGE_SIZE },
        function(inbox){
            // logged in successfully!
            decryptAndDisplayBox(inbox)
        }, 'json').fail(function(xhr){
            alert(xhr.responseText || "Could not reach the server, try again")
        }
    )
}


//
// LOGIN - "CREATE ACCOUNT" MODAL
//

function displayCreateAccountModal(){
    showModal("create-account-template")

    var keys;
    var cb;

    // defer the slow part, so that the modal actually appears
    setTimeout(function(){
        // create a new mailbox. this takes a few seconds...
        keys = openpgp.generate_key_pair(KEY_TYPE_RSA, KEY_SIZE, "")
        sessionStorage["pubHash"] = computePublicHash(keys.publicKeyArmored)

        // Change "Generating..." to "Done", explain what's going on to the user
        $("#createAccountModal h3").text("Welcome!")
        $("#spinner").css("display", "none")
        $("#createForm").css("display", "block")

        // call cb, the user had already pressed the create button
        if (cb) { cb() }
    }, 100)

    $("#createButton").click(function(){
        if (keys) {
            createAccount(keys)
        } else {
            cb = function(){ createAccount(keys) };
        }
    })
}

// Attempts to creates a new account, given a freshly generated key pair.
// Reads token and passphrase. Validates that the token is unique, 
// and the passphrase strong enough.
// Posts the token, a hash of the passphrase, public key, and 
// encrypted private key to the server.
function createAccount(keys){
    var token = validateToken()
    if(token == null) return false
    var pass = validateNewPassword()
    if(pass == null) return false

    // two passphrase hashes, one for login and one to encrypt the private key
    // the server knows only the login hash, and must not know the private key
    var aesKey = computeAesKey(token, pass)
    var passHash = computeAuth(token, pass)

    sessionStorage["token"] = token
    sessionStorage["passHash"] = passHash
    // save for this session only, never in a cookie or localStorage
    sessionStorage["passKey"] = aesKey
    sessionStorage["privateKeyArmored"] = keys.privateKeyArmored

    // encrypt the private key with the user's passphrase
    var cipherPrivateKey = passphraseEncrypt(keys.privateKeyArmored)

    // send it
    var data = {
        token:token,
        passHash:passHash,
        publicKey:keys.publicKeyArmored,
        cipherPrivateKey:bin2hex(cipherPrivateKey)
    }
    $.post("/user/", data, function(){
        $.get("/box/inbox",
            { offset: 0, limit: BOX_PAGE_SIZE },
            function(inbox){
                decryptAndDisplayBox(inbox)
            }, 'json').fail(function(){
                alert("Try refreshing the page, then logging in.")
            }
        )
    }).fail(function(xhr){
        alert(xhr.responseText)
    })
    
    return true
}

function validateToken(){
    var token = $("#createToken").val()
    if(token.match(REGEX_TOKEN)) {
        return token
    } else {
        alert("User must be at least three characters long.\n"
            + "Lowercase letters and numbers only, please.")
        return null
    }
}

function validateNewPassword(){
    var pass1 = $("#createPass").val()
    var pass2 = $("#confirmPass").val()
    if(pass1 != pass2){
        alert("Passphrases must match")
        return null
    }
    if(pass1.length < 10){
        alert("Your passphrase is too short.\n" + 
              "An ordinary password is not strong enough here.\n" +
              "For help, see http://xkcd.com/936/")
        return null
    }
    return pass1
}



//
// BOX
//

function bindBoxEvents(box) {
    // Click on an email to open it
    $("#"+box+" .box-items>li").click(function(e){
        displayEmail($(e.target))
    })
    // Click on a pagination link
    $('#'+box+" .box-pagination a").click(function(e) {
        var box = $(this).data("box")
        var page = $(this).data("page")
        loadDecryptAndDisplayBox(box, page)
        return false
    })
}

function loadDecryptAndDisplayBox(box, page){
    box = box || "inbox"
    page = page || 1
    console.log("Loading, decrypting and displaying "+box+", page "+page)
    $.get("/box/"+box,
        { offset: (page-1)*BOX_PAGE_SIZE, limit: BOX_PAGE_SIZE },
        function(summary){
            decryptAndDisplayBox(summary, box)
        }, 'json').fail(function(){
            displayLogin()
        }
    )
}

function decryptAndDisplayBox(inboxSummary, box){
    box = box || "inbox";
    sessionStorage["pubHash"] = inboxSummary.PublicHash;
    sessionStorage["emailAddress"] = inboxSummary.EmailAddress;

    console.log("Decrypting and displaying "+box)
    getPrivateKey(function(privateKey){
        console.log("Got private key")
        getContacts(function(){
            decryptSubjects(inboxSummary.EmailHeaders, privateKey)
            var data = {
                token:        sessionStorage["token"],
                emailAddress: inboxSummary.EmailAddress,
                pubHash:      inboxSummary.PublicHash,
                box:          inboxSummary.Box,
                offset:       inboxSummary.Offset,
                limit:        inboxSummary.Limit,
                total:        inboxSummary.Total,
                page:         Math.floor(inboxSummary.Offset / inboxSummary.Limit)+1,
                totalPages:   Math.ceil(inboxSummary.Total / inboxSummary.Limit),
                emailHeaders: inboxSummary.EmailHeaders,
            }
            var pages = [];
            for (var i=0; i<data.totalPages; i++) {
                pages.push({page:i+1})
            }
            data.pages = pages
            $("#wrapper").html(render("page-template", data))
            bindSidebarEvents()
            setSelectedTab($("#tab-"+box))
            $("#"+box).html(render("box-template", data))
            bindBoxEvents(box)
        })
    })
}

function decryptSubjects(headers, privateKey){
    for(var i = 0; i < headers.length; i++){
        var h = headers[i]
        h.Subject = tryDecodePgp(h.CipherSubject, privateKey)
        if(h.Subject == null) {
            h.Subject = "(Decryption failed)"
        } else if(trim(h.Subject)==""){
            h.Subject = "(No subject)"
        }
    }
}

function readNextEmail(){
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

function readPrevEmail(){
    var msg = $(".current").prev();
    if (msg.length > 0){
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

    $(".emailControl .replyButton").click(withEmail(emailReply))
    $(".emailControl .replyAllButton").click(withEmail(emailReplyAll))
    $(".emailControl .forwardButton").click(withEmail(emailForward))
    $(".emailControl .archiveButton").click(withEmail(function(email){emailMove(email, "archive", false)}))
    $(".emailControl .moveToInboxButton").click(withEmail(function(email){emailMove(email, "inbox", false)}))
    $(".emailControl .deleteButton").click(withEmail(function(email){emailMove(email, "trash", false)}))
    $(".email .enterFromNameButton").click(withEmail(function(email){
        var name = prompt("Contact name for "+email.from);
        if (!name) {
            return;
        }
        var addr = email.from;
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
                displayStatus("Contact saved")
            });
        });
    }));

    var withLastEmail = function(cb) {
        return function() {
            cb(viewState.getLastEmail());
        };
    };

    $(".threadControl .replyButton").click(withLastEmail(emailReply))
    $(".threadControl .replyAllButton").click(withLastEmail(emailReplyAll))
    $(".threadControl .forwardButton").click(withLastEmail(emailForward))
    $(".threadControl .archiveButton").click(withLastEmail(function(email){emailMove(email, "archive", true)}))
    $(".threadControl .moveToInboxButton").click(withLastEmail(function(email){emailMove(email, "inbox", true)}))
    $(".threadControl .deleteButton").click(withLastEmail(function(email){emailMove(email, "trash", true)}))
}

/**
    Takes an email header, selects its box-item, shows the thread.
    For convenience, you can pass in the li.box-item jquery element,
     which has the relevant .data() attributes.

    emailHeader => {
        msgId
        threadId
        box         // This tells the server what box we're in. Server behavior:
                    // If box is 'inbox', shows everything in 'inbox', 'sent'
                    // If box is 'sent',  shows everything in 'inbox', 'sent'
                    // If box is 'archive', shows everything in 'archive'.
                    // 'trash' is not implemented.
    }
*/
function displayEmail(emailHeader){

    if (emailHeader instanceof jQuery) {
        if (emailHeader.length == 0) {
            return;
        }
        emailHeader = {
            msgId:     emailHeader.data("msgId"),
            threadId:  emailHeader.data("threadId"),
            box:       emailHeader.data("box"),
            subject:   emailHeader.text(),
        };
    } else if (!emailHeader) {
        return;
    }

    var msgId    = emailHeader.msgId;
    var threadId = emailHeader.threadId;
    var box      = emailHeader.box;
    var subject  = emailHeader.subject;

    $("#content").empty();
    $("li.box-item.current").removeClass("current");
    $("li.box-item[data-thread-id='"+threadId+"']").addClass("current");

    getPrivateKey(function(privateKey) {

        var params = {
            msgId:    msgId,
            threadId: threadId,
            box:      box,
        };

        $.get("/email/", params, function(emailDatas){
            var fromAddrs = emailDatas.map("From").map(trimToLower).unique();
            lookupPublicKeys(fromAddrs, function(keyMap, newResolutions) {
                // First, save new pubHashes to contacts so future lookups are faster.
                if (newResolutions.length > 0) {
                    trySaveContacts(addContacts(viewState.contacts, newResolutions))
                }

                // Construct array of email objects.
                var emails = emailDatas.map(function(emailData){
                    decryptAndVerifyEmail(emailData, privateKey, keyMap);
                    return createEmailViewModel(emailData, box, subject);
                });

                // Construct thread element, insert emails
                showEmailThread(emails) 

                // Update view state
                bindEmailEvents();
                viewState.emails = emails; // for keyboard shortcuts & thread control
            })
        }, "json")
    })
}

// Decrypts an email. Checks the signature, if there is one.
// Expects data.CipherBody, sets data.plaintextBody
function decryptAndVerifyEmail(data, privateKey, keyMap){
    var from = trimToLower(data.From);
    var fromKey = keyMap[from].pubKey;
    if (!fromKey) {
        // TODO: color code to show that the email is unverified
        console.log("No key found for "+from+". This email is unverifiable "+
            "regardless of whether it has a signature.");
    }
    data.plaintextBody = tryDecodePgp(data.CipherBody, privateKey, fromKey);
}

function createEmailViewModel(data, box, threadSubject) {
    // Parse From, To, etc
    var from = trimToLower(data.From);
    var fromName = contactNameFromAddress(from);
    var toAddresses = data.To.split(",").map(function(addr){
        addr = trimToLower(addr);
        return {
            address: addr,
            name: contactNameFromAddress(addr),
        };
    });

    // Parse Body
    var parsedBody = parseBody(data.plaintextBody);

    // The model for rendering the email template
    return {
        msgId:       data.MessageID,
        ancestorIds: data.AncestorIDs,
        threadId:    data.ThreadID,
        time:        new Date(data.UnixTime*1000),
        unixTime:    data.UnixTime,
        from:        from,
        fromName:    fromName,
        to:          data.To,
        toAddresses: toAddresses,
        subject:     parsedBody.subject || threadSubject,
        htmlBody:    createHyperlinks(parsedBody.body),
        box:         box,
    };
}

function showEmailThread(emails){
    var thread = {
        threadId:    emails[emails.length-1].threadId,
        subject:     emails[emails.length-1].subject || "(No subject)",
        box:         emails[emails.length-1].box,
    };
    var elThread = $(render("thread-template", thread)).data("thread", thread);
    for (var i=0; i<emails.length; i++) {
        var email = emails[i];
        var elEmail = $(render("email-template", email)).data("email", email);
        elThread.find("#thread-emails").append(elEmail);
    }

    $("#content").empty().append(elThread);
}

var linkRegex = new RegExp("^http(s)?://[a-z0-9-]+(.[a-z0-9-]+)*(:[0-9]+)?(\/.*)?$", "ig")

// Turns URLS into links in the plaintext.
// Returns HTML
function createHyperlinks(text) {
    var safeText =  Handlebars.Utils.escapeExpression(text);
    var exp = /(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig;
    return safeText.replace(exp,"<a href='$1'>$1</a>"); 
}

function emailReply(email){
    if(!email) return
    displayComposeInline(email, email.from, email.subject, "")
}

function emailReplyAll(email){
    if(!email) return
    var allRecipientsExceptMe = email.toAddresses
        .filter(function(addr){
            // email starts with our pubHash -> don't reply to our self
            return addr.address != sessionStorage["emailAddress"];
        })
        .map(function(addr){
            return addr.address.toLowerCase();
        })
        .concat([email.from])
    displayComposeInline(email, allRecipientsExceptMe.join(","), email.subject, "")
}

function emailForward(email){
    if(!email) return
    displayComposeInline(email, "", email.subject, email.body)
}

// email: the email object
// moveThread: if true, moves all emails in box for thread up to email.unixTime.
//  (that way, server doesn't move new emails that the user hasn't seen)
function emailMove(email, box, moveThread){
    if (box == "trash") {
        if (moveThread) {
            if(!confirm("Are you sure you want to delete this thread?")) return;
        } else {
            if(!confirm("Are you sure you want to delete this email?")) return;
        }
    }
    var params = {
        box: box,
        moveThread: (moveThread || false)
    };
    $.ajax({
        url: '/email/'+email.msgId,
        type: 'PUT',
        data: params,
    }).done(function(){
        if (moveThread) {
            $("#thread").remove();
            showNextThread();
        } else {
            removeEmailFromThread(email);
        }
        displayStatus("Moved to "+box)
    }).fail(function(xhr){
        alert("Move to "+box+" failed: "+xhr.responseText)
    })
}

function getEmailElement(msgId) {
    var elEmail = $(".email[data-msg-id='"+msgId+"']");
    if (elEmail.length != 1) {
        console.log("Failed to find exactly 1 email element with msgId:"+msgId);
        return;
    }
    return elEmail;
}

// Remove the email from the thread.
// If thread is empty, show the next thread.
function removeEmailFromThread(email) {
    var elEmail = getEmailElement(email.msgId);
    var elThread = elEmail.closest("#thread");
    elEmail.remove();
    // If this thread has no emails left, then show the next thread.
    if (elThread.find("#thread-emails .email").length == 0) {
        showNextThread();
    }
}

function showNextThread() {
    var newSelection = $(".box .current").next();
    if(newSelection.length == 0) {
        newSelection = $(".box .current").prev();
    }
    $(".box .current").remove();
    displayEmail(newSelection);
}


//
// COMPOSE
//

// cb: function(emailData), emailData has plaintext components including
//  msgId, threadId, ancestorIds, subject, to, body...
function bindComposeEvents(elCompose, cb) {
    elCompose.find(".sendButton").click(function(){
        // generate 160-bit (20 byte) message id
        // secure random generator, so it will be unique
        var msgId = bin2hex(openpgp_crypto_getRandomBytes(20))+"@"+window.location.hostname;
        var threadId    = elCompose.find("[name='threadId']").val() || msgId;
        var ancestorIds = elCompose.find("[name='ancestorIds']").val() || "";
        var subject     = elCompose.find("[name='subject']").val();
        var to          = elCompose.find("[name='to']").val();
        var body        = elCompose.find("[name='body']").val();
        sendEmail(msgId, threadId, ancestorIds, to, subject, body, function(){
            cb({
                msgId:       msgId,
                threadId:    threadId,
                ancestorIds: ancestorIds,
                subject:     subject,
                to:          to,
                body:        body,
            });
        });
    });
}

function displayCompose(to, subject, body){
    // clean up 
    $(".box").html("");
    viewState.emails = null;
    setSelectedTab($("#tab-compose"));
    var elCompose = $(render("compose-template", {
        to:      to,
        subject: subject,
        body:    body || DEFAULT_SIGNATURE,
    }));
    $("#content").empty().append(elCompose);
    bindComposeEvents(elCompose, function(emailData) {
        displayStatus("Sent");
        displayCompose();
    });
}

function displayComposeInline(email, to, subject, body) {
    var elEmail = getEmailElement(email.msgId);
    var newAncestorIds = email.ancestorIds ?
        email.ancestorIds+" <"+email.msgId+">" :
        "<"+email.msgId+">";
    var elCompose = $(render("compose-template", {
        inline:      true,
        threadId:    email.threadId,
        ancestorIds: newAncestorIds,
        to:          to,
        subject:     subject,
        body:        body || DEFAULT_SIGNATURE,
    }));
    elEmail.find(".email-compose").empty().append(elCompose);
    bindComposeEvents(elCompose, function(emailData) {
        displayStatus("Sent");
        emailData.box = email.box;
        displayEmail(emailData);
    });

}

function sendEmail(msgId, threadId, ancestorIds, to, subject, body, cb){
    // validate email addresses
    var toAddresses = to.split(",").map(trimToLower)
    if (toAddresses.length == 0) {
        alert("Enter an email address to send to")
        return;
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
                continue
            }
        }
    }
    if (errors.length > 0) {
        alert("Error:\n"+errors.join("\n"));
        return;
    }

    // extract the recipient public key hashes
    lookupPublicKeys(toAddresses, function(keyMap, newResolutions) {
        var pubKeys = {}; // {toAddress: <pubKey>}

        // Save new addresses to contacts
        if (newResolutions.length > 0) {
            trySaveContacts(addContacts(viewState.contacts, newResolutions))
        }

        // Verify all recipient public keys from keyMap
        var missingKeys = [];
        for (var i = 0; i < toAddresses.length; i++) {
            var toAddr = toAddresses[i];
            var result = keyMap[toAddr];
            if (!result.pubKey) {
                //errors.push("Failed to fetch public key for address "+toAddr+":\n  "+result.error);
                missingKeys.push(toAddr);
                continue;
            }
            pubKeys[toAddr] = result.pubKey;
        }

        // If errors, abort.
        if (errors.length > 0) {
            alert("Error:\n"+errors.join("\n"));
            return;
        }

        if(missingKeys.length > 0){
            if(confirm("Could not find public keys for: "+missingKeys.join(", ")
                +" \nSend unencrypted to all recipients?")){
                sendEmailUnencrypted(msgId, threadId, ancestorIds, toAddresses.join(","), subject, body, cb);
            }
        } else {
            sendEmailEncrypted(msgId, threadId, ancestorIds, pubKeys, subject, body, cb);
        }
    })

    return false
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

    var keyMap = {}       // {<address>: {pubHash, pubKeyArmor, pubKey || error}
    var newResolutions = [] // [{address,pubHash}]

    if (addresses.length == 0) {
        return cb(keyMap, newResolutions)
    }

    loadNotaries(function(notaryKeys) {

        var hashAddresses = [] // addresses for which we know the hash
        var nameAddresses = [] // remaining addresses
        var notaries = Object.keys(notaryKeys)
        var knownHashes = {}   // {<address>: <pubHash>}

        for (var i=0; i<addresses.length; i++) {
            var addr = addresses[i]
            var contact = getContact(addr);
            if (contact) {
                if (contact.pubHash) {
                    var parts = addr.split("@")
                    hashAddresses.push(parts[0]+"#"+contact.pubHash+"@"+parts[1])
                    knownHashes[addr] = contact.pubHash
                } else {
                    knownHashes[addr] = undefined;
                    keyMap[addr] = {
                        pubHash:     undefined,
                        pubKeyArmor: undefined,
                        pubKey:      undefined,
                    };
                }
            } else {
                nameAddresses.push(addr)
            }
        }

        // Nothing to look up
        if (nameAddresses.length == 0 && hashAddresses.length == 0) {
            return cb(keyMap, newResolutions);
        }
        
        var params = {
            nameAddresses: nameAddresses.join(","),
            hashAddresses: hashAddresses.join(","),
            notaries:      notaries.join(","),
        }
        $.post("/publickeys/query", params, function(data) {

            var nameResolution = data.nameResolution
            var publicKeys =     data.publicKeys

            // verify notary responses
            if (nameAddresses.length > 0) {
                var res = verifyNotaryResponses(notaryKeys, nameAddresses, nameResolution)
                // TODO improve error handling
                if (res.errors.length > 0) {
                    alert(res.errors.join("\n\n"))
                    return // halt, do not call cb.
                }
                if (res.warnings.length > 0) {
                    alert(res.warnings.join("\n\n"))
                    // continue
                }
                for (var addr in res.pubHashes) {
                    knownHashes[addr] = res.pubHashes[addr]
                }
            }

            // de-armor keys and set pubHash on the results,
            // and verify against knownHashes.
            for (var addr in publicKeys) {
                var result = publicKeys[addr]
                if (result.status == "ERROR" || result.status == "NO_SUCH_USER") {
                    keyMap[addr] = {error:result.error}
                    continue
                } else if (result.status == "OK") {
                    var pubKeyArmor = result.pubKey
                    // check pubKeyArmor against knownHashes.
                    var computedHash = computePublicHash(pubKeyArmor);
                    if (computedHash != knownHashes[addr]) {
                        // this is a serious error. security breach?
                        var error = "SECURITY WARNING! We received an incorrect key for "+addr;
                        console.log(error, computedHash, knownHashes[addr])
                        alert(error);
                        return // halt, do not call cb.
                    }
                    if (nameAddresses.indexOf(addr) != -1) {
                        newResolutions.push({address:addr, pubHash:computedHash})
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
                        return // halt, do not call cb.
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

            // ensure that we have public keys for all the query addresses.
            for (var i=0; i<addresses.length; i++) {
                var addr = addresses[i]
                if (keyMap[addr] == null) {
                    console.log("Missing lookup result for "+addr+". Bad server impl?")
                    keyMap[addr] = {error:"ERROR: Missing lookup result"}
                }
            }

            cb(keyMap, newResolutions);
        }, "json");
    })
}

// addrPubKeys: {toAddress: <pubKey>}
function sendEmailEncrypted(msgId, threadId, ancestorIds, addrPubKeys, subject, body, cb) {
    // Get the private key so we can sign the encrypted message
    getPrivateKey(function(privateKey) {
        // Get the public key so we can also read it in the sent box
        getPublicKey(function(publicKey) {

            // Encrypt message for all recipients in `addrPubKeys`
            var pubKeys = Object.values(addrPubKeys);
            pubKeys.push(publicKey[0])
            pubKeys = pubKeys.unique(function(pubKey){ return pubKey.getKeyId() })
            
            var cipherSubject = openpgp.write_signed_and_encrypted_message(privateKey[0], pubKeys, subject);
            // Embed the subject into the body for verification
            var subjectAndBody = "Subject: "+subject+"\n\n"+body;
            var cipherBody = openpgp.write_signed_and_encrypted_message(privateKey[0], pubKeys, subjectAndBody);

            // send our message
            var data = {
                msgId:         msgId,
                threadId:      threadId,
                ancestorIds:   ancestorIds,
                to:            Object.keys(addrPubKeys).join(","),
                cipherSubject: cipherSubject,
                cipherBody:    cipherBody
            }
            sendEmailPost(data, cb);
        })
    })
}

function sendEmailUnencrypted(msgId, threadId, ancestorIds, to, subject, body, cb) {
    // send our message
    var data = {
        msgId:         msgId,
        threadId:      threadId,
        ancestorIds:   ancestorIds,
        to:            to,
        subject:       subject,
        body:          body
    };
    sendEmailPost(data, cb);
}

function sendEmailPost(data, cb) {
    $.post("/email/", data, function(){
        cb();
    }).fail(function(xhr){
        alert("Sending failed: "+xhr.responseText);
    })
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
        return {body:plaintextBody, ok:false};
    } else {
        return {subject:parts[1], body:parts[2], ok:true};
    }
}

//
// CONTACTS
//

function displayContacts(){
    loadAndDecryptContacts(function(contacts){
        // clean up 
        $(".box").html("")
        viewState.emails = [];
        setSelectedTab($("#tab-contacts"))

        // render compose form into #content
        var html = render("contacts-template", contacts)
        $("#content").html(html)
        bindContactsEvents()
    })
}

function bindContactsEvents(){
    $(".contacts li .deleteButton").click(deleteRow)
    $(".addContactButton").click(newRow)
    $(".saveContactsButton").click(function(){
        var rows = $(".contacts li")
        var contacts = []
        var needResolution = {} // need to find pubhash before saving
                                // {address: name}
        for(var i = 0; i < rows.length; i++){
            var name = trim($(rows[i]).find(".name").val())
            var address = trim($(rows[i]).find(".address").val())
            var contact = getContact(address);
            if (!address) {
                continue
            } else if (!contact) {
                needResolution[address] = name
                continue
            }
            contacts.push({name:name, address:address, pubHash:contact.pubHash})
        }

        contactsErr = validateContacts(contacts)
        if (contactsErr.errors.length > 0) {
            alert(contactsErr.errors.join("\n"))
            return
        }

        lookupPublicKeys(Object.keys(needResolution), function(keyMap) {
            for (var address in needResolution) {
                if (keyMap[address].error) {
                    alert("Error resolving email address "+address+":\n"+keyMap[address].error)
                    return
                }
                contacts.push({
                    name:    needResolution[address],
                    address: address,
                    pubHash: keyMap[address].pubHash,
                })
            }
            trySaveContacts(contacts, function(){
                displayStatus("Contacts saved")
                displayContacts()
            })
        })
    })
}
function newRow(){
    var row = $(render("new-contact-template"))
    row.find(".deleteButton").click(deleteRow)
    $(".contacts ul").append(row)
}
function deleteRow(e){
    $(e.target).parent().remove()
}

// Returns {contacts || errors}
//     contacts => [{name?,address,pubHash},..]
//     errors   => [<error>,...}
function validateContacts(contacts) {

    if (!(contacts instanceof Array)) {
        throw "Invalid input to validateContacts"
    }

    var errors = []
    var lnames = {}         // unique by lowercased name
    var addresses = {}      // unique by address
    var contactsClean = []

    for(var i = 0; i < contacts.length; i++){
        var contact = contacts[i];
        var name = contact.name ? trim(contact.name) : undefined
        var lname = name ? name.toLowerCase() : undefined
        var address = trimToLower(contact.address)
        var addressMatch = address.match(REGEX_EMAIL)
        var pubHash = contact.pubHash ? trimToLower(contact.pubHash) : undefined

        if (name && !name.match(REGEX_CONTACT_NAME)) {
            errors.push("Invalid contact name: "+name)
        }

        if (address == "") {
            errors.push("No email address for name: "+name)
        } else if(!addressMatch) {
            errors.push("Invalid email address: "+address)
        }

        if(addresses[address]) {
            errors.push("Duplicate email address: "+address)
        } else {
            addresses[address] = true
        }

        if (lname) {
            if(lnames[lname]){
                errors.push("Duplicate name: "+lname)
            } else {
                lnames[lname] = true
            }
        }

        var contact = {address:address};
        if (name)    { contact.name = name; }
        if (pubHash) { contact.pubHash = pubHash; }
        contactsClean.push(contact);
    }

    return {contacts:contactsClean, errors:errors}
}

function trySaveContacts(contacts, done){

    var contactsErr = validateContacts(contacts)

    // if there are mistakes, tell the user and bail
    if(contactsErr.errors.length > 0){
        alert(contactsErr.errors.join("\n"))
        return
    } 

    // sort the contacts book
    contacts = contactsErr.contacts.sortBy(function(contact) {
        if (contact.name) {
            return contact.name
        } else {
            return "~"+contact.address // '~' is a high ord character.
        }
    })

    // set viewState.contacts now, before posting.
    // this prevents race conditions.
    viewState.contacts = contacts

    // encrypt it
    var jsonContacts = JSON.stringify({
        version:  CONTACTS_VERSION,
        contacts: contacts,
    });
    var cipherContacts = passphraseEncrypt(jsonContacts)
    if(!cipherContacts) return

    // send it to the server
    $.post("/user/me/contacts", bin2hex(cipherContacts), "text")
        .done(done)
        .fail(function(xhr){
            alert("Saving contacts failed: "+xhr.responseText)
        })
}

// contacts: an array of existing contacts, e.g. viewState.contacts
// newContacts: new contacts (or a single contact) to merge into contacts
//   where contact is of the form {name, address, pubHash},
//   name and pubHash are optional.
// Returns new array of contacts
function addContacts(contacts, newContacts) {

    // convenience
    if (! (newContacts instanceof Array)) {
        newContacts = [newContacts]
    }

    // create a new array, don't modify the old one.
    var allContacts = []
    for (var i=0; i<contacts.length; i++) {
        var c = contacts[i]
        allContacts.push({name:c.name, pubHash:c.pubHash, address:c.address})
    }
    // defensively delete reference to original contacts.
    contacts = null

    EACH_NEW_CONTACT:
    for (var i=0; i<newContacts.length; i++) {
        var newContact = newContacts[i];

        var name = newContact.name
        var address = newContact.address
        var pubHash = newContact.pubHash

        if (!address) {
            throw "addContacts() new contacts require address"
        }

        // if address is already in contacts, just set the name.
        if (name) {
            for (var i=0; i<allContacts.length; i++) {
                if (allContacts[i].address == address) {
                    allContacts[i].name = name
                    continue EACH_NEW_CONTACT
                }
            }
        }

        // otherwise, add new contact
        var newContact = {
            name:    name ? trim(name) : undefined,
            address: trimToLower(address),
            pubHash: pubHash ? trimToLower(pubHash) : undefined,
        }

        allContacts.push(newContact)
    }

    return allContacts
}

function getContact(address) {
    if (viewState.contacts == null) {
        return null;
    }
    address = trimToLower(address);
    for(var i = 0; i < viewState.contacts.length; i++){
        var contact = viewState.contacts[i];
        if(contact.address==address){
            return contact;
        }
    }
    return null;
}

function contactNameFromAddress(address){
    var contact = getContact(address);
    if (contact) {
        return contact.name;
    }
    return null
}

function contactAddressFromName(name){
    if (viewState.contacts == null) {
        return null;
    }
    name = trimToLower(name)
    for(var i = 0; i < viewState.contacts.length; i++){
        var contact = viewState.contacts[i]
        if(contact.name && contact.name.toLowerCase() == name){
            return contact.address;
        }
    }
    return null
}

function getContacts(fn){
    if(viewState.contacts){
        fn(viewState.contacts)
    } else {
        loadAndDecryptContacts(fn)
    }
}

function loadAndDecryptContacts(fn){
    if(!sessionStorage["passKey"]){
        alert("Missing passphrase. Please log out and back in.");
        return;
    }

    $.get("/user/me/contacts", function(cipherContactsHex){
        var cipherContacts = hex2bin(cipherContactsHex);
        var jsonContacts = passphraseDecrypt(cipherContacts);
        if(!jsonContacts) {
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
    }, "text").fail(function(xhr){
        if(xhr.status == 404){
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
                alert("Error: expected legacy contacts list to have hash address: "+contact.address)
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
        $.post("/publickeys/reverse", params, function(pubHashToAddress) {
            var addresses = [], hashesDeleted = [];
            for(var hash in pubHashToAddress){
                if(pubHashToAddress[hash]==""){
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

    var notaries = Object.keys(notaryKeys)
    var pubHashes = {} // {<address>:<pubHash>}
    var notarized = {} // {<address>:[<notary1@host>,...]}
    var warnings = []
    var errors = []

    for (var notary in notaryKeys) {
        var notaryPublicKey = notaryKeys[notary]
        var notaryRes = notaryResults[notary]
        if (notaryRes.error) {
            // This may be ok if there were enough notaries that succeeded.
            warnings.push("Notary "+notary+" failed: "+notaryRes.error)
            continue
        }
        // Check the signature & check for agreement.
        for (var address in notaryRes.result) {
            var addressRes = notaryRes.result[address]
            addressRes.address = address
            if (addresses.indexOf(address) == -1) {
                // This is strange, notary responded with a spurious address.
                // Handle with care.
                errors.push("Unsolicited notary response from "+notary+" for "+address)
                continue
            }
            if (!verifyNotarySignature(addressRes, notaryPublicKey)) {
                // This is a serious error in terms of security.
                // Handle with care.
                errors.push("Invalid notary response from "+notary+" for "+address)
                continue
            }
            if (notarized[address]) {
                if (pubHashes[address] != addressRes.pubHash) {
                    // This is another serious error in terms of security.
                    // There is disagreement about name resolution.
                    // Handle with care.
                    errors.push("Notary conflict for "+address)
                    continue
                }
                notarized[address].push(notary)
            } else {
                notarized[address] = [notary]
                pubHashes[address] = addressRes.pubHash
            }
        }
    }

    // For now, make sure that all notaries were successful.
    // In the future we'll be more flexible with occasional errors,
    //  especially when we have more notaries serving.
    for (var i=0; i<addresses.length; i++) {
        var address = addresses[i];
        if(!notarized[address] || notarized[address].length != notaries.length) {
            errors.push("Error: missing notaries, could not resolve "+address
                + ". Only heard from: "+(notarized[address]||[]).join(", "))
        }
    }

    return {warnings:warnings, errors:errors, pubHashes:pubHashes}
}

// Load list of notaries.
// TODO Currently just hardcoded, will change in the future.
// TODO Needs to be overridden for local testing.
// TODO Load public keys by querying /notary/id & saving it maybe.
// cb: function(notaries), notaries: {<host>:<publicKey>, ...}
function loadNotaries(cb) {
    
    cb({
        // Production notaries, commented out for local development.
        "hashed.im":
            openpgp.read_publicKey(
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"+
                "\n"+
                "xsBNBFJLk4EBCAC4nrwXquYcsFdixa/ibyqRMivsZiqurfAViNtPdVK+p10YAFkK\n"+
                "GQIi+E4p05k1CyDbHFUChouB+cQk2fSteLbb3VBND91mwixxElcuMVHOhDtObYod\n"+
                "ND++RgwZZJ+OWG9M0zKQxGWBSSiaH2PHfofEmg1rRD7cU+DJPLkuDbG7OMrS3ayW\n"+
                "g4qgXGHfsypR/1R7cytta7l8lCRSJOJnE4MSzVqkg5LU/TbAlI6GFvz1j0MAuPp/\n"+
                "wqnXaGJAOvCtcKSHbtTkhdWdg+/IQkkh1u3TOqIZ3zUg/MiCdg5inoFuW5UIJe2Z\n"+
                "KvEPNLylVjRKxuOzw47IjwlHFIK/Rg1FVtOTABEBAAHNQU5vdGFyeSAoTm90YXJ5\n"+
                "IGZvciBoYXNoZWQuaW0gU2NyYW1ibGUgU2VydmVyKSA8c3VwcG9ydEBoYXNoZWQu\n"+
                "aW0+wsBiBBMBCAAWBQJSS5OBCRCgZUoGo32kEAIbAwIZAQAAOwoIACRIIXmK5C3n\n"+
                "EdNsGZeIeIT9W/1ip68m4VciWfhzWSipRVtjKyTFDS0lFx9I5kpNNA57+8dIWwCh\n"+
                "JaY2Tz4h4lAOEhbp1lLQB+SITqnQsfRBpxvtVCs5LeRZ/3BcCPAIlcVyqHAkuFCx\n"+
                "SHTzpxLvx3dklxuPn7+RnWtfpCwIMjUUHod6mQxVFXkZxom44IMWYGQmLKF416zj\n"+
                "0Jg/JGmSKXMiUSKV2gIPk98Wkz4ab3xhblAbCalK2IAmAkA1QBbhAwqIPAA5rF0d\n"+
                "zZ867WAMTFqiFQ0nipfE/s0opBokNmV/v9881yQ3VtM8PoPfoDX/zjXiETSHhPhF\n"+
                "fkBl+ISqgqvOwE0EUkuTgQEIANvgLWvl0hjbJ6Qo7SC9AlVirgA1tdsL7eGNZJDJ\n"+
                "uGzyhcFGubXQA0TDZl3bdUqCWCWwqNHB4hTSxink75Akfl3R4Vob60eOm3QYccPI\n"+
                "giN9PB0Mt0ixSIbJ3rB/qAV4ZH4Fty2zthbxmqNhsYQBZ75IydQBUwjChD2Shs1t\n"+
                "BQSreB+G95sf6vw0EnjdfpUuy0Aw38gHAGNr05Szep7OQ9Mf3h+9cszDpPVyNDU8\n"+
                "xawQYdMJlVCgAkmSpRbCFIuGanze4ViLrmkhPHbzedDeLxHzq3GxAG2WeGspPLS+\n"+
                "HDr3kGJisHQ4bPRcoPn16xEphCqFLrrUmQ1ErRvCmduUHFcAEQEAAcLAXwQYAQgA\n"+
                "EwUCUkuTgQkQoGVKBqN9pBACGwwAAGv+CACaSfCTIKPhv35dBQSyZI7j7h/Fq6It\n"+
                "opBqeqTEPq8Nz7tHE3b5bnRx0uLEv/gaGRr93fUJU5jdA+kQRp9AEa/wwcFu58VC\n"+
                "vISKdmcZetT6D+hbNqFGTor01rQcO+MSTNFi9jB8AQx7wYKSI3WugsTBAuifzp6E\n"+
                "N+e1s+ADMuAk9e92KNaX3i/2loexfB5f486th7+/ALNo2G4I2SrPFIq5GVNixOkf\n"+
                "vlUab6/0EUC+d25//P3PPgqmNPyEYNrI1fYtqn7VYxa0jycsLOVCd/ak/SwqIlUo\n"+
                "rk3ZF3pZKAwV5UM2IQSgS0fshNrDpuMkRxscv/KYW+tVqYeP8UX1r74k\n"+
                "=J+9O\n"+
                "-----END PGP PUBLIC KEY BLOCK-----"
            ),
        "scramble.io":
            openpgp.read_publicKey(
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"+
                "\n"+
                "xsBNBFJc8kEBCADAcboo0fUDW7oyF18TxSA2sROfJrg186xdHkp/enYjHzHRs2vw\n"+
                "+Bs65Pp6Zug+0+BgoJHbpt7fNlkYchYvaySyAAmGzR6MtPrGR3VBhvslEkbHGW9J\n"+
                "uy0jKs5o1EcrYi9aviUsispz7tsOJszcfNLDCpIf3zbmXV3RNJ5G+tHIuaG1D+Mz\n"+
                "MkF6UO1sgwzG6ES36yaCBedFzzEwBi7At7CSTAGNV0r1ocAi/zkUDvGgpKvvf4lA\n"+
                "Le9kuAuT7ozDPGJGwnPvFpjNxt53OPAegDKHPLVB9ZNaY/Mr9ee5ov3Pl5J7z1JT\n"+
                "qc9RG6Mtlz15UQD1wEzZoEJRJJ+RwUTt8p4PABEBAAHNT05vdGFyeSAoTm90YXJ5\n"+
                "IGZvciB0ZXN0LnNjcmFtYmxlLmlvIFNjcmFtYmxlIFNlcnZlcikgPHN1cHBvcnRA\n"+
                "dGVzdC5zY3JhbWJsZS5pbz7CwGIEEwEIABYFAlJc8kEJEH2a1kplMK9TAhsDAhkB\n"+
                "AADmkggAmGa9aWfHkiRWx3xixJNYDmqzVtfiYs46n2tseiVT6SPaythVsbYNTw2w\n"+
                "M2711CF42IpJZpTUSUQ45zIrQQsNRwbwKjh8g5dCkngRfcDykDRdjMbUmF17/LLp\n"+
                "aCccv70QVPaok/TgLr5QPPYr4OdR2pgyNezjGuHOrlrSQoViXhyD/h91vATh7d2G\n"+
                "m6QkrAt0dI7QNWegVpSfuk9yXTKnBign2mrHc+HM107RYE0WK/oqy70Fa/GeqHE5\n"+
                "5KwS3kLWu38qYnAYw5bpwNdOtl98BM89M6Unp3wq2I4dHj9NKskLNwkCF0cA9vaI\n"+
                "bIw9faDwd9WW5ou1GAT0f/xMEKXbjs7ATQRSXPJBAQgAxk2m0pXwCifo2vKQnnyg\n"+
                "LBt86B91TN2G1yfbigLmRmW15Z+fNuL5AuIz4eYZz6M0hxSQ0lhgEzGjDgIUaUAi\n"+
                "6oCoqf+aTT978KkVEExZR+p/v3hqxwjtDc6q9OAjWCrXpXcPsIfDYGKCDt1Mx802\n"+
                "Gqzw8dBkoy4PnQ6OMqUYnL1vQFui2nrksfrQCtTIlmsICW16frwLI2nPDrwY+GUi\n"+
                "n3UoKGoT5JCXVPQ4sdDbgzJoqGJwe1JMls/+vfPaz1r0jOF/a3Ovau8vOvWSdodk\n"+
                "L2db8HxfIbaMj+zBb6Hume/KdWKiJZ+Xv9ZnqnmjVl+TIz1ncqnfJWpJ5j/cSGsk\n"+
                "CwARAQABwsBfBBgBCAATBQJSXPJBCRB9mtZKZTCvUwIbDAAAJKMIAFhG3a6upAxC\n"+
                "PjCFOKV1L+z8F3N6HEQJBmwuwmWaIj6RhvnWdqBMkjmcxclAvuM9rzYZhrE0XjqK\n"+
                "kZUrJhnCRCmLfWtA6SZE/C65FdCdIZPB04BmIW6MLEOL3+HleB5LD0v6Exx4KvFN\n"+
                "e0clu0m0H+HxvrtnhdDaAEh2cdPZTiOlrbJ3oXwk9B1j/N1AJIqE5RSrrrOXrdl/\n"+
                "3g3j/nGEf0hqhjPmB7kafR7ZbP78ipV1ENraoafk3RtKNKuZI5+2mdzvYYIiRTcH\n"+
                "YE6g+T3KLPalnjqp3RppJ48pCH8bs/ZzeEGVrjDPcSscC5+96FmFvm064fOdSz7m\n"+
                "/YAMYP4dUiE=                                                    \n"+
                "=Mt/n                                                           \n"+
                "-----END PGP PUBLIC KEY BLOCK-----"
            ),
        "dev.hashed.im":
            openpgp.read_publicKey(
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"+
                "\n"+
                "xsBNBFJM2MQBCAC+6XtfSNnub2S3OAUPCPVkQ+5FHQ1BKBft1R1rFlhsBYnBFp9O\n"+
                "9mOG945gkq6tF3cW5IEOrHbTkyB3aHzunoU90AIE5r6FT/9d6BrSU68SdDGimYmd\n"+
                "32UnIZpAYEBxOkVxKH1/qD1SBjqqFjCEfUNVfb+Yrtmpu+X7ZIOPsQvVG49Fm9jz\n"+
                "Ec8czgh1+vZs76qljrNAfcHNNZnwLghF3bFwd0opckBRQ0Fy4iaxSn3ovwjKu2bZ\n"+
                "/fzAMDSzjWm5SVOr3bgDKseJmfP3ILDfAzEH5BksDatPqWRDI96YOFNHNfmJ9AmO\n"+
                "fdLeR234rixSrfcMiCPCk8ghjtkrh6MGFOVbABEBAAHNTU5vdGFyeSAoTm90YXJ5\n"+
                "IGZvciBkZXYuc2NyYW1ibGUuaW8gU2NyYW1ibGUgU2VydmVyKSA8c3VwcG9ydEBk\n"+
                "ZXYuc2NyYW1ibGUuaW8+wsBiBBMBCAAWBQJSTNjECRBkHs2sSxRdNAIbAwIZAQAA\n"+
                "NTIIAHYURtQ9kPzbM2we5NEtSYugGUtaOlfksH4eNdLeSUta0lo5sAhTIDqhpU6r\n"+
                "VZBFC/QMenvsJNjfLrusbDHUduOSdyHOWGMspvYMDD9k5b46HA6Gg/wS1HJvMImp\n"+
                "3wMEnbP0hOx5RGgizYzRJW4t0lGJ24MPvXxyzH4XEWIpev5vskP50e/Al36i4w21\n"+
                "xdJ73JSXw0AqZqaK3dQeZYRqFEK7UDdAWifOmgBWTKn1PH8zFIdf8YPx8y/Atq6K\n"+
                "nEBKmrEAMkwOZxRFXGnQl6ZdvgbGWg3U5L8M7vkf2mQObbqqTkUEDh5DdC4so37t\n"+
                "M9lIDTbqvzo80fUX/l/mzYc6HyTOwE0EUkzYxAEIAKA3QTMKdayva/0VgFXv7vjM\n"+
                "SOqjcqFgcWgIsZyRGjWd04X2KZrAr3iO6V842JO3my34vmNuKG7Bys2A+b0oRrCU\n"+
                "OP+XKmcqYwyf/lzwWgvSzZ/B7wsCn2pic8/gdbFvK4Nl2gwPmD+BPxy7ykdvIdkM\n"+
                "ZYJVyPR9LSoPPXDsFwDXQ9FGtijfS5MeCAOadMHhk8Lzk1gSi4lGwP8seJwllH1d\n"+
                "31YWprpKbMxZOZSvZSc5BvEgGeTgNGDzOnX0UqlAGIbUlwAhP/O/Q7np8LcYYIuS\n"+
                "bwGa51na39Z/MVyZiwJya1Sw4ovNqZiB/LZHe6vObCdvB0MjShEriZnKslKok1UA\n"+
                "EQEAAcLAXwQYAQgAEwUCUkzYxAkQZB7NrEsUXTQCGwwAAAHpCAB3ZRFjStuoO3FR\n"+
                "efXaFQeFXSjV7x9MeFq0atoKp/5HGICnWyGvRWAVLhUu1svs15BeEBOXPKhCyWAc\n"+
                "tzCQVvqlXEK0zcRW74nlOWoQH4QbjrYHQxdzHnzUfOIK2/zOcH0voX+QMu6kyC62\n"+
                "2SRA0PxrANdFMrgRrxKzpptQiTYFvy1cZR/wZ5cutaO2BNBwHh5grPiTtLw9YAUQ\n"+
                "cipCIzR5sCwi1wxU0hXrKlyP2fXFDgcreqP46ZUQObg6SnjvArxMzsYNnStfbW/W\n"+
                "aNQWj12+wxHNgUyo1xhkvPk5g8svGhAFsZHVB93YxkKMX79SFku6nQGNbl7Ez3Mu\n"+
                "hO2q+5YC\n"+
                "=Hmrz\n"+
                "-----END PGP PUBLIC KEY BLOCK-----"
            ),

        /*
        // This is the development notary public key.
        // For development, just copy the following to your ~/.scramble/notary_privkey:
        // https://github.com/dcposch/scramble/wiki/Development-Notary
        // For production, delete this.
        "local.scramble.io":
            openpgp.read_publicKey(
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"+
                "\n"+
                "xsBNBFJR69oBCAC3Ijo61+i0C5lA4c7qVWRHZ3qquEap9jRr4kdyeASmJSGtwlkz\n"+
                "8PmTVzwjvQLqjF69Or1TpWnhVI/Rcq0UILaiwcakk2JaoAzUkKCNnK3hJqZa0h7S\n"+
                "in6PVQK12v9/5kwh4pv9bzVCWe8QOE+oU45DfeOm066EVZvyRttdNxxgtcMsilTI\n"+
                "ecMI/MtELJHoGe7yUNNmScSNolxCBMUbKHMlAVry2SLbaSsiLK5jq+hBubl3Kp/+\n"+
                "XLV6yHRhY9WbC2e1G5UR6VVrwk9Ea66zpvZB+qwoUxHsbbNfR8HceHKORu/MoKvR\n"+
                "pzQqKNy9eUMVCv+RRGIssjbyVm2WQXDxAmOZABEBAAHNTU5vdGFyeSAoTm90YXJ5\n"+
                "IGZvciBkZXYuc2NyYW1ibGUuaW8gU2NyYW1ibGUgU2VydmVyKSA8c3VwcG9ydEBk\n"+
                "ZXYuc2NyYW1ibGUuaW8+wsBiBBMBCAAWBQJSUevaCRDaTZilZe26GwIbAwIZAQAA\n"+
                "gTUIACZOY7dNqr48kHLl4M5DzOYPEuqNvn2HImFhzD2/+F5/BtO/WSXTd37kM1um\n"+
                "9O0bOSk+BRes6K6QK8sGpea/s7vyk4wE6cKZzvgin584lUUHKTlitIc8baj37lBF\n"+
                "tzlxA5ZtqDg98hHhlrY5wfe0OBA8K5n+9B1vGx7zBgT2CUi5evIV49jkrlN9fXH0\n"+
                "wnbh1VIi2BI1HYKls2A/uCemxjSv9GktZDj5r1sijQRiB8dhEekbbkPAoTnUKpoS\n"+
                "LUDxQ2T4A61WzvbwGjwuuSvOBjD5MvlGE+N+DRh7Vsrgt9ZEPiscGA+rIgKDXuvK\n"+
                "ZhvsjTGJdkXghfIO6wFiV6bHz+TOwE0EUlHr2gEIALpLONxcBDwkEXqsnDxvq81r\n"+
                "2mWijAu12L7swcj0OFJxLrm24DRy7Ccu4bxL18iNNDXT2hjkw+JeWfqjpjbVzd0P\n"+
                "5jMfCr3B/IjHfVdW5zO6yJhBDRv5/z1Q8CQdUSECd7y+PNNrWPbdoW1SQD7w+oWB\n"+
                "0AUYJtMq788vd2nJvfNco0noYCeig7u7Cybvxx81DC32F4QfxqoFteHwZOhZzgoa\n"+
                "RBqYtat77i/UjZcx1R5Aluw47YqppwdBAyufKWsAhWGQAd2qyBfcTa2lp0MwSoo9\n"+
                "J4lRf0PiRefj8RWRnrVnX63mpEJiNAuYJ0GDJjv6Q5+OeQEWSyDgI3/hEdfTQ0sA\n"+
                "EQEAAcLAXwQYAQgAEwUCUlHr2gkQ2k2YpWXtuhsCGwwAAHH0CAB9FDx8R3HWbchC\n"+
                "iZ8L4n2kDHwBYpxJ/I5EghHHgExmoC2qRC1nG2ORe1umM/ocixwH+MSP8mn7lwXC\n"+
                "0viOkqq2RmMROFLnsb5LJ4EVFWrtuk3ui3i7CWw7+3/0OevMkavzfeyil4Jj8uhD\n"+
                "DS3tHBdKrNXhHjartmdnxqKU2t91YmcpwoQLt48poSaFgwEhvRZnGqvN2vYiZ56A\n"+
                "jT9EIPPS4RlhGFVGAYtlmTAVuc9oLH0gnlKyHFxBYGVMtyZ3mCPMZTGx0sHVGWr5\n"+
                "mN6bbXranXF15OpoP8XdSwOaGsrvpXw/4ki2YPTmbI6x+1GhNoOsLHppZ1/k84eW\n"+
                "UR5PU4G6\n"+
                "=Qw2D\n"+
                "-----END PGP PUBLIC KEY BLOCK-----"
            ),
        */
    })
}

// Ensure that notaryRes is properly signed with notaryPublicKey.
// notaryRes: {address,pubHash,timestamp,signature}
// returns true or false
function verifyNotarySignature(notaryRes, notaryPublicKey) {
    var toSign = notaryRes.address+"="+(notaryRes.pubHash||"")+"@"+notaryRes.timestamp
    var sig = openpgp.read_message(notaryRes.signature)
    return sig[0].signature.verify(toSign, {obj:notaryPublicKey[0]})
}

//
// CRYPTO
//

// Uses a key derivation function to create an AES-128 key
// Returns 128-bit binary
var scrypt = scrypt_module_factory();
function computeAesKey(token, pass){
    var salt = "2"+token
    return hex2bin(computeScrypt(pass, salt, 16)) // 16 bytes = 128 bits
}

// Backcompat only: uses SHA1 to create a AES-128 key (binary)
// Returns 128-bit binary
function computeAesKeyOld(token, pass){
    var sha1 = new jsSHA("2"+token+pass, "ASCII").getHash("SHA-1", "ASCII")
    return sha1.substring(0, 16) // 16 bytes = 128 bits
}

// Uses a key derivation function to compute the user's auth token
// Returns 160-bit hex
function computeAuth(token, pass){
    var salt = "1"+token
    return computeScrypt(pass, salt, 20) // 20 bytes = 160 bits
}

function computeScrypt(pass, salt, nbytes){
    var param = SCRYPT_PARAMS
    var hash = scrypt.crypto_scrypt(
            scrypt.encode_utf8(pass), 
            scrypt.encode_utf8(salt), 
            param.N, param.r, param.p, // difficulty
            nbytes
        )
    return scrypt.to_hex(hash)
}

// Backcompat only: old SHA1 auth token
// Returns 160-bit hex
function computeAuthOld(token, pass){
    return new jsSHA("1"+token+pass, "ASCII").getHash("SHA-1", "HEX")
}

// Symmetric encryption using a key derived from the user's passphrase
// The user must be logged in: the key must be in sessionStorage
function passphraseEncrypt(plainText){
    if(!sessionStorage["passKey"] || sessionStorage["passKey"] == "undefined"){
        alert("Missing passphrase. Please log out and back in.")
        return null
    }
    var prefixRandom = openpgp_crypto_getPrefixRandom(ALGO_AES128)
    return openpgp_crypto_symmetricEncrypt(
        prefixRandom, 
        ALGO_AES128, 
        sessionStorage["passKey"], 
        plainText)
}

// Symmetric decryption using a key derived from the user's passphrase
// The user must be logged in: the key must be in sessionStorage
function passphraseDecrypt(cipherText){
    if(!sessionStorage["passKey"] || sessionStorage["passKey"] == "undefined"){
        alert("Missing passphrase. Please log out and back in.")
        return null
    }
    var plain
    try {
        plain = openpgp_crypto_symmetricDecrypt(
            ALGO_AES128, 
            sessionStorage["passKey"], 
            cipherText)
    } catch(e) {
        // Backcompat: people with old accounts had weaker key derivation
        plain = openpgp_crypto_symmetricDecrypt(
            ALGO_AES128, 
            sessionStorage["passKeyOld"], 
            cipherText)
        console.log("Warning: old account, used backcompat AES key")
    }
    return plain
}

// Returns the first 80 bits of a SHA1 hash, encoded with a 5-bit ASCII encoding
// Returns a 16-byte string, eg "tnysbtbxsf356hiy"
// This is the same algorithm and format Onion URLS use
function computePublicHash(str){
    // SHA1 hash
    var sha1Hex = new jsSHA(str, "ASCII").getHash("SHA-1", "HEX")

    // extract the first 80 bits as a string of "1" and "0"
    var sha1Bits = []
    // 20 hex characters = 80 bits
    for(var i = 0; i < 20; i++){
        var hexDigit = parseInt(sha1Hex[i], 16)
        for(var j = 0; j < 4; j++){
            sha1Bits[i*4+3-j] = ((hexDigit%2) == 1)
            hexDigit = Math.floor(hexDigit/2)
        }
    }
    
    // encode in base-32: letters a-z, digits 2-7
    var hash = ""
    // 16 5-bit chars = 80 bits
    var ccA = "a".charCodeAt(0)
    var cc2 = "2".charCodeAt(0)
    for(var i = 0; i < 16; i++){
        var digit =
            sha1Bits[i*5]*16 + 
            sha1Bits[i*5+1]*8 + 
            sha1Bits[i*5+2]*4 + 
            sha1Bits[i*5+3]*2 + 
            sha1Bits[i*5+4]
        if(digit < 26){
            hash += String.fromCharCode(ccA+digit)
        } else {
            hash += String.fromCharCode(cc2+digit-26)
        }
    }
    return hash
}

function getPrivateKey(fn){
    if(sessionStorage["privateKeyArmored"]){
        var privateKey = openpgp.read_privateKey(sessionStorage["privateKeyArmored"])
        fn(privateKey)
        return
    }

    $.get("/user/me/key", function(cipherPrivateKeyHex){
        var cipherPrivateKey = hex2bin(cipherPrivateKeyHex)
        var privateKeyArmored = passphraseDecrypt(cipherPrivateKey)
        if(!privateKeyArmored) return
        sessionStorage["privateKeyArmored"] = privateKeyArmored
        var privateKey = openpgp.read_privateKey(privateKeyArmored)
        fn(privateKey)
    }, "text").fail(function(xhr){
        alert("Failed to retrieve our own encrypted private key: "+xhr.responseText)
        return
    })
}

function getPublicKey(fn) {
    if(sessionStorage["publicKeyArmored"]) {
        var publicKey = openpgp.read_publicKey(sessionStorage["publicKeyArmored"])
        fn(publicKey)
        return
    }

    getPrivateKey(function(privateKey) {
        var publicKey = openpgp.read_publicKey(privateKey[0].extractPublicKey())
        fn(publicKey)
        return
    })
}

// if publicKey exists, it is used to verify the signature.
function tryDecodePgp(armoredText, privateKey, publicKey){
    try {
        return decodePgp(armoredText, privateKey, publicKey)
    } catch (err){
        console.log("Decryption failed:", [err, err.stack]);
        return "(Decryption failed)"
    }
}

function decodePgp(armoredText, privateKey, publicKey){
    var msgs = openpgp.read_message(armoredText)
    if(msgs.length != 1){
        alert("Warning. Expected 1 PGP message, found "+msgs.length)
    }
    var msg = msgs[0]
    var sessionKey = null;
    for (var i=0; i<msg.sessionKeys.length; i++) {
        if (msg.sessionKeys[i].keyId.bytes == privateKey[0].getKeyId()) {
            sessionKey = msg.sessionKeys[i];
            break
        }
    }
    if (sessionKey == null) {
        alert("Warning. Matching PGP session key not found")
    }
    if(privateKey.length != 1){
        alert("Warning. Expected 1 PGP private key, found "+privateKey.length)
    }
    var keymat = { key: privateKey[0], keymaterial: privateKey[0].privateKeyPacket}
    if(!keymat.keymaterial.decryptSecretMPIs("")){
        alert("Error. The private key is passphrase protected.")
    }
    var text;
    if (publicKey) {
        var res = msg.decryptAndVerifySignature(keymat, sessionKey, [{obj:publicKey}])
        if (res.length == 0){
            console.log("Warning: this email is unsigned");
            text = msg.decryptWithoutVerification(keymat, sessionKey)[0]
        } else if (!res[0].signatureValid) {
            // old messages will pop this error modal.
            alert("Error. The signature is invalid!");
        } else {
            // valid signature, hooray
            text = res[0].text;
        }
    } else {
        var text = msg.decryptWithoutVerification(keymat, sessionKey)[0]
    }
    return text
}


//
// UTILITY
//

function initPGP(){
  if (window.crypto.getRandomValues) {
    openpgp.init()
    return true
  } else {
    alert("Sorry, you'll need a modern browser to use Scramble.\n"+
          "Use Chrome >= 11, Safari >= 3.1 or Firefox >= 21")
    return false
  }   
}

// openpgp really wants this function.
function showMessages(msg) {
    var err = $("<div />").html(msg).text();
    console.log("OpenPGP.js - "+err);
    if(err.toLowerCase().startsWith("error")){
        throw err;
    }
}

// Renders a Handlebars template, reading from a <script> tag. Returns HTML.
function render(templateId, data) {
    var source = document.getElementById(templateId).textContent
    var template = Handlebars.compile(source)
    return template(data)
}

// Usage: {{formatDate myDate format="MMM YY"}} for "Aug 2013"
Handlebars.registerHelper('formatDate', function(context, block) {
    var str = block.hash.format || "YYYY-MM-DD"
    return moment(context).format(str)
})

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

Handlebars.registerPartial("box-pagination", $('#box-pagination-partial').html())

// The Scramble email address of the currently logged-in user
function getUserEmail(){
    return sessionStorage["token"]+"@"+window.location.hostname
}

// Appends an element to an array, if it's not already in the array
function addIfNotContains(elems, newElem){
    if(elems.indexOf(newElem) < 0){
        elems.push(newElem)
    }
}

function bin2hex(str){
    return util.hexstrdump(str)
}
function hex2bin(str){
    return util.hex2bin(str)
}
function trim(str){
    return str.replace(/^\s+|\s+$/g,'')
}
function trimToLower(str){
    return trim(str).toLowerCase()
}

// Code that must run in the browser goes in here, so we can run tests in console.
// For example, code that require jQuery.
if (typeof window != "undefined") {
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
