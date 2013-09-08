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

var REGEX_TOKEN = /^[a-z0-9][a-z0-9][a-z0-9]+$/
var REGEX_EMAIL = /^([A-Z0-9._%+-]+)@([A-Z0-9.-]+\.[A-Z]{2,4})$/i
var REGEX_HASH_EMAIL = /^([A-F0-9]{40}|[A-Z2-7]{16})@([A-Z0-9.-]+\.[A-Z]{2,4})$/i

var SCRYPT_PARAMS = {
    N:16384, // difficulty=2^14, recommended range 2^14 to 2^20
    r:8,     // recommended values
    p:1
}


//
// SESSION VARIABLES
//
// These are never seen by the server, and never go in cookies or localStorage
// sessionStorage["passKey"] is AES128 key derived from passphrase, used to encrypt to private key
// sessionStorage["privateKeyArmored"] is the plaintext private key, PGP ascii armored
//
// For convenience, we also have
// sessionStorage["pubHash"] +"@scramble.io" is the email of the logged-in user
//



//
// VIEW VARIABLES
// These are even more transient than session variables.
// They go away if you hit Refresh.
//

var viewState = {}
viewState.email = null // plaintext subject, body, etc of the currently opened email
viewState.contacts = null // plaintext address book



//
// LOAD THE SITE
//

$(function(){
    if(!initPGP()) return
    bindKeyboardShortcuts()

    // are we logged in?
    var token = $.cookie("token")
    if(!token || !sessionStorage["passKey"]) {
        displayLogin()
    } else {
        loadDecryptAndDisplayInbox()
    }
})



//
// KEYBOARD SHORTCUTS
//

var keyMap = {
    "j":readNextEmail,
    "k":readPrevEmail,
    "g":{
        "c":displayCompose,
        "i":function(){loadDecryptAndDisplayInbox("inbox")},
        "s":function(){loadDecryptAndDisplayInbox("sent")},
        "a":function(){loadDecryptAndDisplayInbox("archive")}
    },
    "r":emailReply,
    "a":emailReplyAll,
    "f":emailForward,
    "y":function(){moveEmail("archive")},
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
        loadDecryptAndDisplayInbox("inbox")
    })
    $("#tab-sent").click(function(e){
        loadDecryptAndDisplayInbox("sent")
    })
    $("#tab-archive").click(function(e){
        loadDecryptAndDisplayInbox("archive")
    })
    
    // Navigate to Compose
    $("#tab-compose").click(function(e){
        displayCompose()
    })

    // Navigate to Contacts
    $("#tab-contacts").click(function(e){
        displayContacts()
    })
    
    // Log out: click a link, deletes cookies and refreshes the page
    $("#link-logout").click(function(){
        $.removeCookie("token")
        $.removeCookie("passHash")
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
    setCookie("token", token)
    setCookie("passHash", computeAuth(token, pass))
    setCookie("passHashOld", computeAuthOld(token, pass))

    // try fetching the inbox
    $.get("/box/inbox", function(inbox){
        // logged in successfully!
        decryptAndDisplayInbox(inbox)
    }, 'json').fail(function(xhr){
        if(xhr.statusCode == 401) { // unauthorized 
            alert("Incorrect user or passphrase")
        } else {
            alert(xhr.responseText || "Could not reach the server, try again")
        }
    })
}

function setCookie(name, value){
    if(document.location.protocol.toLowerCase().substring(0,5)=="https"){
        $.cookie(name, value, {"secure":true})
    } else {
        $.cookie(name, value)
    }
}



//
// LOGIN - "CREATE ACCOUNT" MODAL
//

function displayCreateAccountModal(){
    showModal("create-account-template")

    // defer the slow part, so that the modal actually appears
    setTimeout(function(){
        // create a new mailbox. this takes a few seconds...
        keys = openpgp.generate_key_pair(KEY_TYPE_RSA, KEY_SIZE, "")
        sessionStorage["pubHash"] = computePublicHash(keys.publicKeyArmored)
        var email = getUserEmail()

        // Change "Generating..." to "Done", explain what's going on to the user
        $("#createAccountModal h3").text("Welcome, "+email)
        $("#spinner").css("display", "none")
        $("#createForm").css("display", "block")
    }, 100)

    $("#createButton").click(function(){
        createAccount(keys)
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
        // set cookies, try loading the inbox
        setCookie("token", token)
        setCookie("passHash", passHash)
        $.get("/box/inbox", function(inbox){
            decryptAndDisplayInbox(inbox)
        }, 'json').fail(function(){
            alert("Try refreshing the page, then logging in.")
        })
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
// INBOX
//

function bindInboxEvents(box) {
    // Click on an email to open it
    $("#"+box+" li").click(function(e){
        displayEmail($(e.target))
    })
}

function loadDecryptAndDisplayInbox(box){
    box = box || "inbox"
    $.get("/box/"+box, function(summary){
        decryptAndDisplayInbox(summary, box)
    }, 'json').fail(function(){
        displayLogin()
    })
}

function decryptAndDisplayInbox(inboxSummary, box){
    box = box || "inbox"
    sessionStorage["pubHash"] = inboxSummary.PublicHash

    getPrivateKey(function(privateKey){
        getContacts(function(){
            decryptSubjects(inboxSummary.EmailHeaders, privateKey)
            var data = {
                token:        $.cookie("token"),
                pubHash:      inboxSummary.PublicHash,
                domain:       document.location.hostname,
                emailHeaders: inboxSummary.EmailHeaders
            }
            $("#wrapper").html(render("page-template", data))
            bindSidebarEvents()
            setSelectedTab($("#tab-"+box))
            $("#"+box).html(render("inbox-template", data))
            bindInboxEvents(box)
        })
    })
}

function decryptSubjects(headers, privateKey){
    for(var i = 0; i < headers.length; i++){
        var h = headers[i]
        h.Subject = tryDecodePgp(h.CipherSubject, privateKey)
        if(trim(h.Subject)==""){
            h.Subject = "(No subject)"
        }
    }
}

function readNextEmail(){
    var msg
    if($(".current").length == 0){
        msg = $("li").first()
    } else {
        msg = $(".current").next()
    }
    displayEmail(msg)
}

function readPrevEmail(){
    var msg = $(".current").prev()
    if(msg.length > 0){
        displayEmail(msg)
    }
}

function moveEmail(box){
    if(!viewState.email) return
    var msgId = viewState.email.id
    $.ajax({
        url: '/email/'+msgId,
        type: 'PUT',
        data: {
            'box':box
        },
    }).done(function(){
        var newSelection = $(".box .current").next()
        if(newSelection.length == 0){
            newSelection = $(".box .current").prev()
        }
        $(".box .current").remove()
        displayEmail(newSelection)

        displayStatus("Moved to "+box)
    }).fail(function(xhr){
        alert("Move to "+box+" failed: "+xhr.responseText)
    })
}



//
// SINGLE EMAIL
//

function bindEmailEvents() {
    $("#replyButton").click(emailReply)
    $("#replyAllButton").click(emailReplyAll)
    $("#forwardButton").click(emailForward)

    $("#archiveButton").click(function(){moveEmail("archive")})
    $("#moveToInboxButton").click(function(){moveEmail("inbox")})

    $("#enterFromNameButton").click(function(){
        var name = prompt("Contact name for "+viewState.email.from)
        if(name){
            trySaveContact(name, viewState.email.from)
            displayEmail($(".box li.current"))
        }
    })
}

// Takes a subject-line <li>, selects it, shows the full email
function displayEmail(target){
    if(target.size()==0) return
    $("li.current").removeClass("current")
    target.addClass("current")

    $.get("/email/"+target.data("id"), function(cipherBody){
        getPrivateKey(function(privateKey){
            var plaintextBody = tryDecodePgp(cipherBody, privateKey)

            var fromName = contactNameFromAddress(target.data("from"))
            var toAddresses = target.data("to").split(",").map(function(addr){
                addr = trimToLower(addr)
                return {
                    address: addr,
                    name: contactNameFromAddress(addr)
                }
            })
            viewState.email = {
                id:          target.data("id"),
                time:        new Date(target.data("time")*1000),

                from:        trimToLower(target.data("from")),
                fromName:    fromName,
                to:          target.data("to"),
                toAddresses: toAddresses,

                isInbox:     target.data("box")=="inbox",
                isArchive:   target.data("box")=="archive",

                subject:     target.text(),
                body:        plaintextBody
            }
            var html = render("email-template", viewState.email)
            $("#content").attr("class", "email").html(html)
            bindEmailEvents()
        })
    }, "text")
}

function emailReply(){
    var email = viewState.email
    if(!email) return
    displayCompose(email.from, email.subject, "")
}

function emailReplyAll(){
    var email = viewState.email
    if(!email) return
    var allRecipientsExceptMe = email.toAddresses
        .filter(function(addr){
            // email starts with our pubHash -> don't reply to our self
            return addr.address.indexOf(sessionStorage["pubHash"]) != 0
        })
        .map(function(addr){
            // use nickname for addresses in the contacts book
            return addr.name ? addr.name : addr.address
        })
        .concat([email.from])
    displayCompose(allRecipientsExceptMe.join(","), email.subject, "")
}

function emailForward(){
    var email = viewState.email
    if(!email) return
    displayCompose("", email.subject, email.body)
}




//
// COMPOSE
//

function bindComposeEvents() {
    $("#sendButton").click(function(){
        var subject = $("#subject").val()
        var to = $("#to").val()
        var body = $("#body").val()

        sendEmail(to, subject, body)
    })
}

function displayCompose(to, subject, body){
    // clean up 
    $(".box").html("")
    viewState.email = null
    setSelectedTab($("#tab-compose"))

    // render compose form into #content
    var html = render("compose-template", {
        to:to,
        subject:subject,
        body:body
    })
    $("#content").attr("class", "compose").html(html)
    bindComposeEvents()
}

function sendEmail(to,subject,body){
    // generate 160-bit (20 byte) message id
    // secure random generator, so it will be unique
    var msgId = bin2hex(openpgp_crypto_getRandomBytes(20))

    // send encrypted if possible
    var toAddresses = to.split(",").map(trimToLower)
    var invalidToAddresses = toAddresses.filter(function(addr){
        return !addr.match(REGEX_EMAIL)
    })
    if(invalidToAddresses.length>0){
        alert("Invalid email addresses "+invalidToAddresses.join(", "))
        return
    }

    // extract the recipient public key hashes
    var pubHashesArr = toAddresses.map(extractPubHash)
    var pubHashes = []
    var unencryptedToAddresses = []
    for(var i = 0; i < toAddresses.length; i++){
        if(pubHashesArr[i]){
            addIfNotContains(pubHashes, pubHashesArr[i])
        } else {
            addIfNotContains(unencryptedToAddresses, toAddresses[i])
        }
    }
    if(unencryptedToAddresses.length > 0){
        prompt("Sending to unencrypted addresses is not yet supported")
        return
    }

    // look up each recipient's public key
    pubHashes.forEach(function(pubHash){
        sendEmailEncrypted(msgId,to,subject,body,'inbox',pubHash)
    })

    // encrypt a special copy to ourselves, for our sent mail folder
    // ... unless we're already emailing to ourselves
    var myPubHash = sessionStorage["pubHash"]
    if(pubHashes.indexOf(myPubHash)<0){
        sendEmailEncrypted(msgId,to,subject,body,'sent',myPubHash)
    }
    return false
}

function sendEmailEncrypted(msgId,to,subject,body,box,pubHash){
    // fetch the recipient public key
    $.get("/user/"+pubHash, function(pubKeyArmor){

        // verify the recipient public key
        var publicKeyHash = computePublicHash(pubKeyArmor)
        if(publicKeyHash != pubHash){
            alert("WARNING: the server gave us an incorrect public key for "+pubHash+"@...\n"
                + "Your message was not sent to that user.")
            return
        }

        // encrypt our message
        var publicKey = openpgp.read_publicKey(pubKeyArmor)
        var cipherSubject = openpgp.write_encrypted_message(publicKey, subject)
        var cipherBody = openpgp.write_encrypted_message(publicKey, body)

        // send our message
        var data = {
            msgId:msgId,
            box: box,
            pubHashTo: pubHash,
            to: to,
            cipherSubject: cipherSubject,
            cipherBody: cipherBody
        }
        $.post("/email/", data, function(){
            displayStatus("Sent")
            displayCompose()
        }).fail(function(xhr){
            alert("Sending failed: "+xhr.responseText)
        })
    }).fail(function(){
        alert("Could not find public key for "+pubHash+"@...")
    })
}

function sendEmailUnencrypted(from, to, subject, body){
    alert("Unimplemented")
}

// Extracts the public-key hash from <public key hash>@<host>
// Return null if the email is not in that form
function extractPubHash(email){
    var match = REGEX_HASH_EMAIL.exec(email)
    if(match == null){
        return null
    }
    return match[1].toLowerCase()
}



//
// CONTACTS
//

function displayContacts(){
    loadAndDecryptContacts(function(contacts){
        // clean up 
        $(".box").html("")
        viewState.email = null
        setSelectedTab($("#tab-contacts"))

        // render compose form into #content
        var html = render("contacts-template", contacts)
        $("#content").attr("class", "contacts").html(html)
        bindContactsEvents()
    })
}

function bindContactsEvents(){
    $(".contacts li .deleteButton").click(deleteRow)
    $("#addContactButton").click(newRow)
    $("#saveContactsButton").click(function(){
        var rows = $(".contacts li")
        var contacts = []
        for(var i = 0; i < rows.length; i++){
            var name = trim($(rows[i]).find(".name").val())
            var address = trim($(rows[i]).find(".address").val())
            if(name=="" && address=="") {
                continue
            } else {
                contacts.push({name:name, address:address})
            }
        }

        trySaveContacts(contacts, function(){
            displayStatus("Contacts saved")
            displayContacts()
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

function trySaveContacts(contacts, done){
    // index the contacts
    var tokens = [], errors = []
    var tokenToAddress = {}, tokenToName = {}, addressToToken = {}
    for(var i = 0; i < contacts.length; i++){
        var name = trim(contacts[i].name)
        var address = trimToLower(contacts[i].address)

        if (name == ""){
            errors.push("No name entered for "+address)
        } else if (address == ""){
            errors.push("No address entered for "+name)
        } else if(!address.match(REGEX_EMAIL)){
            errors.push("The following doesn't look like a valid email address: "+address)
        } 

        var token = name.toLowerCase()
        if(tokenToAddress[token]){
            errors.push("You entered the same name more than once: "+token)
        } else {
            tokenToAddress[token] = address
        }
        if(addressToToken[address]){
            errors.push("You entered the same email address more than once: "+address)
        } else {
            addressToToken[address] = token
        }

        tokens.push(token)
        tokenToName[token] = name
    }

    // if there are mistakes, tell the user and bail
    if(errors.length > 0){
        alert(errors.join("\n"))
        return
    } 

    // sort the contacts book
    tokens.sort()
    var contacts = tokens.map(function(token){
        return {
            name: tokenToName[token],
            address: tokenToAddress[token],
        }
    })
    viewState.contacts = contacts

    // encrypt it
    var jsonContacts = JSON.stringify(contacts)
    var cipherContacts = passphraseEncrypt(jsonContacts)
    if(!cipherContacts) return

    // send it to the server
    $.post("/user/me/contacts", bin2hex(cipherContacts), "text")
        .done(done)
        .fail(function(xhr){
            alert("Saving contacts failed: "+xhr.responseText)
        })
}

function trySaveContact(name, address){
    var newContact = {
        name: trim(name),
        address: trimToLower(address)
    }
    var newContacts = viewState.contacts.concat([newContact])
    trySaveContacts(newContacts, function(){
            displayStatus("Contact saved")
    })
}

function contactNameFromAddress(address){
    address = trimToLower(address)
    for(var i = 0; i < viewState.contacts.length; i++){
        var contact = viewState.contacts[i]
        if(contact.address==address){
            return contact.name
        }
    }
    return null
}



//
// CRYPTO
//

// Uses a key derivation function to create an AES-128 key
// Returns 128-bit binary
var scrypt = scrypt_module_factory();
function computeAesKey(token, pass){
    var salt = "2"+token
    return hex2bin(computeScrypt(token, pass, salt, 16)) // 16 bytes = 128 bits
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
    return computeScrypt(token, pass, salt, 20) // 20 bytes = 160 bits
}

function computeScrypt(token, pass, salt, nbytes){
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

function tryDecodePgp(armoredText, privateKey){
    try {
        return decodePgp(armoredText, privateKey)
    } catch (err){
        return "(Decryption failed)"
    }
}

function decodePgp(armoredText, privateKey){
    var msgs = openpgp.read_message(armoredText)
    if(msgs.length != 1){
        alert("Warning. Expected 1 PGP message, found "+msgs.length)
    }
    var msg = msgs[0]
    if(msg.sessionKeys.length != 1){
        alert("Warning. Expected 1 PGP session key, found "+msg.sessionKeys.length)
    }
    if(privateKey.length != 1){
        alert("Warning. Expected 1 PGP private key, found "+privateKey.length)
    }
    var keymat = { key: privateKey[0], keymaterial: privateKey[0].privateKeyPacket}
    if(!keymat.keymaterial.decryptSecretMPIs("")){
        alert("Error. The private key is passphrase protected.")
    }
    var sessKey = msg.sessionKeys[0]
    var text = msg.decrypt(keymat, sessKey)
    return text
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
        alert("Missing passphrase. Please log out and back in.")
        return
    }

    $.get("/user/me/contacts", function(cipherContactsHex){
        var cipherContacts = hex2bin(cipherContactsHex)
        var jsonContacts = passphraseDecrypt(cipherContacts)
        if(!jsonContacts) {
            return
        }
        viewState.contacts = JSON.parse(jsonContacts)
        fn(viewState.contacts)
    }, "text").fail(function(xhr){
        if(xhr.status == 404){
            viewState.contacts = [{
                name: "me",
                address: getUserEmail()
            }]
            fn(viewState.contacts)
        } else {
            alert("Failed to retrieve our own encrypted contacts: "+xhr.responseText)
        }
    })
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

// The Scramble email address of the currently logged-in user
function getUserEmail(){
    var pubHash = sessionStorage["pubHash"]
    if(!pubHash) throw "Missing public hash"
    return pubHash+"@"+window.location.hostname
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
