//
// SCRAMBLE.IO
//

//
// CONSTANTS
// See https://tools.ietf.org/html/rfc4880
//

var KEY_TYPE_RSA = 1
var KEY_SIZE = 2048

var ALGO_SHA1 = 2
var ALGO_AES128 = 7

var REGEX_USER = /^[a-z0-9][a-z0-9][a-z0-9]+$/
var REGEX_EMAIL = /^([A-Z0-9._%+-]+)@([A-Z0-9.-]+\.[A-Z]{2,4})$/i
var REGEX_HASH_EMAIL = /^([A-F0-9]{40})@([A-Z0-9.-]+\.[A-Z]{2,4})$/i

var REGEX_COOKIE_USER = /user=([^;]+)/
var REGEX_COOKIE_PASS_HASH = /passwordHash=([^;]+)/

function getCookie(regex){
    var match = regex.exec(document.cookie)
    return match == null ? null : unescape(match[1])
}



//
// LOGIN
//

function login(form){
    if(!initPGP()) return false
    var user = getUser()
    var pass = getPassword()

    // make sure we don't send private data
    form.enterButton.disabled = true
    form.password.disabled = true

    // two hashes of (user, pass), one encrypts the private key
    // save to local storage. the server must never see it
    var hashKey = computeKeyHash(user, pass)
    var aes128Key = hashKey.substring(0,16)
    localStorage["passKey"] = aes128Key

    // the other one authenticates us
    var hashLogin = computePassHash(user, pass)
    form.passwordHash.value = hashLogin
    
    return true
}

function create(form){
    if(!initPGP()) return false
    var user = validateUser()
    if(user == null) return false
    var pass = validateNewPassword()
    if(pass == null) return false

    // make sure we don't send private data
    form.createButton.disabled = true
    form.confirmPassword.disabled = true

    // two passphrase hashes, one for login and one to encrypt the private key
    // the server knows only the login hash, and must not know the private key
    var hashLogin = computePassHash(user, pass)
    var hashKey   = computeKeyHash(user, pass)
    
    // create a new mailbox
    var keys = openpgp.generate_key_pair(KEY_TYPE_RSA, KEY_SIZE, "")
    var publicHash = computePublicHash(keys.publicKeyArmored)
    console.log("Creating "+publicHash+"@"+window.location.hostname)

    // encrypt the private key with the user's passphrase
    // first 16 bytes = 128 bits. the hash is binary, not actually "ASCII"
    var aes128Key = hashKey.substring(0,16); 
    var prefixRandom = openpgp_crypto_getPrefixRandom(ALGO_AES128)
    var cipherPrivateKey = openpgp_crypto_symmetricEncrypt(
        prefixRandom, ALGO_AES128, aes128Key, keys.privateKeyArmored)


    // save to local storage
    localStorage["passKey"] = aes128Key
    localStorage["privateKeyArmored"] = keys.privateKeyArmored

    // send it
    form.action = "/user/"+user
    form.user.value = user
    form.passwordHash.value = hashLogin
    form.publicKey.value = keys.publicKeyArmored
    form.cipherPrivateKey.value = bin2hex(cipherPrivateKey); 
    
    return true
}

function computePublicHash(publicKeyArmored){
    return new jsSHA(publicKeyArmored, "ASCII").getHash("SHA-1", "HEX")
}
function computePassHash(user, pass){
    return new jsSHA("1"+user+pass, "ASCII").getHash("SHA-1", "HEX")
}
function computeKeyHash(user, pass){
    return new jsSHA("2"+user+pass, "ASCII").getHash("SHA-1", "ASCII")
}

function getUser(){
    return document.forms.loginForm.user.value.toLowerCase()
}

function getPassword(){
    return document.forms.loginForm.password.value
}

function validateUser(){
    var user = getUser()
    if(user.match(REGEX_USER)) {
        return user
    } else {
        alert("User must be at least three letters and numbers.\n"
            + "No special characters.\n")
        return null
    }
}

function validateNewPassword(){
    var pass1 = document.forms.loginForm.password.value
    var pass2 = document.forms.createForm.confirmPassword.value
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
function readEmail(target){
    if(target.size()==0) return
    $("li.current").removeClass("current")
    target.addClass("current")

    if(!initPGP()) return

    $.get("/email/"+target.data("id"), function(cipherBody){
        $("label").show()

        var plaintextSubject = target.text()
        var emailFrom = target.data("from")
        var emailTo = target.data("to")

        $("#from").text(emailFrom)
        $("#to").text(emailTo)
        $("#subject").text(plaintextSubject)
        decryptPrivateKey(function(privateKey){
            var plaintextBody = decodePgp(cipherBody, privateKey)
            $("#body").text(plaintextBody)
        })
    }, "text")
}

function decryptPrivateKey(fn){
    if(localStorage["privateKeyArmored"]){
        var privateKey = openpgp.read_privateKey(localStorage["privateKeyArmored"])
        fn(privateKey)
        return
    }
    var passKeyAes128 = localStorage["passKey"]
    if(!passKeyAes128){
        alert("Did you delete localStorage?\nPlease log out and back in.")
        return
    }
    alert(passKeyAes128)

    $.get("/user/me", function(cipherPrivateKeyHex){
        var cipherPrivateKey = hex2bin(cipherPrivateKeyHex)
        var privateKeyArmored = openpgp_crypto_symmetricDecrypt(
            ALGO_AES128, passKeyAes128, cipherPrivateKey)
        localStorage["privateKeyArmored"] = privateKeyArmored
        var privateKey = openpgp.read_privateKey(privateKeyArmored)
        fn(privateKey)
    }, "text").fail(function(){
        alert("Failed to retrieve our own encrypted private key")
        return
    })
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

$("li").click(function(e){
    readEmail($(e.target))
})

$(document).keypress(function(e){
    var code = e.charCode || e.which
    if(code==106){ //j
        if($(".current").size() == 0){
            msg = $("li").first()
        } else {
            msg = $(".current").next()
        }
        readEmail(msg)
    } else if (code==107){ //k
        readEmail($(".current").prev())
    }
})



//
// COMPOSE
//

function sendEmail(form){
    if(!initPGP()) return false

    // send encrypted if possible
    var to = form.to.value
    if(!to.match(REGEX_EMAIL)){
        alert("Invalid email address "+to)
        return false
    }
    var toPubHash = extractPubHash(to)
    if(toPubHash == null){
        return confirm("Send email unencrypted?")
    }

    // look up the recipient's public key
    $.get("/user/"+toPubHash, function(data){
        var toPub = openpgp.read_publicKey(data)
        var cipherSubject = openpgp.write_encrypted_message(toPub, form.subject.value)
        var cipherBody = openpgp.write_encrypted_message(toPub, form.body.value)
        alert("This message is going to be sent:\n" + cipherBody)

        // make sure we don't send plaintext
        form.sendButton.disabled = true
        form.subject.disabled = true
        form.body.disabled = true

        form.cipherSubject.value = cipherSubject
        form.cipherBody.value = cipherBody

        form.submit()
    }).fail(function(){
        alert("Could not find public key for "+toPubHash+"@...")
    })
    return false
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
// UTILITY
//

function initPGP(){
  if (window.crypto.getRandomValues) {
    openpgp.init()
    return true
  } else {
    window.alert("Sorry, you'll need a modern browser for this.\nUse Chrome >= 11, Safari >= 3.1 or Firefox >= 21")
    return false
  }   
}

function bin2hex(str){
    return util.hexstrdump(str)
}
function hex2bin(str){
    return util.hex2bin(str)
}

/*window.util = {}
window.util.print_debug_hexstr_dump = function(a,b){
    console.log(a + b)
}
window.util.print_error =
window.util.print_debug = function(a) {
    console.log(a)
}*/
