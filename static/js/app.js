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

function bin2hex(str){
    var ret = ""
    for(var i = 0; i < str.length; i++){
        var c = str.charCodeAt(i)
        ret += hex_chr[c >> 4] + hex_chr[c & 0xF]
    }
    return ret
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

    // send the user+passhash
    var hashLogin = computePassHash(user, pass)
    console.log("WTF: "+hashLogin)
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
    var publicHash = new jsSHA(keys.publicKeyArmored, "ASCII").getHash("SHA-1", "HEX")
    console.log("Creating "+publicHash+"@"+window.location.hostname)

    // encrypt the private key with the user's passphrase
    var hash = new jsSHA("salt"+user+pass, "ASCII").getHash("SHA-1", "ASCII")
    // first 16 bytes = 128 bits. the hash is binary, not actually "ASCII"
    var aes128Key = hashKey.substring(0,16); 
    var prefixRandom = openpgp_crypto_getPrefixRandom(ALGO_AES128)
    var cipherPrivateKey = openpgp_crypto_symmetricEncrypt(
        prefixRandom, ALGO_AES128, aes128Key, keys.privateKeyArmored)


    // send it
    form.action = "/user/"+user
    form.user.value = user
    form.passwordHash.value = hashLogin
    form.publicKey.value = keys.publicKeyArmored
    form.cipherPrivateKey.value = bin2hex(cipherPrivateKey); 
    
    return true
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

function read(target){
    if(target.size()==0) return
    $("li.current").removeClass("current")
    target.addClass("current")

    $.get("/email/"+target.data("id"), function(data){
        $("label").show()

        $("#from").html(target.data("from"))
        $("#to").html(target.data("to"))
        $("#subject").html(target.text())
        $("#body").text(data)
    }, "text")
}

$("li").click(function(e){
    read($(e.target))
})

$(document).keypress(function(e){
    var code = e.charCode || e.which
    if(code==106){ //j
        if($(".current").size() == 0){
            msg = $("li").first()
        } else {
            msg = $(".current").next()
        }
        read(msg)
    } else if (code==107){ //k
        read($(".current").prev())
    }
})



//
// COMPOSE
//

function sendEmail(form){
    if(!initPGP()) return false

    // send encrypted if possible
    var to = form.to.value
    var toPubHash = extractPubHash(to)
    if(toPubHash == null){
        return confirm("Send email unencrypted?");
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

        form.cipherSubject.value = cipherSubject;
        form.cipherBody.value = cipherBody;

        form.submit();
    });
    return false;
}

function sendEmailUnencrypted(from, to, subject, body){
    alert("Unimplemented");
}

function extractPubHash(email){
    var match = /^([0-9a-f]*)@(.*)$/.exec(email)
    if(match == null){
        return null
    }
    if(match[1].length != 40){
        return null
    }
    return match[1]
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

