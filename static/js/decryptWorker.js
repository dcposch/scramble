// This worker receives the user's private key, then decrypts and 
// optionally verifies messages.
//
// The client can spawn multiple of these workers, which run in the
// background, in parallel. This UI shows results immediately---subjects
// and bodies of emails are given placeholders---then filled in as
// decryption of each message completes.


// Work around OpenPGP.js...
var window = {};
var ls = {}
window.localStorage = {
    getItem: function(key){return ls[key]||null},
    setItem: function(key,val){ls[key]=val}
};
// openpgp really wants this function.
window.showMessages = function(msg) {
    var err = $("<div />").html(msg).text();
    console.log("OpenPGP.js - "+err);
    if (err.toLowerCase().startsWith("error")) {
        throw err;
    }
}
importScripts("openpgp.js")
openpgp.init();

var privateKey;

self.onmessage = function(evt){
    var msg = JSON.parse(evt.data);

    // Set private key to use for decryption
    if(msg.type == "key"){
        privateKey = openpgp.read_privateKey(msg.privateKey);
    } else if(msg.type == "cipherText"){
        // Decrypt messages
        var response = {"cacheKey":msg.cacheKey};
        try {
            response.plaintext = decodePgp(msg.armoredText, msg.publicKey);
        } catch(err){
            response.error = ""+err;
        }
        postMessage(JSON.stringify(response));
    }
}

// Decrypts a PGP message destined for our user, given their private key
// If publicKey exists, it is used to verify the sender's signature.
// This is a slow operation (60ms)
function tryDecodePgp(armoredText, publicKey) {
    try {
        return decodePgp(armoredText, publicKey);
    } catch (err) {
        console.log("Decryption failed:", [err, err.stack]);
        return null;
    }
}

function decodePgp(armoredText, publicKey) {
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

