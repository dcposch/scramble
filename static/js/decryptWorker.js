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

importScripts("lib/openpgp.js")
openpgp.init();
util.print_error = function(str) {
    postMessage(JSON.stringify({type:"log", level:"error", message:str}));
};
util.print_warning = function(str) {
    postMessage(JSON.stringify({type:"log", level:"warn", message:str}));
};
util.print_info = function(str) {
    // ignore
};

var privateKey;

self.onmessage = function(evt){
    var msg = JSON.parse(evt.data);

    // Set private key to use for decryption
    if(msg.type == "key"){
        privateKey = openpgp.read_privateKey(msg.privateKey);
    } else if(msg.type == "cipherText"){
        // Decrypt messages
        var response = {type:"decrypt", cacheKey:msg.cacheKey};
        try {
            var publicKey = undefined;
            if (msg.publicKeyArmored) {
                publicKey = openpgp.read_publicKey(msg.publicKeyArmored)[0];
            }
            var decrypted = decryptPgp(msg.armoredText, publicKey);
            response.error = decrypted.error;
            response.warnings = decrypted.warnings;
            response.plaintext = decrypted.plaintext;
        } catch(err){
            response.error = ""+err;
        }
        postMessage(JSON.stringify(response));
    }
}

// Decrypts a PGP message destined for our user, given their private key
// If publicKey exists, it is used to verify the sender's signature.
// This is a slow operation (60ms)
function decryptPgp(armoredText, publicKey) {
    var warnings = [];

    var msgs = openpgp.read_message(armoredText);
    if (msgs.length != 1) {
        warnings.push("Expected 1 PGP message, found "+msgs.length);
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
        warnings.push("Matching PGP session key not found");
    }
    if (privateKey.length != 1) {
        warnings.push("Expected 1 PGP private key, found "+privateKey.length);
    }
    var keymat = { key: privateKey[0], keymaterial: privateKey[0].privateKeyPacket};
    if (!keymat.keymaterial.decryptSecretMPIs("")) {
        return {"error":"Error. The private key is passphrase protected."};
    }
    var text;
    if (publicKey) {
        var res = msg.decryptAndVerifySignature(keymat, sessionKey, [{obj:publicKey}]);
        if (res.length == 0) {
            text = msg.decryptWithoutVerification(keymat, sessionKey)[0];
        } else if (!res[0].signatureValid) {
            // old messages will pop this error modal.
            return {"error":"Error. The signature is invalid!"};
        } else {
            // valid signature, hooray
            text = res[0].text;
        }
    } else {
        text = msg.decryptWithoutVerification(keymat, sessionKey)[0];
    }

    // HACK:
    // openpgp.js will only call util.decode_utf8 if the filehint is 'u',
    //  while golang's openpgp library only encodes to 't'.
    // For now, let's just always call util.decode_utf8.
    //  this will cause util.decode_utf8 to get double called for messages
    //  from openpgp.js, which will most likely do nothing.
    var decodedText = util.decode_utf8(text);

    return {"warnings":warnings,"plaintext":decodedText}
}

