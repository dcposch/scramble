// This worker receives the user's private key, then decrypts and 
// optionally verifies messages.
//
// The client can spawn multiple of these workers, which run in the
// background, in parallel. This UI shows results immediately---subjects
// and bodies of emails are given placeholders---then filled in as
// decryption of each message completes.

var KEY_TYPE_RSA = 1;
var KEY_SIZE = 2048;


// Work around OpenPGP.js...
var ls = {};
var window = {};
window.localStorage = {
    getItem: function(key){return ls[key]||null;},
    setItem: function(key,val){ls[key]=val;}
};
importScripts("/js/lib/openpgp.min.js");
var openpgp = window.openpgp;
var privateKey;

self.onmessage = function(evt){
    var msg = JSON.parse(evt.data);

    // Set private key to use for decryption
    if(msg.type == "set-key"){
        handleSetKey(msg);
    } else if(msg.type == "decrypt-verify"){
        handleDecrypt(msg);
    } else if(msg.type == "generate-key-pair"){
        handleGenKeyPair(msg);
    }
};

//
// Handlers for each job type
// 
function handleSetKey(msg) {
    privateKey = openpgp.key.readArmored(msg.privateKey).keys[0];
}
function handleDecrypt(msg) {
    var response = {
        type:"decrypt", 
        id:msg.id
    };
    setRandom(msg.randomBase64);
    try {
        var publicKeys;
        if (msg.publicKeyArmored) {
            publicKeys = openpgp.key.readArmored(msg.publicKeyArmored).keys;
        }
        var decrypted = decryptPgp(msg.armoredText, publicKeys);
        response.error = decrypted.error;
        response.warnings = decrypted.warnings;
        response.plaintext = decrypted.plaintext;
    } catch(err){
        response.error = ""+err;
    }
    var dbg = "Text "+response.plaintext.length+" rand "+(65000-openpgp.crypto.random.randomBuffer.size);
    postMessage(JSON.stringify({"type":"log", "message":dbg}));
    postMessage(JSON.stringify(response));
}
function handleGenKeyPair(msg) {
    setRandom(msg.randomBase64);
    
    // create a new mailbox. this takes a few seconds...
    var keys = openpgp.generateKeyPair({
        "keyType":KEY_TYPE_RSA, 
        "numBits":KEY_SIZE,
        "userId":"",
        "passphrase":"foo"
    });
    var response = {
        "id": msg.id,
        "publicKeyArmored": keys.publicKeyArmored,
        "privateKeyArmored": keys.privateKeyArmored
    };
    postMessage(JSON.stringify(response));
}

// secure random values must be generated outside, 
// since WebCrypto is not yet available from Web Workers...
function setRandom(randomBase64) {
    var randomBuf = new Uint8Array(atob(randomBase64)
        .split("")
        .map(function(c) { return c.charCodeAt(0); }));
    openpgp.crypto.random.randomBuffer.init(randomBuf.length);
    openpgp.crypto.random.randomBuffer.set(randomBuf);
}

// Decrypts a PGP message destined for our user, given their private key
// If publicKey exists, it is used to verify the sender's signature.
// This is a slow operation (60ms)
function decryptPgp(armoredText, publicKeys) {
    var warnings = [], text;
    var msg = openpgp.message.readArmored(armoredText);
    if(publicKeys){
        var res = openpgp.decryptAndVerifyMessage(privateKey, publicKeys, msg);
        text = res.text;
    } else {
        text = openpgp.decryptMessage(privateKey, msg);
    }
    var decodedText = openpgp.util.decode_utf8(text);
    return {"warnings":warnings,"plaintext":decodedText};
}

