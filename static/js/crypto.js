"use strict";

/* global alert, cache */



var crypto = function() {
    var workers = [],
        pendingDecryption = {},
        scrypt = scrypt_module_factory();

    return {

        decryptPrivateKey: function(cipherPrivateKeyHex) {
          var cipherPrivateKey = hex2bin(cipherPrivateKeyHex),
              privateKeyArmored = this.passphraseDecrypt(cipherPrivateKey);
              
          if (!privateKeyArmored) {
            alert("Can't decrypt our own private key. Please refresh and try again.");
          }
          return privateKeyArmored;
        },

        // Starts web workers
        //
        // See decryptWorker.js for a more detailed explanation
        // of what they do and what messages they send+receive
        startPgpDecryptWorkers: function() {
            for(var i = 0; i < 4; i++){
                var worker = new Worker("js/decryptWorker.js");
                worker.numInProgress = 0;
                worker.postMessage(JSON.stringify({
                    "type":"key",
                    "privateKey": sessionStorage["privateKeyArmored"]
                }));

                worker.onmessage = function(evt){
                    var msg = JSON.parse(evt.data);
                    switch (msg.type) {
                    case "decrypt":
                        var job = pendingDecryption[msg.cacheKey];
                        cache.plaintextCache[msg.cacheKey] = msg.plaintext;
                        if(msg.error){
                            console.log("Error decrypting "+msg.cacheKey+": "+msg.error);
                        }
                        if(msg.warnings){
                            msg.warnings.forEach(function(warn){
                                console.log("Warning decrypting "+msg.cacheKey+": "+warn);
                            });
                        }
                        workers[job.worker].numInProgress--;
                        job.callback(msg.plaintext, msg.error);
                        delete pendingDecryption[msg.cacheKey];
                        break;
                    case "log":
                        console.log("Webworker:", msg.level, msg.message);
                    }
                };
                workers.push(worker);
            }
        },

        // Asynchronously decrypts (and optionally verifies) a PGP message
        //
        // Requires:
        // * unique cache key
        // * ASCII-armored ciphertext
        // * (optional) ASCII-armored public key for signature verification or null
        // * a callback cb(plaintext)
        cachedDecryptPgp: function(cacheKey, armoredText, publicKeyArmored, cb){
            var plain = cache.plaintextCache[cacheKey];
            if (typeof(plain) !== "undefined"){
                cb(plain);
            } else if (pendingDecryption[cacheKey]){
                console.log("Warning: skipping decryption, already in progress: "+cacheKey);
            } else {
                console.log("Decoding "+cacheKey);
                var msg = {
                    "type":"cipherText",
                    "cacheKey":cacheKey,
                    "armoredText":armoredText,
                    "publicKeyArmored":publicKeyArmored
                };
                var bestWorker = 0;
                for(var i = 1; i < workers.length; i++){
                    if(workers[i].numInProgress < workers[bestWorker].numInProgress){
                        bestWorker = i;
                    }
                }
                pendingDecryption[cacheKey] = {"callback":cb,"worker":bestWorker};
                workers[bestWorker].numInProgress++;
                workers[bestWorker].postMessage(JSON.stringify(msg));
            }
        },

        lookupPublicKeysFromNotaries: function(addresses, cb) {

            var keyMap = {};         // {<address>: {pubHash, pubKeyArmor, pubKey || error}
            var newResolutions = []; // [{address,pubHash}]

            this.loadNotaries(function(notaryKeys) {

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
                        var res = this.verifyNotaryResponses(notaryKeys, needResolution, nameResolution);
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
        },

        
        verifyNotaryResponses: function(notaryKeys, addresses, notaryResults) {

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
                    if (!this.verifyNotarySignature(addressRes, notaryPublicKey)) {
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
        },

        // Load list of notaries.
        // cb: function(notaries), notaries: {<host>:<publicKey>, ...}
        loadNotaries: function(cb) {
            if (viewState.notaries) {
                cb(viewState.notaries);

            } else if (sessionStorage["/publickeys/notary"]) {
                var data = JSON.parse(sessionStorage["/publickeys/notary"]);
                var notaries = this.parseNotaries(data.notaries);
                cb(notaries);
            } else {
                $.getJSON(HOST_PREFIX+"/publickeys/notary", function(data) {
                    var notaries = this.parseNotaries(data.notaries);
                    if (!notaries) {
                        alert("Failed to retrieve default notaries from server!");
                        return;
                    }
                    sessionStorage["/publickeys/notary"] = JSON.stringify(data);
                    cb(notaries);
                });
            }
        },

        // notaries: {<notaryName>:<pubKeyArmor>}
        // returns {<notaryName>:<pubKey>}
        parseNotaries: function(notaries) {
            var parsed = {};
            for (var host in notaries) {
                var pubKey = notaries[host];
                parsed[host] = openpgp.read_publicKey(pubKey);
            }

            return parsed;
        },

        // Ensure that notaryRes is properly signed with notaryPublicKey.
        // notaryRes: {address,pubHash,timestamp,signature}
        // returns true or false
        verifyNotarySignature: function(notaryRes, notaryPublicKey) {
            var toSign = notaryRes.address+"="+(notaryRes.pubHash||"")+"@"+notaryRes.timestamp;
            var sig = openpgp.read_message(notaryRes.signature);
            return sig[0].signature.verify(toSign, {obj:notaryPublicKey[0]});
        },



        //
        // CRYPTO
        //

        // Uses a key derivation function to create an AES-128 key
        // Returns 128-bit binary

        computeAesKey: function(token, pass) {
            var salt = "2"+token;
            return hex2bin(computeScrypt(pass, salt, 16)); // 16 bytes = 128 bits
        },

        // Backcompat only: uses SHA1 to create a AES-128 key (binary)
        // Returns 128-bit binary
        computeAesKeyOld: function(token, pass) {
            var sha1 = new jsSHA("2"+token+pass, "ASCII").getHash("SHA-1", "ASCII");
            return sha1.substring(0, 16); // 16 bytes = 128 bits
        },

        // Uses a key derivation function to compute the user's auth token
        // Returns 160-bit hex
        computeAuth: function(token, pass) {
            var salt = "1"+token;
            return computeScrypt(pass, salt, 20); // 20 bytes = 160 bits
        },

        computeScrypt: function(pass, salt, nbytes) {
            var param = SCRYPT_PARAMS;
            var hash = scrypt.crypto_scrypt(
                    scrypt.encode_utf8(pass),
                    scrypt.encode_utf8(salt),
                    param.N, param.r, param.p, // difficulty
                    nbytes
                );
            return scrypt.to_hex(hash);
        },

        // Backcompat only: old SHA1 auth token
        // Returns 160-bit hex
        computeAuthOld: function(token, pass) {
            return new jsSHA("1"+token+pass, "ASCII").getHash("SHA-1", "HEX");
        },

        // Symmetric encryption using a key derived from the user's passphrase
        // The user must be logged in: the key must be in sessionStorage
        passphraseEncrypt: function(plainText) {
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
        },

        // Symmetric decryption using a key derived from the user's passphrase
        // The user must be logged in: the key must be in sessionStorage
        passphraseDecrypt: function(cipherText) {
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
        },

        // Returns the first 80 bits of a SHA1 hash, encoded with a 5-bit ASCII encoding
        // Returns a 16-byte string, eg "tnysbtbxsf356hiy"
        // This is the same algorithm and format Onion URLS use
        computePublicHash: function(str) {
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
        },

        getPrivateKey: function() {
            var armor = sessionStorage["privateKeyArmored"];
            
            return openpgp.read_privateKey(armor);
        },

        getPublicKey: function(fn) {
            var privateKey = this.getPrivateKey();
            var publicKey = openpgp.read_publicKey(privateKey[0].extractPublicKey());
            return publicKey;
        }
    
    };
}