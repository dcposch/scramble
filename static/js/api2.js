"use strict";

/* global $, alert, constants, crypto */


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


function App() {
	var self = $.observable(this);

	self.login = function() {
		$.get(constants.get("HOST_PREFIX") + "/user/me", function(data){
			// (first load after login)
			sessionStorage["emailAddress"] = data.EmailAddress;
			sessionStorage["pubHash"] = data.PublicHash;
			sessionStorage["privateKeyArmored"] = crypto.decryptPrivateKey(data.CipherPrivateKey);

		}, "json").fail(function(){
			alert("Login failed. Please refresh and try again.");
		});
	};
}



function Box() {
	var self = $.observable(this);

	self.getBox = function(box_name, page) {
		var url = constants.get("HOST_PREFIX") + "/box/" + encodeURI(box_name),
			opts = {
				offset: (page - 1) * BOX_PAGE_SIZE,
				limit: BOX_PAGE_SIZE
			}
		;

		$.get(url, opts, function(data) {
			console.log("Got box: " + name + ", data: " + data);
			self.data = data;
			self.trigger("gotBox");
			self.decryptHeaders();
		}, "json").fail(function(xhr) {
			alert(xhr.responseText || "Could not reach the server, try again");
		});
	};

	self.decryptHeaders = function() {
		self.data.headers.forEach(function(header){
			cachedDecodePgp(header.MessageID+" subject", header.CipherSubject, null, function(subject) {
			header.subject = subject;
			self.trigger("updateHeader", header);
			});
		});
	};

	// Asynchronously decrypts a box (eg inbox and sent). Uses Web Workers.
	self.startDecryptingBox = function(boxSummary) {
		// Start decrypting the subjects
		boxSummary.EmailHeaders.forEach(self.decryptSubject);
		// Start prefetching and decrypting the bodies
		boxSummary.EmailHeaders.forEach(self.prefetchAndDecryptThread);
	};

	self.decryptSubject = function(h) {
		crypto.cachedDecryptPgp(h.ThreadID+" subject", h.CipherSubject, null, function(subject){
			if (subject === null) {
				subject = "(Decryption failed)";
			} else if (trim(subject) === "") {
				subject = "(No subject)";
			}
			$("#subject-"+h.HexMessageID).text(subject);
			$("#subject-header-"+h.HexMessageID).text(subject);
		})
	};

	self.prefetchAndDecryptThread = function(h){
		cachedLoadEmail({msgID:h.MessageID, threadID:h.ThreadID}, function(emailDatas) {
			console.log("Prefetched thread, # emails: "+emailDatas.length);
			startDecryptEmailThread(emailDatas); 
		});
	};
}


function Emails() {
	function startDecryptEmailThread(emailDatas){
	    // Asynchronously verify+decrypt
	    var fromAddrs = emailDatas.map("From").map(trimToLower).unique();
	    lookupPublicKeys(fromAddrs, function(keyMap, newResolutions) {
	        // First, save new pubHashes to contacts so future lookups are faster.
	        if (newResolutions.length > 0) {
	            trySaveContacts(addContacts(viewState.contacts, newResolutions));
	        }

	        // Start decrypt+verify on the web workers
	        emailDatas.forEach(function(emailData) {
	            decryptAndVerifyEmail(emailData, keyMap);
	        });
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
}


function Contacts() {
	var self = $.observable(this);

	function getContacts(callback) {
		if (self.data) {
			callback(self.data);
		} else {
			loadAndDecryptContacts(callback);
		}
	}

	function loadAndDecryptContacts(callback) {
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
					self.data = contacts;
					callback(self.data);
				});
			} else if (parsed.version == CONTACTS_VERSION) {
				self.data = parsed.contacts;
				callback(self.data);
			}
		}, "text").fail(function(xhr) {
			if (xhr.status == 404) {
				self.data = [{
					name: "me",
					address: getUserEmail(),
					pubHash: sessionStorage["pubHash"],
				}];
				callback(self.data);
			} else {
				alert("Failed to retrieve our own encrypted contacts: "+xhr.responseText);
			}
		});
	}

}


// Asynchronously decrypts (and optionally verifies) a PGP message
//
// Requires:
// * unique cache key
// * ASCII-armored ciphertext
// * (optional) ASCII-armored public key for signature verification or null
// * a callback cb(plaintext)
function cachedDecodePgp(cacheKey, armoredText, publicKeyArmored, cb){
	var plain = cache.plaintextCache[cacheKey];
	if (typeof(plain) !== "undefined"){
		cb(plain);
	} else {
		console.log("Decoding "+cacheKey+"\n"+armoredText);
		var msg = {
			"type":"cipherText",
			"cacheKey": cacheKey,
			"armoredText": armoredText,
			"publicKeyArmored": publicKeyArmored
		};
		pendingDecryption[cacheKey] = cb;
		workers[workerIx].postMessage(JSON.stringify(msg));
		workerIx = (workerIx + 1) % workers.length; // round robin
	}
}