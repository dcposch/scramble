'use strict';

/* global $, alert, HOST_PREFIX, BOX_PAGE_SIZE */


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
    $.get(HOST_PREFIX+"/user/me", function(data){
      // (first load after login)
      sessionStorage["emailAddress"] = data.EmailAddress;
      sessionStorage["pubHash"] = data.PublicHash;
      sessionStorage["privateKeyArmored"] = decryptPrivateKey(data.CipherPrivateKey);

      startPgpDecryptWorkers();
    }, "json").fail(function(){
      alert("Login failed. Please refresh and try again.");
    })
  };
}



function Box() {
  var self = $.observable(this);

  self.get = function(box_name, page) {
    var url = HOST_PREFIX + '/box/' + encodeURI(box_name),
        opts = {
          offset: (page - 1) * BOX_PAGE_SIZE,
          limit: BOX_PAGE_SIZE
        }
    ;

    $.get(url, opts, function(data) {
      console.log('Got box: ' + name + ', data: ' + data);
      self.data = data;
      self.trigger('get');
      self.decryptHeaders();
    }, 'json').fail(function(xhr) {
      alert(xhr.responseText || "Could not reach the server, try again");
    });
  };

  self.decryptHeaders = function() {
    self.data.headers.forEach(function(header){
      cachedDecodePgp(header.MessageID+" subject", header.CipherSubject, null, function(subject) {
      header.subject = subject;
      self.trigger('updateHeader', header);
      });
    });
  };
}


function Contacts() {

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