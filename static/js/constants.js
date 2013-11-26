'use strict';
//Tucking these away in a closure to keep people from messing with them
var constants = (function() {
  var data = {
    KEY_TYPE_RSA: 1,
    KEY_SIZE: 2048,

    ALGO_SHA1: 2,
    ALGO_AES128: 7,

    BOX_PAGE_SIZE: 20,

    REGEX_TOKEN: /^[a-z0-9][a-z0-9][a-z0-9]+$/,
    REGEX_EMAIL: /^([A-Z0-9._%+-=]+)@([A-Z0-9.-]+\.[A-Z]{2,4})$/i,
    REGEX_BODY: /^Subject: (.*)(?:\r?\n)+([\s\S]*)$/i,
    REGEX_CONTACT_NAME: /^[^@]*$/i,

    SCRYPT_PARAMS: {
        N:16384, // difficulty=2^14, recommended range 2^14 to 2^20
        r:8,     // recommended values
        p:1
    },

    DEFAULT_SIGNATURE: '\n\n--\nSent with https://scramble.io',

    CONTACTS_VERSION: 1,

    HOST_PREFIX: sessionStorage['hostPrefix'] || '', // for chrome extension <- WAT

    // If we get responses from all but n notaries for a given address,
    // and the responses all agree, we accept the public key.
    // 
    // This allow individual notary operators to have brief downtime 
    // (eg upgrading their server) without breaking Scramble, without
    // significantly impacting security.
    //
    // (To MITM a user, an adversary would have to commandeer (n-x)
    //  notaries and then take down the remaining x notaries.)
    MAX_MISSING_NOTARIES: 1
  };

  return {
    get: function(name) {
      return data[name];
    }
  };
})();
