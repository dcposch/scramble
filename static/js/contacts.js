
//
// CONTACTS.JS
// Look up email addresses and public keys by name.
// Public key exchange
//

function keybaseLookup(user, success, fail){
    return $.getJSON("/keybase/user/lookup.json?username="+user)
        .done(function(data){
            if(data.status.code != 0){
                fail("Couldn't find "+user+" in Keybase.");
                return;
            } 
            var keys = data.them.public_keys;
            if(!keys){
                fail("Found "+user+" in Keybase, but they don't have a key!");
                return;
            }
            success(keys.primary);
        }).fail(function(){
            console.warn(arguments);
            fail("Couldn't reach Keybase");
        });
}

