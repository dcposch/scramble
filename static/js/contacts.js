
//
// CONTACTS.JS
// Look up email addresses and public keys by name.
// Public key exchange
//

function keybaseLookup(user){
    return $.getJSON("/keybase/user/lookup.json?username="+user)
        .done(function(data){
            console.log(arguments);
            if(data.status.code != 0){
                alert("Couldn't find "+user+" in Keybase.");
                return;
            }
            var keys = data.them.public_keys;
            if(!keys){
                alert("Found "+user+" in Keybase, but they don't have a key!");
                return;
            }
            alert("Got key for "+user+": "+keys.primary.kid);
        }).fail(function(){
            alert("FAIL");
            console.log(arguments);
        });
}

