
//
// UNIT TESTS
//

var tests = {}

tests.scrypt = function() {
    var hash = computeScrypt("foo", "bar", 20)
    assertEquals(hash, "468b5b132508a02f1868576247763abed96ac41d")
}

tests.auth = function() {
    var hash = computeAuth("test", "iforgot")
    assertEquals(hash, "4d59c0d101cee7f3acfeece2f37faaf642e90a52")
}

tests.key = function() {
    var key = computeAesKey("test", "iforgot")
    assertEquals(bin2hex(key), "9c2a7d2518c5bc0b7ebdba72b8d7c71e")
}

tests.addContacts = function() {

    // normal add
    (function() {
        var contacts = [
            {name:"joe",   address:"joe@hashed.im",  pubHash:"1111111111111111"},
            {name:"alice", address:"alice@hashd.im", pubHash:"2222222222222222"}];
        var merged = addContacts(contacts, [{name:"bob", address:"bob@hashed.im", pubHash:"3333333333333333"}]);
        assertEquals(contacts.map("name").sort().join(" "), "alice joe"); // original contacts should be untouched.
        assertEquals(  merged.map("name").sort().join(" "), "alice bob joe");
    })();

    // set name on existing
    (function() {
        var contacts = [
            {name:undefined, address:"joe@hashed.im",  pubHash:"1111111111111111"},
            {name:"alice",   address:"alice@hashd.im", pubHash:"2222222222222222"}];
        var merged = addContacts(contacts, [{name:"joe", address:"joe@hashed.im", pubHash:"1111111111111111"}]);
        assertEquals(contacts.map("name").sort().join(" "), "alice "); // original contacts should be untouched.
        assertEquals(  merged.map("name").sort().join(" "), "alice joe");
    })();

    // invalid add
    (function() {
        var contacts = [
            {name:"joe",     address:"joe@hashed.im",  pubHash:"1111111111111111"},
            {name:"alice",   address:"alice@hashd.im", pubHash:"2222222222222222"}];
        assertThrows(function(){
            // should fail because address is missing
            addContacts(contacts, [{name:"bob", pubHash:"1111111111111111"}]);
        });
    })();

}

tests.validateContacts = function() {

    // not even contacts...
    (function() {
        assertThrows(function(){
            validateContacts(null)
        })
        assertThrows(function(){
            validateContacts(0)
        })
        assertThrows(function(){
            validateContacts("blah")
        })
    })();

    // basic contacts
    (function() {
        var res;

        res = validateContacts([{name:"bob", address:"bob@hashed.im", pubHash:"1111111111111111"}])
        assertEquals(res.errors.length, 0)
        assertEquals(res.contacts.length, 1)
    })();

    // falsey names -> removed
    (function() {
        var res;

        res = validateContacts([{name:undefined, address:"bob@hashed.im", pubHash:"1111111111111111"}])
        assertEquals(res.errors.length, 0)
        assertEquals(res.contacts.length, 1)
        assertEquals(res.contacts[0].name, undefined)
        assertEquals(res.contacts[0].hasOwnProperty("name"), false)
    })();
}


//
// UNIT TEST RUNNER
//

main()

function main() {
    var testNames = []
    for(var name in tests){
    	testNames.push(name)
    }
    testNames.sort()
    var success = true
    for(var i in testNames){
        success &= run(testNames[i])
    }
    if(success){
        console.log("All succeeded!")
    } else {
        console.log("TESTS FAILED")
        process.exit(1)
    }
}

function run(name){
    var startMs = new Date().getTime()
    console.log("Running "+name)
    var success = true
    try {
        tests[name]()
    } catch (e){
        success = false
        console.log("    FAILED! "+e)
    }
    var elapsedMs = new Date().getTime() - startMs
    console.log("    Took "+elapsedMs+" ms")
    return success
}

function assertThrows(fn) {
    try {
        fn()
    } catch (err) {
        return
    }
    throw "Expected error to be thrown, but nothing happened."
}

function assertEquals(actual, expected){
    if(actual != expected){
        throw "Found "+actual+", expected "+expected
    }
}

function assert(cond, msg){
    if(!cond){
        throw msg || "Assertion failed"
    }
}
