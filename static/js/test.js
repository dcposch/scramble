
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
    console.log(success ? "All succeeded!" : "TESTS FAILED")
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

