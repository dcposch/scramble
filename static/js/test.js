
//
// UNIT TESTS
//

function testScrypt(){
    var hash = computeScrypt("foo", "bar", 20)
    assertEquals(hash, "468b5b132508a02f1868576247763abed96ac41d")
}

function testAuth(){
    var hash = computeAuth("test", "iforgot")
    assertEquals(hash, "4d59c0d101cee7f3acfeece2f37faaf642e90a52")
}

function testKey(){
    var key = computeAesKey("test", "iforgot")
    assertEquals(bin2hex(key), "9c2a7d2518c5bc0b7ebdba72b8d7c71e")
}
$(function(){
    var tests = []
    for(var name in window){
        if(typeof(window[name])==="function" && name.indexOf("test")==0){
            tests.push(name)
        }
    }
    tests.sort()
    var i = 0;
    var runNext = function(){
        run(tests[i++])
        if(i < tests.length) {
            setTimeout(runNext, 10)
        }
    }
    runNext()
})



//
// UNIT TEST RUNNER
//

function run(test){
    var startMs = new Date().getTime()
    log("Running "+test)
    try {
        window[test]()
    } catch (e){
        log("    FAILED! "+e)
    }
    var elapsedMs = new Date().getTime() - startMs
    log("    Took "+elapsedMs+" ms")
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

function log(str){
    $("#console").append("\n"+str)
}

