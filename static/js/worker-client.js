
//
// WEB WORKERS
//
var workers = [];
var pendingDecryption = {}; // job id -> callback function


// Starts web workers
//
// See worker.js for a more detailed explanation
// of what they do and what messages they send+receive
function startPgpDecryptWorkers(){
    for(var i = 0; i < 4; i++){
        var worker = new Worker("js/worker.js");
        worker.numInProgress = 0;
        worker.postMessage(JSON.stringify({
            "type":"set-key",
            "privateKey": sessionStorage["privateKeyArmored"]
        }));
        worker.onmessage = handlePgpWorkerMessage;
        workers.push(worker);
    }
}

function handlePgpWorkerMessage(evt){
    var msg = JSON.parse(evt.data);
    if(msg.type == "decrypt"){
        var job = pendingDecryption[msg.id];
        cache.plaintextCache[msg.id] = msg.plaintext;
        if(msg.error){
            console.log("Error decrypting "+msg.id+": "+msg.error);
        }
        if(msg.warnings){
            msg.warnings.forEach(function(warn){
                console.log("Warning decrypting "+msg.id+": "+warn);
            });
        }
        console.log("Finished decrypting "+msg.id);
        workers[job.worker].numInProgress--;
        for(var i = 0; i < job.callbacks.length; i++){
            job.callbacks[i](msg.plaintext, msg.error);
        }
        delete pendingDecryption[msg.id];
    } else if(msg.type == "log"){
        console.log("Webworker:", msg.level, msg.message);
    }
}

// Show decrypt queue size in tab bar, in real time
function startPgpWorkerWatcher(){
    var totalInProgress = 0;
    setInterval(function(){
        var newTotal = 0;
        for(var i = 0; i < workers.length; i++){
            newTotal += workers[i].numInProgress;
        }
        if(newTotal == totalInProgress){
            return;
        }
        totalInProgress = newTotal;

        // Show in tab bar
        var msg = "";
        if(totalInProgress > 0){
            msg = "Decrypting " + totalInProgress;
        }
        $("#debug-num-decrypting").text(msg);
    }, 100);
}

function workerSubmitJob(job, cb) {
        var bestWorker = 0;
        for(var i = 1; i < workers.length; i++){
            if(workers[i].numInProgress < workers[bestWorker].numInProgress){
                bestWorker = i;
            }
        }
        pendingDecryption[job.id] = {"callbacks":[cb],"worker":bestWorker};
        workers[bestWorker].numInProgress++;
        workers[bestWorker].postMessage(JSON.stringify(msg));
}
