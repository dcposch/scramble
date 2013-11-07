setHostPrefix("https://scramble.io");
main();

// notify parent that we're ready.
window.parent.postMessage("loaded", "*");

// we'll get a ping back with the login credentials.
window.addEventListener("message", receiveMessage, false);
function receiveMessage(event) {
    var token = event.data.token;
    var passphrase = event.data.passphrase;
    login(token, passphrase);
}
