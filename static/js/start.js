$(function() {
    if (chrome.runtime) {
        chrome.runtime.onMessage.addListener(
          function(request, sender, sendResponse) {
            if (request.action == "login") {
                setHostPrefix(request.host);
                login(request.token, request.passphrase);
                main();
            }
        });
    } else {
        main();
    }
});
