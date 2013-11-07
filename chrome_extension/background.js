var credentials = null;

chrome.runtime.onMessage.addListener(
    function(request, sender, sendResponse) {

        // Popup script asked us to remember credentials.
        if (request.action == "remember") {
            credentials = {
                    token:            request.token,
                    passphrase: request.passphrase,
            };
            sendResponse();
            return;
        }

        // scramble.js script asked us for credentials.
        if (request.action == "recall") {
            sendResponse(credentials);
            return;
        }
    }
);

/*
// Load File
function loadFile(url) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', url, false);
    xhr.send(null);
    if (xhr.status === 200) {
        return xhr.responseText;
    }
    return null;
}
*/

