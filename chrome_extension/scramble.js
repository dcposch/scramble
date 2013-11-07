// This is the javascript for the static page that hosts the scramble iframe.
// It runs in the context of a chrome-extension context-script.

// Tell extension background that we've loaded.
// We'll get the login credentials from the popup.
chrome.runtime.sendMessage({action: "recall"}, function(response) {
    loadScramble(response.token, response.passphrase);
});

// Load iframe
function loadScramble(token, passphrase) {
    var url = chrome.extension.getURL("/index.html")
    var iframe = document.createElement("iframe");    
    // NOTE: I don't think we require sandboxing, since the origin of the created
    //  iframe is unique to the browser extension.
    // 
    // http://www.whatwg.org/specs/web-apps/current-work/multipage/the-iframe-element.html#attr-iframe-sandbox
    // When the attribute is set, the content is treated as being from a unique origin...
    // iframe.setAttribute("sandbox", "allow-scripts");
    iframe.src = url;
    iframe.setAttribute("style", "position:absolute; top:0px; left:0px; "+
        "width:100%; height:100%; z-index:999; background-color: white;");
    document.body.appendChild(iframe);

    // Wait for iframe to ping us back
    window.addEventListener("message", function(event) {
        // Send login request to iframe.
        // Must ensure that origin is same as url,
        // By the time this gets called it might have changed.
        var message = {
            token: token,
            passphrase: passphrase
        };
        iframe.contentWindow.postMessage(message, url);
    }, false);
}
