// Wait for "load_scramble" action from popup.
chrome.runtime.onMessage.addListener(
  function(request, sender, sendResponse) {
    if (request.action == "load_scramble") {
        var url = chrome.extension.getURL("/scramble.html")
        window.location = url;
    }
});
