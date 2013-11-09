chrome.runtime.onMessage.addListener(
  function(request, sender, sendResponse) {
    if (request.action == "load_page") {

        chrome.tabs.create({url:chrome.extension.getURL("/index.html")}, function(tab) {
            var message = {
                action:     "load_host",
                host:       request.host
            };
            chrome.tabs.sendMessage(tab.id, message);
        });

    }
});
