if (chrome.runtime) {
    if (sessionStorage["hostPrefix"]) {
        // e.g. user refreshed the chrome extension page.
        $(main);
    } else {
        // Wait for background.js to fire event.
        chrome.runtime.onMessage.addListener(
          function(request, sender, sendResponse) {
            if (request.action == "load_host") {
                $(function() {
                    setHostPrefix(request.host);
                    main();
                });
            }
        });
    }
} else {
    $(main);
}
