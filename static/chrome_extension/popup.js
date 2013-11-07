$(function() {
    $("#button").click(function() {

        chrome.tabs.create({url:chrome.extension.getURL("/index.html")}, function(tab) {

            var token = $("#token").val();
            var passphrase = $("#passphrase").val();

            // TODO: login first so the UX doesn't require
            //  the user to ever enter credentials on the window,
            //  even if the login is incorrect.

            var message = {
                action:     "login",
                host:       "https://scramble.io",
                token:      token,
                passphrase: passphrase
            };
            chrome.tabs.sendMessage(tab.id, message);
        });

    });
});
