$(function() {
    $("#button").click(function() {
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {

            var token = $("#token").val();
            var passphrase = $("#passphrase").val();

            // make background remember login
            var message = {
                action:     "remember",
                token:      token,
                passphrase: passphrase
            };
            chrome.runtime.sendMessage(message, function(response) {
                // load_scramble will change the page,
                //  and the popup window will close.
                chrome.tabs.sendMessage(tabs[0].id, {action:"load_scramble"});
            });
        });
    });
});
