$(function() {
    $("#submit").click(function() {

        var host = $("#other").val();
        if (host && host.indexOf("http") != 0) {
            host = "https://"+host;
        } else if (!host) {
            host = $("#host").val();
        } else if (!host) {
            $("#footer").text("Select a host or enter one, e.g. 'scramble.io'");
            return
        }

        var message = {
            action:     "load_page",
            host:       host
        };
        chrome.runtime.sendMessage(message);

    });
});
