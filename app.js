//
// GPGMAIL.IO
//

function read(target){
    if(target.size()==0) return;
    $("li.current").removeClass("current");
    target.addClass("current");

    $("label").show();

    $("#from").html(target.data("from"));
    $("#to").html(target.data("to"));
    $("#subject").html(target.text());
    $.get("/email/"+target.data("id"), function(data){
        $("#body").text(data);
    }, "text");
}

$("li").click(function(e){
    read($(e.target));
});

$(document).keypress(function(e){
    var code = e.charCode || e.which;
    if(code==106){ //j
        if($(".current").size() == 0){
            msg = $("li").first();
        } else {
            msg = $(".current").next();
        }
        read(msg);
    } else if (code==107){ //k
        read($(".current").prev());
    }
});
