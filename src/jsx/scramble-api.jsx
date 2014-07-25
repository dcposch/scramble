
// TODO: better solution for the Chrome extension
var HOST_PREFIX = sessionStorage["hostPrefix"] || '';

module.exports = {
    getAccount: function(){
        return $.getJSON(HOST_PREFIX + "/user/me");
    },
    postAccount: function(data){
        return $.post(HOST_PREFIX + "/user/new", data);
    },
    getContacts: function() {
        return $.get(HOST_PREFIX+"/user/me/contacts");
    },
    putContacts: function(hexCipherContacts){
        return $.post(HOST_PREFIX+"/user/me/contacts", hexCipherContacts, "text");
    },
    getBox: function(box, page, pageSize) {
        return $.getJSON(HOST_PREFIX+"/box/"+encodeURI(box), {
            offset: (page-1)*pageSize,
            limit: pageSize
        });
    },
    getThread: function(emailID) {
        return $.getJSON(HOST_PREFIX+"/email/", emailID);
    },
    emailMarkAsRead: function(msgID, isRead) {
        return emailUpdate(msgID, {isRead: isRead});
    },
    emailMoveToBox: function(msgID, box) {
        return emailUpdate(msgID, {box: box});
    },
    emailSend: function(data) {
        return $.post(HOST_PREFIX+"/email/", data);
    },

    //
    // NOTARY API
    //
    getNotaries: function(){
        return $.getJSON(HOST_PREFIX+"/publickeys/notary");
    },
    postNotaryQuery: function(needResolution, needPubKey, notaries){
        var params = {
            needResolution: needResolution.join(","),
            needPubKey:    needPubKey.join(","),
            notaries:      notaries.join(","),
        };
        return $.post(HOST_PREFIX+"/publickeys/query", params);
    },
    getPubHashToAddress: function(pubHashes){
        var params = {pubHashes:pubHashes.join(",")};
        return $.post(HOST_PREFIX+"/publickeys/reverse", params);
    }
};

/**
 * Updates a single message. 
 * For example: set read/unread, move from inbox to archive, etc. 
 *
 * Returns a JQuery promise.
 */
function emailUpdate(msgID, params) {
    return $.ajax({
        url: HOST_PREFIX+'/email/'+encodeURI(msgID),
        type: 'PUT',
        data: params,
    });
}

