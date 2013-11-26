'use strict';
/* global $, jQuery, alert */

var boxPresenter, page;

//Model declarations
var box = new Box();
var app = new App();


//ROUTER
$.route(function(hash) {
  //check if logged in
  if (!(page.data.token && page.data.passKey)) {
    return displayLogin();
  }

  if (hash === 'archive' || hash === 'sent' || hash === 'inbox') {
    return app.loadBox(hash);
  }

  if (hash === 'contacts') {
    return loadContacts();
  }

  else {
    return display404();
  }
});


//
function loadBox(hash) {
  appPresenter($('.wrapper'));
  app.init();
  app.on('init', function(){
    boxPresenter($('.box'));
    box.get();
  });
}

function loadContacts() {
  appPresenter($('.wrapper'));
  app.init();
  app.on('init', function(){
    contactsPresenter($('.box'));
    contacts.init();
  });
}

function display404() {

}


appPresenter = function ($root, template) {
  app.on('init', load);

  function load() {
    $root.empty();
    $root.append(render(app.data, template));
  }

}($('.wrapper'), template);



//Box (inbox, sent, etc) presenter
boxPresenter = function ($root, template) {

  box.on('get', load);

  function load() {
    $root.empty();

    var data = {
        offset: box.data.Offset
      , limit: box.data.Limit
      , total: box.data.Total
      , page: Math.floor(box.data.Offset / box.data.Limit) + 1
      , totalPages: Math.ceil(box.data.Total / box.data.Limit)
      , headers: box.data.headers
    };

    $root.html(render(data, template));
  }

  //lazy decryption
  function updateHeader (header) {
    $('#' + header.id).replaceWith(render(data, template));
  }
};


threadPresenter = function ($root, template) {
  
}
