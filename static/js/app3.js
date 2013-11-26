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
    return app.loadContacts();
  }

  else {
    return display404();
  }
});

