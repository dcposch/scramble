'use strict';

function App() {
  var self = $.observable(this),
      box = new Box(),
      contacts = new Contacts();

  self.loadBox = function() {

  }

  self.decryptBox = function() {

  }
}


function Box() {
  var self = $.observable(this);

  self.load = function() {

  }
}


function Contacts() {
  var self = $.observable(this);

  self.load = function() {

  }
}