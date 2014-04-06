
// Stub out certain browser-specific functions that our library dependencies 
// assume to be present, so that we can run unit tests in Node
$ = function(){return {html:function(){}}};
Handlebars = {};
Handlebars.registerHelper = function(){};
Handlebars.registerPartial = function(){};
navigator = {};
navigator.appName = "yoloswag";
chrome = {};
sessionStorage = {};
