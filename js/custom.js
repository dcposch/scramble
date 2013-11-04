'use strict';

/* global $, jQuery */

//ScrambledWriter
(function($) {
  function randomAlphaNum() {
    var rnd = Math.floor(Math.random() * 62);
    if (rnd >= 52) return String.fromCharCode(rnd - 4);
    else if (rnd >= 26) return String.fromCharCode(rnd + 71);
    else return String.fromCharCode(rnd + 65);
  }
  
  $.fn.scrambledWriter = function() {
    this.each(function() {
      var $ele = $(this), str = $ele.text(), progress = 0, replace = /[^\s]/g,
        random = randomAlphaNum, inc = 2;
      $ele.text('');
      var timer = setInterval(function() {
        $ele.text(str.substring(0, progress) + str.substring(progress, str.length).replace(replace, random));
        progress += inc;
        if (progress >= str.length + inc) clearInterval(timer);
      }, 100);
    });
    return this;
  };
})(jQuery);


var parallax = function() {
  var scroll_top = $(window).scrollTop(),
    scroll_bottom = scroll_top + $(window).height();

  $('[data-scroll]').each(function () {
  var el_top_offset = $(this).offset().top
    , opts = $(this).data('scroll')
    , el_bottom_offset = (el_top_offset + $(this).height())
    , top_to_top = (el_top_offset - scroll_top)
    , bottom_to_top = (el_bottom_offset - scroll_top)
    , top_to_bottom = (el_top_offset - scroll_bottom)
  ;

  if ((top_to_bottom < 0) && (bottom_to_top > 0)) {
    $(this).addClass('scroll-visible');
  } else {
    $(this).removeClass('scroll-visible');
  }

  if (opts === 'diagonal-seperator') {
    if ((top_to_bottom * 0.3) > -170) {
    $(this).css('margin-top', (top_to_bottom * 0.3));
    }
  }

  if (opts === 'jumbotron-sign') {
    var opacity = (scroll_top - 350) * -0.003;
    $(this).css('transform', 'translate(0, ' + (scroll_top * -0.3) + 'px)');
    $(this).css('opacity', opacity);
  }
  });
};


$(document).ready(function() {
  
  //RESPONSIVE TITLE
  $('.js-responsive').squishy();
  
  //PARALLAX
  $( window ).scroll(function() {
    parallax();
  });

  //TITLE SCRAMBLE
  $(".js-scramble").scrambledWriter();
});


