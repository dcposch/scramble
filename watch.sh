#!/bin/sh

jekyll serve --watch --baseurl '' &
sass --watch css/style.scss:css/style.css

exit 0
