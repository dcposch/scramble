package main

import (
    "net/http"

    //"io/ioutil"
    //"github.com/dcposch/go-smtpd"
    //"code.google.com/p/go.crypto/openpgp"
    //"encoding/base64"
)

// WEB UI
func main() {
    http.HandleFunc("/email/", emailHandler)
    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/", indexHandler)

    http.HandleFunc("/app.js", staticHandler)
    http.HandleFunc("/style.css", staticHandler)
    http.HandleFunc("/favicon.ico", staticHandler)

    http.ListenAndServe(":8888", nil)
}
