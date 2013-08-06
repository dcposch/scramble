package main

import (
    "log"
    "net/http"

    //"io/ioutil"
    //"github.com/dcposch/go-smtpd"
    //"code.google.com/p/go.crypto/openpgp"
    //"encoding/base64"
)

// WEB UI
func main() {
    http.HandleFunc("/", inboxHandler)
    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/compose", composeHandler)

    http.HandleFunc("/user/", userHandler)
    http.HandleFunc("/user/me", privateHandler)
    http.HandleFunc("/email/", emailHandler)

    http.HandleFunc("/style.css", staticHandler)
    http.HandleFunc("/favicon.ico", staticHandler)
    http.HandleFunc("/doc/", staticHandler)
    http.HandleFunc("/js/", staticHandler)

    http.ListenAndServe(":8888", Log(http.DefaultServeMux))
}

func Log(handler http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
        handler.ServeHTTP(w, r)
    })
}

