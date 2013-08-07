package main

import (
    "log"
    "net/http"

    //"github.com/dcposch/go-smtpd"
    //"code.google.com/p/go.crypto/openpgp"
)

func main() {
    // Rest API
    http.HandleFunc("/user/", userHandler)
    http.HandleFunc("/user/me", privateHandler)
    http.HandleFunc("/email/", emailHandler)
    http.HandleFunc("/inbox", inboxHandler)

    // Resources
    http.HandleFunc("/", staticHandler)

    http.ListenAndServe(":8888", Log(http.DefaultServeMux))
}

func Log(handler http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
        handler.ServeHTTP(w, r)
    })
}

