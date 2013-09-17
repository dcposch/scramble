package main

import (
	"log"
	"net/http"
	"runtime/debug"
	//"github.com/dcposch/go-smtpd"
	//"code.google.com/p/go.crypto/openpgp"
)

func main() {
	// Rest API
	http.HandleFunc("/user/", userHandler)
	http.HandleFunc("/user/me/contacts", contactsHandler)
	http.HandleFunc("/user/me/key", privateKeyHandler)
	http.HandleFunc("/publickeys/", publicKeysHandler)
	http.HandleFunc("/email/", emailHandler)
	http.HandleFunc("/box/", inboxHandler)

	// Resources
	http.HandleFunc("/", staticHandler)

	address := "127.0.0.1:8888"
	log.Printf("Listening on %s\n", address)
	http.ListenAndServe(address, Log(http.DefaultServeMux))
}

func Log(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Send a 500 error if a panic happens during a handler.
		// Without this, Chrome & Firefox were retrying aborted ajax requests,
		// at least to my localhost.
		defer func() {
			if e := recover(); e != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Internal Server Error"))
				log.Printf("%s: %s", e, debug.Stack())
			}
		}()
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}
