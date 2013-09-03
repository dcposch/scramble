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
	http.HandleFunc("/user/me/contacts", contactsHandler)
	http.HandleFunc("/user/me/key", privateKeyHandler)
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
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}
