package main

import (
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
)

func main() {
	// Rest API
	http.HandleFunc("/user/", userHandler)
	http.HandleFunc("/user/me/contacts", contactsHandler)
	http.HandleFunc("/user/me/key", privateKeyHandler)
	http.HandleFunc("/publickeys/query", publicKeysHandler)
	http.HandleFunc("/email/", emailHandler)
	http.HandleFunc("/box/", inboxHandler)
	http.HandleFunc("/nginx_proxy", nginxProxyHandler)
	http.HandleFunc("/notary/id", notaryIdHandler)
	http.HandleFunc("/notary/query", notaryQueryHandler)

	// Resources
	http.HandleFunc("/", staticHandler)

	// SMTP Server
	go StartSMTPServer()

	address := fmt.Sprintf("127.0.0.1:%d", GetConfig().HttpPort)
	log.Printf("Listening on http://%s\n", address)
	http.ListenAndServe(address, recoverAndLog(http.DefaultServeMux))
}

func recoverAndLog(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)

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
		handler.ServeHTTP(w, r)
	})
}
