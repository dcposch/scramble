package main

import (
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
)

func main() {
	// Rest API
	http.HandleFunc("/user/", userHandler)                  // create users, look up hash->pubkey
	http.HandleFunc("/publickeys/notary", notaryIdHandler)  // look up name->pubkey
	http.HandleFunc("/publickeys/query", publicKeysHandler) // look up
	http.HandleFunc("/nginx_proxy", nginxProxyHandler)      // needed for nginx smtp tls proxy

	// Private Rest API
	http.HandleFunc("/user/me/contacts", auth(contactsHandler)) // load contacts
	http.HandleFunc("/user/me/key", auth(privateKeyHandler))    // load encrypted privkey
	http.HandleFunc("/email/", auth(emailHandler))              // load email body
	http.HandleFunc("/box/", auth(inboxHandler))                // load email headers

	// Resources
	http.HandleFunc("/", staticHandler) // html, js, css

	// SMTP Server
	go StartSMTPServer()

	// DEBUG
	var addrs []string
	addrs = append(addrs, "dcposch@test.scramble.io")
	cipher := encryptForUsers("big bad wolf", addrs)
	log.Println("Cipher: " + cipher)

	address := fmt.Sprintf("127.0.0.1:%d", GetConfig().HttpPort)
	log.Printf("Listening on http://%s\n", address)
	http.ListenAndServe(address, recoverAndLog(http.DefaultServeMux))
}

// Wraps an HTTP handler, adding cookie authentication.
//
// The outer function either sends a HTTP 401 (Unauthorized),
// or calls the inner function passing in a valid logged-in username.
func auth(handler func(http.ResponseWriter, *http.Request, *UserID)) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userId, err := authenticate(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		handler(w, r, userId)
	})
}

// Wraps an HTTP handler, adding error logging.
//
// If the inner function panics, the outer function recovers, logs, sends an
// HTTP 500 error response.
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
