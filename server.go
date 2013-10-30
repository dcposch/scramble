package main

import (
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"time"
)

func main() {
	// Rest API
	http.HandleFunc("/user/", userHandler)                            // create users, look up hash->pubkey
	http.HandleFunc("/publickeys/notary", notaryHandler)              // this notary & default client notaries
	http.HandleFunc("/publickeys/seed", publicKeySeedHandler)         // other Scramble servers post to seed here.
	http.HandleFunc("/publickeys/query", publicKeysHandler)           // look up name->pubhash&pubkey
	http.HandleFunc("/publickeys/reverse", auth(reverseQueryHandler)) // look up pubhash->name_address
	http.HandleFunc("/nginx_proxy", nginxProxyHandler)                // needed for nginx smtp tls proxy

	// Private Rest API
	http.HandleFunc("/user/me/contacts", auth(contactsHandler)) // load contacts
	http.HandleFunc("/user/me/key", auth(privateKeyHandler))    // load encrypted privkey
	http.HandleFunc("/email/", auth(emailHandler))              // load email body
	http.HandleFunc("/box/", auth(inboxHandler))                // load email headers

	// Resources
	http.HandleFunc("/", staticHandler) // html, js, css

	// SMTP Incoming Messages
	StartSMTPServer()
	StartSMTPSaver()

	// Serve HTTP on localhost only. Let Nginx terminate HTTPS for us.
	address := fmt.Sprintf("127.0.0.1:%d", GetConfig().HttpPort)
	log.Printf("Listening on http://%s\n", address)
	log.Fatal(http.ListenAndServe(address, recoverAndLog(http.DefaultServeMux)))
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
		// Wrap the ResponseWriter to remember the status
		rww := &ResponseWriterWrapper{-1, w}
		begin := time.Now()

		defer func() {
			// Send a 500 error if a panic happens during a handler.
			// Without this, Chrome & Firefox were retrying aborted ajax requests,
			// at least to my localhost.
			if e := recover(); e != nil {
				rww.WriteHeader(http.StatusInternalServerError)
				rww.Write([]byte("Internal Server Error"))
				log.Printf("%s: %s", e, debug.Stack())
			}

			// Finally, log.
			durationMS := time.Since(begin).Nanoseconds() / 1000000
			if rww.Status == -1 {
				rww.Status = 200
			}
			log.Printf("%s %s %v %v %s", r.RemoteAddr, r.Method, rww.Status, durationMS, r.URL)
		}()

		handler.ServeHTTP(rww, r)
	})
}

// Remember the status for logging
type ResponseWriterWrapper struct {
	Status int
	http.ResponseWriter
}

func (w *ResponseWriterWrapper) WriteHeader(status int) {
	w.Status = status
	w.ResponseWriter.WriteHeader(status)
}
