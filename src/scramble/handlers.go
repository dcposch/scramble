package scramble

import (
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"time"
)

func StartHTTPServer() {
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
	http.HandleFunc("/box/", auth(boxHandler))                  // load email headers

	// Resources
	http.HandleFunc("/", staticHandler) // html, js, css

	// Serve HTTP on localhost only. Let Nginx terminate HTTPS for us.
	address := fmt.Sprintf("127.0.0.1:%d", GetConfig().HTTPPort)
	log.Printf("Listening on http://%s\n", address)
	log.Fatal(http.ListenAndServe(address, recoverAndLogHandler(http.DefaultServeMux)))
}

// Wraps an HTTP handler, adding cookie authentication.
//
// The outer function either sends a HTTP 401 (Unauthorized),
// or calls the inner function passing in a valid logged-in username.
func auth(handler func(http.ResponseWriter, *http.Request, *UserID)) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, err := authenticate(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		handler(w, r, userID)
	})
}

// Wraps an HTTP handler, adding error logging.
//
// If the inner function panics, the outer function recovers, logs, sends an
// HTTP 500 error response.
func recoverAndLogHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wrap the ResponseWriter to remember the status
		rww := &responseWriterWrapper{200, w}
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
			log.Printf("%s %s %v %v %s", r.RemoteAddr, r.Method, rww.Status, durationMS, r.URL)
		}()

		handler.ServeHTTP(rww, r)
	})
}

// Remember the status for logging
type responseWriterWrapper struct {
	Status int
	http.ResponseWriter
}

func (w *responseWriterWrapper) WriteHeader(status int) {
	w.Status = status
	w.ResponseWriter.WriteHeader(status)
}
