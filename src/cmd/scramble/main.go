package main

import (
	"scramble"
)

func main() {
	// HTTP Static Files + REST API
	scramble.StartHTTPServer()

	// SMTP Incoming Messages
	scramble.StartSMTPServer()
	scramble.StartSMTPSaver()
}
