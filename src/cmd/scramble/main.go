package main

import (
	"scramble"
)

func main() {
	// SMTP Incoming Messages
	scramble.StartSMTPServer()
	scramble.StartSMTPSaver()

	// HTTP Static Files + REST API
	scramble.StartHTTPServer()
}
