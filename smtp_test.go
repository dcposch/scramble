// run from the commandline like
// > go test -run TestSendEmail -server hashed.im -v

package main

import (
	"testing"
	"flag"
	"log"
	"time"
)

var serverName = flag.String("server", "", "send a live SMTP request to this server")

func TestSendEmail(t *testing.T) {
	if *serverName == "" {
		log.Println("Skipping live test")
		return
	}

	email := &Email{
		EmailHeader: EmailHeader{
			MessageID:     "someid",
			UnixTime:      time.Now().Unix(),
			From:          "from@localhost.com",
			To:            "to1@"+*serverName+",to2@"+*serverName,
			CipherSubject: "<cipher subject>",
		},
		CipherBody:    "<cipher body>",
	}

	addrs := ParseEmailAddresses(email.To).FilterByHost(*serverName)
	err := smtpSendTo(email, *serverName, addrs)
	if err != nil {
		t.Fatal(err)
	}
}
