// run from the commandline like
// > go test -run TestSendEmail -server hashed.im -v
// also see http://qmail.jms1.net/test-auth.shtml

package scramble

import (
	"flag"
	"log"
	"testing"
	"time"
)

var testServer = flag.String("server", "", "send a live SMTP request to this server")

func TestSendEmail(t *testing.T) {
	if *testServer == "" {
		log.Println("Skipping live test")
		return
	}

	email := &OutgoingEmail{
		Email: Email{
			EmailHeader: EmailHeader{
				MessageID:     "someid",
				UnixTime:      time.Now().Unix(),
				From:          "from@localhost.com",
				To:            "to1@" + *testServer + ",to2@" + *testServer,
				CipherSubject: "<cipher subject>",
			},
			CipherBody: "<cipher body>",
		},
	}

	addrs := ParseEmailAddresses(email.To)
	err := smtpSendTo(email, *testServer, addrs)
	if err != nil {
		t.Fatal(err)
	}
}
