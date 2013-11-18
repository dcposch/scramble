package scramble

import (
	"fmt"
	"log"
	"runtime/debug"
	"strings"
	"time"
)

// Stick it as a deferred statement in gouroutines to prevent the program from crashing.
// Catches panics and emails a report to the configured AdminEmails
func Recover() {
	if e := recover(); e != nil {
		stack := string(debug.Stack())
		errorString := fmt.Sprintf("%s:\n%s", e, stack)
		log.Println("<!> " + errorString)
		messageID := GenerateMessageID().String()
		if len(GetConfig().AdminEmails) > 0 {
			go smtpSendSafe(&OutgoingEmail{
				Email: Email{
					EmailHeader: EmailHeader{
						MessageID: messageID,
						ThreadID:  messageID,
						UnixTime:  time.Now().Unix(),
						From:      "daemon@" + GetConfig().SMTPMxHost,
						To:        strings.Join(GetConfig().AdminEmails, ","),
					},
				},
				IsPlaintext:      true,
				PlaintextSubject: "Panic from Scramble server " + GetConfig().SMTPMxHost,
				PlaintextBody:    errorString,
			})
		} else {
			log.Printf("Set AdminEmails: ['your_email@host',...] in config to receive alerts")
		}
	}
}
