package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"runtime/debug"
	"strings"
)

// Cache MX lookups, eg "gmail.com" -> "gmail-smtp-in.l.google.com"
var mxCache map[string]string
var mxHost string

func init() {
	mxCache = make(map[string]string)
	mxHost = GetConfig().SMTPMxHost
}

// Looks up the SMTP server for an email host
// For example, mxLookUp("gmail.com") returns "gmail-smtp-in.l.google.com"
func mxLookUp(host string) (string, error) {
	cachedServer := mxCache[host]
	if cachedServer != "" {
		return cachedServer, nil
	}

	log.Printf("looking up smtp server (MX record) for %s\n", host)
	mxs, err := net.LookupMX(host)
	if err != nil {
		log.Printf("lookup failed for %s\n", host)
		return "", err
	}
	bestServer, bestPref := "", 1<<16
	for _, mx := range mxs {
		if int(mx.Pref) < bestPref {
			bestPref = int(mx.Pref)
			bestServer = mx.Host
		}
	}

	// trailing dot means full domain name
	if strings.HasSuffix(bestServer, ".") {
		bestServer = bestServer[:len(bestServer)-1]
	} else {
		bestServer = bestServer + "." + host
	}

	mxCache[host] = bestServer
	return bestServer, nil
}

func smtpSend(msg *OutgoingEmail) error {
	mxHostAddrs, failedAddrs := ParseEmailAddresses(msg.To).GroupByMxHost()
	if len(failedAddrs) != 0 {
		// This should never happen.
		panic("Could not resolve some MX records in smtpSend: " + failedAddrs.String())
	}
	// TODO: parallel send?

	errs := []string{}
	for mxHost, addrs := range mxHostAddrs {
		if mxHost == GetConfig().SMTPMxHost {
			continue // don't send to self, local deliveries use different logic.
		}
		err := smtpSendTo(msg, mxHost, addrs)
		if err != nil {
			errMsg := err.Error()
			if strings.HasPrefix(errMsg, "550 5.1.1 ") {
				errMsg = errMsg[len("550 5.1.1 "):]
			}
			if strings.HasSuffix(errMsg, ". Please try") {
				// Make the message a bit nicer for nonexistent email recipients
				errMsg = errMsg[:len(errMsg)-len(". Please try")]
			}
			errs = append(errs, fmt.Sprintf("Couldn't send mail to %v: %s\n",
				addrs, errMsg))
		} else {
			log.Printf("Email sent to \n", mxHost)
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
}

// Must not panic, because Recover() calls this.
func smtpSendSafe(msg *OutgoingEmail) {
	defer func() {
		if e := recover(); e != nil {
			errorString := fmt.Sprintf("%s:\n%s", e, string(debug.Stack()))
			log.Println("<!> " + errorString)
		}
	}()
	err := smtpSend(msg)
	if err != nil {
		log.Printf("SMTP failure: %v", err)
	}
}

const smtpTemplate = `Message-ID: <%s>%s
Content-Type: text/plain
From: <%s>
To: %s
Subject: %s

%s`

const threadHeadersTemplate = `
In-Reply-To: <%s>
X-Scramble-Thread-ID: <%s>
References: %s`

func smtpSendTo(email *OutgoingEmail, smtpHost string, addrs EmailAddresses) error {
	var subject, body string
	if email.IsPlaintext {
		subject = email.PlaintextSubject
		body = email.PlaintextBody
	} else {
		subject = "Encrypted subject"
		body = email.CipherSubject + "\n" + email.CipherBody
	}

	// Construct In-Reply-To/References/X-Scramble-Thread-ID headers
	var threadHeaders = ""
	var ancestorIDs = ParseAngledEmailAddresses(email.AncestorIDs, " ")
	if len(ancestorIDs) > 0 {
		threadHeaders = fmt.Sprintf(threadHeadersTemplate,
			ancestorIDs[len(ancestorIDs)-1].String(),
			email.ThreadID,
			email.AncestorIDs,
		)
	}
	// Fill in smtpTemplate
	msg := fmt.Sprintf(smtpTemplate,
		email.MessageID,
		threadHeaders,
		email.From,
		ParseEmailAddresses(email.To).AngledString(","),
		subject,
		body,
	)
	if email.IsPlaintext {
		msg2 := fmt.Sprintf(smtpTemplate,
			email.MessageID,
			threadHeaders,
			email.From,
			ParseEmailAddresses(email.To).AngledString(","),
			"<plaintext subject>",
			"<plaintext body>",
		)
		log.Printf("SMTP: sending to %s %v\n%s\n", smtpHost, addrs, msg2)
	} else {
		log.Printf("SMTP: sending to %s %v\n%s\n", smtpHost, addrs, msg)
	}

	c, err := smtp.Dial(smtpHost + ":25")
	if err != nil {
		return err
	}
	log.Println("hello")
	if err = c.Hello(mxHost); err != nil {
		return err
	}
	log.Println("starting tls")
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err = c.StartTLS(nil); err != nil {
			log.Printf("warning: STARTTLS failed: %v\n", err)
			c.Text.Close()

			// Try again...
			log.Println("Connection closed. Trying again.")
			c, err = smtp.Dial(smtpHost + ":25")
			if err != nil {
				return err
			}
			log.Println("hello")
			if err = c.Hello(mxHost); err != nil {
				return err
			}
		}
	}
	log.Println("from")
	if err = c.Mail(email.From); err != nil {
		return err
	}
	log.Println("to")
	for _, addr := range addrs.Strings() {
		log.Println("to " + addr)
		if err = c.Rcpt(addr); err != nil {
			return err
		}
	}
	log.Println("data")
	w, err := c.Data()
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(msg))
	if err != nil {
		return err
	}
	log.Println("close")
	err = w.Close()
	if err != nil {
		return err
	}
	return c.Quit()
}
