package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"time"
	"strings"
)

// Cache MX lookups, eg "gmail.com" -> "gmail-smtp-in.l.google.com"
var mxCache map[string]string

func init() {
	mxCache = make(map[string]string)
	go smtpSendLoop()
}

// Looks up the SMTP server for an email host
// For example, smtpLookUp("gmail.com") returns "gmail-smtp-in.l.google.com"
func smtpLookUp(host string) (string, error) {
	cachedServer := mxCache[host]
	if cachedServer != "" {
		return cachedServer, nil
	}

	log.Printf("looking up smtp server (mx record) for %s\n", host)
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
		bestServer = bestServer+"."+host
	}

	mxCache[host] = bestServer
	return bestServer, nil
}

// Polls the outbox every second.
// Sends all messages over SMTP.
func smtpSendLoop() {
	for {
		msgs := CheckoutOutbox(1)
		for _, msg := range msgs {
			go func(msg BoxedEmail) {
				// msg.Address is the destination host for outbox messages
				addrs := ParseEmailAddresses(msg.To).FilterByHost(msg.Address)
				err := smtpSendTo(&msg.Email, msg.Address, addrs)
				if err != nil {
					// TODO: better error handling.
					// mail servers & internet connectivity go down regularly,
					// so maybe create an "outbox-error" box
					// MarkOutboxAs([]BoxedEmail{msg}, "outbox-error")
					panic(err)
				}
				MarkOutboxAs([]BoxedEmail{msg}, "outbox-sent")
			}(msg)
		}
		time.Sleep(time.Second)
	}
}

func smtpSend(msg *Email) error {
	hostAddrs := GroupAddrsByHost(msg.To)
	addrsFailed := EmailAddresses{}
	for host, addrs := range hostAddrs {
		smtpHost, err := smtpLookUp(host)
		if err != nil {
			addrsFailed = append(addrsFailed, addrs...)
		}
		err = smtpSendTo(msg, smtpHost, addrs)
		if err != nil {
			addrsFailed = append(addrsFailed, addrs...)
		}
	}
	if len(addrsFailed) == 0 {
		log.Printf("Email sent!\n")
		return nil
	} else {
		err := errors.New(fmt.Sprintf("SMTP sending failed to %v\n", addrsFailed))
		return err
	}
}

const smtpTemplate = `Message-ID: <%s@%s>
From: <%s>
To: %s
Subject: Encrypted message

%s
%s`

func smtpSendTo(email *Email, smtpHost string, addrs EmailAddresses) error {
	msg := fmt.Sprintf(smtpTemplate,
		email.MessageID, GetConfig().SmtpMxHost,
		email.From,
		ParseEmailAddresses(email.To).AngledString(),
		email.CipherSubject,
		email.CipherBody)
	log.Printf("SMTP: sending to %s\n", smtpHost)
	err := smtp.SendMail(smtpHost+":25", nil, email.From, addrs.Strings(), []byte(msg))
	return err
}
