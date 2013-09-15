package main

import (
	"fmt"
	"log"
	"net"
	"net/smtp"
	"time"
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

	log.Printf("Looking up SMTP Server (MX record) for %s\n", host)
	mxs, err := net.LookupMX(host)
	if err != nil {
		return "", err
	}
	bestServer, bestPref := "", 1<<16
	for _, mx := range mxs {
		if int(mx.Pref) < bestPref {
			bestPref = int(mx.Pref)
			bestServer = mx.Host
		}
	}

	mxCache[host] = bestServer
	return bestServer, nil
}

// Polls the outbox every second.
// Sends all messages over SMTP.
func smtpSendLoop() {
	for {
		msgs := LoadAndFlagOutbox()
		for _, msg := range msgs {
			go smtpSend(&msg)
		}
		time.Sleep(time.Second)
	}
}

func smtpSend(msg *Email) {
	toAddrs := ParseEmailAddresses(msg.To)
	toAddrsByHost := make(map[string][]string)
	for _, toAddr := range toAddrs {
		addrs := toAddrsByHost[toAddr.Host]
		toAddrsByHost[toAddr.Host] = append(addrs, toAddr.String())
	}

	addrsFailed := make([]string, 0)
	for host, addrs := range toAddrsByHost {
		smtpHost, err := smtpLookUp(host)
		if err != nil {
			addrsFailed = append(addrsFailed, addrs...)
		}
		smtpSendTo(msg, smtpHost, addrs)
	}
	if len(addrsFailed) == 0 {
		log.Printf("Email sent!\n")
	} else {
		// TODO: email deliver failed msg to sender
		log.Printf("Warning: sending failed to %v\n", addrsFailed)
	}
}

const smtpTemplate = `From: %s
To: %s
Subject: Encrypted message

%s
%s`

func smtpSendTo(email *Email, smtpHost string, addrs []string) {
	msg := fmt.Sprintf(smtpTemplate,
		email.From,
		email.To,
		email.CipherSubject,
		email.CipherBody)
	log.Printf("SMTP: sending to %s\n", smtpHost)

	smtp.SendMail(smtpHost+":25", nil, email.From, addrs, []byte(msg))
}
