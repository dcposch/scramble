/**
 * Receives SMTP messages from the smtp_server module.
 *
 * Saves emails to the database, puts them into each recipient's inbox.

 * If the email is in plaintext, encrypts it with the recipient's
 * public key before storing.
 */

package main

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"log"
	"net/mail"
	"regexp"
	"strings"
)

var regexSMTPTemplatep = regexp.MustCompile(`(?s)-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----`)

func StartSMTPSaver() {
	// start some savemail workers
	for i := 0; i < 3; i++ {
		go saveEmails()
	}
}

func saveEmails() {
	//  receives values from the channel repeatedly until it is closed.
	for {
		// wrap in func to Recover per saveEmail operation,
		// such that this loop never dies.
		func() {
			defer Recover()
			msg := <-SaveMailChan
			log.Println("Saving mail from " + msg.mailFrom + " to " + strings.Join(msg.rcptTo, ","))
			success := saveEmail(msg)
			msg.saveSuccess <- success
		}()
	}
}

func saveEmail(msg *SMTPMessage) bool {
	err := deliverMailLocally(msg)
	if err != nil {
		log.Printf("Can't save email, DB error: %v\n", err)
		return false
	}
	return true
}

func deliverMailLocally(msg *SMTPMessage) error {

	var cipherSubject, cipherBody string
	cipherPackets := regexSMTPTemplatep.FindAllString(msg.data.textBody, -1)
	// TODO: better way to distinguish between encrypted and unencrypted mail
	if len(cipherPackets) == 2 {
		cipherSubject = cipherPackets[0]
		cipherBody = cipherPackets[1]
	} else {
		cipherSubject = encryptForUsers(msg.data.subject, msg.rcptTo)
		cipherBody = encryptForUsers(msg.data.textBody, msg.rcptTo)
	}

	email := new(Email)
	email.MessageID = msg.data.messageID.String()
	email.UnixTime = msg.time
	email.From = msg.mailFrom
	// TODO: separate To and CC, add BCC
	email.To = joinAddresses(append(msg.data.toList, msg.data.ccList...))
	email.CipherSubject = cipherSubject
	email.CipherBody = cipherBody
	email.ThreadID = msg.data.threadID.String()
	email.AncestorIDs = msg.data.ancestorIDs.AngledStringCappedToBytes(
		" ", GetConfig().AncestorIDsMaxBytes)

	// TODO: consider if transactions are required.
	// TODO: saveMessage may fail if messageID is not unique.
	SaveMessage(email)
	log.Printf("Saved new email %s from %s to %s\n",
		email.MessageID, email.From, email.To)

	// add to inbox locally
	for _, addr := range msg.rcptTo {
		AddMessageToBox(email, addr, "inbox")
	}

	return nil
}

func joinAddresses(addrs []*mail.Address) string {
	var strs []string
	for _, addr := range addrs {
		strs = append(strs, addr.Address)
	}
	return strings.Join(strs, ",")
}

func encryptForUsers(plaintext string, addrs []string) string {
	keys := make([]*openpgp.Entity, 0)
	for _, addr := range addrs {
		token := strings.Split(addr, "@")[0]
		user := LoadUser(token)
		if user == nil {
			// we've already told the SMTP sender that those
			// recipients don't exist on this server
			continue
		}

		entity, err := ReadEntity(user.PublicKey)
		if err != nil {
			panic(err)
		}
		keys = append(keys, entity)
	}
	if len(keys) == 0 {
		log.Printf("Warning: not encrypting incoming mail--unrecognized recipients")
		return plaintext
	}
	log.Printf("Encrypting plaintext for %s, found %d keys\n",
		strings.Join(addrs, ","), len(keys))

	cipherBuffer := new(bytes.Buffer)
	w, err := armor.Encode(cipherBuffer, "PGP MESSAGE", nil)
	if err != nil {
		panic(err)
	}
	plainWriter, err := openpgp.Encrypt(w, keys, nil, nil, nil)
	if err != nil {
		panic(err)
	}
	plainWriter.Write([]byte(plaintext))
	plainWriter.Close()
	w.Close()

	ciphertext := cipherBuffer.String()
	return ciphertext
}
