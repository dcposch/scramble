/**
 * Receives SMTP messages from the smtp_server module.
 *
 * Saves emails to the database, puts them into each recipient's inbox.

 * If the email is in plaintext, encrypts it with the recipient's
 * public key before storing.
 */

package scramble

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
		var textBody string
		if msg.data.textBody == "" && msg.data.body != "" {
			// HTML email, blank body with file attachments, etc
			textBody = "(Sorry, Scramble only supports plain text email for now.)"
		} else {
			textBody = msg.data.textBody
		}
		cipherBody = encryptForUsers("Subject: "+msg.data.subject+"\n\n"+textBody, msg.rcptTo)
	}

	email := new(Email)
	email.MessageID = msg.data.messageID.String()
	email.UnixTime = msg.time
	email.From = msg.data.from.Address
	// TODO: separate To and CC, add BCC
	email.To = joinAddresses(append(msg.data.toList, msg.data.ccList...))
	email.CipherSubject = cipherSubject
	email.CipherBody = cipherBody
	email.ThreadID = msg.data.threadID.String()
	email.AncestorIDs = msg.data.ancestorIDs.AngledStringCappedToBytes(
		" ", GetConfig().AncestorIDsMaxBytes)

	err := SaveMessage(email)
	if err == nil {
		// all good
	} else if strings.HasPrefix(err.Error(), "Error 1062: Duplicate entry") {
		// tried to save mail, but the MessageID already exists
		// this can happen, for example, if you send an email
		// and it gets auto-forwarded back to you
		// sanity check that this is the same message
		// (we can only check From and To since Subject and Body are encrypted)
		oldEmail := LoadMessage(email.MessageID)
		if oldEmail.From != email.From ||
			oldEmail.To != email.To {
			log.Panicf("Same MessageID, different headers! Email %s from %s to %s\n",
				email.MessageID, email.To, email.From)
		}
	} else {
		// unknown error trying to save mail
		panic(err)
	}
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
