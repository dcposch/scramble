package scramble

import (
	"log"
	"net/mail"
	"testing"
)

func TestValidateAddress(t *testing.T) {
	validateAddress("dcposch@gmail.com")
	validateAddress("test2@gpgmail.io")
	validateAddress("update+mk_-dhpd@facebookmail.com")
	validateAddress("dcposch+caf_=dcposch=scramble.io@gmail.com")

	log.Printf("Email address validation looks good\n")
}

func TestParseEmailAddress(t *testing.T) {
	addr, err := mail.ParseAddress("<jaekwon@scramble.io>")
	if err != nil {
		t.Errorf("Failed to parse valid angle-bracket email address %v\n", err)
	}
	addr, err = mail.ParseAddress("jaekwon@scramble.io")
	if err != nil {
		t.Errorf("Failed to parse valid non-angle-bracket email address %v\n", err)
	}
	addr, err = mail.ParseAddress("Jae <jaekwon@scramble.io>")
	if err != nil {
		t.Errorf("Failed to parse valid name + email address %v\n", err)
	}
	if addr.Name != "Jae" || addr.Address != "jaekwon@scramble.io" {
		t.Errorf("Incorrectly parsed valid name + email address: %s %s\n",
			addr.Name, addr.Address)
	}
}
