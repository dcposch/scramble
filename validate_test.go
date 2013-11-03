package main

import (
	"log"
	"testing"
)

func TestValidateAddress(t *testing.T) {
	validateAddress("dcposch@gmail.com")
	validateAddress("test2@gpgmail.io")
	validateAddress("dcposch+caf_=dcposch=scramble.io@gmail.com")

	log.Printf("Email address validation looks good\n")
}
