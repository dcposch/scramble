package main

import (
	"errors"
	"log"
	"regexp"
)

var regexHex = regexp.MustCompile("^(?i)[a-f0-9]+$")
var regexPassHash = regexp.MustCompile("^(?i)[a-f0-9]{40}$")
var regexHash = regexp.MustCompile("^(?i)[a-f0-9]{40}|[a-z2-7]{16}$")
var regexToken = regexp.MustCompile("^(?i)[a-z0-9]{3}[a-z0-9]*$")
var regexAddress = regexp.MustCompile(`^(?i)([A-Z0-9._%+-]+)@([A-Z0-9.-]+\.[A-Z]{2,4})$`)
var regexHashAddress = regexp.MustCompile(`^(?i)([A-Z0-9._%+-]+)(?:#([A-Z2-7]{16}))?@([A-Z0-9.-]+\.[A-Z]{2,4})$`)
var regexHost = regexp.MustCompile(`^(?i)([A-Z0-9.-]+\.[A-Z]{2,4})$`)
var regexPublicKeyArmor = regexp.MustCompile(`^(?s)-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----`)
var regexMessageArmor = regexp.MustCompile(`^(?s)-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----`)

func validatePassHash(str string) string {
	if !regexPassHash.MatchString(str) {
		log.Panicf("Invalid password hash %s", str)
	}
	return str
}
func validateHash(str string) string {
	if !regexHash.MatchString(str) {
		log.Panicf("Invalid hash %s", str)
	}
	return str
}
func validateHex(str string) string {
	if !regexHex.MatchString(str) {
		log.Panicf("Invalid hex value %s", str)
	}
	return str
}
func validateMessageID(str string) string {
	if !regexHex.MatchString(str) || len(str) != 40 {
		log.Panicf("Invalid Scramble email MessageID %s", str)
	}
	return str
}
func validateToken(str string) string {
	if !regexToken.MatchString(str) {
		log.Panicf("Invalid token %s", str)
	}
	return str
}
func validateBox(str string) string {
	if str != "inbox" && str != "sent" && str != "archive" {
		log.Panicf("Expected 'inbox' or 'sent', got %s", str)
	}
	return str
}
func validateAddressSafe(str string) (err error) {
	if !regexAddress.MatchString(str) {
		err = errors.New("Invalid email address " + str)
	}
	return
}
func validateHost(str string) string {
	if !regexHost.MatchString(str) {
		log.Panicf("Invalid host %s", str)
	}
	return str
}
func validatePublicKeyArmor(str string) string {
	if !regexPublicKeyArmor.MatchString(str) {
		log.Panicf("Invalid public key:\n%s", str)
	}
	return str
}
func validateMessageArmor(str string) string {
	if !regexMessageArmor.MatchString(str) {
		log.Panicf("Invalid public key:\n%s", str)
	}
	return str
}
