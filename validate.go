package main

import (
	"log"
	"regexp"
)

// Parts of regular expressions
var atom = "[A-Z0-9!#$%&'*+\\-/=?^_`{|}~]+"
var dotAtom = atom+`(?:\.`+atom+`)*`
var domain = `[A-Z0-9.-]+\.[A-Z]{2,4}`

var regexHex = regexp.MustCompile("^(?i)[a-f0-9]+$")
var regexPassHash = regexp.MustCompile("^(?i)[a-f0-9]{40}$")
var regexHash = regexp.MustCompile("^(?i)[a-f0-9]{40}|[a-z2-7]{16}$")
var regexToken = regexp.MustCompile("^(?i)[a-z0-9]{3}[a-z0-9]*$")
var regexAddress = regexp.MustCompile(`^(?i)(`+dotAtom+`)@(`+dotAtom+`)$`)
var regexAngledAddress = regexp.MustCompile(`(?i)<(`+dotAtom+`)@(`+dotAtom+`)>`)
var regexHost = regexp.MustCompile(`^(?i)(`+domain+`)$`)
var regexPublicKeyArmor = regexp.MustCompile(`^(?s)-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----`)
var regexMessageArmor = regexp.MustCompile(`^(?s)-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----`)
var regexSignatureArmor = regexp.MustCompile(`^(?s)-----BEGIN PGP SIGNATURE-----.*?-----END PGP SIGNATURE-----`)

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
	if !regexAddress.MatchString(str) {
		log.Panicf("Invalid msg-id %s", str)
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
	if str != "inbox" && str != "sent" && str != "archive" && str != "trash" {
		log.Panicf("Expected inbox/sent/archive/trash, got %s", str)
	}
	return str
}
func validateAddressSafe(str string) bool {
	return regexAddress.MatchString(str)
}
func validateAddress(str string) string {
	if !validateAddressSafe(str) {
		log.Panicf("Invalid address %s", str)
	}
	return str
}
func validateHost(str string) string {
	if !regexHost.MatchString(str) {
		log.Panicf("Invalid host %s", str)
	}
	return str
}
func validatePublicKeyArmor(str string) string {
	if !regexPublicKeyArmor.MatchString(str) {
		log.Panicf("Invalid pgp public key:\n%s", str)
	}
	return str
}
func validateMessageArmorSafe(str string) bool {
	return regexMessageArmor.MatchString(str)
}
func validateMessageArmor(str string) string {
	if !validateMessageArmorSafe(str) {
		log.Panicf("Invalid pgp message:\n%s", str)
	}
	return str
}
func validateSignatureArmorSafe(str string) bool {
	return regexSignatureArmor.MatchString(str)
}
func validateSignatureArmor(str string) string {
	if !validateSignatureArmorSafe(str) {
		log.Panicf("Invalid pgp signature:\n%s", str)
	}
	return str
}
