package main

import (
    "log"
    "regexp"
)

var regexHex = regexp.MustCompile("[a-f0-9]+")
var regexHash = regexp.MustCompile("[a-f0-9]{40}|[a-z2-7]{16}")
var regexToken = regexp.MustCompile("[a-z0-9]{3}[a-z0-9]*")

func validateHash(str string) string {
    if !regexHash.MatchString(str) {
        log.Panicf("Invalid hash %s", str)
    }
    return str
}
func validateHex(str string) string {
    if !regexHex.MatchString(str) {
        log.Panicf("Invalid hex value %s",str)
    }
    return str
}
func validateMessageID(str string) string {
    if !regexHex.MatchString(str) || len(str) != 40 {
        log.Panicf("Invalid Scramble email MessageID %s",str)
    }
    return str
}
func validateToken(str string) string {
    if !regexToken.MatchString(str) {
        log.Panicf("Invalid token %s",str)
    }
    return str
}
func validatePublicKey(str string) string {
    if str=="" {
        log.Panicf("Invalid public key:\n%s",str)
    }
    return str
}
func validateBox(str string) string {
    if str!="inbox" && str!="sent" {
        log.Panicf("Expected 'inbox' or 'sent', got %s",str)
    }
    return str
}
