package main

import (
    "regexp"
)

var regexHex = regexp.MustCompile("[a-f0-9]+")
var regexHash = regexp.MustCompile("[a-f0-9]{40}")
var regexToken = regexp.MustCompile("[a-z0-9]{3}[a-z0-9]*")

func validateHash(str string) string {
    if !regexHash.MatchString(str) {
        panic("Invalid hash "+str)
    }
    return str
}
func validateHex(str string) string {
    if !regexHex.MatchString(str) {
        panic("Invalid hex value "+str)
    }
    return str
}
func validateToken(str string) string {
    if !regexToken.MatchString(str) {
        panic("Invalid token "+str)
    }
    return str
}
func validatePublicKey(str string) string {
    if str=="" {
        panic("Invalid public key:\n"+str)
    }
    return str
}
