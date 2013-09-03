package main

import (
	"crypto/sha1"
	"encoding/base32"
	"io"
	"strings"
)

func computeSha1(str string) []byte {
	hash := sha1.New()
	io.WriteString(hash, str)
	return hash.Sum(nil)
}

// Returns the first 80 bits of a SHA1 hash, encoded with a 5-bit ASCII encoding
// Returns a 16-byte string, eg "tnysbtbxsf356hiy"
// This is the same algorithm and format Onion URLS use
func computePublicHash(str string) string {
	sha1 := computeSha1(str)
	sha1First80Bits := sha1[0:10] // 10 bytes = 80 bits
	base32Str := base32.StdEncoding.EncodeToString(sha1First80Bits)
	return strings.ToLower(base32Str)
}
