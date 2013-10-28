package main

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/go.crypto/openpgp/packet"
	"crypto/sha1"
	"encoding/base32"
	"io"
	"strings"
)

func ComputeSha1(str string) []byte {
	hash := sha1.New()
	io.WriteString(hash, str)
	return hash.Sum(nil)
}

// Returns the first 80 bits of a SHA1 hash, encoded with a 5-bit ASCII encoding
// Returns a 16-byte string, eg "tnysbtbxsf356hiy"
// This is the same algorithm and format Onion URLS use
func ComputePublicHash(str string) string {
	sha1 := ComputeSha1(str)
	sha1First80Bits := sha1[0:10] // 10 bytes = 80 bits
	base32Str := base32.StdEncoding.EncodeToString(sha1First80Bits)
	return strings.ToLower(base32Str)
}

func SerializeKeys(entity *openpgp.Entity) (privKeyArmor, pubKeyArmor string, err error) {
	// First serialize the private parts.
	// NOTE: need to call this in order to initialize the newly created entities,
	// otherwise entity.Serialize() will fail
	// https://code.google.com/p/go/issues/detail?id=6483
	b := bytes.NewBuffer(nil)
	w, _ := armor.Encode(b, openpgp.PrivateKeyType, nil)
	err = entity.SerializePrivate(w, nil)
	if err != nil {
		return "", "", err
	}
	w.Close()
	privKeyArmor = b.String()

	// Serialize the public key.
	b.Reset()
	w, _ = armor.Encode(b, openpgp.PublicKeyType, nil)
	err = entity.Serialize(w)
	if err != nil {
		return "", "", err
	}
	w.Close()
	pubKeyArmor = b.String()

	return
}

func ReadEntity(privKeyArmor string) (*openpgp.Entity, error) {
	block, err := armor.Decode(strings.NewReader(privKeyArmor))
	if err != nil {
		return nil, err
	}
	return openpgp.ReadEntity(packet.NewReader(block.Body))
}

func SignText(entity *openpgp.Entity, text string) string {
	/*
		The armored signature from above can be verified in javascript like so:
		```javascript
			sig = openpgp.read_message(sig_armored)
			pk  = openpgp.read_publicKey(pubkey_armored)
			sig[0].signature.verify("some message", {obj:pk[0]})
		```
	*/
	b := bytes.NewBuffer(nil)
	w, _ := armor.Encode(b, openpgp.SignatureType, nil)
	err := openpgp.DetachSign(w, entity, strings.NewReader(text), nil)
	if err != nil {
		panic(err)
	}
	w.Close()
	return b.String()
}
