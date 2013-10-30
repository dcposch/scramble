// See: https://github.com/dcposch/scramble/wiki/Addr-Resolution-via-Notaries

package main

import (
	"code.google.com/p/go.crypto/openpgp"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var regexKeyFile *regexp.Regexp = regexp.MustCompile(`(?s)(-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----)
(-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----)`)

type NotaryInfo struct {
	Entity         *openpgp.Entity
	PublicKeyArmor string
	Hash           string
}

// Info about this notary
var notaryInfo *NotaryInfo
// The notaries that clients will query,
// and the notaries that this server will seed new accounts with.
// {<NotaryMxHost>: <NotaryPublicKeyArmored>}
var notaries = map[string]string{}

func GetNotaryInfo() *NotaryInfo {
	return notaryInfo
}

func GetNotaries() map[string]string {
	return notaries
}

func init() {
	loadThisNotaryInfo()
	loadNotaries()
}

func loadThisNotaryInfo() {
	var privKeyArmor, pubKeyArmor string
	keyFile := os.Getenv("HOME") + "/.scramble/notary_privkey"
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		log.Printf("Creating new keyfiles for notary at %s\n", keyFile)
		entity, _ := openpgp.NewEntity(
			"Notary",
			"Notary for "+GetConfig().SmtpMxHost+" Scramble Server",
			"support@"+GetConfig().SmtpMxHost,
			nil)
		privKeyArmor, pubKeyArmor, err = SerializeKeys(entity)
		err = ioutil.WriteFile(keyFile, []byte(privKeyArmor+"\n"+pubKeyArmor), 0600)
		if err != nil {
			panic(err)
		}
		hash := ComputePublicHash(pubKeyArmor)
		notaryInfo = &NotaryInfo{entity, pubKeyArmor, hash}
	} else {
		parts := regexKeyFile.FindStringSubmatch(string(keyBytes))
		if parts == nil {
			log.Panicf("Invalid keyfile %s.", keyFile)
		}
		privKeyArmor = parts[1]
		pubKeyArmor = parts[2]
		entity, err := ReadEntity(privKeyArmor)
		if err != nil {
			panic(err)
		}
		hash := ComputePublicHash(pubKeyArmor)
		notaryInfo = &NotaryInfo{entity, pubKeyArmor, hash}
	}

	log.Printf("Notary for this host loaded: %v@%v", GetNotaryInfo().Hash, GetConfig().SmtpMxHost)
}

func loadNotaries() {
	notaryFiles := GetConfig().Notaries
	notaryHosts := []string{}
	for notaryHost, filename := range notaryFiles {
		pubKeyBytes, err := ioutil.ReadFile(filename)
		if err != nil {
			panic(err)
		}
		notaries[notaryHost] = string(pubKeyBytes)
		notaryHosts = append(notaryHosts, notaryHost)
	}

	if len(notaries) == 0 {
		log.Panic("No notaries loaded. Was 'Notaries' set in ~/.scramble/config.json?")
	}

	log.Printf("Notaries loaded: %v", strings.Join(notaryHosts, ","))
}

type NotarySignedResult struct {
	PubHash   string `json:"pubHash,omitempty"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

type NotaryResultError struct {
	Result map[string]*NotarySignedResult `json:"result,omitempty"`
	Error  string                         `json:"error,omitempty"`
}

// Returns the hash from name_resolution table.
func ResolveName(name, host string) string {
	addr := name + "@" + host
	hash := GetNameResolution(name, host)

	if hash == "" {

		mxHost, err := mxLookUp(host)
		if err != nil {
			return "" // whatever, we were going to return "" anyways
		}
		if mxHost == GetConfig().SmtpMxHost {
			log.Printf("Well, that's unexpected. Why didn't GetNameResolution pick up the hash for %v?\n"+
				"Using user table instead. But really, this should be in the name_resolution table.", addr)
			return LoadPubHash(name, host)
		}

	}
	return hash
}

func StringForNotaryToSign(name, host, pubHash string, timestamp int64) string {
	return name + "@" + host + "=" + pubHash + "@" + strconv.FormatInt(timestamp, 10)
}

func SignNotaryResponse(name, host, pubHash string, timestamp int64) string {
	toSign := StringForNotaryToSign(name, host, pubHash, timestamp)
	return SignText(notaryInfo.Entity, toSign)
}

// New accounts need to get their token & pubHash seeded.
func SeedUserToNotaries(user *User) {

	name    := user.Token
	host    := user.EmailHost
	address := user.EmailAddress
	pubHash := user.PublicHash
	timestamp := time.Now().Unix()
	signature := SignNotaryResponse(name, host, pubHash, timestamp)

	for notary, _:= range notaries {
		if notary == GetConfig().SmtpMxHost {
			continue
		}
		go func(notary string) {
			log.Println("Seeding new user " + user.EmailAddress + " to " + notary)
			u := url.URL{}
			u.Scheme = "https"
			u.Host = notary
			u.Path = "/publickeys/seed"
			body := url.Values{}
			body.Set("address", address)
			body.Set("pubHash", pubHash)
			body.Set("timestamp", strconv.FormatInt(timestamp, 10))
			body.Set("signature", signature)
			resp, err := http.PostForm(u.String(), body)
			if err != nil {
				log.Printf("Notary seeding failed for %s:\n%s", notary, err.Error())
				return
			}
			resp.Body.Close()
		}(notary)
	}
}
