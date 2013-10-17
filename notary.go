// See: https://github.com/dcposch/scramble/wiki/Addr-Resolution-via-Notaries

package main

import (
	"code.google.com/p/go.crypto/openpgp"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	//"crypto/tls"
)

var regexKeyFile *regexp.Regexp = regexp.MustCompile(`(?s)(-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----)
(-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----)`)

type NotaryInfo struct {
	Entity         *openpgp.Entity
	PublicKeyArmor string
	Hash           string
}

var notaryInfo *NotaryInfo

func GetNotaryInfo() *NotaryInfo {
	return notaryInfo
}

// Load notary keys upon init.
func init() {

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

	log.Printf("Notary loaded: %v@%v", GetNotaryInfo().Hash, GetConfig().SmtpMxHost)
}

type NotarySignedResult struct {
	PubHash   string `json:"pubHash"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

type NotaryResultError struct {
	Result map[string]*NotarySignedResult `json:"result,omitempty"`
	Error  string                         `json:"error,omitempty"`
}

// Returns the hash if known, otherwise queues to fetch later.
func ResolveName(name, host string) string {
	addr := name + "@" + host
	hash := GetNameResolution(name, host)

	// TODO: notary should just send an empty response here
	// We should have a separate endpoint (eg POST /publickeys)
	// for saving new (name, key) pairs to the notary, and that
	// endpoint should respond with NotarySign((name,key)) to confirm
	if hash == "" {
		// for now let's just run a request immediately
		go func() {
			mxHost, err := smtpLookUp(host)
			if err != nil {
				return
			}
			u := url.URL{}
			u.Scheme = "https"
			u.Host = mxHost
			u.Path = "/publickeys/query"
			body := url.Values{}
			body.Set("nameAddresses", addr)
			body.Set("notaries", mxHost)

			resp, err := http.PostForm(u.String(), body)

			if err != nil {
				log.Printf("Secondary notary query failed for %s:\n%s", mxHost, err.Error())
				return
			}
			defer resp.Body.Close()
			respBody, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Printf("Failed to retrieve hash for %s", addr)
				return
			}

			parsed := PublicKeysResponse{}
			err = json.Unmarshal(respBody, &parsed)
			if err != nil {
				log.Printf("Failed to parse response for %s:\n\n%s\n\n%s", addr, respBody, err.Error())
				return
			}
			if len(parsed.NameResolution) != 1 {
				log.Printf("Unexpected number of responses for %s", addr)
				return
			}
			for _, resErr := range parsed.NameResolution {
				if resErr.Result != nil &&
					resErr.Result[addr] != nil &&
					resErr.Result[addr].PubHash != "" {
					AddNameResolution(name, host, resErr.Result[addr].PubHash)
				}
			}
		}()
	}
	return hash
}

func SignNotaryResponse(name, host, pubHash string, timestamp int64) string {
	toSign := name + "@" + host + "=" + pubHash + "@" + strconv.FormatInt(timestamp, 10)
	return SignText(notaryInfo.Entity, toSign)
}

// New accounts need to get their token & pubHash seeded.
func SeedUserToNotaries(user *User) {
	notaries := GetConfig().SeedNotaries
	for _, notary := range notaries {
		if notary == GetConfig().SmtpMxHost {
			continue
		}
		log.Println("Seeding new user " + user.EmailAddress + " to " + notary)
		// Maybe batch in the future, for now just run immediately.
		// This /publickeys/query call will cause the remote notary host to call 'ResolveName',
		// which in turn makes a /publickeys/query call back here.
		go func(notary, userEmailAddress string) {
			u := url.URL{}
			u.Scheme = "https"
			u.Host = notary
			u.Path = "/publickeys/query"
			body := url.Values{}
			body.Set("nameAddresses", userEmailAddress)
			body.Set("notaries", notary)
			resp, err := http.PostForm(u.String(), body)
			if err != nil {
				log.Printf("Notary seeding failed for %s:\n%s", notary, err.Error())
				return
			}
			resp.Body.Close()
		}(notary, user.EmailAddress)
	}
}
