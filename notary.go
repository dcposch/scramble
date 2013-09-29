// See: https://github.com/dcposch/scramble/wiki/Addr-Resolution-via-Notaries

package main

import (
	"regexp"
	"os"
	"io/ioutil"
	"code.google.com/p/go.crypto/openpgp"
	"log"
	"strconv"
	"net/http"
	"net/url"
	"encoding/json"
	"time"
	"fmt"
	//"crypto/tls"
)

var regexKeyFile *regexp.Regexp = regexp.MustCompile(`(?s)(-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----)
(-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----)`)

type NotaryInfo struct {
	Entity *openpgp.Entity
	PublicKeyArmor string
	Hash string
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
		if err != nil { panic(err) }
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
		if err != nil { panic(err) }
		hash := ComputePublicHash(pubKeyArmor)
		notaryInfo = &NotaryInfo{entity, pubKeyArmor, hash}
	}

	log.Printf("Notary loaded: %v@%v", GetNotaryInfo().Hash, GetConfig().SmtpMxHost)
}

//
// ID HANDLER
//

func notaryIdHandler(w http.ResponseWriter, r *http.Request) {

	resJson, err := json.Marshal(struct {
			Address string `json:"address"`
			PubKey  string `json:"pubkey"`
		}{
			GetNotaryInfo().Hash+"@"+GetConfig().SmtpMxHost,
			GetNotaryInfo().PublicKeyArmor,
		},
	)
	if err != nil { panic(err) }
	w.Write(resJson)

}


//
// QUERY HANDLER
//

type NotarySignedResult struct {
	PubHash   string `json:"pubHash"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

type NotaryResultError struct {
	Result map[string]*NotarySignedResult `json:"result,omitempty"`
	Error  string    `json:"error,omitempty"`
}


/*
	POST /notary/query to look up many public hashes from
	 many <name>@<host> addresses.

	Expected form values:
	 - addresses: A comma delimited list of addresses
	 - notaries:  A comma delmited list of notary addresses to forward requests to.
	              Forward recipients (secondary notaries) expect exactly 1 address (self).

	Result format:
	{
		<notaryAddress1>: {
			// ON SUCCESS:
			"result": {
				<queryAddress>: {
					// success:
					"pubhash":   "1234567890123456",
					"timestamp": 1380383422,
					"signature": <armor>,
			   }
			},
			// OR, ON ERROR:
			"error": <message>
		},
		<notaryAddress2>: ...
	}
*/
func notaryQueryHandler( w http.ResponseWriter, r *http.Request) {

	userId := authenticate(r)

	timestamp := time.Now().Unix()

	type NotaryRespErr struct {
		Notary EmailAddress
		Resp   *http.Response
		Err    error
	}

	// the address (name@host) to resolve to hash@host.
	addrs := ParseEmailAddresses(r.FormValue("addresses"))
	// the notaries to ask in the form of hash@host.
	notaries := ParseEmailAddresses(r.FormValue("notaries"))
	res := map[string]*NotaryResultError{}

	// server-to-server queries need no userId,
	// but notaries should only contain this notary's address.
	if userId == nil {
		if len(notaries) != 1 || notaries[0].Host != GetConfig().SmtpMxHost {
			log.Panicf("Expected 1 notary address @"+GetConfig().SmtpMxHost+", got ["+notaries.String()+"]")
		}
	}

	// dispatch query to each notary.
	ch := make(chan *NotaryRespErr)
	counter := 0
	for _, notary := range notaries {
		if notary.Host == GetConfig().SmtpMxHost {
			// if notary is this host
			results := map[string]*NotarySignedResult{}
			res[notary.String()] = &NotaryResultError{results, ""}
			for _, addr := range addrs {
				if addr.IsHashAddress() {
					panic("Cannot accept a hash-address")
				}
				var pubHash string
				if addr.Host == GetConfig().SmtpMxHost {
					pubHash = LoadPubHash(addr.Name)
				} else {
					pubHash = ResolveName(addr.Name, addr.Host)
				}
				// pubHash may be "", and that's a ok.
				results[addr.String()] = &NotarySignedResult{
					pubHash,
					timestamp,
					SignNotaryResponse(addr.Name, addr.Host, pubHash, timestamp),
				}
			}
		} else {
			// if notary is an external host
			counter += 1
			go func(notary EmailAddress, addrs string) {
				u := url.URL{}
				u.Scheme = "https"
				u.Host = notary.Host
				u.Path = "/notary/query"
				body := url.Values{}
				body.Set("addresses", addrs)
				body.Set("notaries", notary.String())
				resp, err := http.PostForm(u.String(), body)
				ch <- &NotaryRespErr{notary, resp, err}
			}(notary, r.FormValue("addresses"))
		}
	}

	// update `res` with responses
	timeout := time.After(5 * time.Second)
	timedOut := false
	for counter > 0 && !timedOut {
		select {
		case notaryRespErr := <-ch:
			counter -= 1
			notary := notaryRespErr.Notary
			if notaryRespErr.Err != nil {
				log.Printf("Error in /notary/query dispatch request: %s", notaryRespErr.Err.Error())
				continue
			} // TODO better error messages
			respBody, err := ioutil.ReadAll(notaryRespErr.Resp.Body)
			defer notaryRespErr.Resp.Body.Close()
			if err != nil {
				log.Printf("Error in /notary/query dispatch request body read: %s", err.Error())
				continue
			} // TODO better error messages
			parsed := map[string]*NotaryResultError{}
			err = json.Unmarshal(respBody, &parsed)
			if err != nil {
				log.Println("Error in /notary/query json parse: %s", err.Error())
				continue
			} // TODO better error messages
			res[notary.String()] = parsed[notary.String()]
		case <-timeout:
			timedOut = true
		}
	}

	// missing notary responses get error messages.
	// client must still verify that addresses aren't missing
	for _, notary := range notaries {
		if res[notary.String()] == nil {
			res[notary.String()] = &NotaryResultError{
				nil,
				fmt.Sprintf("Failed to retrieve notary response from %s", notary.String()),
			}
		}
	}

	// respond back
	resJson, err := json.Marshal(res)
	if err != nil {
		panic(err)
	}
	w.Write(resJson)

	// drain ch
	for counter > 0 {
		select {
		case notaryRespErr := <-ch:
			counter -= 1
			if notaryRespErr.Err != nil {
				log.Printf("Error in (timed out) /notary/query dispatch request drain: %s", notaryRespErr.Err.Error())
				continue
			}
			notaryRespErr.Resp.Body.Close()
		}
	}

}

// returns the hash if known, otherwise queues to fetch later.
func ResolveName(name, host string) string {
	addr := name+"@"+host
	hash := GetNameResolution(name, host)
	if hash == "" {
		// for now let's just defer a request immediately
		defer func(){
			mxHost, err := smtpLookUp(host)
			if err != nil {
				return
			}
			u := url.URL{}
			u.Scheme = "https"
			u.Host = mxHost
			u.Path = "/notary/query"
			body := url.Values{}
			body.Set("addresses", addr)
			body.Set("notaries", "any@"+mxHost) // TODO look it up?

			// Alternatively, use the following snippet to ignore bad certs.
			/*
				tr := &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}
				client := &http.Client{Transport: tr}
				resp, err := client.PostForm(u.String(), body)
			*/
			resp, err := http.PostForm(u.String(), body)

			if err != nil {
				log.Printf("Secondary notary query failed for %s:\n%s", mxHost, err.Error())
				return
			}
			respBody, err := ioutil.ReadAll(resp.Body)
			defer resp.Body.Close()
			if err != nil {
				log.Printf("Failed to retrieve hash for %s", addr)
				return
			}
			parsed := map[string]*NotaryResultError{}
			err = json.Unmarshal(respBody, &parsed)
			if err != nil {
				log.Printf("Failed to parse response for %s:\n\n%s\n\n%s", addr, respBody, err.Error())
				return
			} // TODO better error messages
			if len(parsed) != 1 {
				log.Printf("Unexpected number of responses for %s", addr)
				return
			}
			// TODO: check notary id & signature.
			// Would be good to keep a record of those & notify the administrator for manual review.
			for _, resErr := range parsed {
				if resErr.Result != nil && resErr.Result[addr] != nil {
					AddNameResolution(name, host, resErr.Result[addr].PubHash)
				}
			}

		}()
	}
	return hash
}

func SignNotaryResponse(name, host, pubHash string, timestamp int64) string {
	toSign := name+"@"+host+"="+pubHash+"@"+strconv.FormatInt(timestamp, 10)
	return SignText(notaryInfo.Entity, toSign)
}
