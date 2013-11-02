package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	//"github.com/jaekwon/go-prelude/colors"
)

//
// SERVE HTML, CSS, JS
//

func staticHandler(w http.ResponseWriter, r *http.Request) {
	var path string
	if strings.HasSuffix(r.URL.Path, "/") {
		path = r.URL.Path + "index.html"
	} else {
		path = r.URL.Path
	}
	http.ServeFile(w, r, "static/"+path)
}

//
// USER ROUTE
//

func userHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		publicKeyHandler(w, r)
	} else if r.Method == "POST" {
		createHandler(w, r)
	}
}

// GET /user/<public key hash> for public key lookup
// The server is untrusted, so the client will verify in Javascript
// that the public key we send here matches the hash they requested
func publicKeyHandler(w http.ResponseWriter, r *http.Request) {
	userPubHash := validateHash(r.URL.Path[len("/user/"):])
	userPub := LoadPubKey(userPubHash)
	if userPub == "" {
		http.Error(w, "Not found", http.StatusNotFound)
	} else {
		w.Write([]byte(userPub))
	}
}

// POST /user to create a new account
// Remember that public and private key generation happens
// on the client. Public key, encrypted private key posted here.
func createHandler(w http.ResponseWriter, r *http.Request) {
	user := new(User)
	user.Token = validateToken(r.FormValue("token"))
	if GetConfig().IsReservedName(user.Token) {
		http.Error(w, "That username is reserved", http.StatusBadRequest)
		return
	}
	user.PasswordHash = validatePassHash(r.FormValue("passHash"))
	user.PublicKey = validatePublicKeyArmor(r.FormValue("publicKey"))
	user.PublicHash = ComputePublicHash(user.PublicKey)
	user.CipherPrivateKey = validateHex(r.FormValue("cipherPrivateKey"))
	user.EmailHost = computeEmailHost(r.Host)
	user.EmailAddress = user.Token + "@" + user.EmailHost

	log.Printf("Woot! New user %s %s\n", user.Token, user.PublicHash)

	if !SaveUser(user) {
		http.Error(w, "That username is taken", http.StatusBadRequest)
		return
	}

	// Add user to local name_resolution table
	AddNameResolution(user.Token, user.EmailHost, user.PublicHash)

	// Seed user token & hash to notaries.
	SeedUserToNotaries(user)
}

// GET /user/me/contacts for the logged-in user's encrypted address book
// POST /user/me/contacts to update logged-in user's encrypted address book
// The entire address book is a single blob.
// Because the server never knows the plaintext, it is also
// unable to update individual keys in address book -- whenever
// the user makes changes, the client encrypts and posts all contacts
func contactsHandler(w http.ResponseWriter, r *http.Request, userID *UserID) {
	if r.Method == "GET" {
		cipherContactsHex := LoadContacts(userID.Token)
		if cipherContactsHex == nil {
			http.Error(w, "Not found", http.StatusNotFound)
		} else {
			w.Write([]byte(*cipherContactsHex))
		}
	} else if r.Method == "POST" {
		cipherContactsHex, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}
		SaveContacts(userID.Token, string(cipherContactsHex))
	}
}

// GET /user/me/key for the logged-in user's encrypted private key
func privateKeyHandler(w http.ResponseWriter, r *http.Request, userID *UserID) {
	user := LoadUser(userID.Token)
	if user == nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	w.Write([]byte(user.CipherPrivateKey))
}

func computeEmailHost(requestHost string) string {
	if requestHost == "localhost" || strings.HasPrefix(requestHost, "localhost:") {
		return GetConfig().SMTPMxHost
	}
	if strings.Index(requestHost, ":") == -1 {
		return requestHost
	}
	host, _, err := net.SplitHostPort(requestHost)
	if err != nil {
		panic(err)
	}
	return host
}

//
// INBOX ROUTE
//

// Takes no arguments, returns all the metadata about a user's (in)box.
// Encrypted subjects are returned, but no message bodies.
// The caller must have auth cookies set.
func boxHandler(w http.ResponseWriter, r *http.Request, userID *UserID) {
	box := r.URL.Path[len("/box/"):]
	query := r.URL.Query()
	offset, err := strconv.Atoi(query.Get("offset"))
	if err != nil {
		panic(err)
	}
	limit, err := strconv.Atoi(query.Get("limit"))
	if err != nil {
		panic(err)
	}

	var emailHeaders []EmailHeader
	var total int
	if box == "inbox" || box == "archive" || box == "sent" {
		emailHeaders = LoadBoxByThread(userID.EmailAddress, box, offset, limit)
		total, err = CountBox(userID.EmailAddress, box)
		if err != nil {
			panic(err)
		}
	} else {
		http.Error(w, "Unknown box. "+
			"Expected 'inbox','sent', etc, got "+box,
			http.StatusBadRequest)
		return
	}

	var summary BoxSummary
	summary.EmailAddress = userID.EmailAddress
	summary.PublicHash = userID.PublicHash
	summary.Box = box
	summary.Offset = offset
	summary.Limit = limit
	summary.Total = total
	summary.EmailHeaders = emailHeaders

	summaryJSON, err := json.Marshal(summary)
	if err != nil {
		panic(err)
	}
	w.Write(summaryJSON)
}

//
// EMAIL ROUTE
//

func emailHandler(w http.ResponseWriter, r *http.Request, userID *UserID) {
	if r.Method == "GET" {
		emailFetchHandler(w, r, userID)
	} else if r.Method == "PUT" {
		emailBoxHandler(w, r, userID)
	} else if r.Method == "POST" {
		emailSendHandler(w, r, userID)
	}
}

// GET /email/ fetches an email & all messages
//  in the given box for the given threadID
func emailFetchHandler(w http.ResponseWriter, r *http.Request, userID *UserID) {
	threadID := validateMessageID(r.FormValue("threadID"))
	// We may need this in the future:
	_ = validateBox(r.FormValue("box"))

	threadEmails := LoadThreadFromBoxes(userID.EmailAddress, threadID)
	if len(threadEmails) == 0 {
		http.Error(w, "Not found or unauthorized", http.StatusUnauthorized)
		return
	}
	resJSON, err := json.Marshal(threadEmails)
	if err != nil {
		panic(err)
	}
	w.Write(resJSON)
}

// PUT /email/id can change things about an email, eg what box it's in
func emailBoxHandler(w http.ResponseWriter, r *http.Request, userID *UserID) {
	id := validateMessageID(r.URL.Path[len("/email/"):])
	newBox := validateBox(r.FormValue("box"))
	moveThread := (r.FormValue("moveThread") == "true")

	// For now just delete emails instead of moving to "trash".
	if newBox == "trash" {
		if moveThread {
			DeleteThreadFromBoxes(userID.EmailAddress, id)
		} else {
			DeleteFromBoxes(userID.EmailAddress, id)
		}
	} else {
		if moveThread {
			MoveThread(userID.EmailAddress, id, newBox)
		} else {
			MoveEmail(userID.EmailAddress, id, newBox)
		}
	}
}

// POST /email/ creates a new email from auth user
func emailSendHandler(w http.ResponseWriter, r *http.Request, userID *UserID) {
	email := new(Email)
	email.MessageID = validateMessageID(r.FormValue("msgID"))
	email.ThreadID = validateMessageID(r.FormValue("threadID"))
	email.AncestorIDs = ParseAngledEmailAddresses(r.FormValue("ancestorIDs"), " ").
		AngledStringCappedToBytes(" ", GetConfig().AncestorIDsMaxBytes)
	email.UnixTime = time.Now().Unix()
	email.From = userID.EmailAddress
	email.To = r.FormValue("to")

	// for each address, lookup MX record & determine what to do.
	mxHostAddrs, failedHostAddrs := GroupAddrsByMxHost(email.To)

	// fail immediately if any address cannot be resolved.
	if len(failedHostAddrs) != 0 {
		// TODO: better error handling
		w.WriteHeader(500)
		w.Write([]byte(fmt.Sprintf("Mx lookup failed for (%v)", failedHostAddrs.String())))
		return
	}

	// Handle plaintext emails specially
	outgoingEmail := new(OutgoingEmail)
	if r.FormValue("cipherBody") == "" { // unencrypted
		// Gather local recipients
		localRecipients := EmailAddresses{ParseEmailAddress(userID.EmailAddress)}
		for mxHost, addrs := range mxHostAddrs {
			if mxHost == GetConfig().SMTPMxHost {
				localRecipients = addrs
			}
		}
		localRecipients = localRecipients.Unique()
		// Populate outgoingEmail
		email.CipherSubject = encryptForUsers(r.FormValue("subject"), localRecipients.Strings())
		email.CipherBody = encryptForUsers(r.FormValue("body"), localRecipients.Strings())
		outgoingEmail.Email = *email
		outgoingEmail.PlaintextSubject = r.FormValue("subject")
		outgoingEmail.PlaintextBody = r.FormValue("body")
		outgoingEmail.IsPlaintext = true
	} else { // encrypted
		email.CipherSubject = validateMessageArmor(r.FormValue("cipherSubject"))
		email.CipherBody = validateMessageArmor(r.FormValue("cipherBody"))
		outgoingEmail.Email = *email
		outgoingEmail.IsPlaintext = false
	}

	// TODO: consider if transactions are required.
	// TODO: saveMessage may fail if messageID is not unique.
	SaveMessage(email)

	// add message to sender's sent box
	AddMessageToBox(email, userID.EmailAddress, "sent")

	// TODO: separate goroutine?
	// TODO: parallize mx lookup?

	// Deliver mail locally
	for mxHost, addrs := range mxHostAddrs {
		// if mxHost is GetConfig().SMTPMxHost, assume that the lookup will return itself.
		// this saves us from having to set up test MX records for localhost testing.
		if mxHost == GetConfig().SMTPMxHost {
			// add to inbox locally
			for _, addr := range addrs {
				AddMessageToBox(email, addr.String(), "inbox")
			}
			continue
		}
	}

	// Deliver mail outside synchronously
	// In the future we may want more advanced logic.
	err := smtpSend(outgoingEmail)
	if err != nil {
		panic(err)
	}
}

//
// NGINX
//

// Tells where nginx should forward SMTP to
func nginxProxyHandler(w http.ResponseWriter, r *http.Request) {
	// http://nginx.org/en/docs/mail/ngx_mail_auth_http_module.html
	header := w.Header()
	header.Add("Auth-Status", "OK")
	header.Add("Auth-Server", "127.0.0.1")
	header.Add("Auth-Port", fmt.Sprintf("%d", GetConfig().SMTPPort))
	w.Write([]byte{})
}

//
// NOTARY
//

type NotaryInfoResponse struct {
	MxHost   string            `json:"mxHost"`
	PubKey   string            `json:"pubKey"`
	Notaries map[string]string `json:"notaries"`
}

// Return useful information about this notary,
// and the notaries that its clients use.
func notaryHandler(w http.ResponseWriter, r *http.Request) {
	resJSON, err := json.Marshal(struct {
		MxHost   string            `json:"mxHost"`
		PubKey   string            `json:"pubKey"`
		Notaries map[string]string `json:"notaries"`
	}{
		GetConfig().SMTPMxHost,
		GetNotaryInfo().PublicKeyArmor,
		GetNotaries(),
	},
	)
	if err != nil {
		panic(err)
	}
	// TODO: set cache
	w.Header().Set("Content-Type", "application/json")
	w.Write(resJSON)
}

// Handler for receiving new address & hashes from other Scramble servers.
// This is how this notary knows what the pubHash is for a given address.
func publicKeySeedHandler(w http.ResponseWriter, r *http.Request) {
	address := ParseEmailAddress(r.FormValue("address"))
	pubHash := validateHash(r.FormValue("pubHash"))
	timestamp, err := strconv.ParseInt(r.FormValue("timestamp"), 10, 64)
	if err != nil {
		panic(errors.New("invalid timestamp"))
	}
	signature := validateSignatureArmor(r.FormValue("signature"))

	// TODO: maybe also do a sanity check on the timestamp.

	mxHost, err := mxLookUp(address.Host)
	if err != nil {
		log.Panicf("Cannot seed address %v, mx lookup failed.", address.String())
	}

	mxHostInfo := GetMxHostInfo(mxHost)
	if mxHostInfo == nil || mxHostInfo.NotaryPublicKey == "" {
		resp, err := http.Get("https://" + mxHost + "/publickeys/notary")
		if err != nil {
			log.Panicf("Cannot seed address %v,"+
				" could not fetch mx host notary info", address.String())
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Panicf("Cannot seed address %v,"+
				" could not read mx host notary info", address.String())
		}
		parsed := NotaryInfoResponse{}
		err = json.Unmarshal(body, &parsed)
		if err != nil {
			log.Panicf("Cannot seed address %v,"+
				" could not parse mx host notary info", address.String())
		}
		mxHostInfo = SetMxHostInfo(mxHost, true, parsed.PubKey)
	}

	signed := StringForNotaryToSign(address.Name, address.Host, pubHash, timestamp)
	ok := VerifySignature(mxHostInfo.NotaryPublicKey, signed, signature)

	if ok {
		AddNameResolution(address.Name, address.Host, pubHash)
		// TODO respond with our own signature to speed up user account creation.
	} else {
		log.Panicf("Cannot seed address %v, bad signature!", address.String())
	}

}

// POST /publickeys/query to resolve addresses to public key hashes &
//  also look up public keys from those hashes.
// Read more here:
//  https://github.com/dcposch/scramble/wiki/Name-Resolution-&-Public-Key-Fetching
// The server is untrusted, so the client must verify everything.

const (
	PublicKeysStatusOK          = "OK"
	PublicKeysStatusNoSuchUser  = "NO_SUCH_USER"
	PublicKeysStatusError       = "ERROR"
	PublicKeysStatusNotScramble = "NOT_SCRAMBLE"
)

type PublicKeysPubKeyError struct {
	Status string `json:"status,omitempty"`
	PubKey string `json:"pubKey,omitempty"`
	Error  string `json:"error,omitempty"`
}

type PublicKeysResponse struct {
	NameResolution map[string]*NotaryResultError     `json:"nameResolution,omitempty"` // defined in notary.go
	PublicKeys     map[string]*PublicKeysPubKeyError `json:"publicKeys,omitempty"`
}

func publicKeysHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := authenticate(r)
	timestamp := time.Now().Unix()

	type MxHostRespErr struct {
		MxHost string
		Resp   *http.Response
		Err    error
	}

	type PerMxHostRequest struct {
		NameAddresses EmailAddresses
		HashAddresses EmailAddresses
	}

	// parse addresses & group by mx host
	nameAddrs := ParseEmailAddresses(r.FormValue("nameAddresses"))
	mxHostNameAddrs, failedNameAddrs := GroupAddrsByMxHost(r.FormValue("nameAddresses"))
	mxHostHashAddrs, failedHostAddrs := GroupAddrsByMxHost(r.FormValue("hashAddresses"))
	notaries := strings.Split(r.FormValue("notaries"), ",")
	for _, notary := range notaries {
		validateHost(notary)
	}

	// <mxHost>: true, for nonScramble hosts.
	mxHostInfos := map[string]*MxHostInfo{}
	allMxHosts := map[string]struct{}{}
	for mxHost := range mxHostNameAddrs {
		allMxHosts[mxHost] = struct{}{}
	}
	for mxHost := range mxHostHashAddrs {
		allMxHosts[mxHost] = struct{}{}
	}
	for mxHost := range allMxHosts {
		mxHostInfos[mxHost] = GetMxHostInfo(mxHost)
	}

	res := PublicKeysResponse{}
	res.NameResolution = map[string]*NotaryResultError{}
	res.PublicKeys = map[string]*PublicKeysPubKeyError{}

	// fail immediately if any address cannot be resolved.
	if len(failedHostAddrs) != 0 || len(failedNameAddrs) != 0 {
		// TODO: better error handling
		failedAddrs := append(failedHostAddrs, failedNameAddrs...)
		w.WriteHeader(500)
		w.Write([]byte(fmt.Sprintf("MX lookup failed for (%v)", failedAddrs.String())))
		return
	}

	// server-to-server requests need no userID,
	// but all requested addresses should belong to this server.
	ourMxHost := GetConfig().SMTPMxHost
	if userID == nil {
		for host := range mxHostHashAddrs {
			if host != ourMxHost {
				log.Panicf("Invalid host for server-to-server /publickeys/query request."+
					"Expected %v, got %v", ourMxHost, host)
			}
		}
		if len(notaries) > 1 || notaries[0] != GetConfig().SMTPMxHost {
			log.Panicf("Expected 0 or 1 notary @" + GetConfig().SMTPMxHost +
				", got [" + strings.Join(notaries, ",") + "]")
		}
	}

	// compile requests by mx host.
	allRequests := map[string]*PerMxHostRequest{}
	for mxHost, nameAddrs := range mxHostNameAddrs {
		if mxHostInfos[mxHost] != nil && mxHostInfos[mxHost].IsScramble == false {
			// no point asking a non-scramble mxHost for the key!
			continue
		}
		if allRequests[mxHost] == nil {
			allRequests[mxHost] = &PerMxHostRequest{}
		}
		allRequests[mxHost].HashAddresses = append(allRequests[mxHost].HashAddresses, nameAddrs...)
	}
	for mxHost, hashAddrs := range mxHostHashAddrs {
		if mxHostInfos[mxHost] != nil && mxHostInfos[mxHost].IsScramble == false {
			log.Println("Odd, how does address(es) " + hashAddrs.String() + " have hashes, when mxHost is nonscramble?")
			continue
		}
		if allRequests[mxHost] == nil {
			allRequests[mxHost] = &PerMxHostRequest{}
		}
		allRequests[mxHost].HashAddresses = append(allRequests[mxHost].HashAddresses, hashAddrs...)
	}
	if len(nameAddrs) > 0 {
		for _, notary := range notaries {
			if allRequests[notary] == nil {
				allRequests[notary] = &PerMxHostRequest{}
			}
			allRequests[notary].NameAddresses = nameAddrs
		}
	}

	// dispatch requests to each server.
	ch := make(chan *MxHostRespErr)
	counter := 0
	for mxHost, request := range allRequests {
		if mxHost == GetConfig().SMTPMxHost {
			// if host is this host

			// handle resolution request
			if len(request.NameAddresses) > 0 {
				signedResults := map[string]*NotarySignedResult{}
				thisResult := &NotaryResultError{signedResults, ""}
				for _, addrs := range mxHostNameAddrs {
					for _, addr := range addrs {
						pubHash := ResolveName(addr.Name, addr.Host)
						// pubHash may be "", and that's a ok.
						signedResults[addr.String()] = &NotarySignedResult{
							pubHash,
							timestamp,
							SignNotaryResponse(addr.Name, addr.Host, pubHash, timestamp),
						}
					}
				}
				res.NameResolution[mxHost] = thisResult
			}

			// handle pubkey lookup
			pubKeyLookup := request.HashAddresses
			for mxHost, addrs := range mxHostNameAddrs {
				if mxHost == GetConfig().SMTPMxHost {
					for _, addr := range addrs {
						pubKeyLookup = append(pubKeyLookup, addr)
					}
				}
			}
			for _, addr := range pubKeyLookup {
				name, hash := addr.NameAndHash()
				pubHash := LoadPubHash(name, addr.Host)
				if pubHash == "" {
					res.PublicKeys[addr.StringNoHash()] = &PublicKeysPubKeyError{PublicKeysStatusNoSuchUser, "", "Unknown address " + addr.StringNoHash()}
					continue
				}
				pubKey := LoadPubKey(pubHash)
				if hash == "" || pubHash == hash {
					res.PublicKeys[addr.StringNoHash()] = &PublicKeysPubKeyError{PublicKeysStatusOK, pubKey, ""}
				} else {
					res.PublicKeys[addr.StringNoHash()] = &PublicKeysPubKeyError{PublicKeysStatusError, pubKey, "Wrong hash for address " + addr.StringNoHash()}
				}
			}

		} else {
			// if host is an external host
			counter += 1
			go func(mxHost string, request *PerMxHostRequest) {
				defer Recover()
				u := url.URL{}
				u.Scheme = "https"
				u.Host = mxHost
				u.Path = "/publickeys/query"
				body := url.Values{}
				body.Set("nameAddresses", request.NameAddresses.String())
				body.Set("hashAddresses", request.HashAddresses.String())
				body.Set("notaries", mxHost)
				resp, err := http.PostForm(u.String(), body)
				ch <- &MxHostRespErr{mxHost, resp, err}
			}(mxHost, request)
		}
	}

	// update `res` with responses
	timeout := time.After(5 * time.Second)
	timedOut := false
	for counter > 0 && !timedOut {
		select {
		case mxHostRespErr := <-ch:
			counter -= 1
			mxHost := mxHostRespErr.MxHost
			if mxHostRespErr.Err != nil {
				log.Printf("Error in /publickeys/query dispatch request: %s", mxHostRespErr.Err.Error())
				// Yahoo's mxHost times out like this.
				// Assume the mxHost isn't a scramble host.
				if mxHostInfos[mxHost] == nil {
					mxHostInfos[mxHost] = TrySetMxHostInfo(mxHost, false, "")
				}
				continue
			}
			defer mxHostRespErr.Resp.Body.Close()
			respBody, err := ioutil.ReadAll(mxHostRespErr.Resp.Body)
			log.Println("Dispatch response: ", string(respBody))
			if err != nil {
				log.Printf("Error in /publickeys/query dispatch request body read: %s", err.Error())
				continue
			}
			parsed := PublicKeysResponse{}
			err = json.Unmarshal(respBody, &parsed)
			if err != nil {
				// Assume the mxHost isn't a scramble host.
				if mxHostInfos[mxHost] == nil {
					mxHostInfos[mxHost] = TrySetMxHostInfo(mxHost, false, "")
				}
				log.Println("Error in /publickeys/query json parse: %s", err.Error())
				continue
			} else {
				// Hey, a scramble host.
				if mxHostInfos[mxHost] == nil {
					mxHostInfos[mxHost] = TrySetMxHostInfo(mxHost, true, "")
				}
			}
			// aggregate notary responses
			res.NameResolution[mxHost] = parsed.NameResolution[mxHost]
			// merge pubkeys
			for addr, pubKeyErr := range parsed.PublicKeys {
				// The client still verifies the hash, but
				//  we should still be careful lest it tramples a valid entry
				//  from another host.
				if ParseEmailAddress(addr).Host != mxHost {
					log.Printf("Dispatched /publickeys/query to %s returned public key for an invalid address: %s",
						mxHost, addr)
				} else {
					res.PublicKeys[addr] = pubKeyErr
				}
			}
		case <-timeout:
			timedOut = true
		}
	}

	// If this request is primary,
	// Fill remaining addresses with appropriate error messages
	// Client must still verify that addresses aren't missing
	if userID != nil {
		for mxHost, addrs := range mxHostNameAddrs {
			if mxHost == GetConfig().SMTPMxHost {
				continue // no need to fill error messages, already filled.
			}
			for _, addr := range addrs {
				if res.PublicKeys[addr.StringNoHash()] == nil {
					if mxHostInfos[mxHost] != nil && mxHostInfos[mxHost].IsScramble == false {
						res.PublicKeys[addr.StringNoHash()] = &PublicKeysPubKeyError{PublicKeysStatusNotScramble, "", "Not a scramble address"}
					} else {
						res.PublicKeys[addr.StringNoHash()] = &PublicKeysPubKeyError{PublicKeysStatusError, "", "Failed to retrieve public key"}
					}
				}
			}
		}
		for mxHost, addrs := range mxHostHashAddrs {
			if mxHost == GetConfig().SMTPMxHost {
				continue // no need to fill error messages, already filled.
			}
			for _, addr := range addrs {
				if res.PublicKeys[addr.StringNoHash()] == nil {
					if mxHostInfos[mxHost] != nil && mxHostInfos[mxHost].IsScramble == false {
						res.PublicKeys[addr.StringNoHash()] = &PublicKeysPubKeyError{PublicKeysStatusNotScramble, "", "Not a scramble address"}
					} else {
						res.PublicKeys[addr.StringNoHash()] = &PublicKeysPubKeyError{PublicKeysStatusError, "", "Failed to retrieve public key"}
					}
				}
			}
		}
		if len(nameAddrs) > 0 {
			for _, notary := range notaries {
				if res.NameResolution[notary] == nil {
					res.NameResolution[notary] = &NotaryResultError{
						nil,
						fmt.Sprintf("Failed to retrieve notary response from %s", notary),
					}
				}
			}
		}
	}

	// respond back
	resJSON, err := json.Marshal(res)
	if err != nil {
		panic(err)
	}
	w.Write(resJSON)

	// drain ch
	go func() {
		defer Recover()
		for counter > 0 {
			select {
			case mxHostRespErr := <-ch:
				counter -= 1
				if mxHostRespErr.Err != nil {
					log.Printf("Error in (timed out) /publickeys/query dispatch request drain: %s", mxHostRespErr.Err.Error())
					// Gmail's mxHost times out like this.
					// Assume the mxHost isn't a scramble host.
					if mxHostInfos[mxHostRespErr.MxHost] == nil {
						TrySetMxHostInfo(mxHostRespErr.MxHost, false, "")
					}
					continue
				}
				mxHostRespErr.Resp.Body.Close()
			}
		}
	}()
}

// POST /publickeys/reverse to lookup name from pubhash
// This exists to upgrade legacy contacts lists.
func reverseQueryHandler(w http.ResponseWriter, r *http.Request, userID *UserID) {
	pubHashes := r.FormValue("pubHashes")
	res := map[string]string{}
	for _, pubHash := range strings.Split(pubHashes, ",") {
		if pubHash == "" {
			continue
		}
		address := LoadAddressFromPubHash(pubHash)
		res[pubHash] = address
	}
	resJSON, err := json.Marshal(res)
	if err != nil {
		panic(err)
	}
	w.Write(resJSON)
}
