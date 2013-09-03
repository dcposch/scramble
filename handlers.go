package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
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
	user.PasswordHash = validatePassHash(r.FormValue("passHash"))
	user.PublicKey = validatePublicKey(r.FormValue("publicKey"))
	user.PublicHash = computePublicHash(user.PublicKey)
	user.CipherPrivateKey = validateHex(r.FormValue("cipherPrivateKey"))

	log.Printf("Woot! New user %s %s\n", user.Token, user.PublicHash)

	if !SaveUser(user) {
		http.Error(w, "That username is taken", http.StatusBadRequest)
	}
}

// GET /user/me/contacts for the logged-in user's encrypted address book
// POST /user/me/contacts to update logged-in user's encrypted address book
// The entire address book is a single blob.
// Because the server never knows the plaintext, it is also
// unable to update individual keys in address book -- whenever
// the user makes changes, the client encrypts and posts all contacts
func contactsHandler(w http.ResponseWriter, r *http.Request) {
	userId := authenticate(r)

	if r.Method == "GET" {
		cipherContactsHex := LoadContacts(userId.Token)
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
		SaveContacts(userId.Token, string(cipherContactsHex))
	}
}

// GET /user/me/key for the logged-in user's encrypted private key
func privateKeyHandler(w http.ResponseWriter, r *http.Request) {
	userId := authenticate(r)

	user := LoadUser(userId.Token)
	if user == nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	w.Write([]byte(user.CipherPrivateKey))
}

//
// AUTHENTICATION
//

// Checks cookies, returns the logged-in user token or empty string
func authenticate(r *http.Request) *UserID {
	token, err := r.Cookie("token")
	if err != nil {
		return nil
	}
	passHash, err := r.Cookie("passHash")
	if err != nil {
		return nil
	}
	passHashOld, _ := r.Cookie("passHashOld")
	var passHashOldVal string
	if err != nil {
		passHashOldVal = ""
	} else {
		passHashOldVal = passHashOld.Value
	}
	return authenticateUserPass(token.Value, passHash.Value, passHashOldVal)
}

func authenticateUserPass(token string, passHash string, passHashOld string) *UserID {
	userId := LoadUserID(token)
	if userId == nil {
		return nil
	}
	if passHash == userId.PasswordHash && passHash != "" {
		return userId
	}
	if passHashOld == userId.PasswordHashOld && passHashOld != "" {
		return userId
	}
	return nil
}

//
// INBOX ROUTE
//

// Takes no arguments, returns all the metadata about a user's inbox.
// Encrypted subjects are returned, but no message bodies.
// The caller must have auth cookies set.
func inboxHandler(w http.ResponseWriter, r *http.Request) {
	userId := authenticate(r)
	if userId == nil {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	box := r.URL.Path[len("/box/"):]

	var emailHeaders []EmailHeader
	if box == "inbox" || box == "archive" {
		emailHeaders = LoadBox(userId.PublicHash, box)
	} else if box == "sent" {
		emailHeaders = LoadSent(userId.PublicHash)
	} else {
		http.Error(w, "Unknown box. "+
			"Expected 'inbox','sent', etc, got "+box,
			http.StatusBadRequest)
		return
	}

	var inbox InboxSummary
	inbox.Token = userId.Token
	inbox.PublicHash = userId.PublicHash
	inbox.EmailHeaders = emailHeaders

	inboxJson, err := json.Marshal(inbox)
	if err != nil {
		panic(err)
	}
	w.Write(inboxJson)
}

//
// EMAIL ROUTE
//

func emailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		emailFetchHandler(w, r)
	} else if r.Method == "PUT" {
		emailBoxHandler(w, r)
	} else if r.Method == "POST" {
		emailSendHandler(w, r)
	}
}

// GET /email/id fetches the body
func emailFetchHandler(w http.ResponseWriter, r *http.Request) {
	userId := authenticate(r)
	if userId == nil {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}

	id := r.URL.Path[len("/email/"):]
	validateMessageID(id)

	message := LoadMessage(id, userId.PublicHash)
	w.Write([]byte(message.CipherBody))
}

// PUT /email/id can change things about an email, eg what box it's in
func emailBoxHandler(w http.ResponseWriter, r *http.Request) {
	userId := authenticate(r)
	if userId == nil {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}

	id := r.URL.Path[len("/email/"):]
	validateMessageID(id)
	newBox := validateBox(r.FormValue("box"))

	UpdateEmail(id, userId.PublicHash, newBox)
}

func emailSendHandler(w http.ResponseWriter, r *http.Request) {
	userId := authenticate(r)
	if userId == nil {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}

	email := new(Email)
	email.MessageID = validateMessageID(r.FormValue("msgId"))
	email.UnixTime = time.Now().Unix()
	email.From = userId.PublicHash + "@" + r.Host
	email.To = r.FormValue("to")

	email.PubHashFrom = userId.PublicHash
	email.PubHashTo = validateHash(r.FormValue("pubHashTo"))
	email.Box = validateBox(r.FormValue("box"))
	email.CipherSubject = validateHex(r.FormValue("cipherSubject"))
	email.CipherBody = validateHex(r.FormValue("cipherBody"))

	SaveMessage(email)
}
