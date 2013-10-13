package main

import (
	"errors"
	"net/http"
)

// Checks cookies, returns the logged-in user
//
// Returns nil and a descriptive error if authentication fails
func authenticate(r *http.Request) (*UserID, error) {
	token, err := r.Cookie("token")
	if err != nil {
		return nil, errors.New("Not logged in")
	}
	passHash, err := r.Cookie("passHash")
	if err != nil {
		return nil, errors.New("Not logged in")
	}
	passHashOld, err := r.Cookie("passHashOld")
	var passHashOldVal string
	if err != nil {
		passHashOldVal = ""
	} else {
		passHashOldVal = passHashOld.Value
	}
	return authenticateUserPass(token.Value, passHash.Value, passHashOldVal)
}

// Checks given username nad passphrase hash, returns the logged-in user
//
// Returns nil and a descriptive error if authentication fails
func authenticateUserPass(token string, passHash string, passHashOld string) (*UserID, error) {
	// look up the user
	userId := LoadUserID(token)
	if userId == nil {
		return nil, errors.New("User " + token + " not found")
	}

	// verify password
	if passHash == userId.PasswordHash && passHash != "" {
		return userId, nil
	}
	if passHashOld == userId.PasswordHashOld && passHashOld != "" {
		return userId, nil
	}
	return nil, errors.New("Incorrect passphrase")
}
