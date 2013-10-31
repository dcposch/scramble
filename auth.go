package main

import (
	"errors"
	"net/http"
)

// Checks cookies, returns the logged-in user
//
// Returns nil and a descriptive error if authentication fails
func authenticate(r *http.Request) (*UserID, error) {
	token := r.Header.Get("x-scramble-token")
	if token == "" {
		return nil, errors.New("Not logged in")
	}
	passHash := r.Header.Get("x-scramble-passHash")
	passHashOld := r.Header.Get("x-scramble-passHashOld")
	return authenticateUserPass(token, passHash, passHashOld)
}

// Checks given username nad passphrase hash, returns the logged-in user
//
// Returns nil and a descriptive error if authentication fails
func authenticateUserPass(token string, passHash string, passHashOld string) (*UserID, error) {
	// look up the user
	userID := LoadUserID(token)
	if userID == nil {
		return nil, errors.New("User " + token + " not found")
	}

	// verify password
	if passHash == userID.PasswordHash && passHash != "" {
		return userID, nil
	}
	if passHashOld == userID.PasswordHashOld && passHashOld != "" {
		return userID, nil
	}
	return nil, errors.New("Incorrect passphrase")
}
