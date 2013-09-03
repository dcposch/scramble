package main

// A single user, email address, and key pair
// The email address is <public key hash>@<host>
type User struct {
	UserID
	PublicKey        string
	CipherPrivateKey string
}

// A single user's identifying info
// All hashes are hex encoded
type UserID struct {
	Token           string
	PasswordHash    string
	PasswordHashOld string
	PublicHash      string
}

// Represents an email header with encrypted subject. No body.
type EmailHeader struct {
	MessageID string
	Box       string
	UnixTime  int64
	From      string
	To        string

	PubHashFrom   string
	PubHashTo     string
	CipherSubject string
}

// Represents a full email, header and body PGP encrypted.
type Email struct {
	EmailHeader
	CipherBody string
}

type InboxSummary struct {
	Token        string
	PublicHash   string
	EmailHeaders []EmailHeader
}
