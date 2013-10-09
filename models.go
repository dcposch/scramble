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
	EmailAddress    string
	EmailHost       string
}

// Represents an email header with encrypted subject. No body.
type EmailHeader struct {
	MessageID     string
	UnixTime      int64
	From          string
	To            string
	CipherSubject string
}

// Represents a full email, header and body PGP encrypted.
type Email struct {
	EmailHeader
	CipherBody string
}

type BoxSummary struct {
	EmailAddress string
	PublicHash   string
	Box          string
	Offset       int
	Limit        int
	Total        int
	EmailHeaders []EmailHeader
}

// Represents an email in the box join table.
type BoxedEmail struct {
	Email
	Id           int64
	Box          string
	Address      string
}
