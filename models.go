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
	ThreadID      string
	UnixTime      int64
	From          string
	To            string
	CipherSubject string
}

// Represents a full email, header and body PGP encrypted.
type Email struct {
	EmailHeader
	CipherBody   string
	AncestorIDs  string
}

// Represents an email on the way out.
// Plaintext should never hit the db (or disk)
type OutgoingEmail struct {
	Email
	IsPlaintext      bool
	PlaintextBody    string
	PlaintextSubject string
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

// Known info about an mx host.
type MxHostInfo struct {
	Host            string
	IsScramble      bool
	NotaryPublicKey string
	UnixTime        int64
}
