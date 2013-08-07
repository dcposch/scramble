package main

// A single user, email address, and key pair
// The email address is <public key hash>@<host>
type User struct {
    UserID
    PublicKey string
    CipherPrivateKey string
}

// A single user's identifying info
// All hashes are hex encoded
type UserID struct {
    Token string
    PasswordHash string
    PublicHash string
}

// Represents an email header with encrypted subject. No body.
type EmailHeader struct {
    ID int
    From string
    To string
    Date string
    CipherSubject string
}

// Represents a full email, header and body PGP encrypted.
type Email struct {
    EmailHeader
    CipherBody string
}

type InboxSummary struct {
    Token string
    PublicHash string
    EmailHeaders []EmailHeader
}

