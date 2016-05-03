package scramble

// User represents a single user, email address, and key pair
// The email address is <public key hash>@<host>
type User struct {
	UserID
	PublicKey        string
	CipherPrivateKey string
	SecondaryEmail   string
}

// UserID represents a single user's identifying info
// All hashes are hex encoded
type UserID struct {
	Token           string
	PasswordHash    string
	PasswordHashOld string
	PublicHash      string
	EmailAddress    string
	EmailHost       string
	IsBanned	bool
}

// EmailHeader has standard headers and an PGP-encrypted subject. No body.
type EmailHeader struct {
	MessageID     string
	ThreadID      string
	UnixTime      int64
	From          string
	To            string
	IsRead        bool
	CipherSubject string
}

// Email represents a full email, header and body PGP encrypted.
type Email struct {
	EmailHeader
	CipherBody  string
	AncestorIDs string
}

// Represents an email on the way out.
// Plaintext should never hit the db (or disk)
type OutgoingEmail struct {
	Email
	IsPlaintext      bool
	PlaintextSubject string
	PlaintextBody    string
}

// BoxSummary represents one page from a box (inbox, sent, etc),
// including the email headers and subjects but without andy bodies
type BoxSummary struct {
	EmailAddress string
	PublicHash   string
	Box          string
	Offset       int
	Limit        int
	Total        int
	EmailHeaders []EmailHeader
}

// MxHostInfo represents info from DNS (or from cache)
// info about an mx host.
type MxHostInfo struct {
	Host            string
	IsScramble      bool
	NotaryPublicKey string
	UnixTime        int64
}
