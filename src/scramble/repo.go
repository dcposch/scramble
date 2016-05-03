package scramble

import "database/sql"
import _ "github.com/go-sql-driver/mysql"

import (
	"fmt"
	"log"
	"strings"
	"time"
	//"github.com/jaekwon/go-prelude/colors"
)

var db *sql.DB

func init() {
	conf := GetConfig()
	mysqlHost := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s?charset=utf8",
		conf.DbUser,
		conf.DbPassword,
		conf.DbServer,
		conf.DbCatalog)

	// connect to the database, ping periodically to maintain the connection
	log.Printf("Connecting to %s\n", mysqlHost)
	var err error
	db, err = sql.Open("mysql", mysqlHost)
	if err != nil {
		panic(err)
	}
	go ping()

	// migrate the database
	migrateDb()
}

func ping() {
	defer Recover()
	ticker := time.Tick(time.Minute)
	for {
		<-ticker
		err := db.Ping()
		if err != nil {
			log.Printf("DB not ok: %v\n", err)
		} else {
			log.Printf("DB ok\n")
		}
	}
}

//
// USERS
//

func SaveUser(user *User) bool {
	res, err := db.Exec("insert ignore into user"+
		" (token, password_hash, public_hash, public_key, "+
		"  cipher_private_key, email_host, secondary_email) "+
		" values (?, ?, ?, ?, ?, ?, ?)",
		user.Token, user.PasswordHash, user.PublicHash, user.PublicKey,
		user.CipherPrivateKey, user.EmailHost, user.SecondaryEmail)
	if err != nil {
		panic(err)
	}
	nrows, err := res.RowsAffected()
	if err != nil {
		panic(err)
	}
	return nrows == 1
}

func DeleteUser(token string) {
	res, err := db.Exec("delete from user where token=?", token)
	if err == nil {
		return
	}
	count, err := res.RowsAffected()
	if err != nil || count != 1 {
		log.Panicf("Could not delete user %s: %v", token, err)
	}
}

func LoadUser(token string) *User {
	var user User
	user.Token = token
	err := db.QueryRow("select"+
		" password_hash, password_hash_old, public_hash, "+
		" public_key, cipher_private_key, email_host, secondary_email "+
		" from user where token=?", token).Scan(
		&user.PasswordHash,
		&user.PasswordHashOld,
		&user.PublicHash,
		&user.PublicKey,
		&user.CipherPrivateKey,
		&user.EmailHost,
		&user.SecondaryEmail,
	)
	user.EmailAddress = user.Token + "@" + user.EmailHost
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		panic(err)
	}
	return &user
}

func LoadUserID(token string) *UserID {
	var user UserID
	user.Token = token
	err := db.QueryRow("select " +
		" password_hash, password_hash_old, public_hash, email_host, is_banned" +
		" from user where token=?", token).Scan(
		&user.PasswordHash,
		&user.PasswordHashOld,
		&user.PublicHash,
		&user.EmailHost,
		&user.IsBanned)
	user.EmailAddress = user.Token + "@" + user.EmailHost
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		panic(err)
	}
	return &user
}

// Loads a given public hash by a user's token (name) & email_host
func LoadPubHash(token, emailHost string) string {
	var hash string
	err := db.QueryRow("SELECT public_hash "+
		" FROM user WHERE token=? and email_host=?",
		token, emailHost).Scan(&hash)
	if err == sql.ErrNoRows {
		return ""
	}
	if err != nil {
		panic(err)
	}
	return hash
}

// Loads a given public key by it's hash
// The client then verifies that the key is correct
func LoadPubKey(publicHash string) string {
	var publicKey string
	err := db.QueryRow("SELECT public_key "+
		"FROM user WHERE public_hash=?",
		publicHash).Scan(&publicKey)
	if err == sql.ErrNoRows {
		return ""
	}
	if err != nil {
		panic(err)
	}
	return publicKey
}

// Loads an address from a user's pubHash.
// This exists to upgrade legacy contacts.
func LoadAddressFromPubHash(publicHash string) string {
	var token, emailHost string
	err := db.QueryRow("SELECT token, email_host "+
		"FROM user WHERE public_hash=?",
		publicHash).Scan(&token, &emailHost)
	if err == sql.ErrNoRows {
		return ""
	}
	if err != nil {
		panic(err)
	}
	return token + "@" + emailHost
}

// Loads a user's contacts, or nil if the user doesn't exist
// Returns an encrypted blob for which only they have the key
func LoadContacts(token string) *string {
	var cipherContacts *string
	err := db.QueryRow("SELECT cipher_contacts "+
		"FROM user WHERE token=?", token).Scan(
		&cipherContacts)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		panic(err)
	}
	return cipherContacts
}

func SaveContacts(token string, cipherContacts string) {
	_, err := db.Exec("UPDATE user "+
		"SET cipher_contacts=? WHERE token=?",
		cipherContacts, token)
	if err != nil {
		panic(err)
	}
}

//
// EMAIL HEADERS
//

// Loads all email headers in a certain box
// For example, inbox or sent box
// That are encrypted for a given user
func LoadBox(address string, box string, offset, limit int) []EmailHeader {
	rows, err := db.Query("SELECT m.message_id, m.unix_time, "+
		" m.from_email, m.to_email, b.is_read, m.cipher_subject, m.thread_id "+
		" FROM email AS m INNER JOIN box AS b "+
		" ON b.message_id = m.message_id "+
		" WHERE b.address = ? and b.box=? "+
		" ORDER BY b.unix_time DESC"+
		" LIMIT ?, ? ",
		address, box,
		offset, limit)
	if err != nil {
		panic(err)
	}
	return rowsToHeaders(rows)
}

// Like LoadBox(), but only returns the latest mail in the box for each thread.
func LoadBoxByThread(address string, box string, offset, limit int) []EmailHeader {
	rows, err := db.Query("SELECT e.message_id, e.unix_time, "+
		"e.from_email, e.to_email, m.is_read, e.cipher_subject, e.thread_id "+
		"FROM email AS e INNER JOIN ( "+
		"    SELECT MAX(message_id) as message_id, MIN(is_read) as is_read FROM box "+
		"       WHERE address=? AND box=? "+
		"       GROUP BY thread_id "+
		"       ORDER BY unix_time DESC "+
		"       LIMIT ?, ? "+
		") AS m ON e.message_id = m.message_id "+
		"ORDER BY e.unix_time DESC ",
		address, box,
		offset, limit,
	)
	if err != nil {
		panic(err)
	}
	return rowsToHeaders(rows)
}

func CountBox(address string, box string) (count int, err error) {
	err = db.QueryRow("SELECT count(distinct thread_id) FROM box "+
		" WHERE address = ? and box = ?",
		address, box).Scan(&count)
	return
}

func rowsToHeaders(rows *sql.Rows) []EmailHeader {
	// collect a short description of each email
	headers := make([]EmailHeader, 0)
	for rows.Next() {
		var header EmailHeader
		err := rows.Scan(
			&header.MessageID,
			&header.UnixTime,
			&header.From,
			&header.To,
			&header.IsRead,
			&header.CipherSubject,
			&header.ThreadID,
		)
		if err != nil {
			panic(err)
		}
		headers = append(headers, header)
	}

	return headers
}

//
// EMAIL
//

// Saves a single email, encrypted for (potentially) multiple recipients.
// A single mail server only needs one email for all recipients & sender.
// Associating emails to boxes are done in a join table.
// Outgoing emails for external servers also require an entry in the 'email' table.
func SaveMessage(e *Email) error {
	_, err := db.Exec("insert into email "+
		"(message_id, unix_time, from_email, to_email, "+
		" cipher_subject, cipher_body, "+
		" ancestor_ids, thread_id) "+
		"values (?,?,?,?,?,?,?,?)",
		e.MessageID,
		e.UnixTime,
		e.From,
		e.To,
		e.CipherSubject,
		e.CipherBody,
		e.AncestorIDs,
		e.ThreadID,
	)
	return err
}

// Retrieves a single message, by id
func LoadMessage(id string) Email {
	var email Email
	err := db.QueryRow("SELECT "+
		"unix_time, from_email, to_email, "+
		"cipher_subject, cipher_body, "+
		"ancestor_ids, thread_id "+
		"FROM email WHERE message_id=?",
		id).Scan(
		&email.UnixTime,
		&email.From,
		&email.To,
		&email.CipherSubject,
		&email.CipherBody,
		&email.AncestorIDs,
		&email.ThreadID,
	)
	email.MessageID = id
	if err != nil {
		panic(err)
	}
	return email
}

// Load emails for a given thread
func LoadThread(address, threadID string) []Email {

	rows, err := db.Query("SELECT "+
		"e.message_id, e.unix_time, e.from_email, e.to_email, "+
		"e.cipher_subject, e.cipher_body, "+
		"e.ancestor_ids, e.thread_id "+
		"FROM email AS e INNER JOIN box "+
		"ON e.message_id = box.message_id "+
		"WHERE box.address=? AND box.thread_id=? "+
		"GROUP BY e.message_id "+
		"ORDER BY e.unix_time ASC",
		address,
		threadID,
	)
	if err != nil {
		panic(err)
	}
	return rowsToEmails(rows)
}

func rowsToEmails(rows *sql.Rows) []Email {
	emails := []Email{}
	for rows.Next() {
		var email Email
		err := rows.Scan(
			&email.MessageID,
			&email.UnixTime,
			&email.From,
			&email.To,
			&email.CipherSubject,
			&email.CipherBody,
			&email.AncestorIDs,
			&email.ThreadID,
		)
		if err != nil {
			panic(err)
		}
		emails = append(emails, email)
	}
	return emails
}

// Load thread_ids given message_ids.
// This is used to compute the thread_id of an incoming email.
// Returns threadIDs in the same order as messageIDs.
// e.g. [<id1>, <id1>, "", "", <id2>, ...]
// messageIDs: an []interface{} of strings
func LoadThreadIDsForMessageIDs(messageIDs []interface{}) []string {
	messageIDsPH := "?" + strings.Repeat(",?", len(messageIDs)-1)
	rows, err := db.Query("SELECT message_id, thread_id "+
		"FROM email WHERE message_id IN ("+messageIDsPH+")",
		messageIDs...,
	)
	if err != nil {
		panic(err)
	}
	lookup := map[string]string{}
	for rows.Next() {
		var messageID, threadID string
		err := rows.Scan(&messageID, &threadID)
		if err != nil {
			panic(err)
		}
		lookup[messageID] = threadID
	}
	threadIDs := []string{}
	for _, messageID := range messageIDs {
		threadIDs = append(threadIDs, lookup[messageID.(string)])
	}
	return threadIDs
}

// Associates a message to a box (e.g. inbox, archive)
// Also used to queue outbox messages, in which case
//  the address is just the host portion.
func AddMessageToBox(e *Email, address string, box string) {
	_, err := db.Exec("INSERT INTO box "+
		"(message_id, unix_time, thread_id, address, box) "+
		"VALUES (?,?,?,?,?)",
		e.MessageID,
		e.UnixTime,
		e.ThreadID,
		address,
		box,
	)
	if err != nil {
		panic(err)
	}
}

// Deletes a message from any of a user's box.
// If the email is no longer referenced, it gets deleted
//  from the email table as well.
func DeleteFromBoxes(address string, id string) {
	res, err := db.Exec("DELETE FROM box "+
		"WHERE address=? AND message_id=?",
		address, id)
	count, err := res.RowsAffected()
	if err != nil || count == 0 {
		log.Panicf("Could not delete message %s for %s: %v",
			id, address, err)
	}
	// protected by foreign key constraints
	db.Exec("DELETE FROM email WHERE message_id=?", id)
}

// See which boxes message belongs in for user.
// e.g. ["inbox", "sent"]
func BoxesForMessage(address string, id string) []string {
	rows, err := db.Query("select box from box "+
		"where address=? and message_id=?",
		address, id)
	if err != nil {
		panic(err)
	}
	boxes := []string{}
	for rows.Next() {
		var box string
		err := rows.Scan(&box)
		if err != nil {
			panic(err)
		}
		boxes = append(boxes, box)
	}
	return boxes
}

// Move the email to another box.
// This function only works within the 'inbox'/'archive'/'trash' boxes
func MoveEmail(address string, messageID string, newBox string) {
	if newBox != "inbox" && newBox != "archive" && newBox != "trash" {
		panic("MoveEmail() cannot move emails to " + newBox)
	}
	res, err := db.Exec("update box "+
		"set box=? "+
		"where address=? and message_id=? and box in ('inbox', 'archive', 'trash')",
		newBox, address, messageID)
	if err != nil {
		panic(err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		panic(err)
	}
	if rows != 1 {
		log.Panicf("Expected to move one message (%v/%v), found %v", address, messageID, rows)
	}
}

//
// EMAIL (THREADS)
//

// Move emails in a thread to another box.
// This function only works within the 'inbox'/'archive'/'trash' boxes
func MoveThread(address string, messageID string, newBox string) {
	if newBox != "inbox" && newBox != "archive" && newBox != "trash" {
		panic("MoveEmail() cannot move emails to " + newBox)
	}
	res, err := db.Exec(
		"UPDATE box AS b "+
			"INNER JOIN ( "+
			"SELECT thread_id, unix_time FROM email "+
			"WHERE message_id = ? "+
			") AS e ON "+
			"b.thread_id = e.thread_id "+
			"SET box = ? "+
			"WHERE "+
			"b.address = ? AND "+
			"b.unix_time <= e.unix_time AND "+
			"b.box IN ('inbox', 'archive', 'trash') ",
		messageID, newBox, address)
	if err != nil {
		panic(err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		panic(err)
	}
	if rows == 0 {
		log.Panicf("Expected to move at least one message (%v/%v), found none", address, messageID)
	}
}

// Marks a given set of emails as read (or unread)
func ThreadMarkAsRead(address string, messageID string, isRead bool) {
	_, err := db.Exec(
		"UPDATE box AS b "+
			"INNER JOIN ( "+
			"SELECT thread_id, unix_time FROM email "+
			"WHERE message_id = ? "+
			") AS e ON "+
			"b.thread_id = e.thread_id "+
			"SET is_read = ? "+
			"WHERE "+
			"b.address = ? AND "+
			"b.unix_time <= e.unix_time",
		messageID, isRead, address)
	if err != nil {
		panic(err)
	}
}

// Finds users with new unread mail
// Returns a list of all the secondary emails
func GetUsersWithUnreadMail(minAgeMins int, maxAgeMins int) []string {
	currentUnixTime := time.Now().UTC().Unix()
	minUnixTime := currentUnixTime - int64(maxAgeMins)*60
	maxUnixTime := currentUnixTime - int64(minAgeMins)*60
	rows, err := db.Query(
		"SELECT DISTINCT secondary_email FROM user u "+
			"INNER JOIN box b ON b.address=CONCAT(u.token,'@',u.email_host) "+
			"WHERE b.box='inbox' AND b.is_read=0 AND b.unix_time>? AND b.unix_time<?",
		minUnixTime, maxUnixTime)
	if err != nil {
		panic(err)
	}
	emails := make([]string, 0)
	for rows.Next() {
		var email string
		rows.Scan(&email)
		emails = append(emails, email)
	}
	return emails
}

// Deletes messages of a thread from any of a user's box.
// If the email is no longer referenced, it gets deleted
//  from the email table as well.
func DeleteThreadFromBoxes(address string, messageID string) {
	res, err := db.Exec(
		"DELETE b FROM box AS b "+
			"INNER JOIN ( "+
			"SELECT thread_id, unix_time FROM email "+
			"WHERE message_id = ? "+
			") AS e ON "+
			"b.thread_id = e.thread_id "+
			"WHERE "+
			"b.unix_time <= e.unix_time AND "+
			"b.address = ? ",
		messageID, address)
	if err != nil {
		panic(err)
	}
	count, err := res.RowsAffected()
	if err != nil || count == 0 {
		log.Panicf("Could not delete thread messages for message %s for %s: %v",
			messageID, address, err)
	}
	// protected by foreign key constraints
	db.Exec("DELETE FROM email WHERE message_id=?", messageID)
}

//
// NOTARY
//

func AddNameResolution(name, host, hash string) {
	_, err := db.Exec("INSERT INTO name_resolution "+
		"(name, host, hash, unix_time) "+
		"VALUES (?,?,?,?)",
		name,
		host,
		hash,
		time.Now().Unix(),
	)
	if err != nil {
		panic(err)
	}
}

func DeleteNameResolution(name, host string) {
	_, err := db.Exec("DELETE FROM name_resolution "+
		"WHERE name=? and host=?",
		name,
		host,
	)
	if err != nil {
		panic(err)
	}
}

func GetNameResolution(name, host string) (hash string) {
	err := db.QueryRow("SELECT "+
		"hash FROM name_resolution WHERE "+
		"name=? AND host=?",
		name, host).Scan(
		&hash)
	if err == sql.ErrNoRows {
		return ""
	}
	if err != nil {
		panic(err)
	}
	return
}

func TrySetMxHostInfo(host string, isScramble bool, notaryPublicKey string) *MxHostInfo {
	hostInfo := GetMxHostInfo(host)
	if hostInfo == nil {
		return SetMxHostInfo(host, isScramble, notaryPublicKey)
	}
	return hostInfo
}

func SetMxHostInfo(host string, isScramble bool, notaryPublicKey string) *MxHostInfo {
	now := time.Now().Unix()
	_, err := db.Exec("INSERT INTO mx_hosts "+
		"(host, is_scramble, notary_public_key, unix_time) "+
		"VALUES (?,?,?,?) "+
		"ON DUPLICATE KEY UPDATE "+
		"is_scramble = VALUES(is_scramble), "+
		"notary_public_key = VALUES(notary_public_key), "+
		"unix_time = VALUES(unix_time)",
		host,
		isScramble,
		sql.NullString{notaryPublicKey, notaryPublicKey != ""},
		now,
	)
	if err != nil {
		panic(err)
	}
	return &MxHostInfo{host, isScramble, notaryPublicKey, now}
}

func GetMxHostInfo(host string) *MxHostInfo {
	var info MxHostInfo
	var pubKeyNull sql.NullString
	err := db.QueryRow("SELECT "+
		"host, is_scramble, notary_public_key, unix_time "+
		"FROM mx_hosts WHERE host=?",
		host).Scan(
		&info.Host,
		&info.IsScramble,
		&pubKeyNull,
		&info.UnixTime,
	)
	switch {
	case err == sql.ErrNoRows:
		return nil
	case err != nil:
		panic(err)
	default:
		info.NotaryPublicKey = pubKeyNull.String
		return &info
	}
}
