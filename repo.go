package main

import "database/sql"
import _ "github.com/go-sql-driver/mysql"

import (
	"fmt"
	"log"
	"strconv"
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
		" (token, password_hash, public_hash, public_key, cipher_private_key, email_host)"+
		" values (?, ?, ?, ?, ?, ?)",
		user.Token, user.PasswordHash,
		user.PublicHash, user.PublicKey,
		user.CipherPrivateKey, user.EmailHost)
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
		" password_hash, password_hash_old, public_hash, public_key, cipher_private_key, email_host"+
		" from user where token=?", token).Scan(
		&user.PasswordHash,
		&user.PasswordHashOld,
		&user.PublicHash,
		&user.PublicKey,
		&user.CipherPrivateKey,
		&user.EmailHost)
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
	err := db.QueryRow("select"+
		" password_hash, password_hash_old, public_hash, email_host"+
		" from user where token=?", token).Scan(
		&user.PasswordHash,
		&user.PasswordHashOld,
		&user.PublicHash,
		&user.EmailHost)
	user.EmailAddress = user.Token + "@" + user.EmailHost
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		panic(err)
	}
	return &user
}

// Loads a given public hash by a user's token (name)
func LoadPubHash(token string) string {
	var hash string
	err := db.QueryRow("SELECT public_hash "+
		" FROM user WHERE token=?",
		token).Scan(&hash)
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
	err := db.QueryRow("select public_key"+
		" from user where public_hash=?",
		publicHash).Scan(&publicKey)
	if err == sql.ErrNoRows {
		return ""
	}
	if err != nil {
		panic(err)
	}
	return publicKey
}

// Loads a user's contacts, or nil if the user doesn't exist
// Returns an encrypted blob for which only they have the key
func LoadContacts(token string) *string {
	var cipherContacts *string
	err := db.QueryRow("select cipher_contacts"+
		" from user where token=?", token).Scan(
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
	_, err := db.Exec("update user "+
		" set cipher_contacts=? where token=?",
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
	log.Printf("Fetching %s for %s\n", box, address)

	rows, err := db.Query("SELECT m.message_id, m.unix_time, "+
		" m.from_email, m.to_email, m.cipher_subject "+
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

func CountBox(address string, box string) (count int, err error) {
	err = db.QueryRow("SELECT count(*) FROM box "+
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
			&header.CipherSubject)
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
func SaveMessage(e *Email) {
	_, err := db.Exec("insert into email "+
		"(message_id, unix_time, from_email, to_email, "+
		" cipher_subject, cipher_body) "+
		"values (?,?,?,?,?,?)",
		e.MessageID,
		e.UnixTime,
		e.From,
		e.To,
		e.CipherSubject,
		e.CipherBody)
	if err != nil {
		panic(err)
	}
}

// Retrieves a single message, by id
func LoadMessage(id string) Email {
	var email Email
	err := db.QueryRow("select "+
		"unix_time, from_email, to_email, "+
		"cipher_subject, cipher_body "+
		"from email where message_id=?",
		id).Scan(
		&email.UnixTime,
		&email.From,
		&email.To,
		&email.CipherSubject,
		&email.CipherBody)
	email.MessageID = id
	if err != nil {
		panic(err)
	}
	return email
}

// Associates a message to a box (e.g. inbox, archive)
// Also used to queue outbox messages, in which case
//  the address is just the host portion.
func AddMessageToBox(e *Email, address string, box string) {
	_, err := db.Exec("insert into box "+
		"(message_id, unix_time, address, box) "+
		"values (?,?,?,?)",
		e.MessageID,
		e.UnixTime,
		address,
		box)
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
// OUTBOX
//

// Load and set box as 'outbox-processing'
func CheckoutOutbox(limit int) []BoxedEmail {
	rows, err := db.Query("SELECT m.message_id, m.unix_time, "+
		" m.from_email, m.to_email, m.cipher_subject, m.cipher_body, "+
		" b.id, b.box, b.address "+
		" FROM email AS m INNER JOIN box AS b "+
		" ON b.message_id = m.message_id "+
		" WHERE b.box='outbox' "+
		" ORDER BY b.unix_time ASC "+
		" LIMIT ?",
		limit)
	if err != nil {
		panic(err)
	}
	boxedEmails := []BoxedEmail{}
	for rows.Next() {
		var boxed BoxedEmail
		rows.Scan(
			&boxed.MessageID,
			&boxed.UnixTime,
			&boxed.From,
			&boxed.To,
			&boxed.CipherSubject,
			&boxed.CipherBody,
			&boxed.Id,
			&boxed.Box,
			&boxed.Address,
		)
		boxedEmails = append(boxedEmails, boxed)
	}
	MarkOutboxAs(boxedEmails, "outbox-processing")
	return boxedEmails
}

// Mark box items as "outbox-sent" or "outbox-processing"
func MarkOutboxAs(boxedEmails []BoxedEmail, newBox string) {
	if newBox != "outbox-sent" && newBox != "outbox-processing" {
		panic("MarkOutboxAs() cannot move emails to " + newBox)
	}
	boxedIds := []string{} // Do we really need to convert to strings? :(
	for _, boxedEmail := range boxedEmails {
		boxedIds = append(boxedIds, strconv.FormatInt(boxedEmail.Id, 10))
	}
	_, err := db.Exec("UPDATE box SET box=?, unix_time=? WHERE "+
		"id IN (?) AND box IN ('outbox', 'outbox-processing', 'outbox-sent') ",
		newBox,
		time.Now().Unix(),
		strings.Join(boxedIds, ","),
	)
	if err != nil {
		panic(err)
	}
}

//
// NOTARY
//

func AddNameResolution(name, host, hash string) {
	_, err := db.Exec("INSERT INTO name_resolution "+
		"(name, host, hash) "+
		"VALUES (?,?,?)",
		name,
		host,
		hash)
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
