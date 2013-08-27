package main

import "database/sql"
import _ "github.com/go-sql-driver/mysql"

import (
    "time"
    "os"
    "io/ioutil"
    "strings"
    "log"
)

var db *sql.DB

func init() {
    // read configuration
    configFile := os.Getenv("HOME")+"/.scramble/db.config"
    mysqlHostBytes,err := ioutil.ReadFile(configFile)
    if err != nil {
        log.Panicf("Please create config file %s.\n" +
            "One line, <db user>:<db pass>@<db host, empty if local>/scramble",
            configFile)
    }

    // connect to the database, ping periodically to maintain the connection
    mysqlHost := strings.TrimSpace(string(mysqlHostBytes))+"?charset=utf8"
    log.Printf("Connecting to %s\n", mysqlHost)
    db,err = sql.Open("mysql", mysqlHost)
    if err!=nil {
        panic(err)
    }
    go ping()

    // migrate the database
    migrateDb()
}

func ping(){
    ticker := time.Tick(time.Minute)
    for {
        <-ticker
        err := db.Ping()
        if err!=nil {
            log.Printf("DB not ok: %v\n", err)
        } else {
            log.Printf("DB ok\n")
        }
    }
}



//
// USERS
//

func SaveUser (user *User) bool {
    res,err := db.Exec("insert ignore into user" +
        " (token, password_hash, public_hash, public_key, cipher_private_key)" +
        " values (?, ?, ?, ?, ?)",
        user.Token, user.PasswordHash,
        user.PublicHash, user.PublicKey,
        user.CipherPrivateKey)
    if err != nil {
        panic(err)
    }
    nrows,err := res.RowsAffected()
    if err != nil {
        panic(err)
    }
    return nrows==1
}

func LoadUser (token string) *User {
    var user User
    user.Token = token
    err := db.QueryRow("select" +
        " password_hash, password_hash_old, public_hash, public_key, cipher_private_key" +
        " from user where token=?", token).Scan(
        &user.PasswordHash,
        &user.PasswordHashOld,
        &user.PublicHash,
        &user.PublicKey,
        &user.CipherPrivateKey)
    if err == sql.ErrNoRows {
        return nil
    }
    if err != nil {
        panic(err)
    }
    return &user
}

func LoadUserID (token string) *UserID {
    var user UserID
    user.Token = token
    err := db.QueryRow("select" +
        " password_hash, password_hash_old, public_hash" +
        " from user where token=?", token).Scan(
        &user.PasswordHash,
        &user.PasswordHashOld,
        &user.PublicHash)
    if err == sql.ErrNoRows {
        return nil
    }
    if err != nil {
        panic(err)
    }
    return &user
}

// Loads a given public key by it's hash
// The client then verifies that the key is correct
func LoadPubKey (publicHash string) string {
    var publicKey string
    err := db.QueryRow("select public_key" +
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
func LoadContacts (token string) *string {
    var cipherContacts *string
    err := db.QueryRow("select cipher_contacts" +
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
    _,err := db.Exec("update user "+
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
func LoadBox(pubHashTo string, box string) []EmailHeader {
    log.Printf("Fetching %s for %s\n", box, pubHashTo)

    rows,err := db.Query("select message_id, box, unix_time, "+
        " from_email, to_email, pub_hash_from, pub_hash_to, cipher_subject "+
        " from email where pub_hash_to=? and box=? "+
        " order by unix_time desc", pubHashTo, box)
    if err != nil {
        panic(err)
    }
    return rowsToHeaders(rows)
}

func LoadSent(pubHash string) []EmailHeader{
    rows,err := db.Query("select message_id, box, unix_time, "+
        " from_email, to_email, pub_hash_from, pub_hash_to, cipher_subject "+
        " from email where pub_hash_from=? and pub_hash_to=? "+
        " order by unix_time desc", pubHash, pubHash)
    if err != nil {
        panic(err)
    }
    return rowsToHeaders(rows)
}

func rowsToHeaders(rows *sql.Rows) []EmailHeader {
    // collect a short description of each email
    headers := make([]EmailHeader, 0)
    for rows.Next() {
        var header EmailHeader
        err := rows.Scan(
            &header.MessageID,
            &header.Box,
            &header.UnixTime,
            &header.From,
            &header.To,
            &header.PubHashFrom,
            &header.PubHashTo,
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

// Saves a single email, encrypted for a single recipient.
// When sending one email, this function will be called multiple times.
//
// Incoming email is saved to the inbox
// Outgoing mail to an external server is saved to the outbox, waiting for SMTP
// Outgoing mail to the same domain is saved directly to that user's inbox
// All outgoing mail is also saved to the sender's sent box
func SaveMessage(e *Email) {
    _,err := db.Exec("insert into email " +
        "(message_id, box, unix_time, from_email, to_email, "+
        " pub_hash_from, pub_hash_to, cipher_subject, cipher_body) "+
        "values (?,?,?,?,?,?,?,?,?)",
        e.MessageID,
        e.Box,
        e.UnixTime,
        e.From,
        e.To,
        e.PubHashFrom,
        e.PubHashTo,
        e.CipherSubject,
        e.CipherBody)
    if(err != nil){
        panic(err)
    }
}

// Retrieves a single message, by id
// Because a message will be stored multiple times, encrypted separately
// for each recipient, we must also specify the recipient hash
func LoadMessage (id string, pubHashTo string) Email {
    var email Email
    err := db.QueryRow("select "+
        "box, unix_time, from_email, to_email, "+
        "pub_hash_from, cipher_subject, cipher_body " +
        "from email where message_id=? and pub_hash_to=?",
        id, pubHashTo).Scan(
        &email.Box,
        &email.UnixTime,
        &email.From,
        &email.To,
        &email.PubHashFrom,
        &email.CipherSubject,
        &email.CipherBody)
    email.MessageID = id
    email.PubHashTo = pubHashTo
    if err != nil {
        panic(err)
    }
    return email
}

func UpdateEmail (id string, pubHashTo string, newBox string) {
    _,err := db.Exec("update email "+
        "set box=? "+
        "where message_id=? and pub_hash_to=?",
        newBox,id,pubHashTo)
    if err != nil {
        panic(err)
    }
}

