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

var migrations = [...]string{

    `create table if not exists user (
        token varchar(100) not null,
        password_hash char(40) not null,
        public_hash char(40) not null,
        public_key varchar(4000) not null,
        cipher_private_key varchar(4000) not null,

        primary key (token),
        unique index (public_hash)
    )`,

    `create table if not exists email (
        message_id char(40) not null,
        unix_time bigint not null,
        box enum ('inbox','outbox','sent','archive','trash') not null,

        from_email varchar(254) not null,
        to_email varchar(254) not null,

        pub_hash char(40),
        cipher_subject varchar(1500) not null,
        cipher_body longtext not null,

        primary key (message_id, pub_hash, box),
        index (pub_hash, box)
    )`}


func init() {
    configFile := os.Getenv("HOME")+"/.scramble/db.config"
    mysqlHostBytes,err := ioutil.ReadFile(configFile)
    if err != nil {
        log.Panicf("Please create config file %s.\n" +
            "One line, <db user>:<db pass>@<db host, empty if local>/scramble",
            configFile)
    }

    mysqlHost := strings.TrimSpace(string(mysqlHostBytes))+"?charset=utf8"
    log.Printf("Connecting to %s\n", mysqlHost)
    db,err = sql.Open("mysql", mysqlHost)
    if err!=nil {
        panic(err)
    }
    go ping()

    for _,sql := range migrations {
        _,err = db.Exec(sql)
        if err!=nil {
            panic(err)
        }
    }
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
        " password_hash, public_hash, public_key, cipher_private_key" +
        " from user where token=?", token).Scan(
        &user.PasswordHash,
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
        " password_hash, public_hash" +
        " from user where token=?", token).Scan(
        &user.PasswordHash,
        &user.PublicHash)
    if err == sql.ErrNoRows {
        return nil
    }
    if err != nil {
        panic(err)
    }
    return &user
}

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

func LoadInbox(publicHash string) []EmailHeader {
    return LoadBox(publicHash, "inbox")
}

func LoadOutbox(publicHash string) []EmailHeader {
    return LoadBox(publicHash, "outbox")
}

func LoadBox(publicHash string, box string) []EmailHeader {
    log.Printf("Fetching inbox %s\n", publicHash)

    // query
    rows,err := db.Query("select message_id, unix_time, from_email, to_email, cipher_subject"+
        " from email where pub_hash=? and box=?", publicHash, box)
    if err != nil {
        panic(err)
    }

    // collect a short description of each email in the inbox
    headers := make([]EmailHeader, 0)
    for rows.Next() {
        var header EmailHeader
        rows.Scan(
            &header.MessageID,
            &header.UnixTime,
            &header.From,
            &header.To,
            &header.CipherSubject)
        header.PubHash = publicHash
        header.Box = box
        headers = append(headers, header)
    }

    return headers
}

func SaveMessage(e *Email) {
    _,err := db.Exec("insert into email " +
        "(message_id, box, unix_time, from_email, to_email, "+
        " pub_hash, cipher_subject, cipher_body) "+
        "values (?,?,?,?,?,?,?,?)",
        e.MessageID,
        e.Box,
        e.UnixTime,
        e.From,
        e.To,
        e.PubHash,
        e.CipherSubject,
        e.CipherBody)
    if(err != nil){
        panic(err)
    }
}

func LoadMessage (id string) Email {
    var email Email
    err := db.QueryRow("select "+
        "message_id, box, unix_time, from_email, to_email, "+
        "pub_hash, cipher_subject, cipher_body " +
        "from email where message_id=?",id).Scan(
        &email.MessageID,
        &email.Box,
        &email.UnixTime,
        &email.From,
        &email.To,
        &email.PubHash,
        &email.CipherSubject,
        &email.CipherBody)
    if err != nil {
        panic(err)
    }
    return email
}

