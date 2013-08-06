package main

import "database/sql"
import _ "github.com/go-sql-driver/mysql"

import "os"
import "io/ioutil"
import "strings"
import "log"

var db *sql.DB

var migrations = [...]string{
    `create table if not exists user (
        user varchar(100) not null,
        password_hash char(40) not null,
        public_hash char(40) not null,
        public_key varchar(4000) not null,
        cipher_private_key varchar(4000) not null,

        primary key (user),
        unique index (public_hash)
    )`,
    `create table if not exists email (
        id bigint not null auto_increment,
        from_email varchar(254) not null,
        to_email varchar(254) not null,
        subject varchar(1500) not null,
        body longtext not null,

        primary key (id),
        index (from_email, to_email),
        index (to_email)
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

    for _,sql := range migrations {
        _,err = db.Exec(sql)
        if err!=nil {
            panic(err)
        }
    }
}

func SaveUser (user *User) {
    _,err := db.Exec("insert into user" +
        " (user, password_hash, public_hash, public_key, cipher_private_key)" +
        " values (?, ?, ?, ?, ?)",
        user.User, user.PasswordHash,
        user.PublicHash, user.PublicKey,
        user.CipherPrivateKey)
    if err != nil {
        panic(err)
    }
}

func LoadUser (userName string) *User {
    var user User
    err := db.QueryRow("select" +
        " password_hash, public_hash, public_key, cipher_private_key" +
        " from user where user=?", userName).Scan(
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

func LoadPassHash (user string) string {
    var passHash string
    err := db.QueryRow("select password_hash" +
        " from user where user=?", user).Scan(&passHash)
    if err == sql.ErrNoRows {
        return ""
    }
    if err != nil {
        panic(err)
    }
    return passHash
}

func LoadPubKey (pubHash string) string {
    var pubKey string
    err := db.QueryRow("select public_key" +
        " from user where public_hash=?",
        pubHash).Scan(&pubKey)
    if err == sql.ErrNoRows {
        return ""
    }
    if err != nil {
        panic(err)
    }
    return pubKey
}

func LoadMessage (id int) Email {
    var email Email
    err := db.QueryRow("select id, from_email, to_email, subject, body" +
        " from email where id=?",id).Scan(
        &email.ID,
        &email.From,
        &email.To,
        &email.Subject,
        &email.Body)
    if err != nil {
        panic(err)
    }
    return email
}

func LoadInbox(userHash string) []EmailHeader {
    log.Printf("Fetching inbox %s\n", userHash)

    // query
    rows,err := db.Query("select id, from_email, to_email, subject"+
        " from email where to_email like ?", userHash+"@%")
    if err != nil {
        panic(err)
    }

    // collect a short description of each email in the inbox
    headers := make([]EmailHeader, 0)
    for rows.Next() {
        var header EmailHeader
        rows.Scan(&header.ID, &header.From, &header.To, &header.Subject)
        headers = append(headers, header)
    }

    return headers
}

func SaveMessage(e *Email) {
    _,err := db.Exec("insert into email (from_email, to_email, subject, body) "+
        "values (?,?,?,?)", e.From, e.To, e.Subject, e.Body)
    if(err != nil){
        panic(err)
    }
}
