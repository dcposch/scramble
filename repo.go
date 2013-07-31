package main

import "database/sql"
import _ "github.com/go-sql-driver/mysql"
import "fmt"

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
        subject varchar(998) not null,
        body longtext not null,

        primary key (id),
        index (from_email, to_email),
        index (to_email)
    )`}


func init() {
    mysqlHost := "gpgmail:gpgmail@/gpgmail?charset=utf8"
    fmt.Println("Connecting to "+mysqlHost)
    var err error
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
        sha1hex(user.PublicKey), user.PublicKey,
        user.CipherPrivateKey)
    if err != nil {
        panic(err)
    }
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

func LoadUser (hash string) *User {
    //TODO
    return nil
}

func LoadMessage (id int) Email {
    return Email{
        &EmailHeader{id, "foo@bar.com", "3298jf98j22j8", "testing 123 abc"},
        "lorem ipsum lol lol trololo lololol lol lorem ipsum lol lol trololo lololol lol lorem ipsum lol lol trololo lololol lol lorem ipsum lol lol trololo lololol lol lorem ipsum lol lol trololo lololol lol lorem ipsum lol lol trololo lololol lol lorem ipsum lol lol trololo lololol lol lorem ipsum lol lol trololo lololol lol lorem ipsum lol lol trololo lololol lol lorem ipsum lol lol trololo lololol lol lorem ipsum lol lol trololo lololol lol lorem ipsum lol lol trololo lololol lol <embedded> tags \" escaped \" strings "}
}

func LoadInbox(userHash string) []EmailHeader {
    user := userHash+"@gpgmail.io"
    return []EmailHeader{
        {1, "foo@bar.com", user, "test123 abc"},
        {2, "bar@bar.com", user, "this is an email with a very long subject line yes it is"},
        {3, "baz@bar.com", user, "lulz man (eom)"},
        {4, "baz@bar.com", user, "yolo swag 420"},
        {5, "baz@bar.com", user, "yo"}}
}

func SaveMessage(e Email) {
    //result,err := db.Exec("lolwut?")
    db.Exec("lolwut?")
}
