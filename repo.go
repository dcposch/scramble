package main

import "database/sql"
import _ "github.com/go-sql-driver/mysql"

var db *sql.DB

func init() {
    var err error
    db,err = sql.Open("mysql", "gpgmail:gpgmail@localhost/gpgmail?charset=utf8")
    if err!=nil {
        panic(err)
    }
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
