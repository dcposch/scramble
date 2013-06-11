package main

type User struct {
    // The email address is <hash>@gpgmail.io
    Hash string
    PublicKey string
}

type EmailHeader struct {
    ID int
    From string
    To string
    Subject string
}

type Email struct {
    *EmailHeader
    Body string
}
