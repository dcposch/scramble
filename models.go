package main

type User struct {
    // The email address is <hash>@gpgmail.io
    User string
    PasswordHash string
    PublicKey string
    CipherPrivateKey string
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
