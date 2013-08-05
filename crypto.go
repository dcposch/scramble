package main

import (
    "fmt"
    "io"
    "crypto/sha1"
)

func sha1hex(str string) string {
    hash := sha1.New()
    io.WriteString(hash, str)
    arr := hash.Sum(nil)
    return fmt.Sprintf("%x", arr)
}
