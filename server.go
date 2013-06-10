package main

import (
    //"io/ioutil"
    "html/template"
    "net/http"

    /*"github.com/dcposch/go-smtpd"
    "code.google.com/p/go.crypto/openpgp"
    "encoding/base64"*/
)


// EMAIL
type Email struct {
    From string
    To string
    Subject string
    Body string
}

func loadInbox(user string) ([]Email) {
    return []Email{{"foo@bar.com", user, "test", "body"},
        {"bar@bar.com", user, "test2", "body"},
        {"baz@bar.com", user, "test3", "body trolololo oweif oijfew few oijfew fewoij fewoij ijfewo fewoij fewoij fewijo fewij trolololo oweif oijfew few oijfew fewoij fewoij ijfewo fewoij fewoij fewijo fewijotrolololo oweif oijfew few oijfew fewoij fewoij ijfewo fewoij fewoij fewijo fewijotrolololo oweif oijfew few oijfew fewoij fewoij ijfewo fewoij fewoij fewijo fewijotrolololo oweif oijfew few oijfew fewoij fewoij ijfewo fewoij fewoij fewijo fewijotrolololo oweif oijfew few oijfew fewoij fewoij ijfewo fewoij fewoij fewijo fewijotrolololo oweif oijfew few oijfew fewoij fewoij ijfewo fewoij fewoij fewijo fewijotrolololo oweif oijfew few oijfew fewoij fewoij ijfewo fewoij fewoij fewijo fewijotrolololo oweif oijfew few oijfew fewoij fewoij ijfewo fewoij fewoij fewijo fewijoo"},
        {"baz@bar.com", user, "test4", "body"},
        {"baz@bar.com", user, "test5", "body"}}
}


// WEB UI
var templates = template.Must(template.ParseFiles(
    "header.html",
    "index.html",
    "inbox.html",
    "email.html",
    "compose.html"))

func indexHandler(w http.ResponseWriter, r *http.Request) {
    //user, _ := r.Cookie("user")
    templates.ExecuteTemplate(w, "header.html", nil)
    //if user {
        templates.ExecuteTemplate(w, "inbox.html", loadInbox("herp"))
    //} else {
    //    templates.ExecuteTemplate(w, "login.html", nil)
    //}
    //templates.ExecuteTemplate(w, "footer.html", []string{"inbox.js"})
}

func emailHandler(w http.ResponseWriter, r *http.Request) {
    //user, _ := r.Cookie("user")
}

func staticHandler(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, r.URL.Path[1:])
}

func main() {
    http.HandleFunc("/email/[0-9]+", emailHandler)
    http.HandleFunc("/", indexHandler)

    http.HandleFunc("/style.css", staticHandler)

    http.ListenAndServe(":8888", nil)
}
