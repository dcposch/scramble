package main

import (
    "strconv"
    "html/template"
    "net/http"
)

var templates = template.Must(template.ParseFiles(
    "header.html",
    "index.html",
    "inbox.html",
    "login.html",
    "email.html",
    "compose.html"))

func indexHandler(w http.ResponseWriter, r *http.Request) {
    user, _ := r.Cookie("hash")
    templates.ExecuteTemplate(w, "header.html", nil)
    if user!=nil {
        emailHeaders := LoadInbox("herp")
        templates.ExecuteTemplate(w, "inbox.html", emailHeaders)
    } else {
        templates.ExecuteTemplate(w, "login.html", nil)
    }
    templates.ExecuteTemplate(w, "footer.html", []string{"inbox.js"})
}

func emailHandler(w http.ResponseWriter, r *http.Request) {
    //user, _ := r.Cookie("hash")

    idStr := r.URL.Path[len("/email/"):]
    id,err := strconv.Atoi(idStr)
    if err!=nil {
        http.Error(w, "Invalid email ID "+idStr, 500)
        return
    }

    message := LoadMessage(id)
    w.Write([]byte(message.Body))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    hash := r.FormValue("hash")
    password := r.FormValue("password")

    //TODO: authenticate
    if password!="lulzmclulz" {
        w.WriteHeader(403)
        w.Write([]byte("Bad handle or password"))
        return
    }

    cookie := new(http.Cookie)
    cookie.Name="hash"
    cookie.Value=hash
    http.SetCookie(w, cookie)

    // redirect
    http.Redirect(w, r, "/", http.StatusFound)
}

func staticHandler(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, r.URL.Path[1:])
}

