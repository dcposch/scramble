package main

import (
    "log"
    "strconv"
    "net/http"
    "html/template"
)



//
// HELPERS
//

var templates = template.Must(template.ParseFiles(
    file("header"),
    file("footer"),
    file("login"),
    file("inbox"),
    file("email"),
    file("compose")))

func file(name string) string {
    return "templates/"+name+".html"
}

func staticHandler(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, "static/"+r.URL.Path)
}



//
// USER ROUTE
//

func userHandler(w http.ResponseWriter, r *http.Request) {
    if(r.Method == "GET") {
        fetchUserHandler(w, r)
    } else {
        createHandler(w, r)
    }
}

func fetchUserHandler(w http.ResponseWriter, r *http.Request) {
    userPubHash := r.URL.Path[len("/user/"):]
    userPub := LoadPubKey(userPubHash)
    if userPub == "" {
        http.Error(w, "Not found", 404)
    } else {
        w.Write([]byte(userPub))
    }
}

func createHandler(w http.ResponseWriter, r *http.Request) {
    user := new(User)
    user.User = r.FormValue("user")
    user.PasswordHash = r.FormValue("passwordHash")
    user.PublicKey = r.FormValue("publicKey")
    user.CipherPrivateKey = r.FormValue("cipherPrivateKey")

    log.Printf("Woot! New user %s %s\n", user.User, sha1hex(user.PublicKey))

    SaveUser(user)

    // redirect to inbox
    http.SetCookie(w, makeCookie("user", user.User))
    http.SetCookie(w, makeCookie("passwordHash", user.PasswordHash))
    http.Redirect(w, r, "/", http.StatusFound)
}

func makeCookie(name string, value string) *http.Cookie {
    cookie := new(http.Cookie)
    cookie.Name=name
    cookie.Value=value
    return cookie
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    user := r.FormValue("user")
    passwordHash := r.FormValue("passwordHash")

    if validateUserPass(user, passwordHash) {
        // redirect to inbox
        http.SetCookie(w, makeCookie("user", user))
        http.SetCookie(w, makeCookie("passwordHash", passwordHash))
        http.Redirect(w, r, "/", http.StatusFound)
    } else {
        http.Error(w, "Incorrect user or passphrase", 401)
    }
}

func validateUserPass(user string, passHash string) bool{
    correctHash := LoadPassHash(user)
    return correctHash != "" && passHash == correctHash
}

// Checks cookies, returns the logged-in user id or empty string
func validate(r *http.Request) string{
    user, err := r.Cookie("user")
    if err != nil {
        return ""
    }
    passHash, err := r.Cookie("passwordHash")
    if err != nil || !validateUserPass(user.Value, passHash.Value) {
        return ""
    }
    return user.Value
}



//
// INBOX ROUTE
//

func inboxHandler(w http.ResponseWriter, r *http.Request) {
    user := validate(r)

    templates.ExecuteTemplate(w, "header.html", nil)
    if user != "" {
        emailHeaders := LoadInbox(user)
        templates.ExecuteTemplate(w, "inbox.html", emailHeaders)
    } else {
        templates.ExecuteTemplate(w, "login.html", nil)
    }
    templates.ExecuteTemplate(w, "footer.html", nil)
}

func emailHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == "GET" {
        emailFetchHandler(w, r)
    } else if r.Method == "POST" {
        emailSendHandler(w, r)
    }
}

func emailFetchHandler(w http.ResponseWriter, r *http.Request) {
    idStr := r.URL.Path[len("/email/"):]
    id,err := strconv.Atoi(idStr)
    if err!=nil {
        http.Error(w, "Invalid email ID "+idStr, 500)
        return
    }

    message := LoadMessage(id)
    w.Write([]byte(message.Body))
}



//
// COMPOSE ROUTE
//

func composeHandler(w http.ResponseWriter, r *http.Request) {
    user := validate(r)
    if user=="" {
        http.Error(w, "Not logged in", 401)
        return
    }

    templates.ExecuteTemplate(w, "header.html", nil)
    templates.ExecuteTemplate(w, "compose.html", nil)
    templates.ExecuteTemplate(w, "footer.html", nil)
}

func emailSendHandler(w http.ResponseWriter, r *http.Request) {
    user := validate(r)
    if user=="" {
        http.Error(w, "Not logged in", 401)
        return
    }

    email := new(Email)
    email.From = user
    email.To = r.FormValue("to")
    email.Subject = r.FormValue("cipherSubject")
    email.Body = r.FormValue("cipherBody")

    SaveMessage(email)
}

