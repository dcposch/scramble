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

// GET /user/<public key hash> for public key lookup
// POST /user to create an account
func userHandler(w http.ResponseWriter, r *http.Request) {
    if(r.Method == "GET") {
        getPublicKeyHandler(w, r)
    } else {
        createHandler(w, r)
    }
}

// GET /user/<public key hash> for public key lookup
func getPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
    userPubHash := validateHash(r.URL.Path[len("/user/"):])
    userPub := LoadPubKey(userPubHash)
    if userPub == "" {
        http.Error(w, "Not found", 404)
    } else {
        w.Write([]byte(userPub))
    }
}

func createHandler(w http.ResponseWriter, r *http.Request) {
    user := new(User)
    user.Token = validateToken(r.FormValue("token"))
    user.PasswordHash = validateHash(r.FormValue("passHash"))
    user.PublicKey = validatePublicKey(r.FormValue("publicKey"))
    user.PublicHash = sha1hex(user.PublicKey)
    user.CipherPrivateKey = validateHex(r.FormValue("cipherPrivateKey"))

    log.Printf("Woot! New user %s %s\n", user.Token, user.PublicHash)

    SaveUser(user)

    // redirect to inbox
    http.SetCookie(w, makeCookie("token", user.Token))
    http.SetCookie(w, makeCookie("passHash", user.PasswordHash))
    http.Redirect(w, r, "/", http.StatusFound)
}

func makeCookie(name string, value string) *http.Cookie {
    cookie := new(http.Cookie)
    cookie.Name=name
    cookie.Value=value
    return cookie
}

// GET /user/me for our encrypted private key 
func privateHandler(w http.ResponseWriter, r *http.Request) {
    userId := authenticate(r)

    user := LoadUser(userId.Token)
    if user == nil {
        http.Error(w, "Not found", 404)
        return
    }
    w.Write([]byte(user.CipherPrivateKey))
}



//
// LOGIN AND AUTH
//

func loginHandler(w http.ResponseWriter, r *http.Request) {
    token := r.FormValue("token")
    passHash := r.FormValue("passHash")

    userId := authenticateUserPass(token, passHash)
    if userId != nil {
        // redirect to inbox
        http.SetCookie(w, makeCookie("token", token))
        http.SetCookie(w, makeCookie("passHash", passHash))
        http.Redirect(w, r, "/", http.StatusFound)
    } else {
        http.Error(w, "Incorrect user or passphrase", 401)
    }
}

func authenticateUserPass(token string, passHash string) *UserID {
    userId := LoadUserID(token)
    if userId == nil {
        return nil
    }
    if passHash != userId.PasswordHash || passHash == "" {
        return nil
    }
    return userId
}

// Checks cookies, returns the logged-in user token or empty string
func authenticate(r *http.Request) *UserID {
    token, err := r.Cookie("token")
    if err != nil {
        return nil
    }
    passHash, err := r.Cookie("passHash")
    if err != nil {
        return nil
    }
    return authenticateUserPass(token.Value, passHash.Value)
}



//
// INBOX ROUTE
//

func inboxHandler(w http.ResponseWriter, r *http.Request) {
    userId := authenticate(r)

    templates.ExecuteTemplate(w, "header.html", nil)
    if userId != nil {
        emailHeaders := LoadInbox(userId.PublicHash)
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
    w.Write([]byte(message.CipherBody))
}



//
// COMPOSE ROUTE
//

func composeHandler(w http.ResponseWriter, r *http.Request) {
    userId := authenticate(r)
    if userId==nil {
        http.Error(w, "Not logged in", 401)
        return
    }

    templates.ExecuteTemplate(w, "header.html", nil)
    templates.ExecuteTemplate(w, "compose.html", nil)
    templates.ExecuteTemplate(w, "footer.html", nil)
}

func emailSendHandler(w http.ResponseWriter, r *http.Request) {
    userId := authenticate(r)
    if userId==nil {
        http.Error(w, "Not logged in", 401)
        return
    }

    email := new(Email)
    email.From = userId.PublicHash + "@" + r.URL.Host
    email.To = r.FormValue("to")
    email.CipherSubject = validateHex(r.FormValue("cipherSubject"))
    email.CipherBody = validateHex(r.FormValue("cipherBody"))

    SaveMessage(email)
}

