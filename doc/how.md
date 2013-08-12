<style>
body { 
width:600px;
font-size:16px;
}
.comm {
font-style:italic;
margin:10px 0 10px 20px;
}
.to-server,.to-client {
font-style:normal;
font:bold 14px monospace;
}
.to-server {
background:#deb;
}
.to-server:before {
content: "Client > Server";
margin-right:20px;
}
.to-client {
background:#7cf;
}
.to-client:before {
content: "Server > Client";
margin-right:20px;
}
.comm label {
width:200px;
}
code {
font:bold 14px monospace;
}
</style>

<a href="https://github.com/dcposch/scramble"><img style="position: absolute; top: 0; right: 0; border: 0;" src="https://s3.amazonaws.com/github/ribbons/forkme_right_gray_6d6d6d.png" alt="Fork me on GitHub"></a>


SCRAMBLE.io Details
======

This describes the protocol and how it ties in to the Scramble REST API.

Terms
---
The "client" and "server" refer to Scramble.io code, written in Javascript and Go, respectively.

The "user" is the person using the client.

The client runs in a browser, and is assumed to be trustworthy. 

(This assumption is reasonable if the user is running the browser extension. It becomes weaker if the user is running the web app. See the <a href="/doc/">overview</a> for a description of the threat model.)

The server is not assumed to be trustworthy. Connections to the server may be spied on, even though they are always over HTTPS. Any information the server stores may be spied on as well. The server may even be comandeered by the adversary. In that case, the server becomes the adversary. Denial of service is possible, but loss of private data should not be possible.


Protocol
---
We'll log in as user `A`, and receive an email from user `B`. Finally, we'll send an email to user `B`.

### Creating an account

The client generates an PGP key pair using OpenPGP.js, which uses the Javascript secure random number API. We now have `PubKey(A)` and `PrivKey(A)`.

We could use any public key algorithm here. Currently, we're using 2048-bit RSA.

The user enters a token ("ironman") and passphrase ("correct horse battery staple").

The client computes two hashes, which we'll use for authentication. 

    TokenHash = SHA1(token)
    PassHash  = SHA1("1" || passphrase)

The next step is to derive a symmetric encryption key from the passphrase.

We could use any symmetric encryption algorithm here. Currently, we're using AES-128, which requires 128-bit keys.

    K = first 128 bits of SHA1("2" || passphrase)

This should be unrelated to the authentication hash. The server will see `SHA1(token)` and `PassHash`, but must never know `K`.

    POST /users/

<div class="comm">
Create an account.
<div class="to-server"><label>token hash</label>SHA1(token)</div>
<div class="to-server"><label>passphrase hash</label>SHA1("1" || passphrase)</div>
<div class="to-server"><label>public key</label>PubKey(A)</div>
<div class="to-server"><label>encrypted private key</label>AES128<sub>K</sub>(PrivKey(A))</div>
<div class="to-client"><label>confirm</label>account created</div>
</div>

If the token is already taken, then the account creation request will fail, and the user will try again until they find one that's not taken.

The server has now set up a mail box for user `A`. The corresponding email address is a hash of `PubKey(A)`. We use the same format as Onion URLs: the first 80 bits of `SHA1(PubKey(A))`, encoded in Base32 (RFC4648). For example,

    vqxtivp5tq643a26@scramble.io

We'll refer to the first part (eg `vqxtivp5tq643a26`) as `ShortHash(PubKey(A))`.

### Logging in 

To log in, the user enters a token and passphrase.

The client stores both for the current browser session only. Specifically, the token and `PassHash` are session cookies. The symmetric key K is stored in HTML5 sessionStorage&mdash;it is never sent to the server, and never stored in localStorage or cookies. 

The server is stateless, and does not track sessions. There are no session tokens. Instead, the client sends token and PassHash with every request.


### Loading your inbox

    GET /inbox

<div class="comm">
Load my inbox.
<div class="to-server"><label>token hash</label>SHA1(token)</div>
<div class="to-server"><label>password hash</label>PassHash</div>
The server returns a list of email headers. Each one consists of metadata and an encrypted subject.

Here's one of them:
<div class="to-client"><label>message id</label>160-bit UUID</div>
<div class="to-client"><label>time</label>unix time, no time zone</div>
<div class="to-client"><label>from</label>email address</div>
<div class="to-client"><label>to</label>one or more email addresses</div>
<div class="to-client"><label>cc,bcc</label>...</div>
<div class="to-client"><label>encrypted subject</label>{SignedSubject}<sub>PK(A)</sub></div>
</div>

Loading sent mail, archived mail, and so on will be very similar.

(How viewing sent mail is possible is explained under "Sending an encrypted email" below.)


### Loading an email

The inbox request only gives metadata and encrypted subject lines for each message.

    GET /email/{message id}

<div class="comm">
Authenticate ourselves.
<div class="to-server"><label>token hash</label>SHA1(token)</div>
<div class="to-server"><label>password hash</label>PassHash</div>
<div class="to-server"><label>message id</label>160-bit hex id</div>

Load one email..
<div class="to-client"><label>encrypted body</label>{SignedBody}<sub>PK(A)</sub></div>
</div>


### Sending an encrypted email

The user composes an email.

The first step to sending the email is looking up the public keys of the recipients. Here, we'll assume the email has one recipient, address `B`. If there are multiple recipients, or a CC or BCC, the steps are simply repeated: we have to look up the public key of each recipient, and we encrypt and send our message separately for each recipient.

Remember that address `B` takes the form `NameB@HostB`

When sending to an encrypted address,

    NameB = ShortHash(PubKey(B))

So we look up B's public key. No authentication required.

    GET /users/{address}

<div class="comm">
<div class="to-server"><label>address</label>B</div>
<div class="to-client"><label>public key</label>PubKey(B)</div>
</div>

The client verifies that the server provided the correct public key. It computes `ShortHash` of the response, which should match `NameB`.

Next, the client encrypts and signs both the message and the subject.

Note that "to" and "recipient" are not the same here. You might have five email addresses listed in the "to" field. We must encrypt and sign our message for each one individually. However, each of them should get a message listing all five in the "to" header, so that they can Reply All, for example.

    POST /email/{message id}

<div class="comm">
Authenticate ourselves.
<div class="to-server"><label>token hash</label>SHA1(token)</div>
<div class="to-server"><label>password hash</label>PassHash</div>
Send an email encrypted for a single recipient.
<div class="to-server"><label>message id</label>160-bit UUID, made with SRNG</div>
<div class="to-server"><label>recipient</label>B</div>
<div class="to-server"><label>reply-to</label>(optional, prev message id)</div>
<div class="to-server"><label>to</label>addresses, including B</div>
<div class="to-server"><label>cc,bcc</label>...</div>
<div class="to-server"><label>encrypted subject</label>{SignedSubject}<sub>PK(B)</sub></div>
<div class="to-server"><label>encrypted body</label>{SignedBody}<sub>PK(B)</sub></div>
<div class="to-client"><label>confirm</label>email sent</div>
</div>

Since the message id is long and comes from a secure RNG, there should never be accidental collisions. If someone edits the client and tries to send new message with the same message id as a previous one, the new one is simply ignored.


### Federation

You might notice that the client always talks to its own server to look up public keys.

What happens when `NameA@HostA` wants to send an email to `NameB@HostB`, where both are Scramble addresses, but HostA does not have the public key for NameB?

Scramble servers will use CORS to allow the client to try the lookup again, this time requesting 

    https://HostB/users/B

instead of 

    /users/B

on HostA. The new host is entirely untrusted: we can verify that the answer it gives us is correct.

This lets anyone with a webserver run their own Scramble server. Just clone the Github repo, follow the Quick Start, and you can have your own `{ShortHash}@mydomain.com` address.
    

### Authentication

The authentication is rudimentary. Sending `TokenHash` and `PassHash` with every request is similar to HTTP Basic authentication.

The cookies are created with `secure=true`, so will only ever be transmitted over HTTPS.

Note that we don't need authentication at all for message secrecy. The mechanism is just to avoid leaking info to fellow users, and to prevent a normal person from eg. downloading all the encrypted private keys, and attempting to crack the passphrases used to encrypt them. The authenitcation provides *no* additional protection against central adversaries.

We could just allow any client to download any inbox&mdash;all messages are encrypted with the recipient's public key. That gives any user the same amount of information a central adversary would have. Unfortunately, that does reveal *whether* a particular address received a message or not, and other high-level metadata. For a central adversary, this seems unavoidable. The recourse is to keep the addresses anonymous. For ordinary adversaries, we can avoid leaking any info at all, by using authentication.

Even if you can steal someone's `TokenHash` and `PassHash`, you still cannot:

* Read their email. You can download it, but you don't have the private key to decrypt it.
* Read their inbox (subject lines and metadata) or address book.
* Send encrypted email as them. You don't have the private key to sign it, so the recipient will reject it.

You can send unencrypted email impersonating them, but you can already do that just with sendmail :)


### Sending an unencrypted email

Sending mail to non-Scramble addresses is simpler. The REST route is the same as above. There's no encryption and no signing. Instead of making one POST request per recipient, you make a single POST containing the uncrypted subject and body.


Key storage
---
The way users are stored on the server mirrors the protocol for creating accounts, described above.

    token hash              SHA1(token)
    passphrase hash         SHA1("1" || passphrase)
    public key              PubKey(A)
    public key hash         ShortHash(PubKey(A))
    encrypted private key   AES128<sub>K</sub>(PrivKey(A))

There's an extra column, storing the hash of the user's public key, which corresponds to their email address. The table is indexed to allow fast lookup by token hash or public key hash.


Scenarios
---

### Someone demands the user name of all users 

We can't tell them. We only know the SHA1 hash of each token. (They can demand the list and try to crack the hashes. We warn users to pick tokens that don't identify them.)

### Someone demands to know whether a particular user name exists

They can check this themselves, by trying to create an account with that token.

### Someone demands the inbox for a particular address

The server never stores plaintext messages, so we can't tell them.

### Someone wiretaps connections to the server, and connections to other SMTP servers

This would mean the adversary has either done an SSL MITM attack, or compelled us to allow a secret wiretap.

The server transmits plaintext messages only from and to non-Scramble addresses. Communications between Scramble addresses would remain safe.

The server never sees plaintext address books. Users who keep their Scramble address anonymous would not be revealed even with a full wiretap, even if they are listed in their contacts' address books by their real name.

### Someone takes control of the server

This allows them to serve malicious Javascript.

This won't affect users who install the Chrome extension, once that's available. To them, the server is fully untrusted, and this scenario is the same as the wiretap scenario. The adversary can deny service, to everyone or to particular addresses, but they can't read encrypted mail or address books.

An adversary who controls the server could serve malicious Javascript to all webmail users, or specific ones by IP.

Serving malicious Javascript to all users should be caught very quickly. In the future, there might be a small program for volunteers all over the world to run, which would download the resources (HTML, JS, etc) at random intervals to check that they haven't been tampered with. When we get there, modifications to the resources or even their HTTP cache setings should be caught quickly.

As a result, an adversary that controls the server probably won't want to serve malicious Javascript to all users.

Serving malicious code to a single address (not by IP) should fortunately not be possible. 

When a user visits [https://scramble.io](https://scramble.io), the site loads all resources immediately (index.html, app.js, and style.css). Then, it runs as a single-page web application. All further communication is via XHRs according to the protocol described above. By the time the server knows that a particlar user is logging in, that browser session is already treating the server as untrusted.

Even if the user refreshes the page, the cache settings on resources mean that the browser won't request them again.

This means that a user logging in over Tor&mdash;or, say, from a public library computer&mdash;should be safe, even if they're using web mail and an adversary controls the server.

