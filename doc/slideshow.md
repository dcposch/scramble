title: Scramble your Email
author:
  name: "Jae Kwon"
  url: "hashed.im"
output: slideshow.html
controls: true

--

# Scramble
## NSA-proof Secure Webmail

--

### Email is Insecure

* HTTPS CAs
* NSA "fibertapping"
* FISA / NSL / govt order

--

### Email is Insecure
#### HTTPS CAs

* March 2011 Comodo<br/>
  `mail.google.com`,<br/>
  `login.yahoo.com`, ...
* August 2011 Diginotar<br />
  `*.google.com`
* FireFox & CNNIC

With MITM attacks, HTTPS alone can't be trusted.

--

### Email is Insecure
#### NSA "fibertapping"

* International fibers
* Global Intercept partners
* !(Perfect Forward Secrecy)

--

### Email is Insecure
#### FISA/NSL/govt order

* Lavabit (used by Snowden)
* Silent Circle (Zimmerman)
* TorMail (Marques)
* HushMail, complicit

--

### Solution

* Best crypto primitives
* Webmail w/ untrusted servers
* Open source & federated

Welcome to Scramble!

--

### Scramble
#### Best crypto primitives

* OpenPGP can be secure
* RSA2048 for signing
* RSA2048 & AES128 for encryption

--

### Scramble
#### Webmail w/ untrusted servers

Encrypt all of the things!

* Mail subject & body
* Contacts
* Index blobs (future)

Also, `Scrypt(<PassPhrase>)` for KDF<br />
to encrypt user's `<PrivateKey>`

--

### Scramble
#### Webmail w/ untrusted servers

Can't trust the server,<br/>
Can't trust the javascript.

* Browser plugin
* HTML App Cache

--

### Scramble
#### Name Resolution

A user is identified by hir `<PublicKey>`

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
xsBNBFI/k+wBCADO3eL0Beu5Hqeot4aRTO3ijSD1ddkCiEpTfnd1pCG72E72
wLxsqMt+lI3gVNxeje6eqFlc9K6PrP9hAScQKM0f6wp2NCqfdWmGk9NvTyVp
3WiXQhDNucm+c79FgyvYiIUM8Xjt5AfOQNQ8dyqgoSiQR7lwGbbmen/C4aKS
ilLIn+VuSZYR4Xym0BTX0r/gKKMVfNBgRPIxuHhtFBEyisCWwhDxrDsHP/vU
I9UqeqYQl67o+DcVWAcD0NUpCqtp2OH0s8TVn5Wac7g7n6MK7bPGCnschPfR
mAadQ/Z453AseIlQEtUGV0cia6AP8hoT30/Lh++8TMTB0LMpVzJXqvVjABEB
AAHNAMLAXAQQAQIAEAUCUj+T8AkQS0aTOFk3BcEAAFiwCACjxQo/3bnNOjL4
+Q5QwQM+y8/y2OzrnZAt63RRmmm8AHmO6RrIWhvmb47BcWofaehMGAitrEEz
Oc4sn/Nn15P2/Ffch9X929gYqj2Bq9zFIbo9bTDBGvNgQ6mnPY7E/9nD9p6X
VZW5lSgoXMgkDuuWf1uG38pqJCu9m4YLHzYgqBeUmfMjy5ZWzfc1Z4DQEzNy
T2xaAnhKt8RRIahSl3vqti6Acy5ZHE+GEXzL89D6yQV8uDJCRbaHdMUNPAc+
KyO/vJuje0QPxkloHmy0JKmOIuB+dPkxYaIQUKubm0xoh6BWWg1I3obE7cCn
1IRp6TufNOyBKlkL+2tCczTHdNP5
=o8xa
-----END PGP PUBLIC KEY BLOCK-----
```

--

### Scramble
#### Name Resolution (cont.)

A user is identified by hir `Hash(<PublicKey>)`

`9b66b9f17380bfc04abf342f9df077b69713393e`

Or just the first 80 bits, in base32:

`tntlt4ltqc74asv7`

Still hard to remember!

--

### Scramble
#### Name Resolution (cont.)

How can resolve an address, `jaekwon@hashed.im`<br/>
  to `tntlt4ltqc74asv7`?

* NameCoin?
* Public Key servers?

--

### Scramble
#### Name Resolution (cont.)

An alternative solution

* 1B addresses require < 100Gb to store
* Distributed notary system!

--

### Scramble
#### Name Resolution (cont.)

* Client has a list of trusted notaries,<br/>
  `hashed.im` & `scramble.io`
* Client asks server,<br/>
    "Tell me what `hashed.im` and `scramble.io` think `jaekwon@hashed.im` resolves to"
* Server forwards query to `hashed.im` & `scramble.io`
* Server aggregates & responds
* Client makes a decision

--

### Scramble
#### Open source & federated

* What if Lavabit had been open source?
* Federation == Shutdown Resistance
* Federation allows for notary name resolution

--

### Scramble + Future

* Enigmail compatibility
* Search w/ encrypted indices
* Chat?
* FileSharing?

--

### Questions?

Sign up! https://hashed.im

github: dcposch/scramble<br/>
my fork: jaekwon/scramble
