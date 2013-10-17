package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func init() {
	ensureTestUser()
}

func ensureTestUser() *User {
	DeleteUser("test")

	user := &User{
		UserID: UserID{
			Token:        "test",
			PasswordHash: "5026f031ceea00023da878da2be4660ae85040e8", // 'test test test test'
			PublicHash:   "x6urvahzhylq5swe",
			EmailHost:    GetConfig().SmtpMxHost,
		},
		PublicKey: `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP.js v.1.20130306
Comment: http://openpgpjs.org

xsBNBFI1OTQBCACYn6Bg2kvWcCU6U19MuXpM9P7rhRntbBJURjd8fBCmWKgN
cjgt8lRiPoadE+gBAQou991ZBgDQVxQiX58Vhx3CtFCE/xv2r1afc17EIPnT
L/rKa/juvxGUYXbYwtzxby0kjdHSpHseHp3M3hEa7tFre0o9n53orr69EY93
wwSWwOZfvQ4cWvrMnbQPLfAoBN7WSdEJBM0oPrWuy2R+iw1NlNt460pZaTmL
UnQwn9Dn3Jmwl6ogOMEUpzn0SA5QRszSDJG3ohGebg23LkwDS9zZuxvl2cmR
J+Ux2oL5+uT7U9G7b1SnB9Xev9PsaubbKp90rgnAP4U8o802vLxRXxNLABEB
AAHNAMLAXAQQAQIAEAUCUjU5NgkQxEJQa6kmIFoAAEhHB/9ik1idJ87SZxql
l4JuQD0Ro1//8ulJEBRZPe4OdTyJ55ypkPt2q/CjhQ57tPbAJQ+wOQ9/ShYh
oslvVfPAKKNqjOiHoMMhL/hcZ+hwrNQZvpBcdJv2JCYLyf0ttpwzGfFf9wDE
wl6ofUREvrw5mHPz1sq/c1kGp/xmBg4ixVfC1OmwUea8IGVzsNCCe8/nDziw
XiaG+aHaQ4J6UzTZgqD4dFuFpqqn/xAS5DuqwLp4Ls/p/Yg4Iln4PbEGeMjR
Z3yOxoPXziCPAqtAheyX3hUSqBOKM7k111yjp4KZZdbUrPra82FXsfCVuPJJ
OewXcIuOdtHovjU05JwUjYcg30lZ
=5jon
-----END PGP PUBLIC KEY BLOCK-----`,
		CipherPrivateKey: `11547b42d5b6219fc5937a1cf38ae2ef9c50267e7a93fa5c7c0517ae37f62a6e10edfbf9d2f2ac2f11d1cb8cd75ff7c471b61b11c8a8bfea9b39397a7c57a149ce5cb47cc11d3b8c313a082188ce266c1c61770c128bc7ede95597076d7cda44ee96b385e3b54df472a2520da0c76639aa381aa36a237e7eade675e6a7346c7fc029342c7585dcb02dc7d370393f9015bc93a66082854162959747dbce655b3f21f8fd994fac923c5aac5b367e699349e5adba05f763e176606c55d01800805d135439802709fd4a1334ca7649dc8a1e90f4fdaea209275839dea2b206ce0a1f914507ec7a70698303aaf33bd5065a1504bd2fad13bd4cb8d32aca58f3905ffb3b59dacbb5a2c12114512a366d1f129d334a9c457d5ad75ddc123e5d80f29470a0ebb017d7a2449c0d1edbbd4bef1f0258fe2095cc03a9e48a838b3549a2f503d5595e86f74c7f7708a643588159dbf09132204526734ecf901d6a76f42688cbef926c50efc6ad3e4a8f910ac15dd2e629a748075e11a8b4d8544e3381cf08acadf59d941708e247c0e35078916dff86476dea70e752c715cb228221b483388eb5dca1af3f3854117c31fd3c73c823ca005c11fad22f994395a9916c9c8a013c3d534464e638079d67711b373b7b5f2ba7ac1f6af02b53edd69c95c012bd601ba5246496d4ec8bf66f2080a9848e584f3e47b89f7e656439a330dafd08b25fc634ff5d73bdfbedd6de2a0fe0a61ade243a5987fe1ef09bb2671ada524cb183269bae23b29dfe4a2b53fb5ddc00f8650289ac7bbb9415454e73d051bdc97d6e9a8a8b98103e5926e186b65f1918c78599bf2212f2e2cba314aebf370720f38a1cf86b321b017cd6d71902537f4b21becc1e76ef7149cc1ecf204f27751f32197bed77605950a86308b712a4c4741ca0a20d76806a37219501b8603b588f576aff83d69e2b16916315904ee903535d9efb372df88bb472eda8000d0736eeff4410bb781f8de80115071164826aec58159681c3d14bc66727d85b2f0ce5d790d2530054e50bd9435fd5e6402ef9df428db3b11750ef75839b8f640407e16b8fc5d62c97afaa3927988e25f56048be3122e00c752a9192c4520075dd6df6481c15a9fb430a166d422b26f05004040be7f9311d912ce52971a3cce8409ff7b86fc5d86fdb94d53c63b20412b448e8f7d0873976a2679f04d692412b63df41c4a231358112c2c860a07aef2d689dbfde3b48237ba9cf31d258d82cd5fea68e02c336dbf644f10e5e8e98f98bf79308a5aae3195aec76a7ec5bd7b9832d4bfb1ece7589157f6b49dbc24560a267d51fa2bc5496666019853f39065cc21c5e07c1f73c439e64a2993f0909febc58a640e28f6c9fe5c4c0fc7cef80d1f0a548e4cdec8614246d2a4b6c42fd47f3b7616db858562ff88703e756790ebc3a71171ccc093899b3f3c7849f09da66364ce720bae92e5b107e7f342dd768f73330ec12f348f89978015f35c481a6a582915ecad39cdb451ea4c77a037bf3fe4738f33648017c43e4d6b6d21ec51bc7caa166cf667fa5d376958a90745d16a911912092ca01b2291abcc536ca90a919eb59b343c77b3054d090447b10cea61c12f657770988f6bf47a7c290c09151266f26803c2b11d3a886263e7b1314f7fcf7b652f0837b33bc6045b14f54ab692556d8c42eeaed634038b89923591a9f27f56c79562102223cfa1a3f5bac8bffdd179f0613a6fd69dd548a9666270b1005bb57de7ff6123994a7edc0265a7c6264febb449bd98c5081f12e2432624ccf59639f7ad89eb62746b810364a5754abbbc2e1990fa1e7ac80f868cc05b5f578ce63cb5d5bc5198ab6c469a63a45d2172cc79d387487760f0b1dda00f8021e492f1ed59e3c331d1e8bb616dbb5e78598e3d9aec83dba8f22039adeabaec11ca5c60c270d76864932604314a92035e93e7fb98751d9bc5efc47d48ddf106274581d19410c4934fc6bbb3ad3948d8b08bd46286f136bab271e71f8230392f96d36c0bc686746f6aeab61d55cdc58117f7a4a67838adeeab990dc56a5b0f5597c7c0b33e0c14c538807fcfb9f74ae881d5dffa365f37c1655e789ffb7fd764eedaab49281cdeeda406e7b0ea9126152093b3fa613838f20a53521b9417e6dd4752aff2eb9601f2873fbf1e921a60311102fc6b3d7bffb8431c3bad3df93fb2fe683191e674267a28c6c0eded4c47f76168241b3b5047945ebeb9051102ab602dc4e4fc21dda28917894357610eabce0e3d5dce40a6946b557328a0626881047a02426fdd5b83d177a5b1202073996d84702cadd9dcd0d16875262228d6ffc4de11ef5ad79b57016c5a4c7fd67174d62ddaea6e1f618cb5dd035a608b9bbef3a27ae83c794b0123003b2097ce58e008a44b219f2c3206864a81bc4e0a467704991bd1c1209f00260af96cfd52caf4d560770462859c87c1befc0b99a8f4b562abef9ea5d78482184e53eb9c00e45dad86dce04fc360ffaf8caec87d62f4220befed94d07255ea90e5ffbbfeaabfc6e3a7e3d476e94cd934c62057a31062a70`,
		// vim syntax highlite fix `
	}
	SaveUser(user)
	return LoadUser("test")
}

func requestLoggedIn(handler http.HandlerFunc, method string, path string, form url.Values) *httptest.ResponseRecorder {
	record := httptest.NewRecorder()
	req := &http.Request{
		Method: method,
		URL:    &url.URL{Path: path},
		Header: map[string][]string{},
		Form:   form,
	}
	expires := time.Now().AddDate(0, 0, 1)
	req.AddCookie(&http.Cookie{Name: "token", Value: "test", Expires: expires})
	req.AddCookie(&http.Cookie{Name: "passHash", Value: "5026f031ceea00023da878da2be4660ae85040e8", Expires: expires})
	req.AddCookie(&http.Cookie{Name: "passHashOld", Value: "909b45492bad2efe39489d2d0878ea574ea9a6d4", Expires: expires})
	handler(record, req)
	return record
}

func TestPublicKeysHandler(t *testing.T) {
	var tUser = ensureTestUser()

	record := requestLoggedIn(
		publicKeysHandler,
		"POST", "publickeys/query",
		url.Values{
			"nameAddresses": {tUser.EmailAddress},
			"hashAddresses": {"doesnotexist#2222222222222222@" + GetConfig().SmtpMxHost},
			"notaries":      {GetConfig().SmtpMxHost},
		},
	)
	log.Println(record.Code, record.Body.String())

	parsed := PublicKeysResponse{}
	err := json.Unmarshal(record.Body.Bytes(), &parsed)
	if err != nil {
		log.Fatal("Failed to parse response from publickeys/query: " + err.Error())
	}

	// assertions on parsed
	if parsed.NameResolution == nil {
		log.Fatal("Name resolution failed")
	}
	var hostResultError = parsed.NameResolution[GetConfig().SmtpMxHost]
	if hostResultError == nil {
		log.Fatal("Name resolution failed for host %s", GetConfig().SmtpMxHost)
	}
	var notaryRes = hostResultError.Result[tUser.EmailAddress]
	if notaryRes.PubHash != tUser.PublicHash {
		log.Fatal("Name resolution should have returned pubHash for %s", tUser.EmailAddress)
	}
	if notaryRes.Timestamp < 1380000000 || 9999999999 <= notaryRes.Timestamp {
		log.Fatal("Timestamp out of range")
	}
	if strings.Index(notaryRes.Signature, "-----BEGIN PGP SIGNATURE-----") != 0 {
		log.Fatal("Signature doesn't start with armor")
	}

	var dneRes = parsed.PublicKeys["doesnotexist@"+GetConfig().SmtpMxHost]
	if dneRes.Error != "Unknown name doesnotexist" {
		log.Fatal("Unexpected error message for name that does not exist")
	}

	var tUserRes = parsed.PublicKeys[tUser.EmailAddress]
	if strings.Index(tUserRes.PubKey, "-----BEGIN PGP PUBLIC KEY BLOCK-----") != 0 {
		log.Fatal("Invalid public key response for test user")
	}

}
