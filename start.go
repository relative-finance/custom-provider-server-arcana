package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

var Store = sessions.NewCookieStore([]byte("super-secret-key"))

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func createVerifier() (string, error) {
	verifier := make([]byte, 32)
	_, err := rand.Read(verifier)
	if err != nil {
		return "", err
	}
	return base64URLEncode(verifier), nil
}

func createChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64URLEncode(hash[:])
}

func (a *application) getLoginURL(c echo.Context, flowType, loginType, st string) (string, error) {
	p, ok := a.authMap[loginType]
	if !ok {
		return "", echo.NewHTTPError(http.StatusBadRequest, "login type not available")
	}
	state := "login:" + loginType + ":" + st
	if flowType == "link" {
		state = "link:" + loginType + ":" + st
	}
	s, err := a.signer.Sign([]byte(state))
	if err != nil {
		return "", echo.NewHTTPError(http.StatusInternalServerError)
	}
	sig, err := s.CompactSerialize()
	if err != nil {
		return "", echo.NewHTTPError(http.StatusInternalServerError)
	}
	Store.Options.HttpOnly = true
	Store.Options.SameSite = http.SameSiteStrictMode
	session, _ := Store.Get(c.Request(), "cookie-name")

	options := getOAuthOption(loginType)
	origin := c.Request().Header.Get("Referer")
	parsedURL, err := url.Parse(origin)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusInternalServerError)
	}
	host := parsedURL.Host

	// redirectURL := fmt.Sprintf("%s://%s/complete", parsedURL.Scheme, host)
	redirectURL := fmt.Sprintf("%s://%s/authentication/callback", parsedURL.Scheme, host)
	// redirectURL := fmt.Sprintf("http://localhost:3000/authentication/callback")
	fmt.Println("redirectURLejiefied")
	fmt.Println(redirectURL)

	if loginType == "lichess" {
		verifier, err := createVerifier()
		if err != nil {
			return "", err
		}
		challenge := createChallenge(verifier)

		options = append(options, oauth2.SetAuthURLParam("response_type", "code"))
		options = append(options, oauth2.SetAuthURLParam("client_id", "random"))
		options = append(options, oauth2.SetAuthURLParam("code_challenge_method", "S256"))
		options = append(options, oauth2.SetAuthURLParam("code_challenge", challenge))
		options = append(options, oauth2.SetAuthURLParam("scope", "board:play challenge:write challenge:read bot:play email:read"))
		session.Values["codeVerifier"] = verifier
		session.Save(c.Request(), c.Response().Writer)
	}

	// c := new(OAuth2Config)
	// c.ClientID = p.conf.ClientID
	// c.ClientSecret = p.conf.ClientSecret
	// c.Scopes = p.conf.Scope
	// c.provider = p.conf.Name
	// c.Endpoint = google.Endpoint
	// c.userInfoURL = GOOGLE_USER_INFO_URL

	p.conf.RedirectURL = redirectURL
	url := p.conf.AuthCodeURL(sig, options...)
	return url, nil
}

func getOAuthOption(verifier string) []oauth2.AuthCodeOption {
	var opts []oauth2.AuthCodeOption
	switch verifier {
	case "twitch":
		cl, _ := json.Marshal(map[string]interface{}{
			"userinfo": map[string]interface{}{
				"email":          nil,
				"email_verified": nil,
			},
		})
		opts = append(opts, oauth2.SetAuthURLParam("claims", string(cl)))
	}
	return opts
}
