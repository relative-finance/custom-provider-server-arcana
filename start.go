package main

import (
	"encoding/json"
	"net/http"
	"fmt"
	"net/url"

	"github.com/dchest/uniuri"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

func (a *application) startLogin(c echo.Context) error {
	loginType := c.QueryParam("loginType")
	if loginType == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "loginType query is expected")
	}

	url, err := a.getLoginURL(c, "login", loginType, uniuri.NewLen(10))
	if err != nil {
		return err
	}

	return c.Redirect(http.StatusSeeOther, url)
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

	options := getOAuthOption(loginType)
	origin := c.Request().Header.Get("Referer")
	parsedURL, err := url.Parse(origin)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusInternalServerError)
	}
	host := parsedURL.Host

	redirectURL := fmt.Sprintf("%s://%s/authentication/callback",parsedURL.Scheme, host)
	// redirectURL := fmt.Sprintf("http://localhost:3000/authentication/callback")
	fmt.Println("redirectURLejiefied")
	fmt.Println(redirectURL)

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
