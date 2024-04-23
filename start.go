package main

import (
	"encoding/json"
	"net/http"

	"github.com/dchest/uniuri"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

func (a *application) startLogin(c echo.Context) error {
	loginType := c.QueryParam("loginType")
	if loginType == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "loginType query is expected")
	}

	state := loginType + ":" + uniuri.NewLen(10)
	s, err := a.signer.Sign([]byte(state))
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	sig, err := s.CompactSerialize()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	p, ok := a.authMap[loginType]
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "login type not available")
	}

	options := getOAuthOption(loginType)
	url := p.conf.AuthCodeURL(sig, options...)
	return c.Redirect(http.StatusSeeOther, url)
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
