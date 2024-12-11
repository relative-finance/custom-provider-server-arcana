package main

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

type completeParams struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

func (a *application) completeLogin(c echo.Context) error {
	c.Response().Header().Set("Access-Control-Allow-Credentials", "true")

	params := new(completeParams)
	if err := c.Bind(params); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid parameters")
	}

	stateB64 := params.State
	code := params.Code
	if stateB64 == "" || code == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid query params")
	}

	ss, err := jose.ParseSigned(stateB64, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return echo.NewHTTPError(http.StatusForbidden, "could not parse login state")
	}

	verifiedData, err := ss.Verify(&a.publicKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusForbidden, "could not verify login state")
	}

	state := string(verifiedData)
	sl := strings.Split(state, ":")
	if len(sl) < 3 {
		return echo.NewHTTPError(http.StatusBadRequest, "unexpected state found")
	}

	p, ok := a.authMap[sl[1]]
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "login type not available")
	}

	session, _ := Store.Get(c.Request(), "cookie-name")
	verifier, ok := session.Values["codeVerifier"].(string)
	var oauth2Token *oauth2.Token
	if !ok || verifier == "" {
		oauth2Token, err = p.conf.Exchange(context.Background(), code)
	} else {
		oauth2Token, err = p.conf.Exchange(context.Background(), code, oauth2.SetAuthURLParam("code_verifier", verifier))
	}
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to exchange token")
	}

	accessToken := oauth2Token.AccessToken
	id, err := p.conf.getUserInfo(accessToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get user info")
	}

	if sl[0] != "link" {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid method. has to be a link request")
	}

	showdownUserID, err := a.db.GetUserID(id, sl[1])
	if err != nil {
		return err
	}
	if showdownUserID != "" {
		return echo.NewHTTPError(http.StatusBadRequest, "This account already exists")
	}

	if sl[1] == "lichess" {
		err = a.db.CreateLichessToken(id, accessToken)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "create lichess token %s", err)
		}
	}

	err = a.linkComplete(id, sl[1], sl[2])
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "cannot link %s", err)
	}

	showdownUserID, err = a.db.GetUserID(id, sl[1])
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "cannot get showdownUserID %s", err)
	}

	if showdownUserID == "" {
		return echo.NewHTTPError(http.StatusInternalServerError, "The account does not exist")
	}

	accounts, err := a.db.GetConnectedAccounts(showdownUserID)
	if err != nil {
		return err
	}

	var steamID, lichessID, telegramID, address, email string
	for _, account := range accounts {
		switch account.Provider {
		case "steam":
			steamID = account.ID
		case "lichess":
			lichessID = account.ID
		case TELEGRAM_PROVIDER:
			telegramID = account.ID
		case WALLET_PROVIDER:
			address = account.ID
		case EMAIL_PROVIDER:
			email = account.ID
		}
	}

	accessToken, loginToken, err := a.generateShowdownAuthTokens(
		showdownUserID,
		address,
		email,
		steamID,
		lichessID,
		telegramID,
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to generate tokens")
	}

	http.SetCookie(c.Response(), &http.Cookie{
		Name:     "refresh_token",
		Value:    loginToken,
		Path:     "/",
		Expires:  time.Now().Add(REFRESH_TOKEN_TTL),
		MaxAge:   int(REFRESH_TOKEN_TTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	return c.JSON(http.StatusOK, map[string]string{
		"token":      accessToken,
		"userID":     showdownUserID,
		"loginType":  sl[1],
		"loginToken": loginToken,
	})
}
func (a *application) logoutHandler(c echo.Context) error {
	http.SetCookie(c.Response(), &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	return c.NoContent(http.StatusOK)
}
