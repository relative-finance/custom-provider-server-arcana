package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

type completeParams struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

func (a *application) completeLogin(c echo.Context) error {
	c.Response().Header().Set("Access-Control-Allow-Credentials", "true")
	fmt.Println("complete login called")

	headers := c.Request().Header
	for name, values := range headers {
		for _, value := range values {
			fmt.Println("%s: %s", name, value)
		}
	}
	params := new(completeParams)
	if err := c.Bind(params); err != nil {
		fmt.Println(err)
		return err
	}

	stateB64 := params.State
	code := params.Code
	if stateB64 == "" || code == "" {
		fmt.Println("Invalid query params")
		return errors.New("invalid query params")
	}

	ss, err := jose.ParseSigned(stateB64, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		fmt.Println("could not parse login state")
		return echo.NewHTTPError(http.StatusForbidden, "could not parse login state")
	}

	verifiedData, err := ss.Verify(&a.publicKey)
	if err != nil {
		fmt.Println("could not verify login state")
		return echo.NewHTTPError(http.StatusForbidden, "could not verify login state")
	}

	state := string(verifiedData)
	sl := strings.Split(state, ":")
	if len(sl) < 3 {
		fmt.Println("unexpected state found")
		return errors.New("unexpected state found")
	}

	p, ok := a.authMap[sl[1]]
	if !ok {
		fmt.Println("login type not available")
		return errors.New("login type not available")
	}

	session, _ := Store.Get(c.Request(), "cookie-name")
	verifier, ok := session.Values["codeVerifier"].(string)
	var oauth2Token *oauth2.Token
	if !ok || verifier == "" {
		oauth2Token, err = p.conf.Exchange(context.Background(), code)
		if err != nil {
			fmt.Println("something: %s", err.Error())
			return err
		}
	} else {
		oauth2Token, err = p.conf.Exchange(context.Background(), code, oauth2.SetAuthURLParam("code_verifier", verifier))
		if err != nil {
			fmt.Println("something: %s", err.Error())
			return err
		}
	}

	accessToken := oauth2Token.AccessToken
	id, err := p.conf.getUserInfo(accessToken)
	if err != nil {
		fmt.Println("err:", err)
		return err
	}

	if sl[0] == "link" {
		userID, err := a.db.GetUserID(id, sl[1])
		fmt.Println("getting current userID")
		if err != nil {
			return err
		}
		fmt.Println("userID")
		fmt.Println(userID)
		if userID != "" {
			fmt.Println("This account is already linked")
			return c.String(http.StatusBadRequest, "This account already exists")
		}
	}

	if sl[1] == "lichess" {
		err = a.db.CreateLichessToken(id, accessToken)
		if err != nil {
			fmt.Println(err)
			return err
		}
	}

	if sl[0] == "link" {
		err := a.linkComplete(id, sl[1], sl[2])
		if err != nil {
			fmt.Println(err)
			return err
		}
	}
	// Create JWT
	cl := jwt.Claims{
		Audience:  []string{a.jwtAudience},
		Issuer:    a.selfURL,
		NotBefore: jwt.NewNumericDate(time.Now()),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Minute * 3)),
	}

	// Get user from DB
	user, err := a.db.GetUserID(id, sl[1])
	if err != nil {
		fmt.Println("1")
		fmt.Println(err)
		return err
	}
	if user == "" {
		err := a.db.CreateNewUser(id, sl[1])
		if err != nil {
			fmt.Println("2")
			fmt.Println(err)
			return err
		}
	}
	user, err = a.db.GetUserID(id, sl[1])
	if err != nil {
		fmt.Println("3")
		fmt.Println(err)
		return err
	}
	secondID := ""
	accounts, err := a.db.GetConnectedAccounts(user)
	if err != nil {
		fmt.Println(err)
		return err
	}
	for i := range accounts {
		account := accounts[i]
		if account.Provider != sl[1] {
			secondID = account.ID
		}
	}

	telegramID, err := a.db.GetLinkedTelegramIDFromShowdownID(user)
	if err != nil {
		fmt.Println("Error fetching Telegram ID:", err)
		return err
	}

	customClaims := customClaims{
		UserID:     user,
		LoginType:  sl[1],
		LoginID:    id,
		LinkedID:   secondID,
		TelegramID: telegramID,
	}

	token, err := jwt.Signed(a.signer).Claims(cl).Claims(customClaims).Serialize()
	if err != nil {
		fmt.Println("jwtcreationerror:", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	cl.Audience = []string{cl.Issuer}
	loginToken, err := jwt.Signed(a.signer).Claims(cl).Claims(customClaims).Serialize()
	if err != nil {
		fmt.Println("jwtcreationerror:", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	return c.JSON(http.StatusOK, map[string]string{
		"token":      token,
		"userID":     user,
		"loginType":  sl[1],
		"loginToken": loginToken,
	})
}
