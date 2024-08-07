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

	headers := c.Request().Header
	for name, values := range headers {
		for _, value := range values {
			fmt.Printf("%s: %s", name, value)
		}
	}
	params := new(completeParams)
	if err := c.Bind(params); err != nil {
		return err
	}

	stateB64 := params.State
	code := params.Code
	if stateB64 == "" || code == "" {
		return errors.New("Invalid query params")
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
		return errors.New("unexpected state found")
	}

	p, ok := a.authMap[sl[1]]
	if !ok {
		return errors.New("login type not available")
	}

	oauth2Token, err := p.conf.Exchange(context.Background(), code)
	if err != nil {
		if err.Error() == "oauth2: \"invalid_request\" \"code_verifier required\"" {
			session, _ := Store.Get(c.Request(), "cookie-name")

			verifier, ok := session.Values["codeVerifier"].(string)
			if !ok {
				fmt.Println(verifier)
				fmt.Println("veirfier not found")
				return err
			}
			oauth2Token, err = p.conf.Exchange(context.Background(), code, oauth2.SetAuthURLParam("code_verifier", verifier))
			if err != nil {
				fmt.Println("something: %s", err.Error())
				return err
			}
		} else {
			fmt.Println("exchange:", err, "code:", code)
			return err
		}
	}

	accessToken := oauth2Token.AccessToken
	id, err := p.conf.getUserInfo(accessToken)
	if err != nil {
		fmt.Println("err:", err)
		return err
	}

	if sl[1] == "lichess" {
		err = a.db.CreateLichessToken(id, accessToken)
		if err != nil {
			return err
		}
	}

	if sl[0] == "link" {
		err := a.linkComplete(id, sl[1], sl[2])
		if err != nil {
			return err
		}
		return c.JSON(200, map[string]any{
			"linkComplete":  true,
			"linkedAccount": sl[1],
		})
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
		return err
	}
	if user == "" {
		err := a.db.CreateNewUser(id, sl[1])
		if err != nil {
			return err
		}
	}
	user, err = a.db.GetUserID(id, sl[1])
	if err != nil {
		return err
	}

	// Get or insert user to db, get ID and replace UserID
	customClaims := customClaims{
		UserID:    user,
		LoginType: sl[1],
		LoginID:   id,
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
