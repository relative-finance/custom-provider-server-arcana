package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/labstack/echo/v4"
)

type completeParams struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

func (a *application) completeLogin(c echo.Context) error {
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
		fmt.Println("exchange:", err, "code:", code)
		return err
	}

	accessToken := oauth2Token.AccessToken
	fmt.Println("accessToken:", accessToken)
	id, err := p.conf.getUserInfo(accessToken)
	if err != nil {
		fmt.Println("err:", err)
		return err
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
		Issuer:    a.jwtIssuer,
		NotBefore: jwt.NewNumericDate(time.Now()),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Minute * 3)),
	}

	// Get user from DB
	user, err := a.db.GetUserID(id, sl[1])
	if err != nil {
		return err
	}
	if user == 0 {
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
		UserID:    strconv.Itoa(user),
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
		"userID":     strconv.Itoa(user),
		"loginType":  sl[1],
		"loginToken": loginToken,
	})
}
