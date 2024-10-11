package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dchest/uniuri"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/labstack/echo/v4"
)

func (a *application) linkAccount(c echo.Context) error {
	loginType := c.Param("provider")
	token := c.QueryParam("token")
	if loginType == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "provider is expected")
	}
	if token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "auth token required in header")
	}

	url := cfg.ShowdownUserService + "/access"
	payload := []byte(fmt.Sprintf("{\"access_token\": \"%v\"}", token))
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to authorize")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	tokenMap := map[string]interface{}{}
	if err := json.Unmarshal(body, &tokenMap); err != nil {
		return err
	}
	fmt.Println(tokenMap)
	showdownUserID, ok := tokenMap["ShowdownUserID"].(string)
	if !ok {
		fmt.Println("failed to parse showdownUserID")
		return fmt.Errorf("failed to parse showdownUserID")
	}
	lichessID, ok := tokenMap["LichessID"].(string)
	if !ok {
		fmt.Println("failed to parse LichessID")
		return fmt.Errorf("failed to parse LichessID")
	}
	steamUserID, ok := tokenMap["UserID"].(string)
	if !ok {
		fmt.Println("failed to parse UserID")
		return fmt.Errorf("failed to parse UserID")
	}
	fmt.Println("got all")

	// j, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	// if err != nil {
	// 	fmt.Println(err)
	// 	return err
	// }
	claims := customClaims{}
	claims.UserID = showdownUserID
	if lichessID == "" {
		claims.LoginID = steamUserID
		claims.LoginType = "steam"
	}
	if steamUserID == "" {
		claims.LoginID = lichessID
		claims.LoginType = "lichess"
	}
	fmt.Println(claims)
	// err = j.Claims(&a.publicKey, &claims)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return err
	// }

	st := uniuri.NewLen(10)
	a.cache.Set(st, claims, time.Minute*5)
	url, err = a.getLoginURL(c, "link", loginType, st)
	if err != nil {
		fmt.Println(err)
		return err
	}

	return c.Redirect(http.StatusSeeOther, url)
}

func (a *application) connectedAccounts(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")
	if token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "auth token required in header")
	}

	// TODO: This can be just a middleware with more checks
	j, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		fmt.Println(err)
		return err
	}
	claims := customClaims{}
	err = j.Claims(&a.publicKey, &claims)
	if err != nil {
		fmt.Println(err)
		return err
	}

	accounts, err := a.db.GetConnectedAccounts(claims.UserID)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println("accounts", accounts)
	return c.JSON(200, map[string]any{
		"accounts": accounts,
	})
}

type UserLogin struct {
	Kind        string
	UserID      string
	LocalUserID string
}

func (a *application) linkComplete(userID, loginType, st string) error {
	cl, ok := a.cache.Get(st)
	if !ok {
		return errors.New("could not finish link, try again")
	}
	claims, ok := cl.(customClaims)
	if !ok {
		fmt.Println("error casting to custom claims")
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	err := a.db.LinkToExistingUser(userID, loginType, claims.UserID)
	if err != nil {
		fmt.Println(userID, loginType, claims.UserID)
		fmt.Println("error linking to existing user", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	return nil
}

func (a *application) getUser(c echo.Context) error {
	// Get query parameter
	userID := c.QueryParam("userID")
	// if err != nil {
	// 	return errors.New("Invalid query params")
	// }

	accounts, err := a.db.GetConnectedAccounts(userID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	for _, account := range accounts {
		fmt.Println(account.Provider)
		fmt.Println(account.ID)
		if account.Provider == "steam" {
			return c.JSON(http.StatusOK, map[string]string{
				"steamID": account.ID,
			})
		}
	}
	return echo.NewHTTPError(http.StatusInternalServerError)
}
