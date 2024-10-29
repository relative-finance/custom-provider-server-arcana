package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
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

func (a *application) telegramAuth(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")
	if token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "auth token required")
	}

	var telegramData struct {
		Hash string            `json:"hash"`
		Data map[string]string `json:"data"`
	}

	if err := c.Bind(&telegramData); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	if telegramData.Hash == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "hash is required")
	}

	if !verifyTelegramAuth(telegramData.Data, telegramData.Hash, cfg.TelegramBotToken) {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid telegram authentication")
	}

	telegramUserID := telegramData.Data["id"]
	if telegramUserID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "telegram user id not found")
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

	showdownUserID, ok := tokenMap["ShowdownUserID"].(string)
	if !ok {
		return fmt.Errorf("failed to parse showdownUserID")
	}

	lichessID, ok := tokenMap["LichessID"].(string)
	if !ok {
		return fmt.Errorf("failed to parse LichessID")
	}

	steamUserID, ok := tokenMap["UserID"].(string)
	if !ok {
		return fmt.Errorf("failed to parse UserID")
	}

	existingTelegramID, err := a.db.GetLinkedTelegramIDFromShowdownID(showdownUserID)
	if err != nil {
		return fmt.Errorf("failed to check existing telegram link: %w", err)
	}
	if existingTelegramID != "" && existingTelegramID != telegramUserID {
		return echo.NewHTTPError(http.StatusConflict, "showdownUserID is already linked to another telegram user")
	}

	existingShowdownID, err := a.db.GetLinkedShowdownIDFromTelegramID(telegramUserID)
	if err != nil {
		return fmt.Errorf("failed to check existing showdown link: %w", err)
	}

	if existingShowdownID != "" && existingShowdownID != showdownUserID {
		return echo.NewHTTPError(http.StatusConflict, "telegramUserID is already linked to another showdown user")
	}

	if existingTelegramID == telegramUserID && existingShowdownID == showdownUserID {
		fmt.Println("already linked to same IDs, skipping link")
	} else {
		err = a.db.LinkToExistingUser(telegramUserID, TELEGRAM_PROVIDER, showdownUserID)
		if err != nil {
			return fmt.Errorf("failed to link accounts: %w", err)
		}
	}

	customClaims := customClaims{
		UserID:     showdownUserID,
		LoginType:  TELEGRAM_PROVIDER,
		TelegramID: telegramUserID,
	}

	if lichessID == "" {
		customClaims.LoginID = steamUserID 
		customClaims.LinkedID = lichessID
	}
	if steamUserID == "" {
		customClaims.LoginID = lichessID
		customClaims.LinkedID = steamUserID
	}

	return c.JSON(http.StatusOK, map[string]string{
		"user_id":     customClaims.UserID,
		"login_id":    customClaims.LoginID,
		"login_type":  customClaims.LoginType,
		"linked_id":   customClaims.LinkedID,
		"telegram_id": customClaims.TelegramID,
	})
}

func verifyTelegramAuth(data map[string]string, hash, botToken string) bool {
	h := sha256.New()
	h.Write([]byte(botToken))
	secret := h.Sum(nil)

	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var checkString strings.Builder
	for i, k := range keys {
		if data[k] != "" {
			if i > 0 {
				checkString.WriteString("\n")
			}
			checkString.WriteString(k)
			checkString.WriteString("=")
			checkString.WriteString(data[k])
		}
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(checkString.String()))
	expectedHash := hex.EncodeToString(mac.Sum(nil))

	return expectedHash == hash
}
