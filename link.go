package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

	showdownUserObject, err := a.verifyShowdownAuthToken(token)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("error verifying token %s", err))
	}

	showdownUserID := showdownUserObject.ShowdownUserID
	lichessID := showdownUserObject.LichessID
	steamUserID := showdownUserObject.UserID

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
	url, err := a.getLoginURL(c, "link", loginType, st)
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
		QueryID string `json:"query_id"`
		User    struct {
			ID              int64  `json:"id"`
			FirstName       string `json:"first_name"`
			LastName        string `json:"last_name"`
			Username        string `json:"username"`
			LanguageCode    string `json:"language_code"`
			AllowsWriteToPM bool   `json:"allows_write_to_pm"`
		} `json:"user"`
		AuthDate int64  `json:"auth_date"`
		Hash     string `json:"hash"`
	}

	if err := c.Bind(&telegramData); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	userJSON, err := json.Marshal(telegramData.User)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to marshal user data")
	}

	dataMap := map[string]string{
		"auth_date": fmt.Sprintf("%d", telegramData.AuthDate),
		"query_id":  telegramData.QueryID,
		"user":      string(userJSON),
	}

	if !verifyTelegramAuth(dataMap, telegramData.Hash, cfg.TelegramBotToken) {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid telegram authentication")
	}

	if time.Now().Unix()-telegramData.AuthDate > 86400 {
		return echo.NewHTTPError(http.StatusUnauthorized, "authorization data is outdated")
	}

	telegramUserID := fmt.Sprintf("%d", telegramData.User.ID)
	if telegramUserID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "telegram user id not found")
	}

	showdownUserObject, err := a.verifyShowdownAuthToken(token)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("error verifying token %s", err))
	}

	showdownUserID := showdownUserObject.ShowdownUserID

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
		return c.JSON(http.StatusOK, "already linked")
	} else {
		err = a.db.LinkToExistingUser(telegramUserID, TELEGRAM_PROVIDER, showdownUserID)
		if err != nil {
			return fmt.Errorf("failed to link accounts: %w", err)
		}

		err = a.db.UpsertTelegramUser(
			telegramUserID,
			telegramData.User.FirstName,
			telegramData.User.LastName,
			telegramData.User.Username,
		)
		if err != nil {
			return fmt.Errorf("failed to store telegram user details: %w", err)
		}
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

	return c.JSON(http.StatusOK, map[string]string{
		"token":      accessToken,
		"userID":     showdownUserID,
		"loginType":  "telegram",
		"loginToken": loginToken,
	})
}

func verifyTelegramAuth(data map[string]string, hash, botToken string) bool {
	secret := hmac.New(sha256.New, []byte("WebAppData"))
	secret.Write([]byte(botToken))
	secretKey := secret.Sum(nil)

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

	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(checkString.String()))
	expectedHash := hex.EncodeToString(mac.Sum(nil))

	return expectedHash == hash
}
