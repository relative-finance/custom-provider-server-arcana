package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

func (a *application) getTelegramID(c echo.Context) error {
	apiKey := c.Request().Header.Get("X-API-Key")
	if apiKey != API_KEY {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid API key")
	}

	showdownUserIDs := c.QueryParams()["ShowdownUserID"]
	if len(showdownUserIDs) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "ShowdownUserID query parameter is required")
	}

	var results []TelegramUser

	results, err := a.db.GetTelegramUsersByShowdownIDs(showdownUserIDs)
	if err != nil {
		echo.NewHTTPError(http.StatusInternalServerError, "failed to get the telegram users")
	}

	return c.JSON(http.StatusOK, results)
}

func (a *application) verifyTelegramUser(c echo.Context) error {
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

	showdownUserID, err := a.db.GetLinkedShowdownIDFromTelegramID(telegramUserID)
	if err != nil {
		return fmt.Errorf("failed to check existing showdown link: %w", err)
	}

	if showdownUserID == "" {
		return echo.NewHTTPError(http.StatusNotFound, "telegram id is not linked with any showdown user id")
	}

	accounts, err := a.db.GetConnectedAccounts(showdownUserID)
	if err != nil {
		return fmt.Errorf("failed to get connected accounts: %w", err)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"showdown_id": showdownUserID,
		"accounts":    accounts,
	})
}
