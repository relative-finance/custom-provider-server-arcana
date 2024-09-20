package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

func (a *application) getLichessToken(c echo.Context) error {

	apiKey := c.Request().Header.Get("X-Api-Key")
	if apiKey != API_KEY {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid API key")
	}

	userIDList := c.QueryParams()["userID"]
	showdownUserIDList := c.QueryParams()["showdownUserID"]
	if len(userIDList) == 0 || len(showdownUserIDList) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "userID or showdownUserID query parameters are expected")
	}

	var lichessTokens GetLichessUserInfoRes
	var err error
	var isShowdownUserIds bool

	if len(userIDList) != 0 {
		isShowdownUserIds = false
	} else {
		isShowdownUserIds = true
	}

	if lichessTokens, err = a.db.GetMultipleLichessTokens(userIDList, isShowdownUserIds); err != nil {
		fmt.Println("failed to retrieve tokens", err)
		return c.JSON(http.StatusInternalServerError, "Failed to retrieve tokens")
	}

	// Return the mapping as a JSON response
	return c.JSON(http.StatusOK, lichessTokens)
}

func getAuth(header http.Header) (string, error) {
	auth := header.Get("Authorization")
	parts := strings.Split(auth, " ")
	if len(parts) == 2 && parts[0] == "Bearer" {
		return parts[1], nil
	}
	return "", fmt.Errorf("invalid auth")
}

func (a *application) getLichessTokenFromAccessToken(c echo.Context) error {
	tokenStr, err := getAuth(c.Request().Header)
	if err != nil {
		return err
	}

	url := cfg.ShowdownUserService + "/access"
	payload := []byte(fmt.Sprintf("{\"access_token\": \"%v\"}", tokenStr))

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

	lichessID, ok := tokenMap["LichessID"].(string)
	if !ok {
		return fmt.Errorf("failed to parse lichessID")
	}

	lichessToken, err := a.db.GetLichessToken(lichessID)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, map[string]string{
		"lichessToken": lichessToken,
		"lichessID":    lichessID,
	})
}
