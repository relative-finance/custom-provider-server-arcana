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
		http.Error(c.Response().Writer, "Invalid API key", http.StatusUnauthorized)
		return fmt.Errorf("INVALID API KEY")
	}

	userIDs := c.QueryParam("userIDs")
	if userIDs == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "userIDs query is expected")
	}

	// Split the comma-separated string into a slice of userIDs
	userIDList := strings.Split(userIDs, ",")

	// Call the modified GetLichessTokens function to get the mapping
	lichessTokens, err := a.db.GetMultipleLichessTokens(userIDList)
	if err != nil {
		return err
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
