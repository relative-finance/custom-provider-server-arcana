package main

import (
	"fmt"
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
	if len(userIDList) == 0 && len(showdownUserIDList) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "userID or showdownUserID query parameters are expected")
	}

	var lichessTokens GetLichessUserInfoRes
	var err error

	if len(userIDList) != 0 {
		lichessTokens, err = a.db.GetMultipleLichessTokens(userIDList, false)
	} else {
		lichessTokens, err = a.db.GetMultipleLichessTokens(showdownUserIDList, true)
	}

	if err != nil {
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

	showdownUserObject, err := a.verifyShowdownAuthToken(tokenStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "error verifying token %s", err)
	}

	lichessID := showdownUserObject.LichessID

	if lichessID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "empty lichess id")
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
