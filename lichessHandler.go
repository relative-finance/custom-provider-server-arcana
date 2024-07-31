package main

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
)

func (a *application) getLichessToken(c echo.Context) error {

	apiKey := c.Request().Header.Get("X-Api-Key")
	if apiKey != API_KEY {
		http.Error(c.Response().Writer, "Invalid API key", http.StatusUnauthorized)
		return fmt.Errorf("INVALID API KEY")
	}

	userID := c.QueryParam("userID")
	if userID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "userID query is expected")
	}

	lichessToken, err := a.db.GetLichessToken(userID)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, map[string]string{
		"lichessToken": lichessToken,
	})
}
