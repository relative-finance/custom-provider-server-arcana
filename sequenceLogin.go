package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	gojwt "github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"

	"github.com/MicahParks/keyfunc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var ACCESS_TOKEN_TTL = time.Hour
var REFRESH_TOKEN_TTL = time.Hour * 24 * 7

func (a *application) sequenceLogin(c echo.Context) error {
	// Extract the Authorization header
	authHeader := c.Request().Header.Get("Authorization")

	// Check if the Authorization header is present
	if authHeader == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Authorization header is missing"})
	}

	// Split the header to extract the token
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid Authorization header format"})
	}

	// Extract the JWT token
	token := parts[1]

	claims, err := verifySequenceToken(token)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
	}

	userEmail := claims["email"].(string)
	userAddress := claims["sub"].(string)

	showdownUserID, err := a.db.GetUserID(userEmail, EMAIL_PROVIDER)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error while getting user from db"})
	}

	// This email does not exist currently
	if showdownUserID == "" {
		err := a.db.CreateNewUser(userEmail, EMAIL_PROVIDER)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error creating new user"})
		}
		showdownUserID, err = a.db.GetUserID(userEmail, EMAIL_PROVIDER)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error getting user ID"})
		}
		err = a.db.LinkToExistingUser(userAddress, WALLET_PROVIDER, showdownUserID)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error linking wallet to user"})
		}
	}

	accounts, err := a.db.GetConnectedAccounts(showdownUserID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error getting connected accounts"})
	}

	userSteamID := ""
	userLichessID := ""
	userTelegramID := ""
	for i := range accounts {
		account := accounts[i]
		switch account.Provider {
		case "steam":
			userSteamID = account.ID
		case "lichess":
			userLichessID = account.ID
		case TELEGRAM_PROVIDER:
			userTelegramID = account.ID
		}
	}

	accessToken, refreshToken, err := a.generateShowdownAuthTokens(showdownUserID, userAddress, userEmail, userSteamID, userLichessID, userTelegramID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Error generating tokens"})
	}

	http.SetCookie(c.Response(), &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		Expires:  time.Now().Add(REFRESH_TOKEN_TTL),
		MaxAge:   int(REFRESH_TOKEN_TTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	// Calculate expiresIn timestamp
	expiresIn := time.Now().Add(ACCESS_TOKEN_TTL).Unix()

	return c.JSON(http.StatusOK, map[string]interface{}{
		"access_token":  accessToken,
		"expires_in":    expiresIn,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
	})
}

func (a *application) refreshTokenHandler(c echo.Context) error {
	// Try to get the refresh token from the cookies
	cookie, err := c.Cookie("refresh_token")
	var refreshToken string

	if err == nil && cookie != nil {
		refreshToken = cookie.Value
	} else {
		// If the cookie is not found, check the body
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}

		if err := c.Bind(&req); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
		}

		refreshToken = req.RefreshToken
	}

	if refreshToken == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "refresh_token is required")
	}

	customClaims, err := a.verifyShowdownAuthToken(refreshToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Refresh token validation failed")
	}

	accessToken, _, err := a.generateShowdownAuthTokens(
		customClaims.ShowdownUserID,
		customClaims.Address,
		customClaims.Email,
		customClaims.UserID,
		customClaims.LichessID,
		customClaims.TelegramID,
	)

	if err != nil {
		fmt.Println("token generation error:", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	return c.JSON(http.StatusOK, map[string]string{
		"access_token": accessToken,
	})
}

func (a *application) accessTokenHandler(c echo.Context) error {
	var req struct {
		AccessToken string `json:"access_token"`
	}

	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	if req.AccessToken == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "access_token is required")
	}

	claims, err := a.verifyShowdownAuthToken(req.AccessToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid access token")
	}

	// for backward compatability
	return c.JSON(http.StatusOK, map[string]string{
		"ShowdownUserID": claims.ShowdownUserID,
		"LichessID":      claims.LichessID,
		"UserID":         claims.UserID,
		"Address":        claims.Address,
		"Email":          claims.Email,
	})
}

func (a *application) verifyShowdownAuthToken(showdownAuthToken string) (*showdownUserTokenStruct, error) {
	// Parse the JWT
	var customClaims showdownUserTokenStruct
	parsedJWT, err := jwt.ParseSigned(showdownAuthToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Standard claims and custom claims
	var standardClaims jwt.Claims

	// Verify and extract claims using the signer’s public key
	if err := parsedJWT.Claims(&a.publicKey, &standardClaims, &customClaims); err != nil {
		return nil, fmt.Errorf("failed to verify JWT claims: %w", err)
	}

	// Validate standard claims
	if err := standardClaims.Validate(jwt.Expected{
		Issuer:      a.selfURL,
		AnyAudience: jwt.Audience{a.selfURL},
		Time:        time.Now(),
	}); err != nil {
		return nil, fmt.Errorf("JWT validation failed: %w", err)
	}

	// Return the custom claims if valid
	return &customClaims, nil
}

func (a *application) generateShowdownAuthTokens(showdownUserID, userAddress, userEmail, userSteamID, userLichessID, userTelegramID string) (accessToken, refreshToken string, err error) {
	customClaims := showdownUserTokenStruct{
		ShowdownUserID: showdownUserID,
		Address:        userAddress,
		Email:          userEmail,
		UserID:         userSteamID,
		LichessID:      userLichessID,
		TelegramID:     userTelegramID,
	}

	cl := jwt.Claims{
		Audience:  []string{a.selfURL},
		Issuer:    a.selfURL,
		NotBefore: jwt.NewNumericDate(time.Now()),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Expiry:    jwt.NewNumericDate(time.Now().Add(ACCESS_TOKEN_TTL)),
	}

	cl.Audience = []string{cl.Issuer}
	accessToken, err = jwt.Signed(a.signer).Claims(cl).Claims(customClaims).Serialize()
	if err != nil {
		fmt.Println("jwtcreationerror:", err)
		return "", "", echo.NewHTTPError(http.StatusInternalServerError)
	}
	cl.Expiry = jwt.NewNumericDate(time.Now().Add(REFRESH_TOKEN_TTL))
	refreshToken, err = jwt.Signed(a.signer).Claims(cl).Claims(customClaims).Serialize()
	if err != nil {
		fmt.Println("jwtcreationerror:", err)
		return "", "", echo.NewHTTPError(http.StatusInternalServerError)
	}
	return accessToken, refreshToken, nil
}

// JWKS URI
const jwksURL = "https://waas.sequence.app/.well-known/jwks.json"

// Expected audience claim
const expectedAudience = "https://sequence.build/project/13639"

// verifyToken verifies the gojwt using the public key and validates claims.
func verifySequenceToken(tokenStr string) (map[string]interface{}, error) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	options := keyfunc.Options{
		Ctx: ctx,
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.Keyfunc\nError: %s", err.Error())
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	}

	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		log.Printf("Failed to create JWKS from resource at the given URL.\nError: %s", err.Error())
		return nil, fmt.Errorf("Failed to create JWKS from resource at the given URL.\nError: %s", err.Error())
	}

	token, err := gojwt.Parse(tokenStr, jwks.Keyfunc)
	if err != nil {
		log.Printf("Failed to parse the JWT.\nError: %s", err.Error())
		return nil, fmt.Errorf("Failed to parse the JWT.\nError: %s", err.Error())
	}

	if !token.Valid {
		log.Println("The token is not valid.")
		return nil, fmt.Errorf("The token is not valid.")
	}

	// Extract claims
	claims, ok := token.Claims.(gojwt.MapClaims)
	if !ok || !token.Valid {
		log.Println("invalid token claims")
		return nil, errors.New("invalid token claims")
	}

	// Validate audience
	ok = claims.VerifyAudience(expectedAudience, true)
	if !ok {
		log.Println("invalid audience claim")
		return nil, errors.New("invalid audience claim")
	}

	// Convert claims to a generic map to be returned as JSON
	claimsMap := make(map[string]interface{})
	for key, value := range claims {
		claimsMap[key] = value
	}

	return claimsMap, nil
}
