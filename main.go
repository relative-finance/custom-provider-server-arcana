package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/arcana-network/groot/logger"
	"github.com/go-jose/go-jose/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/patrickmn/go-cache"
	"golang.org/x/oauth2/google"
)

type ProviderDetails struct {
	conf    *OAuth2Config
	idField string
}

type application struct {
	authMap     map[string]*ProviderDetails
	signer      jose.Signer
	publicKey   ecdsa.PublicKey
	selfURL     string
	jwtAudience string
	cache       cache.Cache
	db          UserStore
}

var API_KEY string
var cfg = new(configuration)

func main() {
	// cfg := new(configuration)
	app := new(application)
	app.cache = *cache.New(cache.NoExpiration, 5*time.Minute)

	{
		// Reading config
		cpath := os.Getenv("CONFIG_PATH")
		if len(cpath) == 0 {
			cpath = "config.toml"
		}
		data, err := os.ReadFile(cpath)
		if err != nil {
			panic(err)
		}
		err = toml.Unmarshal(data, cfg)
		if err != nil {
			panic(err)
		}

		API_KEY = cfg.Apikey
	}

	{
		// Loading private key for jwt signature
		privByte, err := os.ReadFile(cfg.KeyFilePath)
		if err != nil {
			panic(err)
		}

		decoded, _ := pem.Decode(privByte)
		k, err := x509.ParsePKCS8PrivateKey(decoded.Bytes)
		if err != nil {
			panic(err)
		}

		key, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			panic("invalid key")
		}
		signer, err := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.ES256, Key: key,
		}, (&jose.SignerOptions{}).WithType("JWT"))
		if err != nil {
			panic(err)
		}

		app.publicKey = key.PublicKey
		app.signer = signer
		app.selfURL = cfg.SelfURL
		app.jwtAudience = cfg.JwtAudience
	}

	{
		connectionStr := fmt.Sprintf("postgresql://%s:%s@%s:%s/%s", cfg.MySQLUser, cfg.MySQLPass, cfg.MySQLHost, cfg.MySQLPort, cfg.MySQLDB)
		fmt.Println(connectionStr)
		fmt.Println(google.Endpoint)
		db, err := connectToDB(connectionStr)
		if err != nil {
			panic(err)
		}
		app.db = db
	}

	{
		// Create available provider auth map
		app.authMap = make(map[string]*ProviderDetails)

		for _, c := range cfg.Verifiers {
			pConf, err := app.getConfig(c)
			if err != nil {
				fmt.Printf("%s verifier config not found in getConfig", c.Name)
			}
			pConf.RedirectURL = cfg.RedirectURL
			app.authMap[c.Name] = &ProviderDetails{
				idField: c.IDKey,
				conf:    pConf,
			}
		}

		if len(app.authMap) == 0 {
			panic("no verifiers set in config")
		}
	}

	e := echo.New()
	e.Use(middleware.CORS())
	e.GET("/start", app.startLogin)
	e.GET("/link/:provider", app.linkAccount)
	e.GET("/connected-accounts", app.connectedAccounts)
	e.POST("/complete", app.completeLogin)
	e.GET("/.well-known/jwks.json", app.JWKSEndpoint)
	e.GET("/user", app.getUser)
	e.GET("/health", healthHandler)
	e.GET("/auth/telegram", app.telegramAuth)

	{
		_, ok := app.authMap["lichess"]
		if ok {
			e.GET("/get_lichess_token", app.getLichessToken)
			e.GET("/lichess/token", app.getLichessTokenFromAccessToken)
		}
	}
	{
		steamConfig, ok := app.authMap["steam"]
		if ok {
			steamHandler := NewSteamHandler(SteamConfig{
				store:        app.db,
				redirectURL:  cfg.RedirectURL,
				selfURL:      app.selfURL,
				clientID:     steamConfig.conf.ClientID,
				clientSecret: steamConfig.conf.ClientSecret,
				signer:       app.signer,
				publicKey:    &app.publicKey,
			}, logger.NewTestLogger())

			e.GET("/steam/oauth2/authorize", steamHandler.Authorize)
			e.GET("/steam/oauth2/redirect", steamHandler.Redirect)
			e.POST("/steam/oauth2/token", steamHandler.TokenExchange)
			e.GET("/steam/oauth2/verify", steamHandler.Verify)
		}
		_ = e.Start(fmt.Sprintf(":%s", cfg.ListenPort))
	}
}

func (a *application) JWKSEndpoint(c echo.Context) error {
	k := jose.JSONWebKey{Key: &a.publicKey}
	k.Use = "sig"
	// Algorithm is a required field
	k.Algorithm = "ES256"
	keyset := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{k},
	}
	return c.JSON(http.StatusOK, keyset)
}

func (app *application) getConfig(providerConf ProviderConfig) (*OAuth2Config, error) {
	c := new(OAuth2Config)
	c.ClientID = providerConf.ClientID
	c.ClientSecret = providerConf.ClientSecret
	c.Scopes = providerConf.Scope
	c.provider = providerConf.Name
	switch providerConf.Name {
	case "google":
		c.Endpoint = google.Endpoint
		c.userInfoURL = GOOGLE_USER_INFO_URL
		return c, nil
	case "epic":
		c.Endpoint = EpicEndpoint
		c.userInfoURL = EPIC_USER_INFO_URL
		return c, nil
	case "twitch":
		c.Endpoint = TwitchEndpoint
		c.userInfoURL = TWITCH_USER_INFO_URL
		return c, nil
	case "steam":
		c.Endpoint = getSteamEndpoint(app.selfURL)
		c.userInfoURL = getSteamUserInfoURL(app.selfURL)
		return c, nil
	case "lichess":
		c.Endpoint = LichessEndpoint
		c.userInfoURL = LICHESS_USER_INFO_URL
		return c, nil
	case "telegram":
		c.Endpoint = TelegramEndpoint
		c.userInfoURL = TELEGRAM_USER_INFO_URL
		return c, nil
	}

	return nil, fmt.Errorf("%s provider not supported", providerConf.Name)
}

func healthHandler(c echo.Context) error {
	c.NoContent(http.StatusOK)
	return nil
}
