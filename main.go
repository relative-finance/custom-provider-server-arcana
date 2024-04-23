package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/go-jose/go-jose/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/oauth2/google"
)

type ProviderDetails struct {
	conf    *OAuth2Config
	idField string
}

type application struct {
	authMap   map[string]*ProviderDetails
	signer    jose.Signer
	publicKey ecdsa.PublicKey
	selfURL   string
}

func main() {
	cfg := new(configuration)
	app := new(application)

	{
		// Reading config
		cpath := os.Getenv("AUTHZ_CONFIG_PATH")
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
	e.POST("/complete", app.completeLogin)
	e.GET("/.well-known/jwks.json", app.JWKSEndpoint)

	_ = e.Start(fmt.Sprintf(":%s", cfg.ListenPort))
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
	}

	return nil, fmt.Errorf("%s provider not supported", providerConf.Name)
}
