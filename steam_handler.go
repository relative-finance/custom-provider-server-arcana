package main

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/arcana-network/groot/logger"
	"github.com/dchest/uniuri"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/imroc/req/v3"
	"github.com/labstack/echo/v4"
)

type Envelope map[string]interface{}

type VerifyResponseStruct struct {
	Name    string `json:"name"`
	Picture string `json:"picture"`
	ID      string `json:"id"`
	AZP     string `json:"azp"`
	IAT     int64  `json:"iat"`
}

type secretKeyKeeper struct {
	sync.Mutex
	keys     []string
	position int
	main     string
	log      logger.Logger
}

type SteamConfig struct {
	store        UserStore
	redirectURL  string
	selfURL      string
	clientID     string
	clientSecret string
	signer       jose.Signer
	publicKey    *ecdsa.PublicKey
}

func NewSteamHandler(conf SteamConfig,
	l logger.Logger) *SteamHandler {

	keys := strings.Split(conf.clientSecret, " ")
	keeper := secretKeyKeeper{
		keys:     keys,
		position: 0,
		main:     keys[0],
		log:      l,
	}
	return &SteamHandler{
		baseURL:         "https://steamcommunity.com/openid/login",
		signer:          conf.signer,
		publicKey:       conf.publicKey,
		store:           conf.store,
		log:             l,
		authURL:         conf.redirectURL,
		selfURL:         conf.selfURL,
		clientID:        conf.clientID,
		clientSecret:    conf.clientSecret,
		secretKeyKeeper: &keeper,
	}
}

func (s *secretKeyKeeper) Get() string {
	s.Lock()
	defer s.Unlock()
	p := s.position % len(s.keys)
	s.position = p + 1
	return s.keys[p]
}

func (s *secretKeyKeeper) IsExpectedSecret(input string) bool {
	return input == s.main
}

type SteamHandler struct {
	baseURL         string
	signer          jose.Signer
	publicKey       *ecdsa.PublicKey
	authURL         string
	selfURL         string
	clientID        string
	clientSecret    string
	secretKeyKeeper *secretKeyKeeper
	store           UserStore
	log             logger.Logger
}

func (v *SteamHandler) Authorize(c echo.Context) error {
	state := c.QueryParam("state")
	clientID := c.QueryParam("client_id")
	redirect_uri := c.QueryParam("redirect_uri")

	redirectURL, err := url.Parse(v.authURL)
	if err != nil {
		return err
	}

	if redirect_uri != redirectURL.String() {
		v.log.Error("invalid redirect", logger.Field{
			"expected": redirectURL.String(),
			"actual":   redirect_uri,
		})

		return errors.New("Invalid redirect url")
	}

	returnToURL, err := url.Parse(v.selfURL)
	if err != nil {
		return err
	}

	returnToURL.Path = "/steam/oauth2/redirect"
	err = v.store.AddSteamSession(clientID, redirectURL.String(), state)
	if err != nil {
		return err
	}

	redirectQ := returnToURL.Query()
	redirectQ.Add("state", state)
	returnToURL.RawQuery = redirectQ.Encode()
	u, err := url.Parse("https://steamcommunity.com/openid/login")
	if err != nil {
		return err
	}

	queryParams := url.Values{}
	queryParams.Add("openid.ns", "http://specs.openid.net/auth/2.0")
	queryParams.Add("openid.return_to", returnToURL.String())
	queryParams.Add("openid.claimed_id", "http://specs.openid.net/auth/2.0/identifier_select")
	queryParams.Add("openid.identity", "http://specs.openid.net/auth/2.0/identifier_select")
	queryParams.Add("openid.mode", "checkid_setup")
	queryParams.Add("openid.realm", fmt.Sprintf("%s://%s", returnToURL.Scheme, returnToURL.Host))
	u.RawQuery = queryParams.Encode()

	return c.Redirect(http.StatusSeeOther, u.String())

}

func (v *SteamHandler) Redirect(c echo.Context) error {
	steamProfileURL := c.QueryParam("openid.claimed_id")
	parts := strings.Split(steamProfileURL, "/")
	steamID := parts[len(parts)-1]
	signature := c.QueryParam("openid.sig")
	nonce := c.QueryParam("openid.response_nonce")
	redirectURL, err := url.Parse(v.selfURL)
	if err != nil {
		return err
	}

	state := c.QueryParam("state")
	redirectURL.Path = "/steam/oauth2/redirect"
	redirectQ := redirectURL.Query()
	redirectQ.Add("state", state)
	redirectURL.RawQuery = redirectQ.Encode()

	verified := v.verifySignature(signature, nonce, redirectURL.String(), steamProfileURL)
	if verified {
		session, err := v.store.GetSteamSession(state)
		if err != nil {
			v.log.Error("get_steam_session", logger.Field{"err": err})
			return echo.NewHTTPError(http.StatusInternalServerError)
		}

		// TODO: Get from config
		u, err := url.Parse(v.authURL)
		if err != nil {
			v.log.Error("", logger.Field{"err": err})
			return err
		}
		code := createRandomString(32)
		v.log.Info("update_steam_session", logger.Field{"session_id": session.ID, "steam_id": steamID, "code": code})
		err = v.store.UpdateSteamSession(session.ID, steamID, code)
		if err != nil {
			v.log.Error("update_steam_session", logger.Field{"err": err})
			return echo.NewHTTPError(http.StatusInternalServerError)
		}

		queryParams := url.Values{}
		queryParams.Add("state", state)
		queryParams.Add("code", code)
		u.RawQuery = queryParams.Encode()

		return c.Redirect(http.StatusSeeOther, u.String())
	} else {
		return echo.NewHTTPError(http.StatusForbidden)
	}
}

func createRandomString(length int) string {
	var StdChars = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
	return uniuri.NewLenChars(length, StdChars)
}

func (v *SteamHandler) verifySignature(sig, nonce, redirectURL, steamProfileURL string) bool {
	res, err := req.R().
		AddQueryParam("openid.ns", "http://specs.openid.net/auth/2.0").
		AddQueryParam("openid.mode", "check_authentication").
		AddQueryParam("openid.op_endpoint", "https://steamcommunity.com/openid/login").
		AddQueryParam("openid.claimed_id", steamProfileURL).
		AddQueryParam("openid.identity", steamProfileURL).
		AddQueryParam("openid.return_to", redirectURL).
		AddQueryParam("openid.response_nonce", nonce).
		AddQueryParam("openid.assoc_handle", "1234567890").
		AddQueryParam("openid.signed", "signed,op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle").
		AddQueryParam("openid.sig", sig).
		Get(v.baseURL)

	if err != nil {
		return false
	}

	if !res.IsSuccessState() {
		return false
	}

	responseString := res.String()
	lines := strings.Split(responseString, "\n")
	validityLine := lines[1]
	validity := strings.Split(validityLine, ":")
	if validity[0] == "is_valid" && validity[1] == "true" {
		return true
	}

	return false
}

func (v *SteamHandler) TokenExchange(c echo.Context) error {
	if c.FormValue("grant_type") != "authorization_code" {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid grant type")
	}

	clientID := c.FormValue("client_id")
	clientSecret := c.FormValue("client_secret")
	redirectURI := c.FormValue("redirect_uri")
	code := c.FormValue("code")
	session, err := v.store.GetSteamSessionByCode(code)
	if err != nil {
		v.log.Error("get_steam_session_by_code", logger.Field{"err": err, "code": code})
		return echo.NewHTTPError(http.StatusForbidden)
	}

	if clientID != session.ClientID {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid client ID")
	}

	if redirectURI != session.RedirectURI {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid redirect URI")
	}

	if !v.secretKeyKeeper.IsExpectedSecret(clientSecret) {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid client secret")
	}

	apiKey := v.secretKeyKeeper.Get()
	profile, err := v.getSteamProfile(apiKey, session.SteamID)
	if err != nil {
		v.log.Error("get_steam_profile", logger.Field{"err": err})
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	err = v.store.DeleteSteamSession(session.ID)
	if err != nil {
		v.log.Error("delete_steam_session", logger.Field{"err": err})
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	publicClaims := jwt.Claims{
		Subject:   profile.SteamID,
		Issuer:    v.selfURL,
		NotBefore: jwt.NewNumericDate(time.Now()),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Minute * 3)),
		Audience:  jwt.Audience{session.ClientID},
	}

	customClaims := SteamClaims{
		SteamID: profile.SteamID,
		Name:    profile.Name,
		Picture: profile.Avatar,
		AZP:     session.ClientID,
	}

	token, err := jwt.Signed(v.signer).
		Claims(publicClaims).
		Claims(customClaims).
		Serialize()

	if err != nil {
		v.log.Error("create_token", logger.Field{"err": err})
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	return c.JSON(http.StatusOK, Envelope{
		"access_token": token,
		"id_token":     token,
		"expires_in":   time.Minute * 3,
	})

}

func (v *SteamHandler) Verify(c echo.Context) error {
	token := c.QueryParam("token")
	if token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Missing token")
	}

	t, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})

	if err != nil {
		v.log.Error("parse_signed", logger.Field{"err": err})
		return echo.NewHTTPError(http.StatusForbidden)
	}

	publicClaims := jwt.Claims{}
	customClaims := SteamClaims{}
	if err := t.Claims(v.publicKey, &publicClaims, &customClaims); err != nil {
		v.log.Error("claims", logger.Field{"err": err})
		return echo.NewHTTPError(http.StatusForbidden)
	}

	err = publicClaims.Validate(jwt.Expected{})
	if err != nil {
		v.log.Error("validate", logger.Field{"err": err})
		return echo.NewHTTPError(http.StatusForbidden, err.Error())
	}

	return c.JSON(http.StatusOK, VerifyResponseStruct{
		Name:    customClaims.Name,
		Picture: customClaims.Picture,
		ID:      customClaims.SteamID,
		AZP:     customClaims.AZP,
		IAT:     publicClaims.IssuedAt.Time().Unix(),
	})

}

func (v *SteamHandler) getSteamProfile(clientSecret, steamID string) (*SteamPlayer, error) {
	// Get from DB
	profile, err := v.store.GetSteamProfile(steamID)
	if err == nil {
		return profile, nil
	}

	// Otherwise get from API
	u, err := url.Parse("https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/")
	if err != nil {
		return nil, err
	}

	queryParams := url.Values{}
	queryParams.Add("key", clientSecret)
	queryParams.Add("steamids", steamID)
	u.RawQuery = queryParams.Encode()

	response := &SteamProfileResponse{}
	_, err = req.R().SetSuccessResult(&response).Get(u.String())
	if err != nil {
		return nil, err
	}

	// Store in DB
	err = v.store.AddSteamProfile(&response.Response.Players[0])
	if err != nil {
		return nil, err
	}

	return &response.Response.Players[0], nil

}

type SteamClaims struct {
	SteamID string `json:"steam_id,omitempty"`
	Name    string `json:"name,omitempty"`
	Picture string `json:"picture,omitempty"`
	Email   string `json:"email,omitempty"`
	AZP     string `json:"azp,omitempty"`
}

type SteamProfileResponse struct {
	Response SteamResponse `json:"response"`
}

type SteamResponse struct {
	Players []SteamPlayer `json:"players"`
}

type SteamPlayer struct {
	SteamID string `json:"steamid"`
	Avatar  string `json:"avatarmedium"`
	Name    string `json:"personaname"`
}
