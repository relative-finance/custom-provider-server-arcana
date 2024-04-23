package main

import (
	"errors"

	"github.com/imroc/req/v3"
	"golang.org/x/oauth2"
)

type OAuth2Config struct {
	oauth2.Config
	userInfoURL string
	provider    string
}

var EpicEndpoint = oauth2.Endpoint{
	AuthURL:   "https://www.epicgames.com/id/authorize",
	TokenURL:  "https://api.epicgames.dev/epic/oauth/v1/token",
	AuthStyle: oauth2.AuthStyleInHeader,
}

var TwitchEndpoint = oauth2.Endpoint{
	AuthURL:  "https://id.twitch.tv/oauth2/authorize",
	TokenURL: "https://id.twitch.tv/oauth2/token",
}

type GoogleUserInfoRes struct {
	Email    string `json:"email"`
	Verified bool   `json:"email_verified"`
}

type EpicUserInfoRes struct {
	Sub string `json:"sub"`
}

type TwitchUserInfo struct {
	Data []TwitchUserInfoInternal `json:"data"`
}

type TwitchUserInfoInternal struct {
	Email string `json:"email"`
	ID    string `json:"id"`
}

func (c *OAuth2Config) getUserInfo(token string) (string, error) {
	switch c.provider {
	case "google":
		var info GoogleUserInfoRes
		res, err := req.R().
			SetQueryParam("access_token", token).
			SetSuccessResult(&info).
			Get(c.userInfoURL)
		if err != nil {
			return "", err
		}
		if res.IsErrorState() {
			return "", errors.New("error during userInfo API call")
		}
		if !info.Verified {
			return "", errors.New("email is not verified")
		}
		return info.Email, nil
	case "epic":
		var info EpicUserInfoRes
		res, err := req.R().
			SetBearerAuthToken(token).
			SetSuccessResult(&info).
			Get(c.userInfoURL)
		if err != nil {
			return "", err
		}
		if res.IsErrorState() {
			return "", errors.New("error during userInfo API call")
		}
		return info.Sub, nil
	case "twitch":
		var info TwitchUserInfo

		res, err := req.R().
			SetHeader("Client-ID", c.ClientID).
			SetBearerAuthToken(token).
			SetSuccessResult(&info).
			Get(c.userInfoURL)

		if err != nil {

			return "", err

		}

		if res.IsErrorState() {

			return "", errors.New("error during userInfo API call")

		}

		if info.Data[0].Email != "" {

			return info.Data[0].Email, nil

		}

		return info.Data[0].ID, nil
	}
	return "", errors.New("provider not found")
}
