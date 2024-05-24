package main

import "net/url"

const GOOGLE_USER_INFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
const EPIC_USER_INFO_URL = "https://api.epicgames.dev/epic/oauth/v1/userInfo"
const TWITCH_USER_INFO_URL = "https://api.twitch.tv/helix/users"

func getSteamUserInfoURL(baseURL string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		panic("invalid baseURL steam")
	}
	u.Path = "/steam/oauth2/verify"
	return u.String()
}

// ... Add more info urls
