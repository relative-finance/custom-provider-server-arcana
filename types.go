package main

type configuration struct {
	ListenPort          string
	RedirectURL         string
	KeyFilePath         string
	SelfURL             string
	JwtAudience         string
	MySQLHost           string
	MySQLPort           string
	MySQLUser           string
	MySQLPass           string
	MySQLDB             string
	Apikey              string
	ShowdownUserService string
	Verifiers           []ProviderConfig
	TelegramBotToken    string
}

type ProviderConfig struct {
	Name         string
	IDKey        string
	ClientID     string
	ClientSecret string
	DiscoveryURL string
	Scope        []string
}

type customClaims struct {
	UserID     string `json:"user_id"`
	LoginID    string `json:"login_id"`
	LoginType  string `json:"login_type"`
	LinkedID   string `json:"linked_id"`
	TelegramID string `json:"telegram_id"`
}

type SteamSession struct {
	ID          int
	SteamID     string
	ClientID    string
	RedirectURI string
	State       string
	Code        string
}

type LichessUserInfo struct {
	LichessId    string `json:"lichessId"`
	LichessToken string `json:"lichessToken"`
}

type GetLichessUserInfoRes map[string]LichessUserInfo

type TelegramUser struct {
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	TelegramID string `json:"telegram_id"`
	Username   string `json:"username"`
}
