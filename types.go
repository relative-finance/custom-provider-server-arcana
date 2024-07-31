package main

type configuration struct {
	ListenPort  string
	RedirectURL string
	KeyFilePath string
	SelfURL     string
	JwtAudience string
	MySQLHost   string
	MySQLPort   string
	MySQLUser   string
	MySQLPass   string
	MySQLDB     string
	Apikey      string
	Verifiers   []ProviderConfig
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
	UserID    string `json:"user_id"`
	LoginID   string `json:"login_id"`
	LoginType string `json:"login_type"`
}

type SteamSession struct {
	ID          int
	SteamID     string
	ClientID    string
	RedirectURI string
	State       string
	Code        string
}
