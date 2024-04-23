package main

type configuration struct {
	ListenPort  string
	RedirectURL string
	KeyFilePath string
	SelfURL     string
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
