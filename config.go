package main

type Config struct {
	Server struct {
		BaseURL   string `toml:"base-url"`
		Bind      string
		SecretKey string `toml:"secret-key"`
		Secure    bool

		RedirectURL string `toml:"redirect-url"`

		AllowedOrigin string `toml:"allowed-origin"`
	}

	Oauth struct {
		ClientID     string `toml:"client-id"`
		ClientSecret string `toml:"client-secret"`
		Scopes       []string

		AuthURL  string `toml:"auth-url"`
		TokenURL string `toml:"token-url"`
	}

	Upstream map[string]struct {
		Address string
		Prefix  string
	}

	Log struct {
		Path string
	}
}
