package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/BurntSushi/toml"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"

	"golang.org/x/oauth2"
)

type Proxy struct {
	config    *Config
	oauth     *oauth2.Config
	upstreams []*Upstream
	store     sessions.Store

	CookieName    string
	SessionPath   string
	AuthorizePath string
	CallbackPath  string
}

func newSessionStore(cfg *Config) sessions.Store {
	// Use the convenience function securecookie.GenerateRandomKey() to create strong keys.
	store := sessions.NewCookieStore(
		[]byte(cfg.Server.SecretKey), // authentication key (validates cookie)
		nil, // encryption key: nil = no encryption
	)
	store.Options = &sessions.Options{
		HttpOnly: true,
		Secure:   cfg.Server.Secure,
	}

	return store
}

func NewProxy(cfg *Config) *Proxy {
	store := newSessionStore(cfg)
	upstreams := make([]*Upstream, 0)
	for _, props := range cfg.Upstream {
		addr, err := url.Parse(props.Address)
		if err != nil {
			log.Panicf("error creating proxy: %s", err)
		}
		u := &Upstream{
			prefix:  props.Prefix,
			url:     addr,
			handler: httputil.NewSingleHostReverseProxy(addr),
		}
		upstreams = append(upstreams, u)
	}

	p := &Proxy{
		config: cfg,
		oauth: &oauth2.Config{
			ClientID:     cfg.Oauth.ClientID,
			ClientSecret: cfg.Oauth.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  cfg.Oauth.AuthURL,
				TokenURL: cfg.Oauth.TokenURL,
			},
			Scopes: cfg.Oauth.Scopes,
		},
		upstreams: upstreams,
		store:     store,

		CookieName:    "proxy-session",
		SessionPath:   "/session",
		AuthorizePath: "/authorize",
		CallbackPath:  "/callback",
	}
	p.oauth.RedirectURL = p.oauthRedirectURI()

	return p
}

func (p *Proxy) setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", p.config.Server.AllowedOrigin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "3600") // (seconds)
	w.Header().Set("Vary", "Origin")
}

func (p *Proxy) Options(rw http.ResponseWriter, req *http.Request) {
	p.setCORSHeaders(rw)
}

// Proxy request to appropriate upstream, or render 404
func (p *Proxy) Proxy(rw http.ResponseWriter, req *http.Request) {
	for _, upstream := range p.upstreams {
		if upstream.Matches(req.URL.Path) {
			p.Send(rw, req, upstream)
			return
		}
	}

	p.Error(rw, req, http.StatusNotFound, "not found")
}

// Rewrite request, sign and send to specified upstream
func (p *Proxy) Send(rw http.ResponseWriter, req *http.Request, upstream http.Handler) {
	session, _ := p.store.Get(req, p.CookieName)

	if session.Values["access_token"] != nil && session.Values["refresh_token"] != nil {
		cached := &oauth2.Token{
			AccessToken:  session.Values["access_token"].(string),
			RefreshToken: session.Values["refresh_token"].(string),
		}
		source := p.oauth.TokenSource(oauth2.NoContext, cached)
		token, err := source.Token()
		if err != nil {
			// Log and skip auth step
			log.Print("failed to generate token object from stored credentials - corrupt session?")
		} else {
			token.SetAuthHeader(req)
		}
	}

	upstream.ServeHTTP(rw, req)
}

// Initialize new session, exchanging basic auth for access and refresh tokens
func (p *Proxy) CreateSession(rw http.ResponseWriter, req *http.Request) {
	session, _ := p.store.Get(req, p.CookieName)

	email, password, ok := req.BasicAuth()
	if !ok {
		rw.Header().Add("WWW-Authenticate", `Basic realm="oauth-token-proxy"`)
		p.Error(rw, req, 401, "unauthorized")
		return
	}

	token, err := p.oauth.PasswordCredentialsToken(oauth2.NoContext, email, password)
	if err != nil {
		log.Printf("OAuth token fetch error: %v", err)
		rw.Header().Add("WWW-Authenticate", `Basic realm="oauth-token-proxy"`)
		p.Error(rw, req, 401, "unauthorized")
		return
	}

	session.Values["access_token"] = token.AccessToken
	session.Values["refresh_token"] = token.RefreshToken

	session.Save(req, rw)
	rw.WriteHeader(201)
}

// Expire the session cookie
func (p *Proxy) DestroySession(rw http.ResponseWriter, req *http.Request) {
	session, _ := p.store.Get(req, p.CookieName)
	session.Options.MaxAge = -1 // MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0'.
	session.Save(req, rw)
}

// Handle requests for the session endpoint
func (p *Proxy) ManageSession(rw http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "PUT":
		p.CreateSession(rw, req)
	case "DELETE":
		p.DestroySession(rw, req)
	default:
		p.Error(rw, req, http.StatusNotFound, "not found")
	}
}

func (p *Proxy) oauthRedirectURI() string {
	baseUrl, err := url.Parse(p.config.Server.BaseURL)
	if err != nil {
		log.Panicf("failed parsing server base URL: %s", err)
	}

	if baseUrl.Scheme == "" {
		baseUrl.Scheme = "https"
	}

	cbPath, err := url.Parse(p.CallbackPath)
	if err != nil {
		log.Panicf("failed parsing OAuth callback path: %s", err)
	}

	return baseUrl.ResolveReference(cbPath).String()
}

// create authorization request and redirect to the OAuth authorize endpoint
func (p *Proxy) Authorize(rw http.ResponseWriter, req *http.Request) {
	session, _ := p.store.Get(req, p.CookieName)

	// CSRF protection
	state, err := RandomString(24) // base64 is 6 bits of entropy per character
	if err != nil {
		log.Printf("failed to generate secure CSRF token: %s", err)
		p.Error(rw, req, 500, "internal server error")
		return
	}

	session.Values["state"] = state
	session.Save(req, rw)

	http.Redirect(rw, req, p.oauth.AuthCodeURL(state), 302)
}

func (p *Proxy) Callback(rw http.ResponseWriter, req *http.Request) {
	session, _ := p.store.Get(req, p.CookieName)

	err := req.ParseForm()
	if err != nil {
		log.Printf("failed to parse callback response body: %s", err)
		p.Error(rw, req, 400, "invalid request")
		return
	}

	values := req.Form
	if len(values["code"]) != 1 || len(values["state"]) != 1 {
		log.Printf("invalid callback response body: %d code fields, %d state fields", len(values["code"]), len(values["state"]))
		p.Error(rw, req, 400, "invalid request")
		return
	}

	code := values["code"][0]
	state := values["state"][0]

	// CSRF protection
	if state != session.Values["state"] {
		log.Printf("CSRF violation! state parameter did not match session value")
		p.Error(rw, req, 400, "invalid request")
		return
	}
	delete(session.Values, "state")

	token, err := p.oauth.Exchange(oauth2.NoContext, code)
	if err != nil {
		log.Printf("failed to exchange code for token: %s", err)
		session.Save(req, rw)
		p.Error(rw, req, 400, "invalid request")
		return
	}

	session.Values["access_token"] = token.AccessToken
	session.Values["refresh_token"] = token.RefreshToken
	session.Save(req, rw)

	http.Redirect(rw, req, p.config.Server.RedirectURL, 302)
}

// Render a JSON-formatted error page
func (p *Proxy) Error(rw http.ResponseWriter, req *http.Request, code int, message string) {
	body := fmt.Sprintf(`{"error":%q}`, message)
	rw.Header().Add("Content-Type", "application/json")
	rw.WriteHeader(code)
	rw.Write([]byte(body))
	rw.Write([]byte("\n"))
}

func (p *Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Method == "OPTIONS" {
		p.Options(rw, req)
		return
	}

	p.setCORSHeaders(rw)
	switch req.URL.Path {
	case p.SessionPath:
		p.ManageSession(rw, req)
	case p.AuthorizePath:
		p.Authorize(rw, req)
	case p.CallbackPath:
		p.Callback(rw, req)
	//case p.RegistrationEndpoint:
	// get access token via client credentials grant
	// use client access token as auth to hit backend api
	default:
		p.Proxy(rw, req)
	}
}

func newJsonVerifier(next http.Handler) http.Handler {
	return &ContentTypeVerifier{ContentType: "application/json", Next: next}
}

var configFilePath = flag.String("c", "/etc/oauth-token-proxy/proxy.ini", "path to config file")

func main() {
	flag.Parse()
	var cfg Config
	_, err := toml.DecodeFile(*configFilePath, &cfg)
	if err != nil {
		log.Fatal("Failed reading config file:", err)
	}

	if cfg.Log.Path != "" {
		lf, err := os.Create(cfg.Log.Path)
		if err != nil {
			log.Fatal("Failed opening log file:", err)
		}
		log.SetOutput(lf)
	}

	if cfg.Server.BaseURL == "" {
		log.Fatal("Missing required base-url setting")
	}

	// CSRF defeat: JSON-only API (reject non-JSON content types)
	s := http.Server{
		Addr:    cfg.Server.Bind,
		Handler: newJsonVerifier(context.ClearHandler(NewProxy(&cfg))),
	}

	log.Println("Proxy server listening on", cfg.Server.Bind)
	err = s.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
