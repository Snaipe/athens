// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package athens

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"snai.pe/go-htutil"
)

type httpError struct {
	Status  int    `json:"-"`
	Message string `json:"message,omitempty"`
}

func (e *httpError) Error() string {
	return e.Message
}

func newHTTPError(status int, e error) *httpError {
	return &httpError{
		Status:  status,
		Message: e.Error(),
	}
}

type statusSniffer struct {
	http.ResponseWriter
	Status int
}

func (s *statusSniffer) WriteHeader(code int) {
	s.Status = code
	s.ResponseWriter.WriteHeader(code)
}

type Server struct {
	HTTPServer   http.Server
	OpenIDConfig OpenIDConfiguration
	Logger       *slog.Logger

	Connectors        []ConnectorConfig
	Clients           ClientStore
	Minter            TokenMinter      // use OpenIDMinter or AccessRefreshMinter for multi-token responses
	Validator         TokenValidator   // validates our own tokens (introspection, revocation, userinfo)
	ExchangeValidator TokenValidator   // validates foreign tokens for token exchange; nil disables exchange
	ExchangeGuard     ExchangeGuard    // validates exchange permissions (scope, attenuation); nil = strict subset
	UserInfo          UserInfoProvider // optional override for the userinfo endpoint
	Keys              KeyManager
	Store             Store
}

func (s *Server) callbackURL(req *http.Request) string {
	scheme := "https"
	if req.TLS == nil {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/callback", scheme, req.Host)
}

func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateUserCode() (string, error) {
	const charset = "BCDFGHJKLMNPQRSTVWXZ"
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	code := make([]byte, 8)
	for i := range code {
		code[i] = charset[int(buf[i])%len(charset)]
	}
	return string(code[:4]) + "-" + string(code[4:]), nil
}

// Handler returns an http.Handler with all OAuth/OIDC routes registered.
// Use this to mount Athens on an existing mux or listener.
func (s *Server) Handler() http.Handler {

	if s.Logger == nil {
		s.Logger = slog.Default()
	}

	negotiate := func(next func(http.ResponseWriter, *http.Request) error) func(http.ResponseWriter, *http.Request) error {
		return func(resp http.ResponseWriter, req *http.Request) error {
			ctype, _ := htutil.NegotiateContent(req.Header, "Accept", "application/json")
			if ctype == "" {
				return &httpError{Status: http.StatusNotAcceptable}
			}
			return next(resp, req)
		}
	}

	log := func(next func(http.ResponseWriter, *http.Request) error) func(http.ResponseWriter, *http.Request) error {
		return func(resp http.ResponseWriter, req *http.Request) error {
			rw := statusSniffer{ResponseWriter: resp, Status: http.StatusOK}

			start := time.Now()
			err := next(&rw, req)
			duration := time.Since(start)

			level := slog.LevelInfo
			if err != nil {
				level = slog.LevelError
			}

			s.Logger.Log(req.Context(), level, "request",
				"method", req.Method,
				"endpoint", req.URL.EscapedPath(),
				"status", rw.Status,
				"duration", duration.String(),
			)
			return err
		}
	}

	handleErr := func(resp http.ResponseWriter, err error) {
		switch e := err.(type) {
		case nil:
			return
		case *oauthError:
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(e.Status)
			_ = json.NewEncoder(resp).Encode(e)
		case *httpError:
			if e.Message != "" {
				resp.Header().Set("Content-Type", "application/json")
			}
			resp.WriteHeader(e.Status)
			if e.Message != "" {
				_ = json.NewEncoder(resp).Encode(e)
			}
		case *redirectError:
			resp.Header().Set("Location", e.URI())
			resp.WriteHeader(http.StatusFound)
		default:
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(resp).Encode(newHTTPError(http.StatusInternalServerError, err))
		}
	}

	api := func(next func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
		handler := log(negotiate(next))
		return func(resp http.ResponseWriter, req *http.Request) {
			handleErr(resp, handler(resp, req))
		}
	}

	page := func(next func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
		handler := log(next)
		return func(resp http.ResponseWriter, req *http.Request) {
			handleErr(resp, handler(resp, req))
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", api(s.getConfig))
	mux.HandleFunc("GET /connectors", api(s.getConnectors))
	mux.HandleFunc("GET /authorize", page(s.handleAuthorize))
	mux.HandleFunc("POST /authorize", page(s.handleAuthorize))
	mux.HandleFunc("GET /callback", page(s.getCallback))
	mux.HandleFunc("POST /oauth/token", api(s.postToken))
	mux.HandleFunc("GET /oauth/jwks", api(s.getJWKS))
	mux.HandleFunc("GET /userinfo", api(s.getUserInfo))
	mux.HandleFunc("POST /oauth/revoke", api(s.postRevoke))
	mux.HandleFunc("POST /oauth/introspect", api(s.postIntrospect))
	mux.HandleFunc("POST /oauth/device", api(s.postDeviceAuthorize))
	if _, ok := s.Clients.(ClientRegistrar); ok {
		mux.HandleFunc("POST /oauth/register", api(s.postRegister))
		mux.HandleFunc("GET /oauth/register/{client_id}", api(s.getClient))
		mux.HandleFunc("PUT /oauth/register/{client_id}", api(s.putClient))
		mux.HandleFunc("DELETE /oauth/register/{client_id}", api(s.deleteClient))
	}

	return mux
}

func (s *Server) Serve(l net.Listener) error {
	s.HTTPServer.Handler = s.Handler()
	return s.HTTPServer.Serve(l)
}

func (s *Server) connector(id string) (Connector, bool) {
	if id == "" && len(s.Connectors) == 1 {
		return s.Connectors[0].Connector, true
	}
	for i := range s.Connectors {
		if s.Connectors[i].ID == id {
			return s.Connectors[i].Connector, true
		}
	}
	return nil, false
}

func (s *Server) revokeToken(ctx context.Context, token string) {
	if revoker, ok := s.Minter.(TokenRevoker); ok {
		_ = revoker.Revoke(ctx, token)
	}
}

func (s *Server) validateToken(ctx context.Context, token string) (map[string]any, error) {
	if s.Validator == nil {
		return nil, fmt.Errorf("no validator configured")
	}

	pubs, err := s.Keys.PublicKeys(ctx)
	if err != nil {
		return nil, err
	}

	for _, pub := range pubs {
		claims, err := s.Validator.Validate(ctx, pub.Key, token)
		if err == nil {
			return claims, nil
		}
	}
	return nil, fmt.Errorf("token validation failed")
}

func (s *Server) authenticateClient(req *http.Request) (*Client, error) {
	var clientID, clientSecret string

	if id, secret, ok := req.BasicAuth(); ok {
		clientID = id
		clientSecret = secret
	} else {
		clientID = req.Form.Get("client_id")
		clientSecret = req.Form.Get("client_secret")
	}

	if clientID == "" {
		return nil, &oauthError{Status: http.StatusUnauthorized, Code: ErrInvalidClient, Description: "missing client credentials"}
	}

	client, err := s.Clients.GetClient(req.Context(), clientID)
	if err != nil {
		return nil, &oauthError{Status: http.StatusUnauthorized, Code: ErrInvalidClient}
	}

	if !client.Public {
		if err := s.Clients.ValidateSecret(req.Context(), client, clientSecret); err != nil {
			return nil, &oauthError{Status: http.StatusUnauthorized, Code: ErrInvalidClient, Description: "invalid client credentials"}
		}
	}

	return client, nil
}

func (s *Server) getConnectors(resp http.ResponseWriter, req *http.Request) error {
	type connectorInfo struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Icon string `json:"icon,omitempty"`
	}
	out := make([]connectorInfo, len(s.Connectors))
	for i, c := range s.Connectors {
		out[i] = connectorInfo{ID: c.ID, Name: c.Name, Icon: c.Icon}
	}
	resp.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(resp).Encode(out)
}

func (s *Server) getConfig(resp http.ResponseWriter, req *http.Request) error {
	config := s.OpenIDConfig
	issuer := config.Issuer

	if config.AuthorizationEndpoint == "" {
		config.AuthorizationEndpoint = issuer + "/authorize"
	}
	if config.TokenEndpoint == "" {
		config.TokenEndpoint = issuer + "/oauth/token"
	}
	if config.JWKSURI == "" {
		config.JWKSURI = issuer + "/oauth/jwks"
	}
	if config.UserInfoEndpoint == "" {
		config.UserInfoEndpoint = issuer + "/userinfo"
	}
	if _, ok := s.Clients.(ClientRegistrar); ok && config.RegistrationEndpoint == "" {
		config.RegistrationEndpoint = issuer + "/oauth/register"
	}
	if _, ok := s.Store.(DeviceCodeStore); ok && config.DeviceAuthorizationEndpoint == "" {
		config.DeviceAuthorizationEndpoint = issuer + "/oauth/device"
	}

	if config.GrantTypesSupported == nil {
		grants := []string{"authorization_code", "client_credentials", "refresh_token"}
		if _, ok := s.Store.(DeviceCodeStore); ok {
			grants = append(grants, "urn:ietf:params:oauth:grant-type:device_code")
		}
		if s.ExchangeValidator != nil {
			grants = append(grants, "urn:ietf:params:oauth:grant-type:token-exchange")
		}
		config.GrantTypesSupported = grants
	}

	if config.IDTokenSigningAlgValuesSupported == nil && s.Keys != nil {
		if pubs, err := s.Keys.PublicKeys(req.Context()); err == nil {
			seen := map[string]bool{}
			for _, pub := range pubs {
				if pub.Algorithm != "" && !seen[pub.Algorithm] {
					config.IDTokenSigningAlgValuesSupported = append(config.IDTokenSigningAlgValuesSupported, pub.Algorithm)
					seen[pub.Algorithm] = true
				}
			}
		}
	}
	if config.ScopesSupported == nil {
		config.ScopesSupported = []string{"openid", "profile", "email", "phone", "address", "offline_access"}
	}
	if config.TokenEndpointAuthMethodsSupported == nil {
		config.TokenEndpointAuthMethodsSupported = []string{"client_secret_basic", "client_secret_post"}
	}
	if config.ResponseTypesSupported == nil {
		config.ResponseTypesSupported = []string{"code"}
	}
	if config.SubjectTypesSupported == nil {
		config.SubjectTypesSupported = []string{"public"}
	}
	if config.ResponseModesSupported == nil {
		config.ResponseModesSupported = []string{"query", "fragment"}
	}

	return json.NewEncoder(resp).Encode(&config)
}

func (s *Server) handleAuthorize(resp http.ResponseWriter, req *http.Request) error {
	if err := req.ParseForm(); err != nil {
		return newHTTPError(http.StatusBadRequest, err)
	}

	var (
		responseType        = req.Form.Get("response_type")
		responseMode        = ResponseMode(req.Form.Get("response_mode"))
		clientID            = req.Form.Get("client_id")
		redirectURI         = req.Form.Get("redirect_uri")
		scope               = req.Form.Get("scope")
		clientState         = req.Form.Get("state")
		nonce               = req.Form.Get("nonce")
		connection          = req.Form.Get("connection")
		codeChallenge       = req.Form.Get("code_challenge")
		codeChallengeMethod = req.Form.Get("code_challenge_method")
	)

	client, err := s.Clients.GetClient(req.Context(), clientID)
	if err != nil {
		return newHTTPError(http.StatusBadRequest, fmt.Errorf("unknown client"))
	}

	redirect, err := url.Parse(redirectURI)
	if err != nil || !s.validRedirectURI(client, redirectURI) {
		return newHTTPError(http.StatusBadRequest, fmt.Errorf("invalid redirect_uri"))
	}

	conn, ok := s.connector(connection)
	if !ok {
		return newRedirectError(redirect, responseMode, ErrInvalidRequest, "unknown connection", "")
	}

	state, err := generateState()
	if err != nil {
		return newRedirectError(redirect, responseMode, ErrServerError, "", "")
	}

	pending := &PendingAuth{
		State:               state,
		Connection:          connection,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		ResponseType:        responseType,
		ResponseMode:        responseMode,
		Scope:               strings.Split(scope, " "),
		ClientState:         clientState,
		Nonce:               nonce,
		PKCEChallenge:       codeChallenge,
		PKCEChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}

	if err := s.Store.SavePendingAuth(req.Context(), pending); err != nil {
		return newRedirectError(redirect, responseMode, ErrServerError, "", "")
	}

	authURL, err := conn.AuthURL(s.callbackURL(req), state)
	if err != nil {
		return newRedirectError(redirect, responseMode, ErrServerError, "", "")
	}

	resp.Header().Set("Location", authURL)
	resp.WriteHeader(http.StatusFound)
	return nil
}

func (s *Server) getCallback(resp http.ResponseWriter, req *http.Request) error {
	state := req.URL.Query().Get("state")
	if state == "" {
		return newHTTPError(http.StatusBadRequest, fmt.Errorf("missing state"))
	}

	pending, err := s.Store.GetPendingAuth(req.Context(), state)
	if err != nil {
		return newHTTPError(http.StatusBadRequest, fmt.Errorf("invalid or expired state"))
	}

	redirect, _ := url.Parse(pending.RedirectURI)

	if errType := req.URL.Query().Get("error"); errType != "" {
		desc := req.URL.Query().Get("error_description")
		return newRedirectError(redirect, pending.ResponseMode, ErrorType(errType), desc, "")
	}

	code := req.URL.Query().Get("code")
	if code == "" {
		return newRedirectError(redirect, pending.ResponseMode, ErrServerError, "missing code from provider", "")
	}

	conn, ok := s.connector(pending.Connection)
	if !ok {
		return newRedirectError(redirect, pending.ResponseMode, ErrServerError, "", "")
	}

	upstreamSubject, upstreamClaims, err := conn.Exchange(req.Context(), s.callbackURL(req), code)
	if err != nil {
		return newRedirectError(redirect, pending.ResponseMode, ErrAccessDenied, err.Error(), "")
	}

	user, err := s.Store.GetOrCreateUser(req.Context(), pending.Connection, upstreamSubject, upstreamClaims)
	if err != nil {
		return newRedirectError(redirect, pending.ResponseMode, ErrServerError, "", "")
	}

	authCode, err := generateState()
	if err != nil {
		return newRedirectError(redirect, pending.ResponseMode, ErrServerError, "", "")
	}

	if err := s.Store.SaveCode(req.Context(), &AuthCode{
		Code:                authCode,
		ClientID:            pending.ClientID,
		Subject:             user.Subject,
		Scope:               pending.Scope,
		RedirectURI:         pending.RedirectURI,
		Nonce:               pending.Nonce,
		PKCEChallenge:       pending.PKCEChallenge,
		PKCEChallengeMethod: pending.PKCEChallengeMethod,
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}); err != nil {
		return newRedirectError(redirect, pending.ResponseMode, ErrServerError, "", "")
	}

	values := url.Values{}
	values.Set("code", authCode)
	if pending.ClientState != "" {
		values.Set("state", pending.ClientState)
	}

	redirect.RawQuery = values.Encode()
	resp.Header().Set("Location", redirect.String())
	resp.WriteHeader(http.StatusFound)
	return nil
}

func (s *Server) validRedirectURI(client *Client, uri string) bool {
	for _, allowed := range client.RedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

func (s *Server) getUserInfo(resp http.ResponseWriter, req *http.Request) error {
	token := extractBearerToken(req)
	if token == "" {
		return &oauthError{Status: http.StatusUnauthorized, Code: ErrInvalidRequest, Description: "missing bearer token"}
	}

	rawClaims, err := s.validateToken(req.Context(), token)
	if err != nil {
		return &oauthError{Status: http.StatusUnauthorized, Code: ErrInvalidGrant, Description: "invalid token"}
	}

	tok := extractTokenInfo(rawClaims)

	if tok.TokenID != "" {
		if revoked, _ := s.Store.IsRevoked(req.Context(), tok.TokenID); revoked {
			return &oauthError{Status: http.StatusUnauthorized, Code: ErrInvalidGrant, Description: "token has been revoked"}
		}
	}

	if s.UserInfo != nil {
		info, err := s.UserInfo.UserInfo(req.Context(), tok.Subject, tok.Scope)
		if err != nil {
			return &oauthError{Status: http.StatusInternalServerError, Code: ErrServerError}
		}
		resp.Header().Set("Content-Type", "application/json")
		return json.NewEncoder(resp).Encode(info)
	}

	user, err := s.Store.GetUser(req.Context(), tok.Subject)
	if err != nil {
		return &oauthError{Status: http.StatusInternalServerError, Code: ErrServerError}
	}

	info := filterClaims(user.Claims, tok.Scope)
	info["sub"] = user.Subject

	resp.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(resp).Encode(info)
}

func (s *Server) postRevoke(resp http.ResponseWriter, req *http.Request) error {
	if err := req.ParseForm(); err != nil {
		resp.WriteHeader(http.StatusOK)
		return nil
	}

	if _, err := s.authenticateClient(req); err != nil {
		return err
	}

	token := req.Form.Get("token")
	if token == "" {
		resp.WriteHeader(http.StatusOK)
		return nil
	}

	if rawClaims, err := s.validateToken(req.Context(), token); err == nil {
		if tokenID, _ := rawClaims["jti"].(string); tokenID != "" {
			_ = s.Store.RevokeToken(req.Context(), tokenID)
		}
	}

	resp.WriteHeader(http.StatusOK)
	return nil
}

type introspectionResponse struct {
	Active   bool   `json:"active"`
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	Subject  string `json:"sub,omitempty"`
	TokenType string `json:"token_type,omitempty"`
}

func (s *Server) postIntrospect(resp http.ResponseWriter, req *http.Request) error {
	if err := req.ParseForm(); err != nil {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidRequest}
	}

	if _, err := s.authenticateClient(req); err != nil {
		return err
	}

	inactive := introspectionResponse{Active: false}

	token := req.Form.Get("token")
	if token == "" {
		resp.Header().Set("Content-Type", "application/json")
		return json.NewEncoder(resp).Encode(&inactive)
	}

	rawClaims, err := s.validateToken(req.Context(), token)
	if err != nil {
		resp.Header().Set("Content-Type", "application/json")
		return json.NewEncoder(resp).Encode(&inactive)
	}

	tok := extractTokenInfo(rawClaims)

	if tok.TokenID != "" {
		if revoked, _ := s.Store.IsRevoked(req.Context(), tok.TokenID); revoked {
			resp.Header().Set("Content-Type", "application/json")
			return json.NewEncoder(resp).Encode(&inactive)
		}
	}

	resp.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(resp).Encode(&introspectionResponse{
		Active:    true,
		Scope:     strings.Join(tok.Scope, " "),
		Subject:   tok.Subject,
		ClientID:  tok.Audience,
		TokenType: "Bearer",
	})
}

type deviceAuthResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

func (s *Server) postDeviceAuthorize(resp http.ResponseWriter, req *http.Request) error {
	dcs, ok := s.Store.(DeviceCodeStore)
	if !ok {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrUnsupportedGrantType}
	}

	if err := req.ParseForm(); err != nil {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidRequest}
	}

	clientID := req.Form.Get("client_id")
	if _, err := s.Clients.GetClient(req.Context(), clientID); err != nil {
		return &oauthError{Status: http.StatusUnauthorized, Code: ErrInvalidClient}
	}

	deviceCode, err := generateState()
	if err != nil {
		return &oauthError{Status: http.StatusInternalServerError, Code: ErrServerError}
	}

	userCode, err := generateUserCode()
	if err != nil {
		return &oauthError{Status: http.StatusInternalServerError, Code: ErrServerError}
	}

	scope := strings.Split(req.Form.Get("scope"), " ")
	expiresIn := 600

	auth := &DeviceAuth{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Scope:      scope,
		ExpiresAt:  time.Now().Add(time.Duration(expiresIn) * time.Second),
		Interval:   5,
	}

	if err := dcs.SaveDeviceAuth(req.Context(), auth); err != nil {
		return &oauthError{Status: http.StatusInternalServerError, Code: ErrServerError}
	}

	resp.Header().Set("Content-Type", "application/json")
	resp.Header().Set("Cache-Control", "no-store")
	return json.NewEncoder(resp).Encode(&deviceAuthResponse{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationURI: s.OpenIDConfig.DeviceAuthorizationEndpoint,
		ExpiresIn:       expiresIn,
		Interval:        5,
	})
}

type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
}

func (s *Server) clientRegistrationURI(clientID string) string {
	return s.OpenIDConfig.Issuer + "/oauth/register/" + clientID
}

func (s *Server) postRegister(resp http.ResponseWriter, req *http.Request) error {
	registrar, ok := s.Clients.(ClientRegistrar)
	if !ok {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidRequest, Description: "dynamic registration not supported"}
	}

	var meta ClientMetadata
	if err := json.NewDecoder(req.Body).Decode(&meta); err != nil {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidRequest, Description: "malformed request body"}
	}

	if len(meta.RedirectURIs) == 0 {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidRequest, Description: "redirect_uris required"}
	}

	client, err := registrar.RegisterClient(req.Context(), &meta)
	if err != nil {
		return &oauthError{Status: http.StatusInternalServerError, Code: ErrServerError}
	}

	resp.Header().Set("Content-Type", "application/json")
	resp.WriteHeader(http.StatusCreated)
	return json.NewEncoder(resp).Encode(&registrationResponse{
		ClientID:                client.ID,
		ClientSecret:            client.Secret,
		ClientIDIssuedAt:        time.Now().Unix(),
		ClientSecretExpiresAt:   0,
		RegistrationAccessToken: client.RegistrationToken,
		RegistrationClientURI:   s.clientRegistrationURI(client.ID),
		RedirectURIs:            client.RedirectURIs,
		TokenEndpointAuthMethod: client.TokenEndpointAuth,
		GrantTypes:              client.GrantTypes,
		ResponseTypes:           client.ResponseTypes,
		Scope:                   strings.Join(client.Scope, " "),
		ClientName:              meta.ClientName,
	})
}

func (s *Server) authenticateRegistrationToken(req *http.Request) (*Client, error) {
	token := extractBearerToken(req)
	if token == "" {
		return nil, &oauthError{Status: http.StatusUnauthorized, Code: ErrInvalidClient, Description: "missing registration access token"}
	}

	clientID := req.PathValue("client_id")
	client, err := s.Clients.GetClient(req.Context(), clientID)
	if err != nil {
		return nil, &oauthError{Status: http.StatusUnauthorized, Code: ErrInvalidClient}
	}

	if client.RegistrationToken == "" || client.RegistrationToken != token {
		return nil, &oauthError{Status: http.StatusUnauthorized, Code: ErrInvalidClient, Description: "invalid registration access token"}
	}

	return client, nil
}

func (s *Server) getClient(resp http.ResponseWriter, req *http.Request) error {
	client, err := s.authenticateRegistrationToken(req)
	if err != nil {
		return err
	}

	resp.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(resp).Encode(&registrationResponse{
		ClientID:                client.ID,
		ClientSecret:            client.Secret,
		ClientIDIssuedAt:        0,
		ClientSecretExpiresAt:   0,
		RegistrationAccessToken: client.RegistrationToken,
		RegistrationClientURI:   s.clientRegistrationURI(client.ID),
		RedirectURIs:            client.RedirectURIs,
		TokenEndpointAuthMethod: client.TokenEndpointAuth,
		GrantTypes:              client.GrantTypes,
		ResponseTypes:           client.ResponseTypes,
		Scope:                   strings.Join(client.Scope, " "),
	})
}

func (s *Server) putClient(resp http.ResponseWriter, req *http.Request) error {
	registrar, ok := s.Clients.(ClientRegistrar)
	if !ok {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidRequest, Description: "dynamic registration not supported"}
	}

	client, err := s.authenticateRegistrationToken(req)
	if err != nil {
		return err
	}

	var meta ClientMetadata
	if err := json.NewDecoder(req.Body).Decode(&meta); err != nil {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidRequest, Description: "malformed request body"}
	}

	updated, err := registrar.UpdateClient(req.Context(), client.ID, &meta)
	if err != nil {
		return &oauthError{Status: http.StatusInternalServerError, Code: ErrServerError}
	}

	resp.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(resp).Encode(&registrationResponse{
		ClientID:                updated.ID,
		ClientSecret:            updated.Secret,
		ClientIDIssuedAt:        0,
		ClientSecretExpiresAt:   0,
		RegistrationAccessToken: updated.RegistrationToken,
		RegistrationClientURI:   s.clientRegistrationURI(updated.ID),
		RedirectURIs:            updated.RedirectURIs,
		TokenEndpointAuthMethod: updated.TokenEndpointAuth,
		GrantTypes:              updated.GrantTypes,
		ResponseTypes:           updated.ResponseTypes,
		Scope:                   strings.Join(updated.Scope, " "),
	})
}

func (s *Server) deleteClient(resp http.ResponseWriter, req *http.Request) error {
	registrar, ok := s.Clients.(ClientRegistrar)
	if !ok {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidRequest, Description: "dynamic registration not supported"}
	}

	client, err := s.authenticateRegistrationToken(req)
	if err != nil {
		return err
	}

	if err := registrar.DeleteClient(req.Context(), client.ID); err != nil {
		return &oauthError{Status: http.StatusInternalServerError, Code: ErrServerError}
	}

	resp.WriteHeader(http.StatusNoContent)
	return nil
}

func extractBearerToken(req *http.Request) string {
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}
