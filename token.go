// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package athens

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)


func (s *Server) postToken(resp http.ResponseWriter, req *http.Request) error {
	if err := req.ParseForm(); err != nil {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidRequest, Description: "malformed request body"}
	}

	switch req.Form.Get("grant_type") {
	case "authorization_code":
		return s.handleAuthorizationCode(resp, req)
	case "refresh_token":
		return s.handleRefreshToken(resp, req)
	case "client_credentials":
		return s.handleClientCredentials(resp, req)
	case "urn:ietf:params:oauth:grant-type:device_code":
		return s.handleDeviceCode(resp, req)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		return s.handleTokenExchange(resp, req)
	default:
		return &oauthError{Status: http.StatusBadRequest, Code: ErrUnsupportedGrantType}
	}
}

func (s *Server) handleAuthorizationCode(resp http.ResponseWriter, req *http.Request) error {
	client, err := s.authenticateClient(req)
	if err != nil {
		return err
	}

	authCode, err := s.Store.RedeemCode(req.Context(), req.Form.Get("code"))
	if err != nil {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidGrant, Description: "invalid or expired authorization code"}
	}

	if authCode.ClientID != client.ID {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidGrant, Description: "client mismatch"}
	}

	if authCode.RedirectURI != req.Form.Get("redirect_uri") {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidGrant, Description: "redirect_uri mismatch"}
	}

	if authCode.PKCEChallenge != "" {
		verifier := req.Form.Get("code_verifier")
		if verifier == "" {
			return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidGrant, Description: "code_verifier required"}
		}
		if !verifyPKCE(authCode.PKCEChallenge, authCode.PKCEChallengeMethod, verifier) {
			return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidGrant, Description: "PKCE verification failed"}
		}
	}

	return s.issueTokens(resp, req, client, authCode.Subject, authCode.Scope, authCode.Nonce, "authorization_code")
}

func (s *Server) handleRefreshToken(resp http.ResponseWriter, req *http.Request) error {
	client, err := s.authenticateClient(req)
	if err != nil {
		return err
	}

	refreshToken := req.Form.Get("refresh_token")

	claims, err := s.validateToken(req.Context(), refreshToken)
	if err != nil {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidGrant, Description: "invalid refresh token"}
	}

	info := extractTokenInfo(claims)

	if info.Audience != client.ID {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidGrant, Description: "client mismatch"}
	}

	s.revokeToken(req.Context(), refreshToken)

	scope := info.Scope
	if requested := req.Form.Get("scope"); requested != "" {
		scope = strings.Split(requested, " ")
	}

	return s.issueTokens(resp, req, client, info.Subject, scope, "", "refresh_token")
}

func (s *Server) handleClientCredentials(resp http.ResponseWriter, req *http.Request) error {
	client, err := s.authenticateClient(req)
	if err != nil {
		return err
	}

	if client.Public {
		return &oauthError{Status: http.StatusUnauthorized, Code: ErrInvalidClient, Description: "public clients cannot use client_credentials"}
	}

	scope := strings.Split(req.Form.Get("scope"), " ")

	_, key, err := s.Keys.CurrentKey(req.Context())
	if err != nil {
		return &oauthError{Status: http.StatusInternalServerError, Code: ErrServerError}
	}

	tokenID, _ := generateState()
	claims := buildTokenClaims(tokenID, client.ID, client.ID, scope, "", nil)

	result, err := s.Minter.Mint(req.Context(), key, TokenTypeAccessToken, claims)
	if err != nil {
		return &oauthError{Status: http.StatusInternalServerError, Code: ErrServerError}
	}

	return s.writeTokenResponse(resp, result)
}

func (s *Server) handleDeviceCode(resp http.ResponseWriter, req *http.Request) error {
	dcs, ok := s.Store.(DeviceCodeStore)
	if !ok {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrUnsupportedGrantType}
	}

	clientID := req.Form.Get("client_id")
	if clientID == "" {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidClient}
	}

	deviceCode := req.Form.Get("device_code")
	if deviceCode == "" {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidGrant}
	}

	auth, err := dcs.GetDeviceAuth(req.Context(), deviceCode)
	if err != nil {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidGrant}
	}

	if auth.ClientID != clientID {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidGrant}
	}

	if time.Now().After(auth.ExpiresAt) {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrExpiredToken}
	}

	if !auth.Approved {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrAuthorizationPending}
	}

	client, err := s.Clients.GetClient(req.Context(), clientID)
	if err != nil {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidClient}
	}

	return s.issueTokens(resp, req, client, auth.Subject, auth.Scope, "", "device_code")
}

func (s *Server) handleTokenExchange(resp http.ResponseWriter, req *http.Request) error {
	if s.ExchangeValidator == nil {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrUnsupportedGrantType}
	}

	client, err := s.authenticateClient(req)
	if err != nil {
		return err
	}

	subjectToken := req.Form.Get("subject_token")
	if subjectToken == "" {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidRequest, Description: "subject_token required"}
	}

	pubs, err := s.Keys.PublicKeys(req.Context())
	if err != nil {
		return &oauthError{Status: http.StatusInternalServerError, Code: ErrServerError}
	}

	var rawClaims map[string]any
	for _, pub := range pubs {
		rawClaims, err = s.ExchangeValidator.Validate(req.Context(), pub.Key, subjectToken)
		if err == nil {
			break
		}
	}
	if rawClaims == nil {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidGrant, Description: "invalid subject_token"}
	}

	info := extractTokenInfo(rawClaims)

	if info.TokenID != "" {
		revoked, _ := s.Store.IsRevoked(req.Context(), info.TokenID)
		if revoked {
			return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidGrant, Description: "subject_token has been revoked"}
		}
	}

	scope := info.Scope
	if requested := req.Form.Get("scope"); requested != "" {
		scope = strings.Split(requested, " ")
	}

	if s.ExchangeGuard != nil {
		if err := s.ExchangeGuard.CanExchange(req.Context(), subjectToken, scope, info.Scope); err != nil {
			return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidGrant, Description: err.Error()}
		}
	} else {
		if err := defaultScopeCheck(scope, info.Scope); err != nil {
			return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidScope, Description: err.Error()}
		}
	}

	audience := client.ID
	if requested := req.Form.Get("audience"); requested != "" {
		audience = requested
	} else if info.Audience != "" {
		audience = info.Audience
	}

	_, key, err := s.Keys.CurrentKey(req.Context())
	if err != nil {
		return &oauthError{Status: http.StatusInternalServerError, Code: ErrServerError}
	}

	requestedType := req.Form.Get("requested_token_type")
	if requestedType == "" {
		requestedType = TokenTypeAccessToken
	}

	tokenID, _ := generateState()
	claims := buildTokenClaims(tokenID, info.Subject, audience, scope, "", nil)

	// Pass through non-standard form parameters as claims so minters
	// can route and include them (e.g. build_id for build tokens).
	standard := map[string]bool{
		"grant_type": true, "subject_token": true, "subject_token_type": true,
		"requested_token_type": true, "audience": true, "scope": true,
		"client_id": true, "client_secret": true,
	}
	for k, vs := range req.Form {
		if !standard[k] && len(vs) > 0 {
			claims[k] = vs[0]
		}
	}

	result, err := s.Minter.Mint(req.Context(), key, requestedType, claims)
	if err != nil {
		return &oauthError{Status: http.StatusBadRequest, Code: ErrInvalidRequest, Description: "unsupported requested_token_type"}
	}

	_ = s.Store.RegisterToken(req.Context(), &TokenRecord{
		TokenID:  tokenID,
		Subject:  info.Subject,
		ClientID: client.ID,
		Scope:    scope,
		Grant:    "token-exchange",
		IssuedAt: time.Now(),
	})

	return s.writeTokenResponse(resp, result)
}

func (s *Server) issueTokens(resp http.ResponseWriter, req *http.Request, client *Client, subject string, scope []string, nonce string, grant string) error {
	user, err := s.Store.GetUser(req.Context(), subject)
	if err != nil {
		return &oauthError{Status: http.StatusInternalServerError, Code: ErrServerError}
	}

	userClaims := filterClaims(user.Claims, scope)

	_, key, err := s.Keys.CurrentKey(req.Context())
	if err != nil {
		return &oauthError{Status: http.StatusInternalServerError, Code: ErrServerError}
	}

	tokenID, _ := generateState()
	claims := buildTokenClaims(tokenID, subject, client.ID, scope, nonce, userClaims)

	result, err := s.Minter.Mint(req.Context(), key, TokenTypeAccessToken, claims)
	if err != nil {
		return &oauthError{Status: http.StatusInternalServerError, Code: ErrServerError}
	}

	_ = s.Store.RegisterToken(req.Context(), &TokenRecord{
		TokenID:  tokenID,
		Subject:  subject,
		ClientID: client.ID,
		Scope:    scope,
		Grant:    grant,
		IssuedAt: time.Now(),
	})

	return s.writeTokenResponse(resp, result)
}

func (s *Server) writeTokenResponse(resp http.ResponseWriter, result any) error {
	resp.Header().Set("Content-Type", "application/json")
	resp.Header().Set("Cache-Control", "no-store")
	resp.Header().Set("Pragma", "no-cache")
	return json.NewEncoder(resp).Encode(result)
}

func defaultScopeCheck(requested, granted []string) error {
	allowed := make(map[string]bool, len(granted))
	for _, s := range granted {
		allowed[s] = true
	}
	for _, s := range requested {
		if !allowed[s] {
			return fmt.Errorf("scope %q not in original token", s)
		}
	}
	return nil
}

func containsScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}
