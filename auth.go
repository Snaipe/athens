// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package athens

import (
	"context"
	"crypto"
	"fmt"
	"time"
)

// ConnectorConfig associates a connector with display metadata for
// the login page.
type ConnectorConfig struct {
	ID        string
	Name      string
	Icon      string
	Connector Connector
}

// Connector authenticates users via an external identity provider.
// Implementations use only basic types so that connector sub-modules
// need not depend on Athens.
type Connector interface {
	// AuthURL returns the URL to redirect the user to for authentication.
	// callbackURL is Athens' callback endpoint; the upstream provider should
	// redirect back to it. state is an opaque token that must be forwarded
	// as the "state" parameter in the upstream authorization request.
	// The connector uses its own configured scopes for the upstream request;
	// the client's requested scopes are Athens' concern, not the connector's.
	AuthURL(callbackURL string, state string) (string, error)

	// Exchange trades an authorization code from the upstream provider for
	// a user identity. It returns the subject identifier and a claims map.
	// callbackURL must match the value used in AuthURL.
	Exchange(ctx context.Context, callbackURL string, code string) (string, map[string]any, error)
}

// Standard token type URIs from RFC 8693.
const (
	TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken      = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeJWT          = "urn:ietf:params:oauth:token-type:jwt"
)

// TokenMinter produces tokens. The returned value is inspected via
// structural interfaces — Athens looks for Token()/TTL() on simple
// results, and AccessToken()/IDToken()/RefreshToken() on composite
// results. Minter sub-modules need not import Athens.
//
// tokenType is the requested token type URI (from RFC 8693
// requested_token_type). The result should expose URI() string for
// the issued_token_type response field.
type TokenMinter interface {
	Mint(ctx context.Context, key crypto.Signer, tokenType string, claims map[string]any) (any, error)
}

// TokenValidator parses and validates tokens previously issued by a
// TokenMinter. Returns the claims map from the token.
type TokenValidator interface {
	Validate(ctx context.Context, key crypto.PublicKey, token string) (map[string]any, error)
}

// ExchangeGuard validates whether a token exchange should proceed.
// Implementations check token properties (e.g. reject attenuated biscuits)
// and scope policies (e.g. requested scopes must be a subset of granted,
// or custom hierarchy rules). Set on the Server's ScopePolicy field.
// If not set, Athens uses strict scope subset checking and permits all
// token formats.
type ExchangeGuard interface {
	CanExchange(ctx context.Context, token string, requestedScope []string, grantedScope []string) error
}

// TokenRevoker is optionally implemented by minters that support
// revocation (e.g. the opaque minter). Athens calls this during
// refresh token rotation to invalidate the old token.
type TokenRevoker interface {
	Revoke(ctx context.Context, token string) error
}

// MultiValidator tries each validator in order, returning the first
// successful result.
type MultiValidator []TokenValidator

func (mv MultiValidator) Validate(ctx context.Context, key crypto.PublicKey, token string) (map[string]any, error) {
	var lastErr error
	for _, v := range mv {
		claims, err := v.Validate(ctx, key, token)
		if err == nil {
			return claims, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no validators configured")
}

// OpenIDMinter issues access tokens, plus ID tokens when the "openid"
// scope is present and refresh tokens when "offline_access" is present.
type OpenIDMinter struct {
	Access  TokenMinter
	ID      TokenMinter
	Refresh TokenMinter
}

func (m OpenIDMinter) Mint(ctx context.Context, key crypto.Signer, tokenType string, claims map[string]any) (any, error) {
	// Non-empty tokenType beyond the default: route by role
	if tokenType != "" && tokenType != TokenTypeAccessToken {
		switch tokenType {
		case TokenTypeIDToken, TokenTypeJWT:
			if m.ID != nil {
				return m.ID.Mint(ctx, key, tokenType, claims)
			}
		case TokenTypeRefreshToken:
			if m.Refresh != nil {
				return m.Refresh.Mint(ctx, key, tokenType, claims)
			}
		}
		return nil, fmt.Errorf("unsupported token type: %s", tokenType)
	}

	// Normal flow: produce full token set
	accessResult, err := m.Access.Mint(ctx, key, TokenTypeAccessToken, claims)
	if err != nil {
		return nil, err
	}

	token, ttl, uri := extractSingleToken(accessResult)
	set := &tokenSet{
		AccessToken:     token,
		IssuedTokenType: uri,
		TokenType:       "Bearer",
		ExpiresIn:       int(ttl.Seconds()),
		Scope:           joinScope(claims["scope"]),
	}

	scopes := extractScope(claims["scope"])

	if containsScope(scopes, "openid") && m.ID != nil {
		idResult, err := m.ID.Mint(ctx, key, TokenTypeIDToken, claims)
		if err != nil {
			return nil, err
		}
		idToken, _, idURI := extractSingleToken(idResult)
		if idURI != "" && idURI != TokenTypeJWT {
			return nil, fmt.Errorf("ID token minter must produce JWTs (URI %s), got %s", TokenTypeJWT, idURI)
		}
		set.IDToken = idToken
	}

	if containsScope(scopes, "offline_access") && m.Refresh != nil {
		refreshResult, err := m.Refresh.Mint(ctx, key, TokenTypeRefreshToken, claims)
		if err != nil {
			return nil, err
		}
		set.RefreshToken, _, _ = extractSingleToken(refreshResult)
	}

	return set, nil
}

func (m OpenIDMinter) Validate(ctx context.Context, key crypto.PublicKey, token string) (map[string]any, error) {
	for _, sub := range []TokenMinter{m.Access, m.ID, m.Refresh} {
		if v, ok := sub.(TokenValidator); ok {
			if claims, err := v.Validate(ctx, key, token); err == nil {
				return claims, nil
			}
		}
	}
	return nil, fmt.Errorf("validation failed")
}

func (m OpenIDMinter) Revoke(ctx context.Context, token string) error {
	if r, ok := m.Refresh.(TokenRevoker); ok {
		return r.Revoke(ctx, token)
	}
	return nil
}

// AccessRefreshMinter issues access tokens, plus refresh tokens when
// the "offline_access" scope is present.
type AccessRefreshMinter struct {
	Access  TokenMinter
	Refresh TokenMinter
}

func (m AccessRefreshMinter) Mint(ctx context.Context, key crypto.Signer, tokenType string, claims map[string]any) (any, error) {
	if tokenType != "" && tokenType != TokenTypeAccessToken {
		switch tokenType {
		case TokenTypeRefreshToken:
			if m.Refresh != nil {
				return m.Refresh.Mint(ctx, key, tokenType, claims)
			}
		}
		return nil, fmt.Errorf("unsupported token type: %s", tokenType)
	}

	accessResult, err := m.Access.Mint(ctx, key, TokenTypeAccessToken, claims)
	if err != nil {
		return nil, err
	}

	token, ttl, uri := extractSingleToken(accessResult)
	set := &tokenSet{
		AccessToken:     token,
		IssuedTokenType: uri,
		TokenType:       "Bearer",
		ExpiresIn:       int(ttl.Seconds()),
		Scope:           joinScope(claims["scope"]),
	}

	scopes := extractScope(claims["scope"])
	if containsScope(scopes, "offline_access") && m.Refresh != nil {
		refreshResult, err := m.Refresh.Mint(ctx, key, TokenTypeRefreshToken, claims)
		if err != nil {
			return nil, err
		}
		set.RefreshToken, _, _ = extractSingleToken(refreshResult)
	}

	return set, nil
}

func (m AccessRefreshMinter) Validate(ctx context.Context, key crypto.PublicKey, token string) (map[string]any, error) {
	for _, sub := range []TokenMinter{m.Access, m.Refresh} {
		if v, ok := sub.(TokenValidator); ok {
			if claims, err := v.Validate(ctx, key, token); err == nil {
				return claims, nil
			}
		}
	}
	return nil, fmt.Errorf("validation failed")
}

func (m AccessRefreshMinter) Revoke(ctx context.Context, token string) error {
	if r, ok := m.Refresh.(TokenRevoker); ok {
		return r.Revoke(ctx, token)
	}
	return nil
}

// tokenSet is the JSON-marshalable result returned by composite minters.
type tokenSet struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in,omitempty"`
	Scope           string `json:"scope,omitempty"`
	IDToken         string `json:"id_token,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
}

func (t *tokenSet) Token() string      { return t.AccessToken }
func (t *tokenSet) TTL() time.Duration { return time.Duration(t.ExpiresIn) * time.Second }

// RoutingMinter dispatches to different minters based on the requested
// token type URI or the presence of specific claims.
//
// Routing order:
//  1. If tokenType matches a key in URIs, use that minter.
//  2. Otherwise, check claims for keys in Claims — the first match maps
//     to a URI, which is then looked up in URIs.
//  3. Fall back to Default.
type RoutingMinter struct {
	URIs    map[string]TokenMinter // token type URI → minter
	Claims  map[string]string      // claim key → URI (route if claim present)
	Default TokenMinter
}

func (m RoutingMinter) Mint(ctx context.Context, key crypto.Signer, tokenType string, claims map[string]any) (any, error) {
	if minter, ok := m.URIs[tokenType]; ok {
		return minter.Mint(ctx, key, tokenType, claims)
	}

	for claim, uri := range m.Claims {
		if _, ok := claims[claim]; ok {
			if minter, ok := m.URIs[uri]; ok {
				return minter.Mint(ctx, key, uri, claims)
			}
		}
	}

	if m.Default != nil {
		return m.Default.Mint(ctx, key, tokenType, claims)
	}

	return nil, fmt.Errorf("no minter for token type %q", tokenType)
}

func extractSingleToken(result any) (token string, ttl time.Duration, uri string) {
	if t, ok := result.(interface{ Token() string }); ok {
		token = t.Token()
	}
	if t, ok := result.(interface{ TTL() time.Duration }); ok {
		ttl = t.TTL()
	}
	if u, ok := result.(interface{ URI() string }); ok {
		uri = u.URI()
	}
	return token, ttl, uri
}


// UserInfoProvider returns claims about a user for the userinfo endpoint.
// Optional — if not set, Athens serves claims from the UserStore.
type UserInfoProvider interface {
	UserInfo(ctx context.Context, subject string, scope []string) (map[string]any, error)
}

// Client represents a registered OAuth 2.0 client.
type Client struct {
	ID                    string
	Secret                string
	RegistrationToken     string // RFC 7592 — for client self-management
	RedirectURIs          []string
	GrantTypes            []string
	ResponseTypes         []string
	Scope                 []string
	TokenEndpointAuth     string // client_secret_basic, client_secret_post, none
	Public                bool
}

// ClientStore provides access to registered clients.
type ClientStore interface {
	GetClient(ctx context.Context, id string) (*Client, error)
	ValidateSecret(ctx context.Context, client *Client, secret string) error
}

// ClientRegistrar extends ClientStore with dynamic client registration
// (RFC 7591) and management (RFC 7592).
type ClientRegistrar interface {
	ClientStore
	RegisterClient(ctx context.Context, meta *ClientMetadata) (*Client, error)
	UpdateClient(ctx context.Context, id string, meta *ClientMetadata) (*Client, error)
	DeleteClient(ctx context.Context, id string) error
}

// ClientMetadata is the metadata submitted during dynamic client
// registration (RFC 7591) and updates (RFC 7592).
type ClientMetadata struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	TOSUri                  string   `json:"tos_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
}

// KeyManager manages signing keys. Athens provides a default
// implementation; consumers may supply their own.
type KeyManager interface {
	CurrentKey(ctx context.Context) (kid string, key crypto.Signer, err error)
	PublicKeys(ctx context.Context) ([]PublicKey, error)
}

// PublicKey is a public key entry served on the JWKS endpoint.
type PublicKey struct {
	KID       string
	Algorithm string
	Key       crypto.PublicKey
	ExpiresAt time.Time
}

// User is an Athens-managed user account. Athens assigns its own subject
// identifier and tracks which upstream connections are linked.
type User struct {
	Subject     string
	Claims      map[string]any
	Connections map[string]string // connection name -> upstream subject
}

// UserStore manages user accounts. Athens calls GetOrCreateUser during
// the callback flow; the implementation controls the merge policy
// (e.g. match by email across connections).
type UserStore interface {
	GetOrCreateUser(ctx context.Context, connection string, upstreamSubject string, claims map[string]any) (*User, error)
	GetUser(ctx context.Context, subject string) (*User, error)
}

// Store is the backing store for Athens' internal state.
// Device code and refresh token support are optional — Athens checks
// for the DeviceCodeStore and RefreshTokenStore interfaces at runtime.
type Store interface {
	CodeStore
	TokenStatusStore
	AuthSessionStore
	UserStore
}

// AuthCode is an authorization code issued during the authorization flow.
type AuthCode struct {
	Code                string
	ClientID            string
	Subject             string
	Scope               []string
	RedirectURI         string
	Nonce               string
	ExpiresAt           time.Time
	PKCEChallenge       string
	PKCEChallengeMethod string
}

// CodeStore persists and redeems authorization codes.
type CodeStore interface {
	SaveCode(ctx context.Context, code *AuthCode) error
	RedeemCode(ctx context.Context, code string) (*AuthCode, error)
}

// TokenRecord describes an issued token.
type TokenRecord struct {
	TokenID  string
	Subject  string
	ClientID string
	Scope    []string
	Grant    string
	IssuedAt time.Time
	Revoked  bool
}

// TokenStatusStore tracks issued tokens and their revocation state.
// Every token issuance registers a record; consumers can list tokens
// by subject for management pages.
type TokenStatusStore interface {
	RegisterToken(ctx context.Context, record *TokenRecord) error
	RevokeToken(ctx context.Context, tokenID string) error
	IsRevoked(ctx context.Context, tokenID string) (bool, error)
	TokensBySubject(ctx context.Context, subject string) ([]*TokenRecord, error)
}

// PendingAuth is the state Athens persists between redirecting the user
// to an upstream connector and handling the callback.
type PendingAuth struct {
	State               string
	Connection          string
	ClientID            string
	RedirectURI         string
	ResponseType        string
	ResponseMode        ResponseMode
	Scope               []string
	ClientState         string
	Nonce               string
	PKCEChallenge       string
	PKCEChallengeMethod string
	ExpiresAt           time.Time
}

// AuthSessionStore persists pending authorization sessions.
type AuthSessionStore interface {
	SavePendingAuth(ctx context.Context, auth *PendingAuth) error
	GetPendingAuth(ctx context.Context, state string) (*PendingAuth, error)
}


// DeviceAuth is a pending device authorization (RFC 8628).
type DeviceAuth struct {
	DeviceCode string
	UserCode   string
	ClientID   string
	Scope      []string
	ExpiresAt  time.Time
	Interval   int
	Subject    string
	Approved   bool
}

// DeviceCodeStore persists device authorization state. Implement this
// on your Store to enable the device code flow (RFC 8628).
type DeviceCodeStore interface {
	SaveDeviceAuth(ctx context.Context, auth *DeviceAuth) error
	GetDeviceAuth(ctx context.Context, deviceCode string) (*DeviceAuth, error)
	GetDeviceAuthByUserCode(ctx context.Context, userCode string) (*DeviceAuth, error)
	ApproveDeviceAuth(ctx context.Context, userCode string, subject string) error
}
