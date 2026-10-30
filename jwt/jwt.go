// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

type Config struct {
	Issuer string
	TTL    time.Duration
}

type Minter struct {
	cfg Config
}

func New(cfg Config) *Minter {
	if cfg.TTL == 0 {
		cfg.TTL = 1 * time.Hour
	}
	return &Minter{cfg: cfg}
}

type Result struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in,omitempty"`
	Scope           string `json:"scope,omitempty"`
}

func (r Result) Token() string      { return r.AccessToken }
func (r Result) TTL() time.Duration { return time.Duration(r.ExpiresIn) * time.Second }
func (r Result) URI() string        { return "urn:ietf:params:oauth:token-type:jwt" }

func (m *Minter) Mint(_ context.Context, key crypto.Signer, tokenType string, claims map[string]any) (any, error) {
	value, _, err := m.sign(key, claims, m.cfg.TTL)
	if err != nil {
		return nil, err
	}
	return Result{
		AccessToken:     value,
		IssuedTokenType: "urn:ietf:params:oauth:token-type:jwt",
		TokenType:       "Bearer",
		ExpiresIn:       int(m.cfg.TTL.Seconds()),
		Scope:           joinScope(claims["scope"]),
	}, nil
}

func (m *Minter) Validate(_ context.Context, key crypto.PublicKey, tokenStr string) (map[string]any, error) {
	token, err := gojwt.Parse(tokenStr, func(t *gojwt.Token) (any, error) {
		return key, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(gojwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return map[string]any(claims), nil
}

func (m *Minter) sign(key crypto.Signer, claims map[string]any, ttl time.Duration) (string, time.Duration, error) {
	now := time.Now()
	jwtClaims := gojwt.MapClaims{
		"iss": m.cfg.Issuer,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	}
	for k, v := range claims {
		jwtClaims[k] = v
	}

	method, err := signingMethod(key)
	if err != nil {
		return "", 0, err
	}

	token := gojwt.NewWithClaims(method, jwtClaims)
	signed, err := token.SignedString(key)
	if err != nil {
		return "", 0, fmt.Errorf("signing token: %w", err)
	}

	return signed, ttl, nil
}

func joinScope(v any) string {
	switch s := v.(type) {
	case []string:
		return strings.Join(s, " ")
	case []any:
		parts := make([]string, 0, len(s))
		for _, v := range s {
			if str, ok := v.(string); ok {
				parts = append(parts, str)
			}
		}
		return strings.Join(parts, " ")
	case string:
		return s
	default:
		return ""
	}
}

func signingMethod(key crypto.Signer) (gojwt.SigningMethod, error) {
	switch key.Public().(type) {
	case *ecdsa.PublicKey:
		return gojwt.SigningMethodES256, nil
	case *rsa.PublicKey:
		return gojwt.SigningMethodRS256, nil
	case ed25519.PublicKey:
		return gojwt.SigningMethodEdDSA, nil
	default:
		return nil, fmt.Errorf("unsupported key type %T", key)
	}
}
