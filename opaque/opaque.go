// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package opaque

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// Store persists opaque token claims. The consumer implements this
// on the same backing store used for the rest of their application.
type Store interface {
	SaveToken(ctx context.Context, token string, claims map[string]any, expiresAt time.Time) error
	GetToken(ctx context.Context, token string) (map[string]any, error)
	DeleteToken(ctx context.Context, token string) error
}

type Config struct {
	Store Store
	TTL   time.Duration
}

type Minter struct {
	store Store
	ttl   time.Duration
}

func New(cfg Config) *Minter {
	if cfg.TTL == 0 {
		cfg.TTL = 1 * time.Hour
	}
	return &Minter{store: cfg.Store, ttl: cfg.TTL}
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
func (r Result) URI() string        { return "urn:ietf:params:oauth:token-type:access_token" }

func (m *Minter) Mint(ctx context.Context, _ crypto.Signer, tokenType string, claims map[string]any) (any, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generating token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(b)

	if err := m.store.SaveToken(ctx, token, claims, time.Now().Add(m.ttl)); err != nil {
		return nil, fmt.Errorf("saving token: %w", err)
	}

	return Result{
		AccessToken:     token,
		IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		TokenType:       "Bearer",
		ExpiresIn:       int(m.ttl.Seconds()),
		Scope:           joinScope(claims["scope"]),
	}, nil
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

func (m *Minter) Validate(ctx context.Context, _ crypto.PublicKey, token string) (map[string]any, error) {
	claims, err := m.store.GetToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

func (m *Minter) Revoke(ctx context.Context, token string) error {
	return m.store.DeleteToken(ctx, token)
}
