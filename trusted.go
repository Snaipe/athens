// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package athens

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TrustedIssuer validates tokens from a trusted OIDC issuer by fetching
// their JWKS via standard OIDC discovery. No federation required — just
// standard /.well-known/openid-configuration → jwks_uri → keys.
type TrustedIssuer struct {
	issuer    string
	client    *http.Client
	mu        sync.RWMutex
	keys      []crypto.PublicKey
	fetchedAt time.Time
	cacheTTL  time.Duration
	refreshed bool // true if we already force-refreshed within this cache window
}

// NewTrustedIssuer creates a validator that trusts tokens from the given
// OIDC issuer. Keys are fetched lazily and cached.
func NewTrustedIssuer(issuer string) *TrustedIssuer {
	return &TrustedIssuer{
		issuer:   issuer,
		client:   http.DefaultClient,
		cacheTTL: 1 * time.Hour,
	}
}

func (t *TrustedIssuer) Validate(ctx context.Context, _ crypto.PublicKey, token string) (map[string]any, error) {
	// Parse without verification to check issuer matches
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	unverified, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}
	claims, ok := unverified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}
	iss, _ := claims["iss"].(string)
	if iss != t.issuer {
		return nil, fmt.Errorf("issuer mismatch: got %s, want %s", iss, t.issuer)
	}

	keys, err := t.getKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching keys for %s: %w", t.issuer, err)
	}

	if result, err := t.tryValidate(token, keys); err == nil {
		return result, nil
	}

	// Key rotation: force refresh and retry, but only once per cache window
	t.mu.RLock()
	alreadyRefreshed := t.refreshed
	t.mu.RUnlock()

	if alreadyRefreshed {
		return nil, fmt.Errorf("token validation failed (keys already refreshed this cycle)")
	}

	keys, err = t.refreshKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("refreshing keys for %s: %w", t.issuer, err)
	}

	return t.tryValidate(token, keys)
}

func (t *TrustedIssuer) tryValidate(token string, keys []crypto.PublicKey) (map[string]any, error) {
	var lastErr error
	for _, key := range keys {
		parsed, err := jwt.Parse(token, func(tok *jwt.Token) (any, error) {
			return key, nil
		})
		if err != nil {
			lastErr = err
			continue
		}
		if !parsed.Valid {
			lastErr = fmt.Errorf("invalid token")
			continue
		}
		result, ok := parsed.Claims.(jwt.MapClaims)
		if !ok {
			lastErr = fmt.Errorf("unexpected claims type")
			continue
		}
		return map[string]any(result), nil
	}
	return nil, fmt.Errorf("no key matched: %w", lastErr)
}

func (t *TrustedIssuer) refreshKeys(ctx context.Context) ([]crypto.PublicKey, error) {
	keys, err := t.fetchKeys(ctx)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.keys = keys
	t.fetchedAt = time.Now()
	t.refreshed = true
	t.mu.Unlock()
	return keys, nil
}

func (t *TrustedIssuer) getKeys(ctx context.Context) ([]crypto.PublicKey, error) {
	t.mu.RLock()
	if t.keys != nil && time.Since(t.fetchedAt) < t.cacheTTL {
		keys := t.keys
		t.mu.RUnlock()
		return keys, nil
	}
	t.mu.RUnlock()

	keys, err := t.fetchKeys(ctx)
	if err != nil {
		return nil, err
	}

	t.mu.Lock()
	t.keys = keys
	t.fetchedAt = time.Now()
	t.refreshed = false // new cache window, allow one refresh again
	t.mu.Unlock()

	return keys, nil
}

func (t *TrustedIssuer) fetchKeys(ctx context.Context) ([]crypto.PublicKey, error) {
	// Fetch OIDC discovery
	discoURL := t.issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery returned %d", resp.StatusCode)
	}

	var disco struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&disco); err != nil {
		return nil, err
	}
	if disco.JWKSURI == "" {
		return nil, fmt.Errorf("no jwks_uri in discovery")
	}

	// Fetch JWKS
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, disco.JWKSURI, nil)
	if err != nil {
		return nil, err
	}
	resp, err = t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return ParseJWKS(body)
}
