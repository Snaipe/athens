// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package federation

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"snai.pe/athens"
)

// Resolver resolves trust chains from a leaf entity up to a configured
// trust anchor. It fetches entity configurations and subordinate
// statements, validates signatures, and caches results.
type Resolver struct {
	Anchors []TrustAnchor
	Client  *http.Client

	mu    sync.RWMutex
	cache map[string]*cacheEntry
}

type cacheEntry struct {
	statement *EntityStatement
	expiresAt time.Time
}

func NewResolver(anchors []TrustAnchor) *Resolver {
	return &Resolver{
		Anchors: anchors,
		Client:  http.DefaultClient,
		cache:   make(map[string]*cacheEntry),
	}
}

// Resolve builds and validates a trust chain for the given entity.
// Returns the chain if a path to a trusted anchor is found.
func (r *Resolver) Resolve(ctx context.Context, entityID string) (*TrustChain, error) {
	config, err := r.fetchEntityConfig(ctx, entityID)
	if err != nil {
		return nil, fmt.Errorf("fetching entity config for %s: %w", entityID, err)
	}

	if config.IsExpired() {
		return nil, fmt.Errorf("entity config for %s is expired", entityID)
	}

	return r.buildChain(ctx, config, nil, 10)
}

// ResolveKeys resolves a trust chain and returns the entity's protocol
// keys (from their metadata JWKS). This is what you need to validate
// tokens from that entity. If the entity is a configured trust anchor,
// its keys are returned directly without fetching.
func (r *Resolver) ResolveKeys(ctx context.Context, entityID string) ([]crypto.PublicKey, error) {
	for i := range r.Anchors {
		if r.Anchors[i].EntityID == entityID {
			return r.Anchors[i].Keys, nil
		}
	}

	chain, err := r.Resolve(ctx, entityID)
	if err != nil {
		return nil, err
	}

	leaf := chain.Statements[0]
	return athens.ParseJWKS(leaf.JWKS)
}

func (r *Resolver) buildChain(ctx context.Context, current *EntityStatement, chain []*EntityStatement, maxDepth int) (*TrustChain, error) {
	if maxDepth <= 0 {
		return nil, fmt.Errorf("max trust chain depth exceeded")
	}

	chain = append(chain, current)

	// Check if we've reached a trust anchor
	for i := range r.Anchors {
		anchor := &r.Anchors[i]
		if anchor.EntityID == current.Issuer {
			return &TrustChain{
				Anchor:     anchor,
				Statements: chain,
			}, nil
		}
	}

	// Not an anchor — walk up via authority_hints
	if len(current.AuthorityHints) == 0 {
		return nil, fmt.Errorf("no authority_hints and not a trust anchor: %s", current.Subject)
	}

	var lastErr error
	for _, hint := range current.AuthorityHints {
		// Fetch the superior's entity config
		superiorConfig, err := r.fetchEntityConfig(ctx, hint)
		if err != nil {
			lastErr = err
			continue
		}

		if superiorConfig.IsExpired() {
			lastErr = fmt.Errorf("superior %s entity config expired", hint)
			continue
		}

		// Fetch the subordinate statement from the superior about the current entity
		subStmt, err := r.fetchSubordinateStatement(ctx, superiorConfig, current.Subject)
		if err != nil {
			lastErr = err
			continue
		}

		if subStmt.IsExpired() {
			lastErr = fmt.Errorf("subordinate statement from %s about %s expired", hint, current.Subject)
			continue
		}

		// Validate the subordinate statement is signed by the superior
		superiorKeys, err := athens.ParseJWKS(superiorConfig.JWKS)
		if err != nil {
			lastErr = err
			continue
		}

		if err := verifyStatement(subStmt, superiorKeys); err != nil {
			lastErr = fmt.Errorf("subordinate statement signature invalid: %w", err)
			continue
		}

		// Add the subordinate statement and continue up
		chain = append(chain, subStmt)
		result, err := r.buildChain(ctx, superiorConfig, chain, maxDepth-1)
		if err != nil {
			lastErr = err
			continue
		}
		return result, nil
	}

	return nil, fmt.Errorf("no valid trust path found for %s: %w", current.Subject, lastErr)
}

func (r *Resolver) fetchEntityConfig(ctx context.Context, entityID string) (*EntityStatement, error) {
	// Check cache
	r.mu.RLock()
	if entry, ok := r.cache[entityID]; ok && time.Now().Before(entry.expiresAt) {
		r.mu.RUnlock()
		return entry.statement, nil
	}
	r.mu.RUnlock()

	wellKnown := entityID + "/.well-known/openid-federation"
	stmt, err := r.fetchAndParseStatement(ctx, wellKnown)
	if err != nil {
		return nil, err
	}

	// Verify self-signed (iss == sub for entity configs)
	if !stmt.IsConfiguration() {
		return nil, fmt.Errorf("entity config for %s has iss != sub", entityID)
	}

	keys, err := athens.ParseJWKS(stmt.JWKS)
	if err != nil {
		return nil, fmt.Errorf("parsing JWKS for %s: %w", entityID, err)
	}

	if err := verifyStatement(stmt, keys); err != nil {
		return nil, fmt.Errorf("entity config signature invalid for %s: %w", entityID, err)
	}

	// Cache
	r.mu.Lock()
	r.cache[entityID] = &cacheEntry{
		statement: stmt,
		expiresAt: time.Unix(stmt.ExpiresAt, 0),
	}
	r.mu.Unlock()

	return stmt, nil
}

func (r *Resolver) fetchSubordinateStatement(ctx context.Context, superior *EntityStatement, subordinateID string) (*EntityStatement, error) {
	if superior.Metadata == nil || superior.Metadata.FederationEntity == nil {
		return nil, fmt.Errorf("superior %s has no federation entity metadata", superior.Subject)
	}

	fetchEndpoint := superior.Metadata.FederationEntity.FederationFetchEndpoint
	if fetchEndpoint == "" {
		return nil, fmt.Errorf("superior %s has no fetch endpoint", superior.Subject)
	}

	u, err := url.Parse(fetchEndpoint)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("sub", subordinateID)
	u.RawQuery = q.Encode()

	return r.fetchAndParseStatement(ctx, u.String())
}

func (r *Resolver) fetchAndParseStatement(ctx context.Context, rawURL string) (*EntityStatement, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/entity-statement+jwt")

	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, rawURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return parseStatement(string(body))
}

// parseStatement extracts claims from a JWT without verifying the signature.
// Signature verification is done separately once we have the appropriate keys.
func parseStatement(tokenStr string) (*EntityStatement, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parsing JWT: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}

	data, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	var stmt EntityStatement
	if err := json.Unmarshal(data, &stmt); err != nil {
		return nil, err
	}

	// Store the raw token for signature verification
	stmt.rawToken = tokenStr
	return &stmt, nil
}

// verifyStatement checks that the statement JWT was signed by one of
// the provided keys.
func verifyStatement(stmt *EntityStatement, keys []crypto.PublicKey) error {
	if stmt.rawToken == "" {
		return fmt.Errorf("no raw token to verify")
	}

	var lastErr error
	for _, key := range keys {
		keyFunc := func(t *jwt.Token) (any, error) {
			return key, nil
		}
		_, err := jwt.Parse(stmt.rawToken, keyFunc)
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return fmt.Errorf("no key verified the statement: %w", lastErr)
}
