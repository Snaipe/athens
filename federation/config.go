// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package federation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Entity represents this Athens instance as a federation entity.
// It serves the entity configuration at /.well-known/openid-federation
// and provides the resolver for validating foreign tokens.
type Entity struct {
	// EntityID is this entity's identifier (the issuer URL).
	EntityID string

	// Key is the federation signing key (used to sign entity configs).
	Key crypto.Signer

	// AuthorityHints are the entity IDs of our immediate superiors.
	AuthorityHints []string

	// Metadata is protocol-role metadata to include in the entity config.
	Metadata *EntityMetadata

	// Resolver resolves trust chains to validate foreign entities.
	Resolver *Resolver

	// ConfigTTL is how long the entity config is valid. Defaults to 24h.
	ConfigTTL time.Duration
}

// ServeEntityConfig handles GET /.well-known/openid-federation
func (e *Entity) ServeEntityConfig(resp http.ResponseWriter, req *http.Request) {
	ttl := e.ConfigTTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":             e.EntityID,
		"sub":             e.EntityID,
		"iat":             now.Unix(),
		"exp":             now.Add(ttl).Unix(),
		"authority_hints": e.AuthorityHints,
	}

	if e.Metadata != nil {
		metaJSON, err := json.Marshal(e.Metadata)
		if err == nil {
			var metaMap map[string]any
			json.Unmarshal(metaJSON, &metaMap)
			claims["metadata"] = metaMap
		}
	}

	jwks, err := publicKeyJWKS(e.Key)
	if err != nil {
		http.Error(resp, "internal error", http.StatusInternalServerError)
		return
	}
	claims["jwks"] = jwks

	method, err := signingMethod(e.Key)
	if err != nil {
		http.Error(resp, "internal error", http.StatusInternalServerError)
		return
	}

	token := jwt.NewWithClaims(method, claims)
	signed, err := token.SignedString(e.Key)
	if err != nil {
		http.Error(resp, "internal error", http.StatusInternalServerError)
		return
	}

	resp.Header().Set("Content-Type", "application/entity-statement+jwt")
	resp.Write([]byte(signed))
}

// ValidateEntityToken validates a token from a foreign entity by
// resolving their trust chain and verifying the token signature.
func (e *Entity) ValidateEntityToken(ctx context.Context, issuerID string, token string) (map[string]any, error) {
	if e.Resolver == nil {
		return nil, fmt.Errorf("no resolver configured")
	}

	keys, err := e.Resolver.ResolveKeys(ctx, issuerID)
	if err != nil {
		return nil, fmt.Errorf("resolving trust chain for %s: %w", issuerID, err)
	}

	var lastErr error
	for _, key := range keys {
		parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
			return key, nil
		})
		if err != nil {
			lastErr = err
			continue
		}
		claims, ok := parsed.Claims.(jwt.MapClaims)
		if !ok || !parsed.Valid {
			lastErr = fmt.Errorf("invalid token claims")
			continue
		}
		return map[string]any(claims), nil
	}
	return nil, fmt.Errorf("token validation failed: %w", lastErr)
}

func publicKeyJWKS(key crypto.Signer) (map[string]any, error) {
	// Serialize the public key to JWK format
	pub := key.Public()
	jwkData, err := marshalPublicKeyJWK(pub)
	if err != nil {
		return nil, err
	}
	return map[string]any{"keys": []any{jwkData}}, nil
}

func marshalPublicKeyJWK(pub crypto.PublicKey) (map[string]any, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return map[string]any{
			"kty": "RSA",
			"n":   b64Encode(k.N.Bytes()),
			"e":   b64Encode(big.NewInt(int64(k.E)).Bytes()),
			"use": "sig",
		}, nil
	case *ecdsa.PublicKey:
		crv := ""
		byteLen := 0
		switch k.Curve {
		case elliptic.P256():
			crv = "P-256"
			byteLen = 32
		case elliptic.P384():
			crv = "P-384"
			byteLen = 48
		case elliptic.P521():
			crv = "P-521"
			byteLen = 66
		default:
			return nil, fmt.Errorf("unsupported EC curve")
		}
		xPad := make([]byte, byteLen)
		yPad := make([]byte, byteLen)
		xBytes := k.X.Bytes()
		yBytes := k.Y.Bytes()
		copy(xPad[byteLen-len(xBytes):], xBytes)
		copy(yPad[byteLen-len(yBytes):], yBytes)
		return map[string]any{
			"kty": "EC",
			"crv": crv,
			"x":   b64Encode(xPad),
			"y":   b64Encode(yPad),
			"use": "sig",
		}, nil
	case ed25519.PublicKey:
		return map[string]any{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   b64Encode([]byte(k)),
			"use": "sig",
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type %T", pub)
	}
}

func b64Encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func signingMethod(key crypto.Signer) (jwt.SigningMethod, error) {
	switch key.Public().(type) {
	case *ecdsa.PublicKey:
		return jwt.SigningMethodES256, nil
	case *rsa.PublicKey:
		return jwt.SigningMethodRS256, nil
	case ed25519.PublicKey:
		return jwt.SigningMethodEdDSA, nil
	default:
		return nil, fmt.Errorf("unsupported key type %T", key)
	}
}
