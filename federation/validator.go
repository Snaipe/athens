// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package federation

import (
	"context"
	"crypto"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Validator implements token validation by resolving the issuer's
// trust chain and verifying the token with the issuer's keys.
// It satisfies the TokenValidator interface structurally (no Athens import).
type Validator struct {
	Entity *Entity
}

// Validate parses the token, extracts the issuer, resolves their trust
// chain, and verifies the signature. Returns the claims map on success.
func (v *Validator) Validate(ctx context.Context, _ crypto.PublicKey, token string) (map[string]any, error) {
	// First, parse without verification to get the issuer
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	unverified, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}

	claims, ok := unverified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}

	issuer, _ := claims["iss"].(string)
	if issuer == "" {
		return nil, fmt.Errorf("token has no issuer")
	}

	// If the issuer is ourselves, skip federation — use the provided key
	// (this would be handled by Athens' own validator, not us)
	if issuer == v.Entity.EntityID {
		return nil, fmt.Errorf("token issued by self; use local validator")
	}

	// Resolve the issuer's trust chain and validate
	return v.Entity.ValidateEntityToken(ctx, issuer, token)
}
