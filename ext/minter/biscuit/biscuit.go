// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package biscuit

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
)

// Fact maps a claim key to a biscuit fact predicate. When the claim is
// present, the fact is added to the authority block.
type Fact struct {
	Predicate string // e.g. "build_id" → generates build_id({value})
	ClaimKey  string // key in the claims map
}

// Check is a biscuit check template added to the authority block.
// Placeholders like {claim_key} are substituted from the claims map.
type Check struct {
	Template string // e.g. "check if build_active({build_id})"
}

type Config struct {
	TTL    time.Duration
	Facts  []Fact
	Checks []Check
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
	value string
	ttl   time.Duration
}

func (r Result) Token() string      { return r.value }
func (r Result) TTL() time.Duration { return r.ttl }
func (r Result) URI() string        { return "https://doc.biscuitsec.org/reference/specifications" }

func (m *Minter) Mint(_ context.Context, key crypto.Signer, tokenType string, claims map[string]any) (any, error) {
	privKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("biscuit requires ed25519 key, got %T", key)
	}

	var lines []string
	params := map[string]biscuit.Term{}

	// Standard claims → facts
	if sub, ok := claims["sub"].(string); ok {
		params["sub"] = biscuit.String(sub)
		lines = append(lines, `user({sub})`)
	}
	if aud, ok := claims["aud"].(string); ok {
		params["aud"] = biscuit.String(aud)
		lines = append(lines, `audience({aud})`)
	}
	if jti, ok := claims["jti"].(string); ok {
		params["jti"] = biscuit.String(jti)
		lines = append(lines, `token_id({jti})`)
	}
	if nonce, ok := claims["nonce"].(string); ok && nonce != "" {
		params["nonce"] = biscuit.String(nonce)
		lines = append(lines, `nonce({nonce})`)
	}
	for i, s := range extractScopes(claims["scope"]) {
		k := fmt.Sprintf("scope%d", i)
		params[k] = biscuit.String(s)
		lines = append(lines, fmt.Sprintf(`scope({%s})`, k))
	}

	// User-configured facts from claims
	for _, f := range m.cfg.Facts {
		val, ok := claims[f.ClaimKey]
		if !ok {
			continue
		}
		paramKey := "fact_" + f.ClaimKey
		params[paramKey] = claimToTerm(val)
		lines = append(lines, fmt.Sprintf(`%s({%s})`, f.Predicate, paramKey))
	}

	// Expiry check
	expiry := time.Now().Add(m.cfg.TTL)
	params["expiry"] = biscuit.Date(expiry)
	lines = append(lines, `check if time($t), $t < {expiry}`)

	// User-configured checks with claim substitution
	for _, c := range m.cfg.Checks {
		tmpl := c.Template
		for k, v := range claims {
			if s, ok := v.(string); ok {
				paramKey := "check_" + k
				params[paramKey] = biscuit.String(s)
				tmpl = strings.ReplaceAll(tmpl, "{"+k+"}", "{"+paramKey+"}")
			}
		}
		lines = append(lines, tmpl)
	}

	blockStr := strings.Join(lines, ";\n") + ";"

	block, err := parser.FromStringBlockWithParams(blockStr, params)
	if err != nil {
		return nil, fmt.Errorf("parsing authority block: %w", err)
	}

	builder := biscuit.NewBuilder(privKey)
	builder.AddBlock(block)

	b, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("building biscuit: %w", err)
	}

	raw, err := b.Serialize()
	if err != nil {
		return nil, fmt.Errorf("serializing biscuit: %w", err)
	}

	return Result{value: base64.URLEncoding.EncodeToString(raw), ttl: m.cfg.TTL}, nil
}

func (m *Minter) Validate(_ context.Context, key crypto.PublicKey, tokenStr string) (map[string]any, error) {
	pubKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("biscuit requires ed25519 key, got %T", key)
	}

	raw, err := base64.URLEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("decoding token: %w", err)
	}

	b, err := biscuit.Unmarshal(raw)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling biscuit: %w", err)
	}

	authorizer, err := b.Authorizer(pubKey)
	if err != nil {
		return nil, fmt.Errorf("verifying biscuit: %w", err)
	}

	now, err := parser.FromStringFactWithParams(
		`time({now})`,
		map[string]biscuit.Term{"now": biscuit.Date(time.Now())},
	)
	if err != nil {
		return nil, fmt.Errorf("building time fact: %w", err)
	}
	authorizer.AddFact(now)

	policy, err := parser.FromStringPolicy(`allow if true`)
	if err != nil {
		return nil, fmt.Errorf("building policy: %w", err)
	}
	authorizer.AddPolicy(policy)

	if err := authorizer.Authorize(); err != nil {
		return nil, fmt.Errorf("authorization failed: %w", err)
	}

	claims := map[string]any{}

	// Extract standard facts
	queryString := func(name, predicate string) {
		rule, err := parser.FromStringRule(fmt.Sprintf(`data($x) <- %s($x)`, predicate))
		if err != nil {
			return
		}
		facts, err := authorizer.Query(rule)
		if err != nil || len(facts) == 0 {
			return
		}
		if s, ok := facts[0].Predicate.IDs[0].(biscuit.String); ok {
			claims[name] = string(s)
		}
	}
	queryString("sub", "user")
	queryString("aud", "audience")
	queryString("jti", "token_id")
	queryString("nonce", "nonce")

	// Extract user-configured facts
	for _, f := range m.cfg.Facts {
		queryString(f.ClaimKey, f.Predicate)
	}

	// Extract scopes
	rule, err := parser.FromStringRule(`data($x) <- scope($x)`)
	if err == nil {
		facts, err := authorizer.Query(rule)
		if err == nil {
			var scopes []string
			for _, f := range facts {
				if s, ok := f.Predicate.IDs[0].(biscuit.String); ok {
					scopes = append(scopes, string(s))
				}
			}
			if len(scopes) > 0 {
				claims["scope"] = scopes
			}
		}
	}

	return claims, nil
}

func (m *Minter) CanExchange(_ context.Context, tokenStr string, requestedScope []string, grantedScope []string) error {
	raw, err := base64.URLEncoding.DecodeString(tokenStr)
	if err != nil {
		return fmt.Errorf("decoding token: %w", err)
	}
	b, err := biscuit.Unmarshal(raw)
	if err != nil {
		return fmt.Errorf("unmarshaling biscuit: %w", err)
	}
	if b.BlockCount() > 0 {
		return fmt.Errorf("attenuated tokens cannot be exchanged")
	}
	return nil
}

func claimToTerm(v any) biscuit.Term {
	switch val := v.(type) {
	case string:
		return biscuit.String(val)
	case int:
		return biscuit.Integer(val)
	case int64:
		return biscuit.Integer(val)
	case float64:
		return biscuit.Integer(int64(val))
	case bool:
		return biscuit.Bool(val)
	default:
		return biscuit.String(fmt.Sprint(val))
	}
}

func extractScopes(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		result := make([]string, 0, len(s))
		for _, v := range s {
			if str, ok := v.(string); ok {
				result = append(result, str)
			}
		}
		return result
	case string:
		if s == "" {
			return nil
		}
		return strings.Split(s, " ")
	default:
		return nil
	}
}
