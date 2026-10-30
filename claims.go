// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package athens

import "strings"

var scopeClaims = map[string][]string{
	"profile": {"name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at"},
	"email":   {"email", "email_verified"},
	"phone":   {"phone_number", "phone_number_verified"},
	"address": {"address"},
}

func filterClaims(claims map[string]any, scopes []string) map[string]any {
	result := map[string]any{}
	for _, scope := range scopes {
		keys, ok := scopeClaims[scope]
		if !ok {
			continue
		}
		for _, key := range keys {
			if v, ok := claims[key]; ok {
				result[key] = v
			}
		}
	}
	return result
}

func buildTokenClaims(tokenID, subject, audience string, scope []string, nonce string, userClaims map[string]any) map[string]any {
	claims := map[string]any{
		"jti":   tokenID,
		"sub":   subject,
		"aud":   audience,
		"scope": scope,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	for k, v := range userClaims {
		claims[k] = v
	}
	return claims
}

type validatedToken struct {
	TokenID  string
	Subject  string
	Audience string
	Scope    []string
}

func extractTokenInfo(claims map[string]any) validatedToken {
	t := validatedToken{}
	t.TokenID, _ = claims["jti"].(string)
	t.Subject, _ = claims["sub"].(string)
	t.Audience, _ = claims["aud"].(string)
	t.Scope = extractScope(claims["scope"])
	return t
}

func joinScope(v any) string {
	scopes := extractScope(v)
	return strings.Join(scopes, " ")
}

func extractScope(v any) []string {
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
