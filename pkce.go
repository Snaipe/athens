// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package athens

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

func verifyPKCE(challenge, method, verifier string) bool {
	switch method {
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		expected := base64.RawURLEncoding.EncodeToString(h[:])
		return subtle.ConstantTimeCompare([]byte(challenge), []byte(expected)) == 1
	case "plain":
		return subtle.ConstantTimeCompare([]byte(challenge), []byte(verifier)) == 1
	default:
		return false
	}
}
