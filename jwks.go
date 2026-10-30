// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package athens

import (
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
)

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	KTY string `json:"kty"`
	KID string `json:"kid,omitempty"`
	ALG string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	CRV string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

func marshalJWK(pub PublicKey) (jwk, error) {
	k := jwk{
		KID: pub.KID,
		ALG: pub.Algorithm,
		Use: "sig",
	}
	switch key := pub.Key.(type) {
	case *rsa.PublicKey:
		k.KTY = "RSA"
		k.N = b64url(key.N.Bytes())
		k.E = b64url(big.NewInt(int64(key.E)).Bytes())
	case *ecdsa.PublicKey:
		k.KTY = "EC"
		byteLen := (key.Curve.Params().BitSize + 7) / 8
		switch key.Curve {
		case elliptic.P256():
			k.CRV = "P-256"
		case elliptic.P384():
			k.CRV = "P-384"
		case elliptic.P521():
			k.CRV = "P-521"
		default:
			return k, fmt.Errorf("unsupported EC curve")
		}
		k.X = b64url(padLeft(key.X.Bytes(), byteLen))
		k.Y = b64url(padLeft(key.Y.Bytes(), byteLen))
	case ed25519.PublicKey:
		k.KTY = "OKP"
		k.CRV = "Ed25519"
		k.X = b64url([]byte(key))
	default:
		return k, fmt.Errorf("unsupported key type %T", key)
	}
	return k, nil
}

// ParseJWKS parses a JWK Set and returns the public keys.
func ParseJWKS(data []byte) ([]crypto.PublicKey, error) {
	var set jwkSet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("parsing JWKS: %w", err)
	}
	keys := make([]crypto.PublicKey, 0, len(set.Keys))
	for _, k := range set.Keys {
		pub, err := parseJWK(k)
		if err != nil {
			continue
		}
		keys = append(keys, pub)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no usable keys in JWKS")
	}
	return keys, nil
}

func parseJWK(k jwk) (crypto.PublicKey, error) {
	switch k.KTY {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.CRV {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve: %s", k.CRV)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}, nil
	case "OKP":
		if k.CRV != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve: %s", k.CRV)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		return ed25519.PublicKey(xBytes), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", k.KTY)
	}
}

func (s *Server) getJWKS(resp http.ResponseWriter, req *http.Request) error {
	pubs, err := s.Keys.PublicKeys(req.Context())
	if err != nil {
		return err
	}

	set := jwkSet{Keys: make([]jwk, 0, len(pubs))}
	for _, pub := range pubs {
		k, err := marshalJWK(pub)
		if err != nil {
			return err
		}
		set.Keys = append(set.Keys, k)
	}

	resp.Header().Set("Content-Type", "application/json")
	resp.Header().Set("Cache-Control", "public, max-age=3600")
	return json.NewEncoder(resp).Encode(&set)
}
