// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net"

	"snai.pe/athens"
	"snai.pe/athens/federation"
	jwtminter "snai.pe/athens/jwt"
)

// startService runs a second Athens instance that trusts the SSO server
// via federation. It accepts token exchange requests: present a token
// from the SSO, get back a service-specific token.
func startService(addr, serviceIssuer string, ssoIssuer string, ssoKey crypto.PublicKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	jwt := jwtminter.New(jwtminter.Config{Issuer: serviceIssuer})

	// Trust the SSO as a federation trust anchor. In production this
	// would resolve dynamically via trust chains; here we configure the
	// SSO's public key directly as a trust anchor.
	resolver := federation.NewResolver([]federation.TrustAnchor{{
		EntityID: ssoIssuer,
		Keys:     []crypto.PublicKey{ssoKey},
	}})

	fedEntity := &federation.Entity{
		EntityID:       serviceIssuer,
		Key:            key,
		AuthorityHints: []string{ssoIssuer},
		Resolver:       resolver,
	}

	store := NewMemoryStore()

	srv := &athens.Server{
		Clients: &StaticClients{
			Clients: map[string]*athens.Client{
				"service-client": {
					ID:         "service-client",
					Secret:     "service-secret",
					GrantTypes: []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
					Scope:      []string{"openid", "profile", "email"},
				},
			},
		},
		Minter:            jwt,
		Validator:         jwt,
		ExchangeValidator: &federation.Validator{Entity: fedEntity},
		Keys:              &SingleKey{key: key, kid: "service-key"},
		Store:             store,
		OpenIDConfig: athens.OpenIDConfiguration{
			Issuer:                           serviceIssuer,
			TokenEndpoint:                    serviceIssuer + "/oauth/token",
			JWKSURI:                          serviceIssuer + "/oauth/jwks",
			ResponseTypesSupported:           []string{"code"},
			SubjectTypesSupported:            []string{"public"},
			IDTokenSigningAlgValuesSupported: []string{"ES256"},
		},
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("service on %s (trusts SSO via federation)", addr)
	log.Fatal(srv.Serve(l))
}
