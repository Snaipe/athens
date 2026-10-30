// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net"
	"os"

	"snai.pe/athens"
	"snai.pe/athens/ext/connector/github"
	"snai.pe/athens/ext/connector/oidc"
	jwtminter "snai.pe/athens/jwt"
	"snai.pe/athens/opaque"
)

func main() {
	ctx := context.Background()

	var connectors []athens.ConnectorConfig

	// Google Cloud SDK's public OAuth client ID. This is embedded in the
	// open-source gcloud CLI and works with localhost redirect URIs.
	// Replace with your own credentials for production use:
	//   https://console.cloud.google.com/apis/credentials
	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")
	if googleClientID == "" {
		googleClientID = "32555940559.apps.googleusercontent.com"
	}
	googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	if googleClientSecret == "" {
		googleClientSecret = "ZmssLNjJy2998hD4CTg2ejr2"
	}
	{
		c, err := oidc.New(ctx, oidc.Config{
			Issuer:       "https://accounts.google.com",
			ClientID:     googleClientID,
			ClientSecret: googleClientSecret,
		})
		if err != nil {
			log.Fatal(err)
		}
		connectors = append(connectors, athens.ConnectorConfig{ID: "google", Name: "Google", Connector: c})
	}

	if id := os.Getenv("MICROSOFT_CLIENT_ID"); id != "" {
		tenant := os.Getenv("MICROSOFT_TENANT_ID")
		if tenant == "" {
			tenant = "common"
		}
		c, err := oidc.New(ctx, oidc.Config{
			Issuer:       "https://login.microsoftonline.com/" + tenant + "/v2.0",
			ClientID:     id,
			ClientSecret: os.Getenv("MICROSOFT_CLIENT_SECRET"),
		})
		if err != nil {
			log.Fatal(err)
		}
		connectors = append(connectors, athens.ConnectorConfig{ID: "microsoft", Name: "Microsoft", Connector: c})
	}

	if id := os.Getenv("GITHUB_CLIENT_ID"); id != "" {
		connectors = append(connectors, athens.ConnectorConfig{
			ID:        "github",
			Name:      "GitHub",
			Connector: github.New(github.Config{ClientID: id, ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET")}),
		})
	}

	connectors = append(connectors, athens.ConnectorConfig{ID: "test", Name: "Test", Connector: &TestConnector{}})

	if len(connectors) == 1 {
		log.Println("no external connectors configured; using test connector only")
		log.Println("set GOOGLE_CLIENT_ID, MICROSOFT_CLIENT_ID, or GITHUB_CLIENT_ID for real providers")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	issuer := os.Getenv("ISSUER")
	if issuer == "" {
		issuer = "http://localhost:8080"
	}

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	store := NewMemoryStore()

	jwt := jwtminter.New(jwtminter.Config{Issuer: issuer})
	minter := athens.OpenIDMinter{
		Access:  jwt,
		ID:      jwt,
		Refresh: opaque.New(opaque.Config{Store: store}),
	}

	srv := &athens.Server{
		Connectors: connectors,
		Clients: &StaticClients{
			Clients: map[string]*athens.Client{
				"example": {
					ID:           "example",
					Secret:       "example-secret",
					RedirectURIs: []string{"http://localhost:8081/callback"},
					GrantTypes:   []string{"authorization_code", "refresh_token"},
					Scope:        []string{"openid", "profile", "email"},
				},
			},
		},
		Minter:    minter,
		Validator: minter,
		Keys:          &SingleKey{key: key, kid: "default"},
		Store:    store,
		OpenIDConfig: athens.OpenIDConfiguration{
			Issuer:                            issuer,
			AuthorizationEndpoint:             issuer + "/authorize",
			TokenEndpoint:                     issuer + "/oauth/token",
			JWKSURI:                           issuer + "/oauth/jwks",
			UserInfoEndpoint:                  issuer + "/userinfo",
			ResponseTypesSupported:            []string{"code"},
			SubjectTypesSupported:             []string{"public"},
			IDTokenSigningAlgValuesSupported:  []string{"ES256"},
			ScopesSupported:                   []string{"openid", "profile", "email"},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic"},
		},
	}

	connectorNames := make([]string, 0, len(connectors))
	for _, c := range connectors {
		connectorNames = append(connectorNames, c.ID)
	}

	// Start a second Athens instance ("service") that trusts the SSO
	// via federation and accepts token exchange.
	go startService(":8082", "http://localhost:8082", issuer, key.Public())

	go startTestClient(":8081", issuer, connectorNames, store)

	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("SSO server on %s", addr)
	log.Printf("open http://localhost:8081 in your browser")
	log.Fatal(srv.Serve(l))
}

type SingleKey struct {
	key *ecdsa.PrivateKey
	kid string
}

func (k *SingleKey) CurrentKey(_ context.Context) (string, crypto.Signer, error) {
	return k.kid, k.key, nil
}

func (k *SingleKey) PublicKeys(_ context.Context) ([]athens.PublicKey, error) {
	return []athens.PublicKey{{
		KID:       k.kid,
		Algorithm: "ES256",
		Key:       k.key.Public(),
	}}, nil
}
