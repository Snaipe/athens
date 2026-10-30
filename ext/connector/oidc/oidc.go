// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package oidc

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string // scopes to request from the upstream provider; defaults to ["openid"]
}

type Connector struct {
	provider *oidc.Provider
	oauth2   oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func New(ctx context.Context, cfg Config) (*Connector, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email"}
	}
	return &Connector{
		provider: provider,
		oauth2: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
	}, nil
}

func (c *Connector) AuthURL(callbackURL string, state string) (string, error) {
	cfg := c.oauth2
	cfg.RedirectURL = callbackURL
	return cfg.AuthCodeURL(state), nil
}

func (c *Connector) Exchange(ctx context.Context, callbackURL string, code string) (string, map[string]any, error) {
	cfg := c.oauth2
	cfg.RedirectURL = callbackURL

	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return "", nil, fmt.Errorf("token exchange: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", nil, fmt.Errorf("no id_token in token response")
	}

	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", nil, fmt.Errorf("id_token verification: %w", err)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return "", nil, fmt.Errorf("parsing claims: %w", err)
	}

	return idToken.Subject, claims, nil
}
