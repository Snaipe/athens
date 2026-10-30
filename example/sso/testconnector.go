// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package main

import (
	"context"
	"net/url"
)

type TestConnector struct{}

func (c *TestConnector) AuthURL(callbackURL string, state string) (string, error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("state", state)
	q.Set("code", "test-auth-code")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (c *TestConnector) Exchange(_ context.Context, _ string, _ string) (string, map[string]any, error) {
	return "test-user-1", map[string]any{
		"name":  "Test User",
		"email": "test@example.com",
	}, nil
}
