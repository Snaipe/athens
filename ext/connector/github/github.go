// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"golang.org/x/oauth2"
	oauth2github "golang.org/x/oauth2/github"
)

type Config struct {
	ClientID     string
	ClientSecret string
}

type Connector struct {
	oauth2 oauth2.Config
}

func New(cfg Config) *Connector {
	return &Connector{
		oauth2: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     oauth2github.Endpoint,
			Scopes:       []string{"read:user", "user:email"},
		},
	}
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

	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))

	user, err := fetchUser(client)
	if err != nil {
		return "", nil, err
	}

	subject := strconv.FormatInt(user.ID, 10)
	claims := map[string]any{
		"name":              user.Name,
		"preferred_username": user.Login,
		"picture":           user.AvatarURL,
		"profile":           user.HTMLURL,
	}

	if user.Email != "" {
		claims["email"] = user.Email
		claims["email_verified"] = true
	} else if email, err := fetchPrimaryEmail(client); err == nil && email != "" {
		claims["email"] = email
		claims["email_verified"] = true
	}

	return subject, claims, nil
}

type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
	HTMLURL   string `json:"html_url"`
}

func fetchUser(client *http.Client) (*githubUser, error) {
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, fmt.Errorf("github user api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github user api: status %d", resp.StatusCode)
	}

	var user githubUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("github user api: %w", err)
	}
	return &user, nil
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func fetchPrimaryEmail(client *http.Client) (string, error) {
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return "", fmt.Errorf("github emails api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github emails api: status %d", resp.StatusCode)
	}

	var emails []githubEmail
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", fmt.Errorf("github emails api: %w", err)
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	return "", nil
}
