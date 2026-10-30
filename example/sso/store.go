// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"snai.pe/athens"
)

type MemoryStore struct {
	mu        sync.Mutex
	codes     map[string]*athens.AuthCode
	tokenRecs map[string]*athens.TokenRecord
	pending   map[string]*athens.PendingAuth
	tokens    map[string]map[string]any
	devices   map[string]*athens.DeviceAuth
	userCodes map[string]string // user_code -> device_code

	users      map[string]*athens.User // subject -> user
	emailIndex map[string]string       // email -> subject
	connIndex  map[string]string       // "connection:upstream_subject" -> subject
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		codes:      make(map[string]*athens.AuthCode),
		tokenRecs:  make(map[string]*athens.TokenRecord),
		pending:    make(map[string]*athens.PendingAuth),
		tokens:     make(map[string]map[string]any),
		devices:    make(map[string]*athens.DeviceAuth),
		userCodes:  make(map[string]string),
		users:      make(map[string]*athens.User),
		emailIndex: make(map[string]string),
		connIndex:  make(map[string]string),
	}
}

func (s *MemoryStore) GetOrCreateUser(_ context.Context, connection string, upstreamSubject string, claims map[string]any) (*athens.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	connKey := connection + ":" + upstreamSubject

	// check if this connection+subject is already linked
	if subject, ok := s.connIndex[connKey]; ok {
		user := s.users[subject]
		for k, v := range claims {
			user.Claims[k] = v
		}
		return user, nil
	}

	// try to merge by email
	if email, ok := claims["email"].(string); ok && email != "" {
		if subject, ok := s.emailIndex[email]; ok {
			user := s.users[subject]
			user.Connections[connection] = upstreamSubject
			s.connIndex[connKey] = subject
			for k, v := range claims {
				user.Claims[k] = v
			}
			return user, nil
		}
	}

	// create new user
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	subject := base64.RawURLEncoding.EncodeToString(b)

	user := &athens.User{
		Subject:     subject,
		Claims:      claims,
		Connections: map[string]string{connection: upstreamSubject},
	}
	s.users[subject] = user
	s.connIndex[connKey] = subject
	if email, ok := claims["email"].(string); ok && email != "" {
		s.emailIndex[email] = subject
	}
	return user, nil
}

func (s *MemoryStore) GetUser(_ context.Context, subject string) (*athens.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[subject]
	if !ok {
		return nil, fmt.Errorf("unknown user: %s", subject)
	}
	return user, nil
}

func (s *MemoryStore) SaveCode(_ context.Context, code *athens.AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code.Code] = code
	return nil
}

func (s *MemoryStore) RedeemCode(_ context.Context, code string) (*athens.AuthCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[code]
	if !ok || time.Now().After(c.ExpiresAt) {
		delete(s.codes, code)
		return nil, fmt.Errorf("invalid or expired code")
	}
	delete(s.codes, code)
	return c, nil
}

func (s *MemoryStore) RegisterToken(_ context.Context, record *athens.TokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenRecs[record.TokenID] = record
	return nil
}

func (s *MemoryStore) RevokeToken(_ context.Context, tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.tokenRecs[tokenID]; ok {
		rec.Revoked = true
	}
	return nil
}

func (s *MemoryStore) IsRevoked(_ context.Context, tokenID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.tokenRecs[tokenID]
	return ok && rec.Revoked, nil
}

func (s *MemoryStore) TokensBySubject(_ context.Context, subject string) ([]*athens.TokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []*athens.TokenRecord
	for _, rec := range s.tokenRecs {
		if rec.Subject == subject {
			result = append(result, rec)
		}
	}
	return result, nil
}

func (s *MemoryStore) SavePendingAuth(_ context.Context, auth *athens.PendingAuth) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[auth.State] = auth
	return nil
}

func (s *MemoryStore) GetPendingAuth(_ context.Context, state string) (*athens.PendingAuth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[state]
	if !ok || time.Now().After(p.ExpiresAt) {
		delete(s.pending, state)
		return nil, fmt.Errorf("invalid or expired session")
	}
	delete(s.pending, state)
	return p, nil
}

func (s *MemoryStore) SaveToken(_ context.Context, token string, claims map[string]any, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = claims
	return nil
}

func (s *MemoryStore) GetToken(_ context.Context, token string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	claims, ok := s.tokens[token]
	if !ok {
		return nil, fmt.Errorf("unknown token")
	}
	return claims, nil
}

func (s *MemoryStore) DeleteToken(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
	return nil
}

func (s *MemoryStore) SaveDeviceAuth(_ context.Context, auth *athens.DeviceAuth) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[auth.DeviceCode] = auth
	s.userCodes[auth.UserCode] = auth.DeviceCode
	return nil
}

func (s *MemoryStore) GetDeviceAuth(_ context.Context, deviceCode string) (*athens.DeviceAuth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.devices[deviceCode]
	if !ok {
		return nil, fmt.Errorf("unknown device code")
	}
	return a, nil
}

func (s *MemoryStore) GetDeviceAuthByUserCode(_ context.Context, userCode string) (*athens.DeviceAuth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dc, ok := s.userCodes[userCode]
	if !ok {
		return nil, fmt.Errorf("unknown user code")
	}
	return s.devices[dc], nil
}

func (s *MemoryStore) ApproveDeviceAuth(_ context.Context, userCode string, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dc, ok := s.userCodes[userCode]
	if !ok {
		return fmt.Errorf("unknown user code")
	}
	auth := s.devices[dc]
	auth.Approved = true
	auth.Subject = subject
	return nil
}

type StaticClients struct {
	Clients map[string]*athens.Client
}

func (s *StaticClients) GetClient(_ context.Context, id string) (*athens.Client, error) {
	c, ok := s.Clients[id]
	if !ok {
		return nil, fmt.Errorf("unknown client: %s", id)
	}
	return c, nil
}

func (s *StaticClients) ValidateSecret(_ context.Context, client *athens.Client, secret string) error {
	if client.Public {
		return nil
	}
	if client.Secret != secret {
		return fmt.Errorf("invalid client secret")
	}
	return nil
}
