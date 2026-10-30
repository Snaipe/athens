// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package athens

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"
	"time"
)

// RotatingKeyConfig configures the built-in rotating key manager.
type RotatingKeyConfig struct {
	// Algorithm is the signing algorithm. Supported: ES256, ES384, RS256, EdDSA.
	Algorithm string

	// RotateEvery is how often a new key is generated. Defaults to 24h.
	RotateEvery time.Duration

	// RetireAfter is how long old keys remain in the JWKS after rotation,
	// so tokens signed with them can still be verified. Defaults to 48h.
	RetireAfter time.Duration

	// Store persists keys across restarts. Required.
	Store KeyStore
}

// KeyStore persists key material for the rotating key manager.
type KeyStore interface {
	SaveKey(ctx context.Context, entry *KeyEntry) error
	LoadKeys(ctx context.Context) ([]*KeyEntry, error)
	DeleteKey(ctx context.Context, kid string) error
}

// KeyEntry is a persisted key record.
type KeyEntry struct {
	KID       string
	Algorithm string
	Key       crypto.Signer
	CreatedAt time.Time
	ExpiresAt time.Time
}

// RotatingKeyManager automatically rotates signing keys on a schedule.
// It implements KeyManager.
type RotatingKeyManager struct {
	cfg     RotatingKeyConfig
	mu      sync.RWMutex
	keys    []*KeyEntry
	current *KeyEntry
}

// NewRotatingKeyManager creates a key manager that automatically rotates
// signing keys on the configured schedule.
func NewRotatingKeyManager(cfg RotatingKeyConfig) (*RotatingKeyManager, error) {
	if cfg.Store == nil {
		panic("athens: RotatingKeyConfig.Store must not be nil")
	}
	if cfg.Algorithm == "" {
		cfg.Algorithm = "EdDSA"
	}
	if cfg.RotateEvery == 0 {
		cfg.RotateEvery = 24 * time.Hour
	}
	if cfg.RetireAfter == 0 {
		cfg.RetireAfter = 48 * time.Hour
	}

	m := &RotatingKeyManager{cfg: cfg}

	keys, err := cfg.Store.LoadKeys(context.Background())
	if err != nil {
		return nil, fmt.Errorf("loading keys: %w", err)
	}
	m.keys = keys
	for _, k := range keys {
		if m.current == nil || k.CreatedAt.After(m.current.CreatedAt) {
			m.current = k
		}
	}

	if m.current == nil || time.Since(m.current.CreatedAt) > cfg.RotateEvery {
		if err := m.rotate(context.Background()); err != nil {
			return nil, fmt.Errorf("generating initial key: %w", err)
		}
	}

	go m.runRotation()
	return m, nil
}

func (m *RotatingKeyManager) CurrentKey(_ context.Context) (string, crypto.Signer, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.current == nil {
		return "", nil, fmt.Errorf("no signing key available")
	}
	return m.current.KID, m.current.Key, nil
}

func (m *RotatingKeyManager) PublicKeys(_ context.Context) ([]PublicKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	result := make([]PublicKey, 0, len(m.keys))
	for _, k := range m.keys {
		if !k.ExpiresAt.IsZero() && now.After(k.ExpiresAt) {
			continue
		}
		result = append(result, PublicKey{
			KID:       k.KID,
			Algorithm: k.Algorithm,
			Key:       k.Key.Public(),
			ExpiresAt: k.ExpiresAt,
		})
	}
	return result, nil
}

func (m *RotatingKeyManager) rotate(ctx context.Context) error {
	key, err := generateKey(m.cfg.Algorithm)
	if err != nil {
		return err
	}

	kid, err := generateKID()
	if err != nil {
		return err
	}

	now := time.Now()
	entry := &KeyEntry{
		KID:       kid,
		Algorithm: m.cfg.Algorithm,
		Key:       key,
		CreatedAt: now,
		ExpiresAt: now.Add(m.cfg.RotateEvery + m.cfg.RetireAfter),
	}

	if err := m.cfg.Store.SaveKey(ctx, entry); err != nil {
		return err
	}

	m.mu.Lock()
	m.keys = append(m.keys, entry)
	m.current = entry
	m.mu.Unlock()

	m.retire(ctx)
	return nil
}

func (m *RotatingKeyManager) retire(ctx context.Context) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	live := m.keys[:0]
	for _, k := range m.keys {
		if k.ExpiresAt.IsZero() || now.Before(k.ExpiresAt) {
			live = append(live, k)
		} else {
			_ = m.cfg.Store.DeleteKey(ctx, k.KID)
		}
	}
	m.keys = live
}

func (m *RotatingKeyManager) runRotation() {
	ticker := time.NewTicker(m.cfg.RotateEvery)
	defer ticker.Stop()
	for range ticker.C {
		_ = m.rotate(context.Background())
	}
}

func generateKey(algorithm string) (crypto.Signer, error) {
	switch algorithm {
	case "ES256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ES384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "RS256":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "EdDSA":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

func generateKID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	kid := make([]byte, len(b))
	for i, v := range b {
		kid[i] = charset[int(v)%len(charset)]
	}
	return string(kid), nil
}
