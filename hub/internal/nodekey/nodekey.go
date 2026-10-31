// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package nodekey generates, hashes and authenticates node keys.
//
// A node key is 32 random bytes rendered "tsk_" + 64 lowercase hex. Only
// its SHA-256 is stored. Lookup is by hash: the hash of a 256-bit secret
// reveals nothing useful through lookup timing, so no separate
// constant-time comparison is needed.
package nodekey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
)

const prefix = "tsk_"

// ErrInvalid is returned for malformed or unknown keys.
var ErrInvalid = errors.New("invalid node key")

// Generate returns a new key and its hash.
func Generate() (key string, hash []byte) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("nodekey: crypto/rand failed: " + err.Error())
	}
	key = prefix + hex.EncodeToString(b[:])
	h := sha256.Sum256([]byte(key))
	return key, h[:]
}

// Hash validates the key format and returns its hash.
func Hash(key string) ([]byte, error) {
	if len(key) != len(prefix)+64 || !strings.HasPrefix(key, prefix) {
		return nil, ErrInvalid
	}
	for _, c := range key[len(prefix):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, ErrInvalid
		}
	}
	h := sha256.Sum256([]byte(key))
	return h[:], nil
}

// Lookup resolves a key hash to a node id.
type Lookup interface {
	NodeIDByKeyHash(ctx context.Context, hash []byte) (string, error)
}

// Authenticator resolves bearer keys to node ids with a positive cache.
// Invalidate must be called on rotation and deletion, Purge on factory
// reset; both take effect immediately.
type Authenticator struct {
	lookup Lookup

	mu     sync.RWMutex
	gen    uint64            // bumped by every invalidation
	byHash map[string]string // hash -> node id
	byNode map[string]string // node id -> hash
}

// NewAuthenticator returns an Authenticator backed by lookup.
func NewAuthenticator(l Lookup) *Authenticator {
	return &Authenticator{lookup: l, byHash: map[string]string{}, byNode: map[string]string{}}
}

// Authenticate returns the node id owning key.
func (a *Authenticator) Authenticate(ctx context.Context, key string) (string, error) {
	h, err := Hash(key)
	if err != nil {
		return "", err
	}
	hk := string(h)
	a.mu.RLock()
	id, ok := a.byHash[hk]
	gen := a.gen
	a.mu.RUnlock()
	if ok {
		return id, nil
	}
	id, err = a.lookup.NodeIDByKeyHash(ctx, h)
	if errors.Is(err, domain.ErrNotFound) {
		return "", ErrInvalid
	}
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	// Callers change the database before invalidating. If any
	// invalidation happened since the lookup started, the result may be
	// stale: answer it (it was valid when read) but do not cache it.
	if a.gen == gen {
		if old, exists := a.byNode[id]; exists {
			delete(a.byHash, old)
		}
		a.byHash[hk] = id
		a.byNode[id] = hk
	}
	a.mu.Unlock()
	return id, nil
}

// Invalidate drops the cached key of a node.
func (a *Authenticator) Invalidate(nodeID string) {
	a.mu.Lock()
	a.gen++
	if h, ok := a.byNode[nodeID]; ok {
		delete(a.byHash, h)
		delete(a.byNode, nodeID)
	}
	a.mu.Unlock()
}

// Purge drops all cached keys.
func (a *Authenticator) Purge() {
	a.mu.Lock()
	a.gen++
	a.byHash = map[string]string{}
	a.byNode = map[string]string{}
	a.mu.Unlock()
}
