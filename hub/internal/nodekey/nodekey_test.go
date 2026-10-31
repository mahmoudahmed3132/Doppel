// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package nodekey

import (
	"context"
	"regexp"
	"sync"
	"testing"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
)

type memLookup struct {
	mu    sync.Mutex
	keys  map[string]string
	calls int
}

func (m *memLookup) NodeIDByKeyHash(_ context.Context, h []byte) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if id, ok := m.keys[string(h)]; ok {
		return id, nil
	}
	return "", domain.ErrNotFound
}

func TestGenerateFormat(t *testing.T) {
	k, h := Generate()
	if !regexp.MustCompile(`^tsk_[0-9a-f]{64}$`).MatchString(k) || len(h) != 32 {
		t.Fatalf("bad key %q", k)
	}
	h2, err := Hash(k)
	if err != nil || string(h2) != string(h) {
		t.Fatal("hash mismatch")
	}
	for _, bad := range []string{"", "tsk_", "tsk_" + string(make([]byte, 64)), "TSK_" + k[4:], k[:len(k)-1] + "G"} {
		if _, err := Hash(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestRotationAndDeletionImmediate(t *testing.T) {
	ctx := context.Background()
	oldKey, oldHash := Generate()
	l := &memLookup{keys: map[string]string{string(oldHash): "node-00000001"}}
	a := NewAuthenticator(l)

	for i := 0; i < 3; i++ {
		if id, err := a.Authenticate(ctx, oldKey); err != nil || id != "node-00000001" {
			t.Fatal(id, err)
		}
	}
	if l.calls != 1 {
		t.Fatalf("cache not used: %d lookups", l.calls)
	}

	newKey, newHash := Generate()
	l.mu.Lock()
	delete(l.keys, string(oldHash))
	l.keys[string(newHash)] = "node-00000001"
	l.mu.Unlock()
	a.Invalidate("node-00000001")

	if _, err := a.Authenticate(ctx, oldKey); err != ErrInvalid {
		t.Fatalf("old key accepted after rotation: %v", err)
	}
	if id, err := a.Authenticate(ctx, newKey); err != nil || id != "node-00000001" {
		t.Fatal(id, err)
	}

	l.mu.Lock()
	delete(l.keys, string(newHash))
	l.mu.Unlock()
	a.Invalidate("node-00000001")
	if _, err := a.Authenticate(ctx, newKey); err != ErrInvalid {
		t.Fatalf("deleted node's key accepted: %v", err)
	}
}
