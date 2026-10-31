// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are the argon2id cost parameters.
type Argon2Params struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

// DefaultArgon2 follows the RFC 9106 second recommended option (64 MiB).
var DefaultArgon2 = Argon2Params{MemoryKiB: 64 * 1024, Time: 3, Threads: 2}

const (
	saltLen = 16
	keyLen  = 32
)

var b64 = base64.RawStdEncoding

// Hasher hashes and verifies passwords with argon2id. A semaphore bounds
// concurrent hashes so unauthenticated login floods cannot exhaust memory.
type Hasher struct {
	params Argon2Params
	sem    chan struct{}
}

// NewHasher returns a Hasher allowing at most concurrency parallel hashes.
func NewHasher(p Argon2Params, concurrency int) *Hasher {
	if concurrency < 1 {
		concurrency = 1
	}
	return &Hasher{params: p, sem: make(chan struct{}, concurrency)}
}

func (h *Hasher) acquire(ctx context.Context) error {
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() { <-h.sem }

// Hash returns a PHC-format argon2id string.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	p := h.params
	key := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.MemoryKiB, p.Time, p.Threads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

var errBadHash = errors.New("unsupported password hash")

// Verify reports whether password matches encoded. The stored parameters are
// used, so cost changes do not invalidate existing hashes.
func (h *Hasher) Verify(ctx context.Context, password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errBadHash
	}
	var v int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return false, errBadHash
	}
	var p Argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Time, &p.Threads); err != nil ||
		p.MemoryKiB < 8 || p.MemoryKiB > 1<<21 || p.Time < 1 || p.Time > 16 || p.Threads < 1 {
		return false, errBadHash
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, errBadHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) < 16 {
		return false, errBadHash
	}
	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	defer h.release()
	got := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
