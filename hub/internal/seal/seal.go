// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package seal encrypts the Hub's secrets at rest (THREATMODEL R1).
//
// Two-level keys: a random 32-byte data-encryption key (DEK) seals every
// secret value; the DEK itself is stored wrapped by a key-encryption key
// (KEK) that lives outside the database (a key file or Docker secret, behind
// the KeyProvider interface). Rotating the KEK re-wraps the DEK only.
//
// A sealed value is "enc:v1:" + base64url(nonce || AES-256-GCM ciphertext).
// The additional authenticated data binds each value to its place (table,
// column, row), so a ciphertext copied to another row or column does not open.
// The prefix makes migration idempotent: a value without it is plaintext.
//
// Boundary: this protects database files, snapshots and backups taken without
// the KEK. It does not protect against an attacker who is root on the running
// Hub host (the DEK is in process memory, the KEK file is readable).
package seal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Prefix marks a sealed value.
const Prefix = "enc:v1:"

// KeyLen is the length of the KEK and the DEK.
const KeyLen = 32

// Errors.
var (
	ErrNotSealed = errors.New("seal: value is not sealed")
	ErrOpen      = errors.New("seal: cannot open value (wrong key, wrong place, or tampered)")
	ErrBadKEK    = errors.New("seal: key-encryption key must be 32 bytes (64 hex characters, or 32 raw bytes)")
	ErrWrongKEK  = errors.New("seal: the key-encryption key does not unwrap the stored data key")
)

// IsSealed reports whether v carries the sealed prefix.
func IsSealed(v string) bool { return strings.HasPrefix(v, Prefix) }

// KeyProvider supplies the key-encryption key. Implementations may read a
// file, a Docker secret, or call a KMS; the Hub only needs the bytes.
type KeyProvider interface {
	KEK(ctx context.Context) ([]byte, error)
	// Describe names the source for logs (never the key).
	Describe() string
}

// FileProvider reads the KEK from a file holding 64 hex characters (optional
// trailing newline) or exactly 32 raw bytes.
type FileProvider struct{ Path string }

// KEK implements KeyProvider.
func (p FileProvider) KEK(context.Context) ([]byte, error) {
	b, err := os.ReadFile(p.Path)
	if err != nil {
		return nil, fmt.Errorf("reading key-encryption key file: %w", err)
	}
	return ParseKEK(b)
}

// Describe implements KeyProvider.
func (p FileProvider) Describe() string { return "file " + p.Path }

// StaticProvider holds a KEK in memory (tests, key rotation).
type StaticProvider struct{ Key []byte }

// KEK implements KeyProvider.
func (p StaticProvider) KEK(context.Context) ([]byte, error) { return p.Key, nil }

// Describe implements KeyProvider.
func (p StaticProvider) Describe() string { return "static" }

// ParseKEK accepts 64 hex characters (surrounding whitespace ignored) or 32 raw bytes.
func ParseKEK(b []byte) ([]byte, error) {
	if len(b) == KeyLen {
		return append([]byte(nil), b...), nil
	}
	if k, err := hex.DecodeString(strings.TrimSpace(string(b))); err == nil && len(k) == KeyLen {
		return k, nil
	}
	return nil, ErrBadKEK
}

// GenerateKEK returns a new random KEK as 64 hex characters.
func GenerateKEK() (string, error) {
	k := make([]byte, KeyLen)
	if _, err := rand.Read(k); err != nil {
		return "", err
	}
	return hex.EncodeToString(k), nil
}

// Fingerprint identifies a KEK without revealing it (for backup manifests and logs).
func Fingerprint(kek []byte) string {
	h := sha256.Sum256(append([]byte("doppel-kek-fingerprint-v1\x00"), kek...))
	return hex.EncodeToString(h[:8])
}

const wrapAAD = "doppel-dek-wrap-v1"

// NewDEK returns a random data key.
func NewDEK() ([]byte, error) {
	k := make([]byte, KeyLen)
	_, err := rand.Read(k)
	return k, err
}

// Wrap encrypts dek under kek.
func Wrap(kek, dek []byte) (string, error) {
	return seal(kek, []byte(wrapAAD), dek)
}

// Unwrap decrypts a wrapped data key.
func Unwrap(kek []byte, wrapped string) ([]byte, error) {
	dek, err := open(kek, []byte(wrapAAD), wrapped)
	if err != nil {
		return nil, ErrWrongKEK
	}
	if len(dek) != KeyLen {
		return nil, ErrWrongKEK
	}
	return dek, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyLen {
		return nil, ErrBadKEK
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func seal(key, aad, pt []byte) (string, error) {
	g, err := gcm(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize()) // Seal appends to it; no size arithmetic on input length
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(g.Seal(nonce, nonce, pt, aad)), nil
}

func open(key, aad []byte, v string) ([]byte, error) {
	if !IsSealed(v) {
		return nil, ErrNotSealed
	}
	raw, err := base64.RawURLEncoding.DecodeString(v[len(Prefix):])
	if err != nil {
		return nil, ErrOpen
	}
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(raw) < g.NonceSize()+g.Overhead() {
		return nil, ErrOpen
	}
	pt, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], aad)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// Sealer seals and opens values with the DEK.
type Sealer struct {
	dek    []byte
	strict bool
}

// New returns a Sealer for dek.
func New(dek []byte) (*Sealer, error) {
	if len(dek) != KeyLen {
		return nil, ErrBadKEK
	}
	return &Sealer{dek: append([]byte(nil), dek...)}, nil
}

// SetStrict makes Open refuse unsealed values. Call it once every secret has
// been migrated, so a plaintext value written into the database by someone
// with file access is refused rather than trusted.
func (s *Sealer) SetStrict(v bool) { s.strict = v }

// Seal encrypts plaintext, bound to aad (for example "settings/siem_token").
// An empty plaintext stays empty: "not set" must remain observable.
func (s *Sealer) Seal(aad, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	return seal(s.dek, []byte(aad), []byte(plaintext))
}

// Open decrypts a value sealed for aad. An empty value is returned as is. An
// unsealed value is returned as is unless the Sealer is strict.
func (s *Sealer) Open(aad, v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if !IsSealed(v) {
		if s.strict {
			return "", ErrNotSealed
		}
		return v, nil
	}
	pt, err := open(s.dek, []byte(aad), v)
	return string(pt), err
}
