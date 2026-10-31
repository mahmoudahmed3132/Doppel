// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

// Package ids generates identifiers used by the Hub.
package ids

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("ids: crypto/rand failed: " + err.Error())
	}
	return b
}

// UUIDv7 returns an RFC 9562 version 7 UUID for Hub-raised events.
// Ordering within one millisecond is not guaranteed (Hub events are
// ordered by their sequence number, not their id).
func UUIDv7(now time.Time) string {
	b := random(16)
	ms := uint64(now.UnixMilli())
	for i := 0; i < 6; i++ {
		b[i] = byte(ms >> (40 - 8*i))
	}
	b[6] = 0x70 | b[6]&0x0f
	b[8] = 0x80 | b[8]&0x3f
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

var uuidV7RE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// NormalizeUUIDv7 lower-cases id and reports whether it is a canonical
// version 7 UUID.
func NormalizeUUIDv7(id string) (string, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	return id, uuidV7RE.MatchString(id)
}

// NodeID returns "node-" + 8 lowercase hex.
func NodeID() string { return "node-" + hex.EncodeToString(random(4)) }

// Token returns n random bytes encoded base64url without padding.
func Token(n int) string { return base64.RawURLEncoding.EncodeToString(random(n)) }

// Hex returns n random bytes hex-encoded.
func Hex(n int) string { return hex.EncodeToString(random(n)) }

// Short returns a prefixed short random id, e.g. Short("ht") = "ht_1a2b3c4d5e6f".
func Short(prefix string) string { return fmt.Sprintf("%s_%s", prefix, Hex(6)) }
