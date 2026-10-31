// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package sensor

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// uuidGen produces RFC 9562 version 7 UUIDs. Within one millisecond the
// 12-bit rand_a field is used as a counter seeded randomly (RFC 9562 §6.2,
// method 1), so IDs from one process sort in creation order.
type uuidGen struct {
	mu      sync.Mutex
	lastMS  int64
	counter uint16 // 12 bits used
	now     func() time.Time
}

func newUUIDGen(now func() time.Time) *uuidGen {
	if now == nil {
		now = time.Now
	}
	return &uuidGen{now: now}
}

func (g *uuidGen) next() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand never fails on supported platforms; a failure here is
		// unrecoverable and must not yield predictable IDs.
		panic("sensor: crypto/rand failed: " + err.Error())
	}

	g.mu.Lock()
	ms := g.now().UnixMilli()
	if ms <= g.lastMS {
		// Same millisecond or clock went backwards: keep the previous
		// timestamp and advance the counter.
		ms = g.lastMS
		g.counter++
		if g.counter > 0x0fff {
			// Counter exhausted: borrow the next millisecond.
			ms++
			g.counter = uint16(b[6]&0x03)<<8 | uint16(b[7])
		}
	} else {
		// New millisecond: seed counter with random bits, leaving headroom.
		g.counter = uint16(b[6]&0x07)<<8 | uint16(b[7])
	}
	g.lastMS = ms
	ctr := g.counter
	g.mu.Unlock()

	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	b[6] = 0x70 | byte(ctr>>8)&0x0f
	b[7] = byte(ctr)
	b[8] = 0x80 | b[8]&0x3f

	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:])
}
