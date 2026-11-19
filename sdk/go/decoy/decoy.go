// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package decoy holds building blocks shared by interactive service decoys
// (protocol emulators behind one or more listeners): a multi-listener
// "proto:port" list, the accept loop, input sanitising, the password capture
// policy and a per-source event limiter. Protocol emulation stays in each
// sensor; reporting goes through sensor.Reporter.
//
// Imported from TrueSignal (see PROVENANCE.md): ParseServices, Accept,
// RemoteIP, Sanitize and Limiter are that SDK add-on's; Capture is adapted to
// the base capture key (TS_CAPTURE_KEY, hex) and sensor.Fields.
package decoy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

// Service is one decoy listener: a protocol name and a port.
type Service struct {
	Proto string
	Port  int
}

// ParseServices parses "proto:port,proto:port" into a validated list. It
// rejects protocols not in allowed, bad ports and a port used twice. The Hub
// separately rejects two sensors on one node binding the same port
// (listen_ports_env).
func ParseServices(raw string, allowed ...string) ([]Service, error) {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	var out []Service
	seen := map[int]bool{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		proto, portStr, found := strings.Cut(part, ":")
		if !found {
			return nil, fmt.Errorf("bad service %q, want proto:port", part)
		}
		proto = strings.ToLower(strings.TrimSpace(proto))
		if !ok[proto] {
			return nil, fmt.Errorf("unsupported protocol %q (want %s)", proto, strings.Join(allowed, ", "))
		}
		port, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("bad port in %q", part)
		}
		if seen[port] {
			return nil, fmt.Errorf("port %d used twice", port)
		}
		seen[port] = true
		out = append(out, Service{Proto: proto, Port: port})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no services configured")
	}
	return out, nil
}

// Accept serves connections from ln until ctx ends.
func Accept(ctx context.Context, ln net.Listener, handle func(net.Conn)) {
	defer ln.Close()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go handle(conn)
	}
}

// RemoteIP is the peer address without the port.
func RemoteIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// Sanitize makes attacker input safe to log and to carry in a JSON event:
// invalid UTF-8 is replaced and the value is capped at n bytes.
func Sanitize(s string, n int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "?")
	}
	if n > 0 && len(s) > n {
		s = s[:n]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// Capture decides how much of a captured secret leaves the decoy: "hash"
// (default) records a keyed HMAC-SHA256 and the length, never the secret;
// "plain" opts in to cleartext; "none" records only that something was
// submitted. A real password landing in the Hub or SIEM is credential
// material under PCI DSS, so the default never stores the recoverable value.
//
// The key is the node capture key the Hub injects (TS_CAPTURE_KEY, hex), so
// the Hub can recognise planted honeytokens (docs/sensors.md, honeytoken
// matching contract).
type Capture struct {
	mode string
	key  []byte
}

// CaptureModeKey and CaptureKeyKey are the settings NewCapture reads.
const (
	CaptureModeKey = "TS_PASSWORD_CAPTURE"
	CaptureKeyKey  = "TS_CAPTURE_KEY"
)

// NewCapture reads the capture mode and key from the sensor's settings.
// Hash mode without a valid key is an error: the decoy must not run with a
// key the Hub cannot reproduce.
func NewCapture(r sensor.Reporter) (Capture, error) {
	mode, _ := r.Setting(CaptureModeKey)
	raw, _ := r.Setting(CaptureKeyKey)
	return NewCaptureWith(mode, raw)
}

// NewCaptureWith builds a Capture from a mode and a hex key.
func NewCaptureWith(mode, hexKey string) (Capture, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "plain", "none":
		return Capture{mode: mode}, nil
	case "", "hash":
		key, err := hex.DecodeString(strings.TrimSpace(hexKey))
		if err != nil || len(key) < 16 {
			return Capture{}, fmt.Errorf("%s (set by the Hub) is required for password capture \"hash\"", CaptureKeyKey)
		}
		return Capture{mode: "hash", key: key}, nil
	}
	return Capture{}, fmt.Errorf("%s must be hash, plain or none", CaptureModeKey)
}

// Password returns event fields for a submitted password.
func (c Capture) Password(password string) sensor.Fields {
	return c.Secret("password", password)
}

// Secret labels a captured value (password, community string) under prefix,
// e.g. prefix "password" gives password_hmac / password_length.
func (c Capture) Secret(prefix, value string) sensor.Fields {
	switch c.mode {
	case "plain":
		return sensor.Fields{sensor.F(prefix, Sanitize(value, 256))}
	case "none":
		return sensor.Fields{sensor.F(prefix+"_submitted", value != "")}
	default:
		mac := hmac.New(sha256.New, c.key)
		mac.Write([]byte(value))
		return sensor.Fields{sensor.F(prefix+"_hmac", hex.EncodeToString(mac.Sum(nil))), sensor.F(prefix+"_length", len(value))}
	}
}

// DeriveKey deterministically derives a 32-byte key from captureKey and a
// domain-separated purpose label using HMAC-SHA256. Decoys use it to derive
// per-node, per-sensor identities (such as SSH host key seeds, SNMPv3 engine
// IDs, and NTLM persona defaults) so two Doppel nodes never share identical
// fingerprints without persisting key material to disk.
func DeriveKey(captureKey []byte, purpose string) []byte {
	mac := hmac.New(sha256.New, captureKey)
	mac.Write([]byte(purpose))
	return mac.Sum(nil)
}

// Limiter caps how many events one source can raise per window, so a password
// spray of thousands of attempts cannot flood the Hub and the SIEM. Allow
// reports whether to emit, and how many events were suppressed since the last
// one emitted for that source (attach it as suppressed_since_last).
//
// State is bounded: at most maxTracked sources are tracked individually.
// Expired entries are swept at most once per window (those with suppressed
// attempts survive one extra window to report them), so a flood of distinct
// (e.g. spoofed UDP) sources costs amortised O(1) per call. When the table is
// still full, untracked sources share one overflow budget.
type Limiter struct {
	mu         sync.Mutex
	limit      int
	window     time.Duration
	maxTracked int
	seen       map[string]*limitState
	lastSweep  time.Time
	now        func() time.Time
}

type limitState struct {
	start      time.Time
	count      int
	suppressed int
}

// overflowKey is the shared bucket for sources that arrive while the table is
// full. It cannot collide with an IP address.
const overflowKey = "\x00overflow"

// NewLimiter allows limit events per source per window.
func NewLimiter(limit int, window time.Duration) *Limiter {
	return &Limiter{limit: limit, window: window, maxTracked: 10000, seen: map[string]*limitState{}, now: time.Now}
}

// Allow records one event from src.
func (l *Limiter) Allow(src string) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if _, tracked := l.seen[src]; !tracked && len(l.seen) >= l.maxTracked {
		if now.Sub(l.lastSweep) >= l.window {
			for k, v := range l.seen {
				// An expired entry still holding suppressed attempts is kept
				// one extra window, so a source that comes back gets that count
				// in suppressed_since_last; after that it is dropped, so stale
				// entries cannot hold the table full for good.
				age := now.Sub(v.start)
				if age >= 2*l.window || (age >= l.window && v.suppressed == 0) {
					delete(l.seen, k)
				}
			}
			l.lastSweep = now
		}
		if len(l.seen) >= l.maxTracked {
			src = overflowKey
		}
	}
	st, ok := l.seen[src]
	if !ok || now.Sub(st.start) >= l.window {
		prev := 0
		if ok {
			prev = st.suppressed
		}
		l.seen[src] = &limitState{start: now, count: 1}
		return true, prev
	}
	if st.count < l.limit {
		st.count++
		s := st.suppressed
		st.suppressed = 0
		return true, s
	}
	st.suppressed++
	return false, 0
}

// ServePacket reads datagrams from pc until ctx ends and calls handle for
// each with a private copy of the payload, so handle may keep it. Datagrams
// longer than maxSize are truncated to maxSize bytes and still delivered
// (the handler's parser rejects them); a read error other than shutdown is
// retried. handle runs on the read goroutine: it must be quick and must not
// block, because a slow handler would otherwise let an attacker queue
// unbounded work. Replies are the handler's job; keep them no larger than
// the request (see network-service-decoy.md, anti-amplification).
func ServePacket(ctx context.Context, pc net.PacketConn, maxSize int, handle func(from net.Addr, payload []byte)) {
	if maxSize <= 0 {
		maxSize = 1500
	}
	defer pc.Close()
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	buf := make([]byte, maxSize)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		handle(from, append([]byte(nil), buf[:n]...))
	}
}
