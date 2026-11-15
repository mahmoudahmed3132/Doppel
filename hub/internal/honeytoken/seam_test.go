// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package honeytoken_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/compose"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/honeytoken"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ingest"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/sourcelist"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

type lists struct{ m ported.SourceMatcher }

func (l lists) Whitelist() ported.SourceMatcher     { return l.m }
func (l lists) KnownScanners() ported.SourceMatcher { return l.m }

type sink struct {
	mu   sync.Mutex
	recs []domain.Record
}

func (s *sink) Enqueue(r domain.Record)              { s.mu.Lock(); s.recs = append(s.recs, r); s.mu.Unlock() }
func (s *sink) Notify(domain.EnrichedEvent)          {}
func (s *sink) PublishEvent(domain.EnrichedEvent)    {}
func (s *sink) raised(trigger string) []domain.Event { return s.events(trigger) }
func (s *sink) events(trigger string) (out []domain.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.recs {
		if r.Event != nil && r.Event.Trigger == trigger {
			out = append(out, r.Event.Event)
		}
	}
	return out
}

var master = []byte("0123456789abcdef0123456789abcdef")

func capture(nodeID string) []byte { return compose.CaptureKey(master, nodeID) }

func pwHMAC(key []byte, pw string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(pw))
	return hex.EncodeToString(m.Sum(nil))
}

// The real module behind ported.HoneytokenService, driven by the ingest
// pipeline: a token planted on one node is recognised by username and by
// the reporting node's password HMAC, and raises honeytoken_used.
func TestModuleThroughPipeline(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "hub.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, n := range []string{"node-00000001", "node-00000002"} {
		db.CreateNode(ctx, &domain.Node{ID: n, Alias: n, KeyHash: []byte(n), CreatedAt: now})
		db.CreateSensor(ctx, &domain.Sensor{NodeID: n, ID: "ts-sensor-web", CatalogueName: "web-router-decoy", Version: "1.0.0", CreatedAt: now})
	}
	svc := &honeytoken.Service{Store: db, CaptureKey: capture, Now: func() time.Time { return now }}

	tok, err := svc.Ensure(ctx, "node-00000001", "ts-sensor-files")
	if err != nil || !strings.HasPrefix(tok.ID, "ht_") || !strings.HasPrefix(tok.Username, "svc_") || len(tok.Secret) != 15 || tok.Status != "active" {
		t.Fatalf("%+v %v", tok, err)
	}
	again, _ := svc.Ensure(ctx, "node-00000001", "ts-sensor-files")
	other, _ := svc.Ensure(ctx, "node-00000002", "ts-sensor-files")
	if again.ID != tok.ID || again.Secret != tok.Secret || other.ID == tok.ID {
		t.Fatal("tokens must be stable per sensor and distinct across sensors")
	}

	empty, _ := sourcelist.Parser{}.Parse(nil)
	out := &sink{}
	p := &ingest.Pipeline{Store: db, Lists: lists{empty}, Honeytokens: svc, SIEM: out, Notifier: out, Live: out,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now }}
	send := func(id, node string, details map[string]any) {
		t.Helper()
		raw, _ := json.Marshal(details)
		ev := &domain.Event{EventID: id, NodeID: node, SensorID: "ts-sensor-web", Trigger: "web_login_attempt", Severity: "high",
			OccurredAt: now, ReceivedAt: now, Source: "10.9.9.9", Target: "router", Details: raw}
		if _, err := p.Process(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	// 1. Username only, in DOMAIN\user form, on another node.
	send("0192f000-0000-7000-8000-000000000001", "node-00000002", map[string]any{"username": `CORP\` + strings.ToUpper(tok.Username)})
	// 2. Password HMAC under the reporting node's own key, wrong username.
	send("0192f000-0000-7000-8000-000000000002", "node-00000002", map[string]any{"username": "admin", "password_hmac": pwHMAC(capture("node-00000002"), tok.Secret), "protocol": "http", "dst_port": 8080})
	// 3. Password HMAC under another node's key: no match.
	send("0192f000-0000-7000-8000-000000000003", "node-00000002", map[string]any{"username": "admin", "password_hmac": pwHMAC(capture("node-00000001"), tok.Secret)})

	used := out.raised(domain.TriggerHoneytokenUsed)
	if len(used) != 2 {
		t.Fatalf("honeytoken_used raised %d times, want 2", len(used))
	}
	var d0, d1 map[string]any
	json.Unmarshal(used[0].Details, &d0)
	json.Unmarshal(used[1].Details, &d1)
	if d0["matched_on"] != "username" || d0["honeytoken_id"] != tok.ID || d0["planted_node_id"] != "node-00000001" {
		t.Fatalf("username match %v", d0)
	}
	if d1["matched_on"] != "password" || d1["protocol"] != "http" || d1["dst_port"] != 8080.0 {
		t.Fatalf("hmac match %v", d1)
	}
	if strings.Contains(string(used[0].Details)+string(used[1].Details), tok.Secret) {
		t.Fatal("secret leaked into the raised event")
	}
	list, _ := svc.List(ctx)
	for _, h := range list {
		if h.ID == tok.ID && h.UseCount != 2 {
			t.Fatalf("use count %d", h.UseCount)
		}
	}
	inv, _ := svc.Inventory(ctx, now)
	b, _ := json.Marshal(inv)
	if len(inv) != 2 || strings.Contains(string(b), tok.Secret) || strings.Contains(string(b), other.Secret) {
		t.Fatalf("inventory %s", b)
	}
}
