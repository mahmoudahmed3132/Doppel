// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package beacon_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/beacon"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ingest"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/sourcelist"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

type lists struct{ m ported.SourceMatcher }

func (l lists) Whitelist() ported.SourceMatcher     { return l.m }
func (l lists) KnownScanners() ported.SourceMatcher { return l.m }

type sink struct {
	mu  sync.Mutex
	evs []domain.EnrichedEvent
}

func (s *sink) Enqueue(domain.Record)       {}
func (s *sink) Notify(domain.EnrichedEvent) {}
func (s *sink) PublishEvent(e domain.EnrichedEvent) {
	s.mu.Lock()
	s.evs = append(s.evs, e)
	s.mu.Unlock()
}

// The real module behind ported.BeaconService: a beacon is created against
// the deployed receiver's zone, its artefact plants the token, and a
// receiver report of that token is resolved by the ingest pipeline.
func TestModuleThroughPipeline(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "hub.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.CreateNode(ctx, &domain.Node{ID: "node-000000b1", Alias: "edge", KeyHash: []byte("k"), CreatedAt: now})
	svc := &beacon.Service{Store: db, Now: func() time.Time { return now },
		ReceiverKey: func(context.Context) (string, error) { return "receiver-key", nil },
		Domains:     beacon.ZonesFromFleet(db)}

	if _, err := svc.Create(ctx, beacon.TypeDNS, "file server", ""); !errors.Is(err, beacon.ErrInvalid) {
		t.Fatalf("created without a receiver zone: %v", err)
	}
	db.CreateSensor(ctx, &domain.Sensor{NodeID: "node-000000b1", ID: "ts-sensor-token-receiver", CatalogueName: beacon.ReceiverCatalogueName,
		Version: "1.0.0", Config: map[string]string{beacon.DomainConfigKey: "T.Example.COM."}, CreatedAt: now})
	if _, err := svc.Create(ctx, "web_bug", "x", ""); !errors.Is(err, beacon.ErrInvalid) {
		t.Fatal("unknown type accepted")
	}
	b, err := svc.Create(ctx, beacon.TypeKubeconfig, "jump host ~/.kube", "planted 2026-11")
	if err != nil || b.Domain != "t.example.com" || !beacon.ValidToken("receiver-key", b.Token) {
		t.Fatalf("%+v %v", b, err)
	}
	art, err := svc.Artefact(ctx, b.ID)
	if err != nil || !strings.Contains(string(art.Body), b.Token+".t.example.com") || art.ContentType != "application/yaml" {
		t.Fatalf("%+v %v", art, err)
	}

	empty, _ := sourcelist.Parser{}.Parse(nil)
	out := &sink{}
	p := &ingest.Pipeline{Store: db, Lists: lists{empty}, Beacons: svc, SIEM: out, Notifier: out, Live: out,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now }}
	report := func(id, token string) domain.EnrichedEvent {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"token": token, "channel": "dns", "qname": token + ".t.example.com"})
		ev := &domain.Event{EventID: id, NodeID: "node-000000b1", SensorID: "ts-sensor-token-receiver", Trigger: domain.TriggerBeaconTriggered,
			Severity: "high", OccurredAt: now, ReceivedAt: now, Source: "198.51.100.53", Target: "dns", Details: raw}
		if _, err := p.Process(ctx, ev); err != nil {
			t.Fatal(err)
		}
		out.mu.Lock()
		defer out.mu.Unlock()
		return out.evs[len(out.evs)-1]
	}
	got := report("0192f000-0000-7000-8000-0000000000b1", strings.ToUpper(b.Token))
	var d map[string]any
	json.Unmarshal(got.Details, &d)
	if got.Severity != domain.SeverityCritical || d["beacon"].(map[string]any)["id"] != b.ID {
		t.Fatalf("known token: %s %v", got.Severity, d)
	}
	got = report("0192f000-0000-7000-8000-0000000000b2", "aaaaaaaaaaaaaaaaaaaaaaaa")
	json.Unmarshal(got.Details, &d)
	if got.Severity != domain.SeverityMedium || d["beacon_known"] != false {
		t.Fatalf("unknown token: %s %v", got.Severity, d)
	}
	l, _ := svc.List(ctx)
	if len(l) != 1 || l[0].UseCount != 1 {
		t.Fatalf("use count %+v", l)
	}
	if err := svc.Delete(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	if r, _ := svc.Resolve(ctx, b.Token); r != nil {
		t.Fatal("deleted beacon still resolves")
	}
}
