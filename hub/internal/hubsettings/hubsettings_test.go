// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package hubsettings

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ported/stub"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/store"
)

func newSvc(t *testing.T, parser bool) (*Service, *store.DB) {
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "ts.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := &Service{Store: db, DefaultRegistry: "https://registry.example/", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if parser {
		s.Parser = stub.ExactSourceList{}
	}
	s.Load(context.Background())
	return s, db
}

func ptr[T any](v T) *T { return &v }

func TestDefaultsAndUpdate(t *testing.T) {
	s, _ := newSvc(t, true)
	ctx := context.Background()
	v := s.Get(ctx)
	if v.RegistryURL != "https://registry.example/" || v.UpdateCheckHours != 24 || v.Retention.HistoryDays != 30 ||
		v.Retention.ArchiveAfterDays != 0 || !v.SourceListsActive || len(v.Whitelist) != 0 {
		t.Fatalf("%+v", v)
	}
	if s.Whitelist() != nil {
		t.Fatal("empty list must not match")
	}
	p := Patch{PublicEndpoint: ptr("https://Hub.Example.com/"), UpdateCheckHours: ptr(0),
		Whitelist: &[]string{"10.0.0.7", " 10.0.0.7 ", "", "scanner.corp"}}
	p.Retention = &struct {
		ArchiveAfterDays       *int `json:"archive_after_days"`
		PurgeArchivedAfterDays *int `json:"purge_archived_after_days"`
		HistoryDays            *int `json:"history_days"`
	}{ArchiveAfterDays: ptr(30)}
	v, err := s.Update(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if v.PublicEndpoint != "https://hub.example.com" || v.UpdateCheckHours != 0 || v.Retention.ArchiveAfterDays != 30 ||
		strings.Join(v.Whitelist, ",") != "10.0.0.7,scanner.corp" {
		t.Fatalf("%+v", v)
	}
	if !s.Whitelist().Match("10.0.0.7:4444") || s.Whitelist().Match("10.0.0.8") {
		t.Fatal("whitelist not applied immediately")
	}
	// A fresh service (restart) loads the same matcher.
	s2 := &Service{Store: s.Store, Parser: stub.ExactSourceList{}, Log: s.Log}
	s2.Load(ctx)
	if s2.Whitelist() == nil || !s2.Whitelist().Match("scanner.corp") {
		t.Fatal("whitelist not loaded at start")
	}
}

func TestValidation(t *testing.T) {
	s, _ := newSvc(t, true)
	ctx := context.Background()
	bad := []Patch{
		{PublicEndpoint: ptr("ftp://x")},
		{RegistryURL: ptr("http://registry.example/")}, // http outside development
		{CatalogueRefreshHours: ptr(0)},
		{UpdateCheckHours: ptr(-1)},
		{Whitelist: &[]string{"ok", "bad\nentry"}},
		{KnownScanners: &[]string{strings.Repeat("a", 300)}},
	}
	for i, p := range bad {
		if _, err := s.Update(ctx, p); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d accepted: %v", i, err)
		}
	}
	many := make([]string, MaxListEntries+1)
	for i := range many {
		many[i] = "h" + strings.Repeat("x", i%5)
	}
	if _, err := s.Update(ctx, Patch{Whitelist: &many}); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversized list accepted")
	}
	// A failed patch changes nothing.
	if v := s.Get(ctx); v.PublicEndpoint != "" {
		t.Fatal("partial update persisted")
	}
	if _, err := s.ReplaceAssets(ctx, []byte(`[]`)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("assets accepted without the PORTED module")
	}
}

func TestListsStoredButInactiveWithoutParser(t *testing.T) {
	s, _ := newSvc(t, false)
	v, err := s.Update(context.Background(), Patch{Whitelist: &[]string{"10.0.0.7"}})
	if err != nil || v.SourceListsActive || len(v.Whitelist) != 1 || s.Whitelist() != nil {
		t.Fatalf("%+v %v", v, err)
	}
}

func TestRetention(t *testing.T) {
	s, db := newSvc(t, false)
	ctx := context.Background()
	now := time.Now()
	for i, age := range []time.Duration{100 * 24 * time.Hour, 40 * 24 * time.Hour, time.Hour} {
		db.InsertEvent(ctx, &domain.Event{EventID: string(rune('a' + i)), NodeID: "node-00000001", SensorID: "ts-sensor-a",
			Trigger: "x", Severity: "low", OccurredAt: now.Add(-age), ReceivedAt: now.Add(-age), Source: "s", Target: "t", Details: []byte("{}")})
	}
	// Default: nothing archived or purged.
	s.RunRetention(ctx, db, now)
	f := false
	if ev, _ := db.Events(ctx, store.EventFilter{Archived: &f}); len(ev) != 3 {
		t.Fatal("retention active by default")
	}
	p := Patch{}
	p.Retention = &struct {
		ArchiveAfterDays       *int `json:"archive_after_days"`
		PurgeArchivedAfterDays *int `json:"purge_archived_after_days"`
		HistoryDays            *int `json:"history_days"`
	}{ArchiveAfterDays: ptr(30), PurgeArchivedAfterDays: ptr(90)}
	s.Update(ctx, p)
	if err := s.RunRetention(ctx, db, now); err != nil {
		t.Fatal(err)
	}
	all, _ := db.Events(ctx, store.EventFilter{})
	unarchived, _ := db.Events(ctx, store.EventFilter{Archived: &f})
	if len(all) != 2 || len(unarchived) != 1 {
		t.Fatalf("all %d unarchived %d", len(all), len(unarchived))
	}
}
