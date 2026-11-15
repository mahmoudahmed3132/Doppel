// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

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

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported/stub"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/sourcelist"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

func newSvc(t *testing.T, parser bool) (*Service, *store.DB) {
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "ts.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := &Service{Store: db, DefaultRegistry: "https://registry.example/", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if parser {
		s.Parser = sourcelist.Parser{}
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
	s2 := &Service{Store: s.Store, Parser: sourcelist.Parser{}, Log: s.Log}
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

// With the asset module installed (stub): validated, normalised, stored,
// indexed for enrichment, rebuilt from storage on restart; invalid or
// oversized inventories are refused without replacing the current one.
func TestAssetInventoryWithModule(t *testing.T) {
	s, db := newSvc(t, false)
	ctx := context.Background()
	if _, err := s.ReplaceAssets(ctx, []byte(`[]`)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("without the module: %v", err)
	}
	s.Assets = stub.Assets{}
	norm, err := s.ReplaceAssets(ctx, []byte(` [ {"match":"10.0.0.7", "name":"jump-host", "criticality":"high"} ] `))
	if err != nil || !strings.HasPrefix(string(norm), `[{"match":"10.0.0.7"`) {
		t.Fatalf("%s %v", norm, err)
	}
	if a := s.AssetIndex(ctx).Lookup("10.0.0.7:22"); a == nil || a.Name != "jump-host" || a.Criticality != "high" {
		t.Fatalf("lookup %+v", a)
	}
	for _, bad := range []string{`{"not":"a list"}`, `[{"match":"","name":"x","criticality":"low"}]`,
		`[{"match":"a","name":"x","criticality":"severe"}]`, `[{"match":"a","name":"x","criticality":"low","extra":1}]`,
		`[` + strings.Repeat(`{"match":"a","name":"x","criticality":"low"},`, MaxAssetsBytes/40) + `{}]`} {
		if _, err := s.ReplaceAssets(ctx, []byte(bad)); err == nil {
			t.Errorf("accepted %.60s", bad)
		}
	}
	if s.AssetIndex(ctx).Lookup("10.0.0.7") == nil {
		t.Fatal("a refused replacement must keep the current inventory")
	}
	// Restart: the index is rebuilt from the stored inventory.
	s2 := &Service{Store: db, Assets: stub.Assets{}, Log: s.Log}
	s2.Load(ctx)
	if a := s2.AssetIndex(ctx).Lookup("10.0.0.7"); a == nil || a.Name != "jump-host" {
		t.Fatalf("after reload %+v", a)
	}
}

// With the real matcher: saving validates strictly (an invalid CIDR is
// refused and the current list kept); a stored list from before validation
// is loaded leniently instead of being dropped.
func TestSourceListsWithRealMatcher(t *testing.T) {
	s, db := newSvc(t, true)
	ctx := context.Background()
	if _, err := s.Update(ctx, Patch{Whitelist: &[]string{"10.0.0.0/8", "scanner.example"}}); err != nil {
		t.Fatal(err)
	}
	if !s.Whitelist().Match("10.9.8.7:443") || !s.Whitelist().Match("scanner.example") || s.Whitelist().Match("11.0.0.1") {
		t.Fatal("whitelist semantics")
	}
	if _, err := s.Update(ctx, Patch{Whitelist: &[]string{"10.0.0.0/33"}}); err == nil {
		t.Fatal("invalid CIDR saved")
	}
	if !s.Whitelist().Match("10.1.1.1") {
		t.Fatal("refused update replaced the current list")
	}
	// A list stored before CIDR validation ("legacy/name") still loads.
	v := `["legacy/name","192.168.0.0/16"]`
	if err := db.PutSettings(ctx, map[string]*string{KeyWhitelist: &v}); err != nil {
		t.Fatal(err)
	}
	s2 := &Service{Store: db, Parser: sourcelist.Parser{}, Log: s.Log}
	s2.Load(ctx)
	if wl := s2.Whitelist(); wl == nil || !wl.Match("legacy/name") || !wl.Match("192.168.4.4") {
		t.Fatal("stored legacy list dropped or mis-parsed")
	}
}
