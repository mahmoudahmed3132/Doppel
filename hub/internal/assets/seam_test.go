// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package assets_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/assets"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/enrich"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/hubsettings"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

// The real module behind ported.AssetInventory: saved through the settings
// service, rebuilt after a restart, and applied by the enricher.
func TestModuleThroughSettingsAndEnricher(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "hub.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &hubsettings.Service{Store: db, Assets: assets.Module{}, DefaultRegistry: "https://registry.example/", Log: logger}
	if err := s.Load(ctx); err != nil {
		t.Fatal(err)
	}
	norm, err := s.ReplaceAssets(ctx, json.RawMessage(` [
		{"name":" office LAN ","address":"10.20.0.0/16","criticality":"Medium"},
		{"name":"jump-host","address":"10.20.1.7","criticality":"critical","owner":"IT","tags":["pci", " "]} ] `))
	if err != nil || !strings.Contains(string(norm), `"name":"office LAN"`) || !strings.Contains(string(norm), `"tags":["pci"]`) {
		t.Fatalf("%s %v", norm, err)
	}
	for _, bad := range []string{`{"not":"a list"}`, `[{"name":"x","address":"10.0.0.0/33"}]`,
		`[{"name":"x","address":"10.1.1.1","criticality":"severe"}]`, `[{"name":"x","address":"10.1.1.1","extra":1}]`,
		`[{"name":"a","address":"10.1.1.1"},{"name":"b","address":"10.1.1.1"}]`} {
		if _, err := s.ReplaceAssets(ctx, json.RawMessage(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	// Restart, then enrich: the most specific range wins.
	s2 := &hubsettings.Service{Store: db, Assets: assets.Module{}, DefaultRegistry: "https://registry.example/", Log: logger}
	if err := s2.Load(ctx); err != nil {
		t.Fatal(err)
	}
	e := &enrich.Enricher{Assets: s2}
	got := e.Enrich(ctx, &domain.Event{Source: "10.20.1.7:445"}).Enrichment.Asset
	if got == nil || got.Name != "jump-host" || got.Criticality != "critical" {
		t.Fatalf("jump host: %+v", got)
	}
	if got := e.Enrich(ctx, &domain.Event{Source: "10.20.9.9"}).Enrichment.Asset; got == nil || got.Name != "office LAN" || got.Criticality != "medium" {
		t.Fatalf("range: %+v", got)
	}
	if got := e.Enrich(ctx, &domain.Event{Source: "192.0.2.1"}).Enrichment.Asset; got != nil {
		t.Fatalf("unknown source matched: %+v", got)
	}
}
