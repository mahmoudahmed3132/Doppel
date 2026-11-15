// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package geoip

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/enrich"
)

// The real module behind ported.GeoLocator, through the Hub's enricher.
func TestLocatorThroughEnricher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geoip", "dbip-city-lite.mmdb")
	copyFixture(t, "dbip-city-test.mmdb", path)
	s := New(path, false, nil)
	t.Cleanup(s.Close)
	e := &enrich.Enricher{Geo: Locator{S: s}}

	ev := &domain.Event{Source: "81.2.69.160:4431", Details: json.RawMessage(`{}`)}
	loc := e.Enrich(context.Background(), ev).Enrichment.Location
	if loc == nil || loc.CountryCode != "GB" || loc.City != "London" || loc.Basis != "source" || loc.Address != "81.2.69.160" {
		t.Fatalf("source: %+v", loc)
	}
	// A public EDNS client subnet wins over the resolver's source address.
	ev = &domain.Event{Source: "81.2.69.160", Details: json.RawMessage(`{"client_subnet":"203.0.113.0/24"}`)}
	loc = e.Enrich(context.Background(), ev).Enrichment.Location
	if loc == nil || loc.Basis != "client_subnet" || loc.City != "Ashburn" {
		t.Fatalf("client subnet: %+v", loc)
	}
	// Internal sources are never located.
	if loc := e.Enrich(context.Background(), &domain.Event{Source: "10.1.2.3"}).Enrichment.Location; loc != nil {
		t.Fatalf("internal source located: %+v", loc)
	}
	// No database: disabled, no location.
	off := &enrich.Enricher{Geo: Locator{S: New(filepath.Join(t.TempDir(), "none.mmdb"), false, nil)}}
	if loc := off.Enrich(context.Background(), &domain.Event{Source: "81.2.69.160"}).Enrichment.Location; loc != nil {
		t.Fatal("located without a database")
	}
}
