// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ported"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ported/stub"
)

type nodes map[string]string

func (n nodes) Node(_ context.Context, id string) (*domain.Node, error) {
	if a, ok := n[id]; ok {
		return &domain.Node{ID: id, Alias: a}, nil
	}
	return nil, errors.New("not found")
}

type assets struct{ ix ported.AssetIndex }

func (a assets) AssetIndex(context.Context) ported.AssetIndex { return a.ix }

func TestEnrichWithAllModules(t *testing.T) {
	inv := stub.Assets{}
	norm, err := inv.Validate(json.RawMessage(`[{"match":"10.0.0.7","name":"jump-host","criticality":"high"}]`))
	if err != nil {
		t.Fatal(err)
	}
	ix, _ := inv.Index(norm)
	e := &Enricher{
		Nodes:  nodes{"node-0000000a": "dmz-1"},
		Attack: stub.Attack{Map: map[string]domain.AttackMapping{"tcp_connection": {Primary: domain.Technique{ID: "T1046", Tactics: []string{"discovery"}}}}},
		Assets: assets{ix},
		Geo:    stub.Geo{Table: map[string]domain.Location{"10.0.0.7": {CountryCode: "EG", Country: "Egypt", City: "Cairo"}}},
	}
	ev := &domain.Event{NodeID: "node-0000000a", Trigger: "tcp_connection", Source: "10.0.0.7:51544", Details: []byte(`{"k":1}`)}
	out := e.Enrich(context.Background(), ev)
	if out.NodeAlias != "dmz-1" || out.Enrichment.Attack == nil || out.Enrichment.Attack.Primary.ID != "T1046" {
		t.Fatalf("%+v", out)
	}
	if out.Enrichment.Asset == nil || out.Enrichment.Asset.Name != "jump-host" {
		t.Fatalf("asset %+v", out.Enrichment.Asset)
	}
	if l := out.Enrichment.Location; l == nil || l.City != "Cairo" || l.Basis != "source" || l.Address != "10.0.0.7" {
		t.Fatalf("location %+v", l)
	}
	if out.Event.Source != ev.Source || string(out.Event.Details) != `{"k":1}` {
		t.Fatal("enrichment must not modify the event")
	}
}

func TestEnrichAbsentOrUnmatched(t *testing.T) {
	// No modules: only the alias (unknown node: empty), nothing else.
	out := (&Enricher{Nodes: nodes{}}).Enrich(context.Background(), &domain.Event{NodeID: "node-x", Trigger: "t", Source: "1.2.3.4"})
	if out.NodeAlias != "" || out.Enrichment.Attack != nil || out.Enrichment.Asset != nil || out.Enrichment.Location != nil {
		t.Fatalf("%+v", out.Enrichment)
	}
	// Modules installed but no match, and GeoIP disabled.
	e := &Enricher{Attack: stub.Attack{}, Assets: assets{}, Geo: stub.Geo{Disabled: true, Table: map[string]domain.Location{"1.2.3.4": {}}}}
	out = e.Enrich(context.Background(), &domain.Event{Trigger: "t", Source: "1.2.3.4", Details: []byte(`not json`)})
	if out.Enrichment.Attack != nil || out.Enrichment.Asset != nil || out.Enrichment.Location != nil {
		t.Fatalf("%+v", out.Enrichment)
	}
	b, _ := json.Marshal(out.Enrichment)
	if string(b) != "{}" {
		t.Fatalf("absent enrichment must be omitted from the API: %s", b)
	}
}
