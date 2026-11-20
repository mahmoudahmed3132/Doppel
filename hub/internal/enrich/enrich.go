// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package enrich computes output-only event enrichment (§6.5 step 6): node
// alias, ATT&CK mapping, source asset and location. It is evaluated on every
// read, so inventory or database changes apply to past events too.
package enrich

import (
	"context"
	"encoding/json"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

// Nodes resolves node aliases.
type Nodes interface {
	Node(ctx context.Context, id string) (*domain.Node, error)
}

// AssetIndexProvider returns the current asset index (nil when none).
type AssetIndexProvider interface {
	AssetIndex(ctx context.Context) ported.AssetIndex
}

// Enricher implements ingest.Enricher. Collaborators may be nil in tests.
type Enricher struct {
	Nodes  Nodes
	Attack ported.AttackMapper
	Assets AssetIndexProvider
	Geo    ported.GeoLocator
}

// Enrich returns ev with enrichment. Failures degrade to "no enrichment".
func (e *Enricher) Enrich(ctx context.Context, ev *domain.Event) domain.EnrichedEvent {
	out := domain.EnrichedEvent{Event: *ev}
	if out.SourceKind == "" {
		out.SourceIP, out.SourcePort, out.SourceKind = domain.ParseSource(out.Source)
	}
	if len(out.Labels) == 0 && out.SourceIP != "" {
		out.Labels = domain.SourceLabels(out.SourceIP)
	}
	src := out.CorrelationSource()
	if e.Nodes != nil {
		if n, err := e.Nodes.Node(ctx, ev.NodeID); err == nil {
			out.NodeAlias = n.Alias
		}
	}
	if e.Attack != nil {
		out.Enrichment.Attack = e.Attack.For(ev.Trigger)
	}
	if e.Assets != nil {
		if ix := e.Assets.AssetIndex(ctx); ix != nil {
			out.Enrichment.Asset = ix.Lookup(src)
		}
	}
	if e.Geo != nil {
		if e.Geo.Enabled() {
			var details map[string]any
			_ = json.Unmarshal(ev.Details, &details)
			out.Enrichment.Location = e.Geo.Locate(src, details)
		}
		if out.Enrichment.Location != nil && out.Enrichment.Location.ASN > 0 {
			out.Enrichment.ASN = out.Enrichment.Location.ASN
			out.Enrichment.ASOrg = out.Enrichment.Location.ASOrg
		} else if asnLoc, ok := e.Geo.(interface{ LookupASN(string) (uint, string) }); ok {
			if asn, org := asnLoc.LookupASN(src); asn > 0 {
				out.Enrichment.ASN, out.Enrichment.ASOrg = asn, org
			}
		}
	}
	return out
}
