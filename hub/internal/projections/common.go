// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package projections holds the analytics projections behind
// ported.Projection (QUESTIONS Q56): insights, sources, geo_map, attack_path
// and report. Each receives the window's events, already enriched by the Hub
// (asset, location, ATT&CK).
//
// Imported from TrueSignal (see PROVENANCE.md): the aggregations are that
// codebase's sources, geomap, path and report projections, adapted from its
// event store to domain.EnrichedEvent; insights is a clean-room implementation
// from docs/clean-specs/insights-projection.md.
package projections

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/geoip"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

// Rollup modes for the group_by projection parameter (F-002).
const (
	GroupByIP       = "ip"
	GroupBySubnet24 = "subnet24"
	GroupBySubnet64 = "subnet64"
	GroupByASN      = "asn"
)

func parseGroupBy(params map[string]string) (string, error) {
	if params == nil {
		return GroupByIP, nil
	}
	g := strings.ToLower(strings.TrimSpace(params["group_by"]))
	switch g {
	case "", GroupByIP:
		return GroupByIP, nil
	case GroupBySubnet24, GroupBySubnet64, GroupByASN:
		return g, nil
	default:
		return "", errors.New("group_by must be ip, subnet24, subnet64 or asn")
	}
}

// sourceKey returns the correlation key for an event: source_ip when set
// (rolled up according to groupBy), and source otherwise (F-002).
func sourceKey(e domain.EnrichedEvent, groupBy string, geo *geoip.Service) string {
	ip := e.EffectiveSourceIP()
	if ip == "" {
		return e.Source
	}
	switch groupBy {
	case GroupBySubnet24:
		if a, err := netip.ParseAddr(ip); err == nil {
			a = a.WithZone("").Unmap()
			if a.Is4() {
				return netip.PrefixFrom(a, 24).Masked().String()
			}
		}
		return ip
	case GroupBySubnet64:
		if a, err := netip.ParseAddr(ip); err == nil {
			a = a.WithZone("").Unmap()
			if a.Is6() {
				return netip.PrefixFrom(a, 64).Masked().String()
			}
		}
		return ip
	case GroupByASN:
		asn := e.Enrichment.ASN
		if asn == 0 && e.Enrichment.Location != nil {
			asn = e.Enrichment.Location.ASN
		}
		if asn == 0 && geo != nil {
			asn, _ = geo.LookupASN(ip)
		}
		if asn > 0 {
			return fmt.Sprintf("AS%d", asn)
		}
		return ip
	default:
		return ip
	}
}

func normalizeQuerySource(raw, groupBy string, geo *geoip.Service) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if ip, _, kind := domain.ParseSource(raw); kind == domain.SourceKindIP && ip != "" {
		return sourceKey(domain.EnrichedEvent{Event: domain.Event{Source: raw, SourceIP: ip, SourceKind: domain.SourceKindIP}}, groupBy, geo)
	}
	return raw
}

// attacker excludes what the Hub raises about its own fleet (liveness and
// apply failures) and fire drills unless the request opted in with
// include_drills (F-001); honeytoken and beacon use are attacker activity.
// Drills are recognised by the stored flag, not the source text, so a real
// event whose source merely reads "Fire drill" stays counted.
func attacker(ctx context.Context, e domain.Event) bool {
	if e.Source == domain.HubSource {
		return false
	}
	if e.Drill && !ported.IncludeDrills(ctx) {
		return false
	}
	switch e.Trigger {
	case domain.TriggerSensorStopped, domain.TriggerSensorHeartbeatLost, domain.TriggerSensorRecovered,
		domain.TriggerSensorTamperSuspected, domain.TriggerNodeApplyFailed,
		domain.TriggerNodeOffline, domain.TriggerNodeOnline, domain.TriggerConfigDrift:
		return false
	}
	return true
}

var sevRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func sortedKeys(m map[string]bool, max int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

// oldestFirst returns the events sorted by occurrence, oldest first.
func oldestFirst(events []domain.EnrichedEvent) []domain.EnrichedEvent {
	out := append([]domain.EnrichedEvent(nil), events...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].OccurredAt.Before(out[j].OccurredAt) })
	return out
}
