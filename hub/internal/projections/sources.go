// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package projections

import (
	"context"
	"net/netip"
	"sort"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

// Profile is one source's activity and classification.
type Profile struct {
	Source       string `json:"source"`
	Events       int    `json:"events"`
	Decoys       int    `json:"decoys"`
	FirstSeen    string `json:"firstSeen"`
	LastSeen     string `json:"lastSeen"`
	IsIP         bool   `json:"isIp"`
	Internal     bool   `json:"internal"`
	Whitelisted  bool   `json:"whitelisted"`
	KnownScanner bool   `json:"knownScanner"`
	// Asset is the inventory asset the source belongs to, if any.
	Asset *domain.AssetMatch `json:"asset"`
}

var internalRanges = func() []netip.Prefix {
	var out []netip.Prefix
	for _, c := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC 1918
		"100.64.0.0/10",  // RFC 6598 shared address space
		"127.0.0.0/8",    // loopback
		"169.254.0.0/16", // link-local
		"fc00::/7",       // unique local
		"fe80::/10",      // link-local
		"::1/128",
	} {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}()

// Classify returns whether source is an IP address and, if so, whether it
// is in a private, loopback or link-local range.
func Classify(source string) (isIP, internal bool) {
	a, err := netip.ParseAddr(source)
	if err != nil {
		if ap, err := netip.ParseAddrPort(source); err == nil {
			a = ap.Addr()
		} else {
			return false, false
		}
	}
	a = a.Unmap()
	for _, p := range internalRanges {
		if p.Contains(a) {
			return true, true
		}
	}
	return true, false
}

// Sources is the sources projection: every source in the window, busiest
// first. Whitelisted / KnownScanner are the classification of the source's
// latest event.
type Sources struct{}

func (Sources) Name() string { return "sources" }

func (Sources) Build(_ context.Context, events []domain.EnrichedEvent, _ map[string]string) (any, error) {
	type agg struct {
		p      *Profile
		decoys map[string]bool
	}
	by := map[string]*agg{}
	for _, e := range oldestFirst(events) {
		if !attacker(e.Event) || e.Source == "" {
			continue
		}
		a := by[e.Source]
		if a == nil {
			isIP, internal := Classify(e.Source)
			a = &agg{p: &Profile{Source: e.Source, FirstSeen: ts(e.OccurredAt), IsIP: isIP, Internal: internal}, decoys: map[string]bool{}}
			by[e.Source] = a
		}
		a.p.Events++
		a.p.LastSeen = ts(e.OccurredAt)
		a.p.Whitelisted, a.p.KnownScanner = e.Whitelisted, e.KnownScanner
		a.decoys[e.NodeID+"/"+e.SensorID] = true
		if e.Enrichment.Asset != nil {
			a.p.Asset = e.Enrichment.Asset
			// An inventoried address is internal even in public space.
			a.p.Internal = true
		}
	}
	out := make([]Profile, 0, len(by))
	for _, a := range by {
		a.p.Decoys = len(a.decoys)
		out = append(out, *a.p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Events != out[j].Events {
			return out[i].Events > out[j].Events
		}
		return out[i].Source < out[j].Source
	})
	return map[string]any{"sources": out}, nil
}
