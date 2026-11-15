// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

// The receiver state and event reporting. Imported from TrueSignal (see
// PROVENANCE.md): these hunks of its Token Receiver main.go are claude-new;
// the program entry point (main.go) is new.

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/decoy"
	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

// Trigger is the event the receiver raises. The Hub resolves the token to
// the beacon it created and enriches the event.
const Trigger = "beacon_triggered"

type receiver struct {
	ts       sensor.Reporter
	zone     zone
	verify   verifier
	proxies  []*net.IPNet
	cooldown time.Duration
	replies  *decoy.Limiter // DNS replies per source

	mu   sync.Mutex
	seen map[string]*cooldownState // token|channel
	now  func() time.Time
}

type cooldownState struct {
	last    time.Time
	repeats int
}

const maxCooldownEntries = 10000

// report raises beacon_triggered for tok unless the same token fired on the
// same channel within the cooldown: one lookup is several queries (A, AAAA,
// HTTPS, resolver retries), one page load can be several requests. The
// suppressed count rides on the next event as repeats_since_last.
func (r *receiver) report(tok, channel, src string, d sensor.Fields) {
	key := tok + "|" + channel
	r.mu.Lock()
	now := r.now()
	st := r.seen[key]
	if st != nil && now.Sub(st.last) < r.cooldown {
		st.repeats++
		r.mu.Unlock()
		return
	}
	repeats := 0
	if st != nil {
		repeats = st.repeats
	}
	if len(r.seen) >= maxCooldownEntries {
		for k, v := range r.seen {
			if now.Sub(v.last) >= r.cooldown {
				delete(r.seen, k)
			}
		}
	}
	r.seen[key] = &cooldownState{last: now}
	r.mu.Unlock()

	d = append(sensor.Fields{sensor.F("token", tok), sensor.F("channel", channel)}, d...)
	if repeats > 0 {
		d = append(d, sensor.F("repeats_since_last", repeats))
	}
	r.ts.ReportSeverity(sensor.SeverityCritical, Trigger, src, fmt.Sprintf("%s (%s)", strings.ToUpper(channel), r.zone.domain), d)
}

func parseCIDRs(raw string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			if ip := net.ParseIP(part); ip != nil && ip.To4() != nil {
				part += "/32"
			} else {
				part += "/128"
			}
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("TS_TRUSTED_PROXIES: bad entry %q", part)
		}
		out = append(out, n)
	}
	return out, nil
}

// loadZone reads TS_BEACON_DOMAIN, TS_BEACON_NS and TS_ANSWER_IPV4.
func loadZone(domain, nsList, ipv4 string) (zone, error) {
	z := zone{domain: strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))}
	if z.domain == "" || !strings.Contains(z.domain, ".") {
		return z, fmt.Errorf("TS_BEACON_DOMAIN must be a delegated zone such as t.example.com")
	}
	for _, n := range strings.Split(nsList, ",") {
		if n = strings.ToLower(strings.Trim(strings.TrimSpace(n), ".")); n != "" {
			z.ns = append(z.ns, n)
		}
	}
	if len(z.ns) == 0 {
		z.ns = []string{"ns1." + z.domain}
	}
	if ipv4 = strings.TrimSpace(ipv4); ipv4 != "" {
		ip := net.ParseIP(ipv4)
		if ip == nil || ip.To4() == nil {
			return z, fmt.Errorf("TS_ANSWER_IPV4 %q is not an IPv4 address", ipv4)
		}
		z.ipv4 = ip.To4()
	}
	return z, nil
}
