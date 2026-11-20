// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package domain

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// SourceKind classifies an event's source field (F-002).
type SourceKind string

const (
	SourceKindIP    SourceKind = "ip"
	SourceKindLocal SourceKind = "local"
	SourceKindDrill SourceKind = "drill"
	SourceKindOther SourceKind = "other"
)

// Valid reports whether k is a known source kind.
func (k SourceKind) Valid() bool {
	switch k {
	case SourceKindIP, SourceKindLocal, SourceKindDrill, SourceKindOther:
		return true
	}
	return false
}

// HostLocalLabel is attached to loopback and Docker Desktop NAT sources.
const HostLocalLabel = "host_local"

var dockerDesktopNAT = netip.MustParsePrefix("192.168.65.0/24")

// ParseSource parses a raw event source string into its canonical IP address
// (IPv4-mapped IPv6 unmapped to IPv4, IPv6 zone stripped), optional TCP/UDP
// port (1..65535), and SourceKind ("ip", "local", "drill", or "other").
func ParseSource(raw string) (ip string, port *int, kind SourceKind) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil, SourceKindOther
	}
	if strings.EqualFold(s, "Fire drill") {
		return "", nil, SourceKindDrill
	}
	if strings.EqualFold(s, "local") {
		return "", nil, SourceKindLocal
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.WithZone("").Unmap()
		return a.String(), nil, SourceKindIP
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		if a, err := netip.ParseAddr(s[1 : len(s)-1]); err == nil {
			a = a.WithZone("").Unmap()
			return a.String(), nil, SourceKindIP
		}
	}
	if host, portStr, err := net.SplitHostPort(s); err == nil && host != "" && portStr != "" {
		if !strings.HasPrefix(portStr, "+") && !strings.HasPrefix(portStr, "-") {
			if p, err := strconv.Atoi(portStr); err == nil && p >= 1 && p <= 65535 {
				if a, err := netip.ParseAddr(host); err == nil {
					a = a.WithZone("").Unmap()
					return a.String(), &p, SourceKindIP
				}
			}
		}
	}
	return "", nil, SourceKindOther
}

// IsHostLocal reports whether source (a raw source string, canonical IP, or
// CIDR prefix) is a loopback address (127.0.0.0/8, ::1) or inside the Docker
// Desktop NAT subnet (192.168.65.0/24).
func IsHostLocal(source string) bool {
	if ip, _, kind := ParseSource(source); kind == SourceKindIP {
		if a, err := netip.ParseAddr(ip); err == nil {
			a = a.WithZone("").Unmap()
			return a.IsLoopback() || dockerDesktopNAT.Contains(a)
		}
	}
	if p, err := netip.ParsePrefix(strings.TrimSpace(source)); err == nil {
		p = p.Masked()
		a := p.Addr().WithZone("").Unmap()
		if a.Is4() && p.Bits() >= 8 && a.IsLoopback() {
			return true
		}
		if a.Is6() && p.Bits() == 128 && a.IsLoopback() {
			return true
		}
		if a.Is4() && p.Bits() >= 24 && dockerDesktopNAT.Contains(a) {
			return true
		}
	}
	return false
}

// SourceLabels returns the per-event labels for a source IP ("host_local" for
// loopback and Docker Desktop NAT sources).
func SourceLabels(sourceIP string) []string {
	if sourceIP != "" && IsHostLocal(sourceIP) {
		return []string{HostLocalLabel}
	}
	return nil
}

// EffectiveSource returns the event's normalized (source_ip, source_port,
// source_kind), parsing e.Source on the fly when the struct was constructed in
// memory without running Normalize.
func (e Event) EffectiveSource() (ip string, port *int, kind SourceKind) {
	if e.SourceIP != "" || e.SourceKind != "" {
		k := e.SourceKind
		if k == "" {
			k = SourceKindIP
		}
		return e.SourceIP, e.SourcePort, k
	}
	return ParseSource(e.Source)
}

// EffectiveSourceIP returns source_ip when set (or parsed from e.Source when
// unnormalized), and "" otherwise.
func (e Event) EffectiveSourceIP() string {
	ip, _, _ := e.EffectiveSource()
	return ip
}

// CorrelationSource returns source_ip when it is set, and source otherwise.
func (e Event) CorrelationSource() string {
	if ip := e.EffectiveSourceIP(); ip != "" {
		return ip
	}
	return e.Source
}
