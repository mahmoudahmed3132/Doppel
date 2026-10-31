// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package httpapi

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Network interprets forwarding headers. They are believed only when the
// direct peer is a trusted proxy; with no trusted proxies they are ignored.
type Network struct {
	Trusted []netip.Prefix
}

func (n Network) trusted(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range n.Trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func peer(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// ClientIP returns the client address: the direct peer, or — behind trusted
// proxies — the right-most X-Forwarded-For entry that is not a trusted proxy.
func (n Network) ClientIP(r *http.Request) string {
	p := peer(r)
	if !p.IsValid() {
		return "unknown"
	}
	if !n.trusted(p) {
		return p.String()
	}
	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(h, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break // malformed chain: stop at the last address we can trust
		}
		a = a.Unmap()
		if !n.trusted(a) {
			return a.String()
		}
		p = a
	}
	return p.String()
}

func lastHeaderValue(r *http.Request, name string) string {
	vals := r.Header.Values(name)
	if len(vals) == 0 {
		return ""
	}
	parts := strings.Split(vals[len(vals)-1], ",")
	return strings.TrimSpace(parts[len(parts)-1])
}

// IsHTTPS reports whether the client connection is HTTPS (directly, or as
// stated by a trusted proxy's X-Forwarded-Proto).
func (n Network) IsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return n.trusted(peer(r)) && strings.EqualFold(lastHeaderValue(r, "X-Forwarded-Proto"), "https")
}

// Origin returns the origin the client used to reach the Hub.
func (n Network) Origin(r *http.Request) string {
	scheme := "http"
	if n.IsHTTPS(r) {
		scheme = "https"
	}
	host := r.Host
	if n.trusted(peer(r)) {
		if h := lastHeaderValue(r, "X-Forwarded-Host"); h != "" {
			host = h
		}
	}
	return scheme + "://" + strings.ToLower(host)
}
