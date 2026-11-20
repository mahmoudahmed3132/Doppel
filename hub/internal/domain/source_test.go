// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package domain

import (
	"net/netip"
	"testing"
)

func intPtr(n int) *int { return &n }

func TestParseSourceTable(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantIP   string
		wantPort *int
		wantKind SourceKind
		wantHost bool
	}{
		// IPv4:port
		{name: "ipv4 with ephemeral port", input: "203.0.113.9:51234", wantIP: "203.0.113.9", wantPort: intPtr(51234), wantKind: SourceKindIP},
		{name: "ipv4 with port 1", input: "198.51.100.1:1", wantIP: "198.51.100.1", wantPort: intPtr(1), wantKind: SourceKindIP},
		{name: "ipv4 with port 65535", input: "192.0.2.42:65535", wantIP: "192.0.2.42", wantPort: intPtr(65535), wantKind: SourceKindIP},
		{name: "ipv4 loopback with port", input: "127.0.0.1:43210", wantIP: "127.0.0.1", wantPort: intPtr(43210), wantKind: SourceKindIP, wantHost: true},
		{name: "docker desktop nat with port", input: "192.168.65.1:50123", wantIP: "192.168.65.1", wantPort: intPtr(50123), wantKind: SourceKindIP, wantHost: true},
		{name: "ipv4 with surrounding whitespace", input: "  10.0.0.5:2222 \t", wantIP: "10.0.0.5", wantPort: intPtr(2222), wantKind: SourceKindIP},

		// [v6]:port
		{name: "ipv6 with port", input: "[2001:db8::1]:443", wantIP: "2001:db8::1", wantPort: intPtr(443), wantKind: SourceKindIP},
		{name: "ipv6 non-canonical with port", input: "[2001:0db8:0000:0000:0000:0000:0000:0001]:8443", wantIP: "2001:db8::1", wantPort: intPtr(8443), wantKind: SourceKindIP},
		{name: "ipv6 loopback with port", input: "[::1]:54321", wantIP: "::1", wantPort: intPtr(54321), wantKind: SourceKindIP, wantHost: true},
		{name: "ipv6 with zone and port", input: "[fe80::1%eth0]:22", wantIP: "fe80::1", wantPort: intPtr(22), wantKind: SourceKindIP},
		{name: "ipv4-mapped ipv6 with port", input: "[::ffff:192.0.2.15]:8080", wantIP: "192.0.2.15", wantPort: intPtr(8080), wantKind: SourceKindIP},
		{name: "ipv4-mapped ipv6 loopback with port", input: "[::ffff:127.0.0.1]:9000", wantIP: "127.0.0.1", wantPort: intPtr(9000), wantKind: SourceKindIP, wantHost: true},

		// Bare IPs
		{name: "bare ipv4", input: "10.20.30.40", wantIP: "10.20.30.40", wantPort: nil, wantKind: SourceKindIP},
		{name: "bare ipv4 loopback", input: "127.0.0.53", wantIP: "127.0.0.53", wantPort: nil, wantKind: SourceKindIP, wantHost: true},
		{name: "bare docker desktop nat", input: "192.168.65.254", wantIP: "192.168.65.254", wantPort: nil, wantKind: SourceKindIP, wantHost: true},
		{name: "bare ipv6", input: "2001:db8::dead:beef", wantIP: "2001:db8::dead:beef", wantPort: nil, wantKind: SourceKindIP},
		{name: "bare ipv6 non-canonical", input: "2001:0DB8:0:0:0:0:0:2", wantIP: "2001:db8::2", wantPort: nil, wantKind: SourceKindIP},
		{name: "bare ipv6 loopback", input: "::1", wantIP: "::1", wantPort: nil, wantKind: SourceKindIP, wantHost: true},
		{name: "bracketed bare ipv6 loopback", input: "[::1]", wantIP: "::1", wantPort: nil, wantKind: SourceKindIP, wantHost: true},
		{name: "bare ipv6 with zone", input: "fe80::a:b%en0", wantIP: "fe80::a:b", wantPort: nil, wantKind: SourceKindIP},
		{name: "bracketed bare ipv6 with zone", input: "[fe80::a:b%en0]", wantIP: "fe80::a:b", wantPort: nil, wantKind: SourceKindIP},
		{name: "bare ipv4-mapped ipv6", input: "::ffff:203.0.113.7", wantIP: "203.0.113.7", wantPort: nil, wantKind: SourceKindIP},

		// Fire drill & local
		{name: "fire drill exact", input: "Fire drill", wantIP: "", wantPort: nil, wantKind: SourceKindDrill},
		{name: "fire drill lowercase", input: "fire drill", wantIP: "", wantPort: nil, wantKind: SourceKindDrill},
		{name: "local exact", input: "local", wantIP: "", wantPort: nil, wantKind: SourceKindLocal},
		{name: "local uppercase", input: "LOCAL", wantIP: "", wantPort: nil, wantKind: SourceKindLocal},

		// Hostnames & identifiers
		{name: "hostname", input: "scanner.example.com", wantIP: "", wantPort: nil, wantKind: SourceKindOther},
		{name: "hostname with port", input: "scanner.example.com:443", wantIP: "", wantPort: nil, wantKind: SourceKindOther},
		{name: "hub source", input: HubSource, wantIP: "", wantPort: nil, wantKind: SourceKindOther},
		{name: "short host", input: "drill-host", wantIP: "", wantPort: nil, wantKind: SourceKindOther},

		// Garbage
		{name: "empty", input: "", wantIP: "", wantPort: nil, wantKind: SourceKindOther},
		{name: "whitespace only", input: "   ", wantIP: "", wantPort: nil, wantKind: SourceKindOther},
		{name: "port zero", input: "192.0.2.1:0", wantIP: "", wantPort: nil, wantKind: SourceKindOther},
		{name: "port overflow", input: "192.0.2.1:65536", wantIP: "", wantPort: nil, wantKind: SourceKindOther},
		{name: "negative port", input: "192.0.2.1:-80", wantIP: "", wantPort: nil, wantKind: SourceKindOther},
		{name: "plus port", input: "192.0.2.1:+80", wantIP: "", wantPort: nil, wantKind: SourceKindOther},
		{name: "non-numeric port", input: "192.0.2.1:http", wantIP: "", wantPort: nil, wantKind: SourceKindOther},
		{name: "missing port after colon", input: "192.0.2.1:", wantIP: "", wantPort: nil, wantKind: SourceKindOther},
		{name: "out-of-range ipv4 octets", input: "999.999.999.999:80", wantIP: "", wantPort: nil, wantKind: SourceKindOther},
		{name: "malformed ipv6", input: "[2001:db8:::1]:80", wantIP: "", wantPort: nil, wantKind: SourceKindOther},
		{name: "unclosed bracket", input: "[::1:80", wantIP: "", wantPort: nil, wantKind: SourceKindOther},
		{name: "random garbage", input: "not!an@ip#address$123", wantIP: "", wantPort: nil, wantKind: SourceKindOther},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotIP, gotPort, gotKind := ParseSource(tc.input)
			if gotIP != tc.wantIP {
				t.Errorf("ParseSource(%q) ip = %q, want %q", tc.input, gotIP, tc.wantIP)
			}
			if (gotPort == nil) != (tc.wantPort == nil) || (gotPort != nil && *gotPort != *tc.wantPort) {
				t.Errorf("ParseSource(%q) port = %v, want %v", tc.input, gotPort, tc.wantPort)
			}
			if gotKind != tc.wantKind {
				t.Errorf("ParseSource(%q) kind = %q, want %q", tc.input, gotKind, tc.wantKind)
			}
			if gotHost := IsHostLocal(tc.input); gotHost != tc.wantHost {
				t.Errorf("IsHostLocal(%q) = %v, want %v", tc.input, gotHost, tc.wantHost)
			}
		})
	}
}

func FuzzParseSource(f *testing.F) {
	seeds := []string{
		"203.0.113.9:51234",
		"[2001:db8::1]:443",
		"[fe80::1%eth0]:22",
		"[::ffff:192.0.2.1]:8080",
		"10.0.0.5",
		"::1",
		"[::1]",
		"192.168.65.1:12345",
		"Fire drill",
		"local",
		"scanner.example.com:80",
		"",
		"garbage:99999",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		ip, port, kind := ParseSource(input)
		if !kind.Valid() {
			t.Fatalf("invalid kind %q for %q", kind, input)
		}
		if kind == SourceKindIP {
			a, err := netip.ParseAddr(ip)
			if err != nil {
				t.Fatalf("kind=ip but ip %q is not a valid netip.Addr: %v", ip, err)
			}
			if a.Zone() != "" || a.Is4In6() || a.String() != ip {
				t.Fatalf("ip %q is not canonical (zone=%q, is4in6=%v, canonical=%q)", ip, a.Zone(), a.Is4In6(), a.String())
			}
			if port != nil && (*port < 1 || *port > 65535) {
				t.Fatalf("port %d out of range", *port)
			}
		} else {
			if ip != "" || port != nil {
				t.Fatalf("kind=%q must have empty ip and nil port, got ip=%q port=%v", kind, ip, port)
			}
		}
	})
}
