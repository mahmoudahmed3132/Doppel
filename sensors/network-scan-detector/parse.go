// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"encoding/binary"
	"net"
)

// TCP flag bits.
const (
	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagPSH = 0x08
	flagACK = 0x10
	flagURG = 0x20
)

// Probe is one inbound packet that may be part of a scan.
type Probe struct {
	Src     string
	Proto   string // tcp | udp
	DstPort int
	Flags   byte   // TCP only
	Window  uint16 // TCP only
	Options string // TCP option kinds in order, e.g. "M" (MSS), "MSTNW"
	TTL     int
	IPID    uint16 // IPv4 only
}

// ParseFrame decodes an Ethernet frame (off = 14) or a raw IP packet
// (off = 0). It returns false for anything that is not IPv4/IPv6 TCP/UDP.
func ParseFrame(b []byte, ethernet bool) (Probe, bool) {
	if ethernet {
		if len(b) < 14 {
			return Probe{}, false
		}
		et := binary.BigEndian.Uint16(b[12:14])
		b = b[14:]
		if et == 0x8100 || et == 0x88a8 { // VLAN tag
			if len(b) < 4 {
				return Probe{}, false
			}
			et = binary.BigEndian.Uint16(b[2:4])
			b = b[4:]
		}
		switch et {
		case 0x0800, 0x86dd:
		default:
			return Probe{}, false
		}
	}
	return parseIP(b)
}

func parseIP(b []byte) (Probe, bool) {
	if len(b) < 1 {
		return Probe{}, false
	}
	var (
		p     Probe
		proto byte
		l4    []byte
	)
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return p, false
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return p, false
		}
		if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 { // non-first fragment
			return p, false
		}
		proto, p.TTL, p.IPID = b[9], int(b[8]), binary.BigEndian.Uint16(b[4:6])
		p.Src = net.IP(b[12:16]).String()
		l4 = b[ihl:]
	case 6:
		if len(b) < 40 {
			return p, false
		}
		proto, p.TTL = b[6], int(b[7])
		p.Src = net.IP(b[8:24]).String()
		l4 = b[40:] // extension headers are not followed
	default:
		return p, false
	}
	switch proto {
	case 6:
		if len(l4) < 20 {
			return p, false
		}
		p.Proto = "tcp"
		p.DstPort = int(binary.BigEndian.Uint16(l4[2:4]))
		p.Flags = l4[13]
		p.Window = binary.BigEndian.Uint16(l4[14:16])
		off := int(l4[12]>>4) * 4
		if off >= 20 && off <= len(l4) {
			p.Options = optionKinds(l4[20:off])
		}
	case 17:
		if len(l4) < 8 {
			return p, false
		}
		p.Proto = "udp"
		p.DstPort = int(binary.BigEndian.Uint16(l4[2:4]))
	default:
		return p, false
	}
	return p, true
}

// optionKinds summarises TCP options: M=MSS, W=window scale, S=SACK
// permitted, T=timestamps, N=NOP, ?=other.
func optionKinds(o []byte) string {
	var out []byte
	for i := 0; i < len(o) && len(out) < 16; {
		k := o[i]
		switch k {
		case 0:
			return string(out)
		case 1:
			out = append(out, 'N')
			i++
			continue
		}
		if i+1 >= len(o) || o[i+1] < 2 {
			return string(out)
		}
		switch k {
		case 2:
			out = append(out, 'M')
		case 3:
			out = append(out, 'W')
		case 4:
			out = append(out, 'S')
		case 8:
			out = append(out, 'T')
		default:
			out = append(out, '?')
		}
		i += int(o[i+1])
	}
	return string(out)
}

// IsScanProbe reports whether p can be part of a port scan: any UDP
// datagram, or a TCP segment without ACK and without RST (SYN, FIN, NULL,
// Xmas). Established traffic always carries ACK.
func IsScanProbe(p Probe) bool {
	if p.Proto == "udp" {
		return true
	}
	return p.Flags&flagACK == 0 && p.Flags&flagRST == 0
}

// ScanType classifies one probe.
func ScanType(p Probe) string {
	if p.Proto == "udp" {
		return "udp"
	}
	f := p.Flags & (flagFIN | flagSYN | flagPSH | flagURG)
	switch {
	case f == 0:
		return "null"
	case f == flagFIN:
		return "fin"
	case f == flagFIN|flagPSH|flagURG:
		return "xmas"
	case f&flagSYN != 0:
		// A SYN with the full option set of an OS TCP stack is a normal
		// connect(); crafted SYN scans carry few or no options.
		if len(p.Options) >= 4 {
			return "connect"
		}
		return "syn"
	}
	return "other"
}

// ToolGuess applies simple public fingerprints, returning "" unless
// confident.
func ToolGuess(p Probe) string {
	if p.Proto != "tcp" || p.Flags&flagSYN == 0 {
		return ""
	}
	switch {
	case p.IPID == 54321 && p.Window == 65535:
		return "zmap"
	case p.Options == "M" && (p.Window == 1024 || p.Window == 2048 || p.Window == 3072 || p.Window == 4096):
		return "nmap"
	case p.Options == "" && p.Window == 1024:
		return "masscan"
	}
	return ""
}
