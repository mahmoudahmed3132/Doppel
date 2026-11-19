// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/decoy"
	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

const (
	dnsHeaderLen        = 12
	dnsMaxUDPPacketSize = 1472
	dnsMaxTCPMsgSize    = 4096
	dnsMaxTCPQueries    = 16
	dnsMaxNameWireLen   = 255
	dnsMaxLabelLen      = 63
	dnsMaxLabels        = 128

	dnsFlagQR       uint16 = 0x8000
	dnsFlagOpcode   uint16 = 0x7800
	dnsFlagRD       uint16 = 0x0100
	dnsRcodeRefused uint16 = 5

	dnsTypeIXFR uint16 = 251
	dnsTypeAXFR uint16 = 252
)

// dnsQuery is the parsed first question of an RFC 1035 DNS query.
type dnsQuery struct {
	ID       uint16
	Flags    uint16
	QName    string
	QType    uint16
	QClass   uint16
	Question []byte // exact raw question wire bytes (from offset 12 to qEnd)
}

// parseDNSQuery parses the 12-byte header and first question of an RFC 1035
// query. Responses (QR=1), compression pointers in the question section, and
// malformed or oversized names are rejected.
func parseDNSQuery(msg []byte) (*dnsQuery, error) {
	if len(msg) < dnsHeaderLen || len(msg) > dnsMaxTCPMsgSize {
		return nil, errors.New("dns: invalid message length")
	}
	id := binary.BigEndian.Uint16(msg[0:2])
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&dnsFlagQR != 0 {
		return nil, errors.New("dns: ignoring response packet")
	}
	qdcount := binary.BigEndian.Uint16(msg[4:6])
	if qdcount == 0 {
		return nil, errors.New("dns: zero questions")
	}

	pos := dnsHeaderLen
	var labels []string
	wireLen := 0
	for {
		if pos >= len(msg) {
			return nil, errors.New("dns: truncated qname")
		}
		l := int(msg[pos])
		pos++
		wireLen++
		if wireLen > dnsMaxNameWireLen {
			return nil, errors.New("dns: qname exceeds 255 bytes")
		}
		if l == 0 {
			break
		}
		if l&0xC0 != 0 {
			return nil, errors.New("dns: compression pointer not allowed in question")
		}
		if l > dnsMaxLabelLen {
			return nil, errors.New("dns: label exceeds 63 bytes")
		}
		if len(labels) >= dnsMaxLabels {
			return nil, errors.New("dns: too many labels")
		}
		if pos+l > len(msg) {
			return nil, errors.New("dns: truncated label")
		}
		wireLen += l
		if wireLen > dnsMaxNameWireLen {
			return nil, errors.New("dns: qname exceeds 255 bytes")
		}
		labels = append(labels, strings.ToLower(string(msg[pos:pos+l])))
		pos += l
	}

	if pos+4 > len(msg) {
		return nil, errors.New("dns: truncated qtype/qclass")
	}
	qtype := binary.BigEndian.Uint16(msg[pos : pos+2])
	qclass := binary.BigEndian.Uint16(msg[pos+2 : pos+4])
	qEnd := pos + 4

	qname := "."
	if len(labels) > 0 {
		qname = decoy.Sanitize(strings.Join(labels, "."), dnsMaxNameWireLen)
	}

	return &dnsQuery{
		ID:       id,
		Flags:    flags,
		QName:    qname,
		QType:    qtype,
		QClass:   qclass,
		Question: msg[dnsHeaderLen:qEnd],
	}, nil
}

// buildDNSRefused builds a minimal REFUSED reply containing only the 12-byte
// header and the raw first question bytes. The reply length is strictly
// <= len(req).
func buildDNSRefused(q *dnsQuery, reqLen int) []byte {
	replyLen := dnsHeaderLen + len(q.Question)
	if replyLen > reqLen {
		return nil
	}
	out := make([]byte, replyLen)
	binary.BigEndian.PutUint16(out[0:2], q.ID)
	respFlags := dnsFlagQR | (q.Flags & (dnsFlagOpcode | dnsFlagRD)) | dnsRcodeRefused
	binary.BigEndian.PutUint16(out[2:4], respFlags)
	binary.BigEndian.PutUint16(out[4:6], 1) // QDCOUNT = 1
	// ANCOUNT = NSCOUNT = ARCOUNT = 0
	copy(out[dnsHeaderLen:], q.Question)
	return out
}

func dnsQTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 48:
		return "DNSKEY"
	case dnsTypeIXFR:
		return "IXFR"
	case dnsTypeAXFR:
		return "AXFR"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

func dnsQClassName(c uint16) string {
	switch c {
	case 1:
		return "IN"
	case 3:
		return "CH"
	case 4:
		return "HS"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("CLASS%d", c)
	}
}

// HandleDNSPacket processes one UDP DNS datagram and sends a REFUSED reply
// echoing only the question, subject to the per-source reply rate limiter.
func (d *Decoy) HandleDNSPacket(pc net.PacketConn, from net.Addr, payload []byte, dstPort int) {
	ip := decoy.RemoteIP(from)
	reply := d.ProcessDNS(ip, payload, "udp", dstPort)
	if len(reply) == 0 || len(reply) > len(payload) {
		return
	}
	if !d.allowReply(ip) {
		return
	}
	_, _ = pc.WriteTo(reply, from)
}

// HandleDNSTCPConn serves bounded RFC 1035 §4.2.2 length-prefixed DNS queries
// over TCP, always replying REFUSED. AXFR/IXFR queries are reported at high
// severity.
func (d *Decoy) HandleDNSTCPConn(conn net.Conn, dstPort int) {
	defer conn.Close()
	ip := decoy.RemoteIP(conn.RemoteAddr())
	if !d.acquireTCP(ip) {
		return
	}
	defer d.releaseTCP(ip)

	totalDeadline := d.now().Add(d.totalTimeout)
	var lenBuf [2]byte
	for i := 0; i < dnsMaxTCPQueries; i++ {
		dl := d.now().Add(d.idleTimeout)
		if totalDeadline.Before(dl) {
			dl = totalDeadline
		}
		_ = conn.SetDeadline(dl)

		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if msgLen < dnsHeaderLen || msgLen > dnsMaxTCPMsgSize {
			return
		}
		msg := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		reply := d.ProcessDNS(ip, msg, "tcp", dstPort)
		if len(reply) == 0 || len(reply) > len(msg) {
			return
		}
		var outLen [2]byte
		binary.BigEndian.PutUint16(outLen[:], uint16(len(reply)))
		if _, err := conn.Write(outLen[:]); err != nil {
			return
		}
		if _, err := conn.Write(reply); err != nil {
			return
		}
	}
}

// ProcessDNS parses msg, emits a dns_query event, and returns the REFUSED
// wire reply (guaranteed len(reply) <= len(msg), or nil on invalid input).
func (d *Decoy) ProcessDNS(ip string, msg []byte, transport string, dstPort int) []byte {
	q, err := parseDNSQuery(msg)
	if err != nil {
		return nil
	}

	sev := sensor.SeverityMedium
	if transport == "tcp" && (q.QType == dnsTypeAXFR || q.QType == dnsTypeIXFR) {
		sev = sensor.SeverityHigh
	}

	fields := sensor.Fields{
		sensor.F("protocol", "dns"),
		sensor.F("transport", transport),
		sensor.F("dst_port", dstPort),
		sensor.F("qname", q.QName),
		sensor.F("qtype", dnsQTypeName(q.QType)),
		sensor.F("qclass", dnsQClassName(q.QClass)),
	}
	d.emit(sev, TriggerDNSQuery, ip, fmt.Sprintf("DNS %s port %d", transport, dstPort), fields)

	return buildDNSRefused(q, len(msg))
}
