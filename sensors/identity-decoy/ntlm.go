// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/ber"
	"github.com/mahmoudahmed3132/Doppel/sdk/go/decoy"
)

// MS-NLMP constants.
const (
	ntlmSignature        = "NTLMSSP\x00"
	ntlmTypeNegotiate    = 1
	ntlmTypeChallenge    = 2
	ntlmTypeAuthenticate = 3

	ntlmFlagUnicode                 uint32 = 0x00000001
	ntlmFlagRequestTarget           uint32 = 0x00000004
	ntlmFlagNTLM                    uint32 = 0x00000200
	ntlmFlagTargetTypeDomain        uint32 = 0x00010000
	ntlmFlagExtendedSessionSecurity uint32 = 0x00080000
	ntlmFlagTargetInfo              uint32 = 0x00800000
	ntlmFlagVersion                 uint32 = 0x02000000
	ntlmFlag128                     uint32 = 0x20000000
	ntlmFlag56                      uint32 = 0x80000000

	avIDEOL             uint16 = 0x0000
	avIDNbComputerName  uint16 = 0x0001
	avIDNbDomainName    uint16 = 0x0002
	avIDDnsComputerName uint16 = 0x0003
	avIDDnsDomainName   uint16 = 0x0004
	avIDDnsTreeName     uint16 = 0x0005
	avIDTimestamp       uint16 = 0x0007

	ntlmRevisionCurrent byte = 0x0F

	maxNTLMMsgSize = 16 << 10
	maxNTLMField   = 256
)

var (
	oidSPNEGO  = []uint32{1, 3, 6, 1, 5, 5, 2}
	oidNTLMSSP = []uint32{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}

	errNTLMInvalid   = errors.New("ntlm: invalid message")
	errNTLMTooLarge  = errors.New("ntlm: message too large")
	errNTLMTruncated = errors.New("ntlm: truncated message")
)

// OSVersion holds the Windows major.minor.build advertised in NTLM CHALLENGE.
type OSVersion struct {
	Major uint8
	Minor uint8
	Build uint16
}

// Persona holds the domain controller identity advertised across NTLM, LDAP and TLS.
type Persona struct {
	DomainDNS     string
	DomainNetBIOS string
	Hostname      string
	OS            OSVersion
}

// FQDN returns the lowercase fully qualified domain name (e.g. "dc01.corp.local").
func (p Persona) FQDN() string {
	h := strings.ToLower(strings.TrimSpace(p.Hostname))
	d := strings.ToLower(strings.TrimSpace(p.DomainDNS))
	if d == "" {
		return h
	}
	return h + "." + d
}

// DefaultNamingContext converts DomainDNS (e.g. "corp.local") to "DC=corp,DC=local".
func (p Persona) DefaultNamingContext() string {
	parts := strings.Split(strings.TrimSpace(p.DomainDNS), ".")
	dcs := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			dcs = append(dcs, "DC="+part)
		}
	}
	if len(dcs) == 0 {
		return "DC=corp,DC=local"
	}
	return strings.Join(dcs, ",")
}

// NTLMNegotiate is a parsed MS-NLMP Type 1 message.
type NTLMNegotiate struct {
	Flags       uint32
	Domain      string
	Workstation string
}

// NTLMAuthenticate is a parsed MS-NLMP Type 3 message.
type NTLMAuthenticate struct {
	Flags       uint32
	Domain      string
	Username    string
	Workstation string
	LMResponse  []byte
	NTResponse  []byte
}

func ntlmMessageType(msg []byte) (uint32, error) {
	if len(msg) > maxNTLMMsgSize {
		return 0, errNTLMTooLarge
	}
	if len(msg) < 12 {
		return 0, errNTLMTruncated
	}
	if !bytes.HasPrefix(msg, []byte(ntlmSignature)) {
		return 0, errNTLMInvalid
	}
	return binary.LittleEndian.Uint32(msg[8:12]), nil
}

func extractNTLMField(msg []byte, descOff int) ([]byte, error) {
	if descOff+8 > len(msg) {
		return nil, errNTLMTruncated
	}
	fLen := uint64(binary.LittleEndian.Uint16(msg[descOff : descOff+2]))
	// descOff+2..descOff+4 is MaxLen (ignored on read per MS-NLMP).
	fOff := uint64(binary.LittleEndian.Uint32(msg[descOff+4 : descOff+8]))
	if fLen == 0 {
		return nil, nil
	}
	if fOff > uint64(len(msg)) || fLen > uint64(len(msg))-fOff {
		return nil, errNTLMTruncated
	}
	return msg[fOff : fOff+fLen], nil
}

// parseNTLMType1 parses an MS-NLMP NEGOTIATE_MESSAGE (Type 1).
func parseNTLMType1(msg []byte) (NTLMNegotiate, error) {
	mt, err := ntlmMessageType(msg)
	if err != nil {
		return NTLMNegotiate{}, err
	}
	if mt != ntlmTypeNegotiate {
		return NTLMNegotiate{}, errNTLMInvalid
	}
	if len(msg) < 16 {
		return NTLMNegotiate{}, errNTLMTruncated
	}
	out := NTLMNegotiate{
		Flags: binary.LittleEndian.Uint32(msg[12:16]),
	}
	if len(msg) >= 32 {
		if dom, err := extractNTLMField(msg, 16); err == nil && len(dom) > 0 {
			out.Domain = decoy.Sanitize(string(dom), maxNTLMField)
		}
		if ws, err := extractNTLMField(msg, 24); err == nil && len(ws) > 0 {
			out.Workstation = decoy.Sanitize(string(ws), maxNTLMField)
		}
	}
	return out, nil
}

// buildNTLMType2 constructs an MS-NLMP CHALLENGE_MESSAGE (Type 2) with a random
// 8-byte server challenge and TargetInfo AV_PAIRs populated from persona.
func buildNTLMType2(p Persona, challenge [8]byte, now time.Time) []byte {
	targetName := encodeUTF16LE(strings.ToUpper(p.DomainNetBIOS))
	targetInfo := buildTargetInfo(p, now)

	const headerLen = 56
	targetNameOff := uint32(headerLen)
	targetInfoOff := targetNameOff + uint32(len(targetName))

	flags := ntlmFlagUnicode |
		ntlmFlagRequestTarget |
		ntlmFlagNTLM |
		ntlmFlagTargetTypeDomain |
		ntlmFlagExtendedSessionSecurity |
		ntlmFlagTargetInfo |
		ntlmFlagVersion |
		ntlmFlag128 |
		ntlmFlag56

	out := make([]byte, headerLen+len(targetName)+len(targetInfo))
	copy(out[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(out[8:12], ntlmTypeChallenge)

	// TargetNameFields
	binary.LittleEndian.PutUint16(out[12:14], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(out[14:16], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(out[16:20], targetNameOff)

	// NegotiateFlags
	binary.LittleEndian.PutUint32(out[20:24], flags)

	// ServerChallenge
	copy(out[24:32], challenge[:])

	// Reserved [32:40] stays zero.

	// TargetInfoFields
	binary.LittleEndian.PutUint16(out[40:42], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(out[42:44], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(out[44:48], targetInfoOff)

	// Version [48:56]
	out[48] = p.OS.Major
	out[49] = p.OS.Minor
	binary.LittleEndian.PutUint16(out[50:52], p.OS.Build)
	out[55] = ntlmRevisionCurrent

	copy(out[targetNameOff:], targetName)
	copy(out[targetInfoOff:], targetInfo)
	return out
}

func buildTargetInfo(p Persona, now time.Time) []byte {
	var buf bytes.Buffer
	writeAV := func(id uint16, val []byte) {
		var hdr [4]byte
		binary.LittleEndian.PutUint16(hdr[0:2], id)
		binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(val)))
		buf.Write(hdr[:])
		buf.Write(val)
	}
	writeAV(avIDNbDomainName, encodeUTF16LE(strings.ToUpper(p.DomainNetBIOS)))
	writeAV(avIDNbComputerName, encodeUTF16LE(strings.ToUpper(p.Hostname)))
	writeAV(avIDDnsDomainName, encodeUTF16LE(strings.ToLower(p.DomainDNS)))
	writeAV(avIDDnsComputerName, encodeUTF16LE(p.FQDN()))
	writeAV(avIDDnsTreeName, encodeUTF16LE(strings.ToLower(p.DomainDNS)))

	// Windows FILETIME: 100-nanosecond intervals since 1601-01-01T00:00:00Z.
	const epochDiff100ns int64 = 116444736000000000
	ft := uint64(now.UTC().UnixNano()/100 + epochDiff100ns)
	var ts [8]byte
	binary.LittleEndian.PutUint64(ts[:], ft)
	writeAV(avIDTimestamp, ts[:])

	writeAV(avIDEOL, nil)
	return buf.Bytes()
}

// parseNTLMType3 parses an MS-NLMP AUTHENTICATE_MESSAGE (Type 3).
func parseNTLMType3(msg []byte) (NTLMAuthenticate, error) {
	mt, err := ntlmMessageType(msg)
	if err != nil {
		return NTLMAuthenticate{}, err
	}
	if mt != ntlmTypeAuthenticate {
		return NTLMAuthenticate{}, errNTLMInvalid
	}
	if len(msg) < 52 {
		return NTLMAuthenticate{}, errNTLMTruncated
	}

	lmResp, err := extractNTLMField(msg, 12)
	if err != nil {
		return NTLMAuthenticate{}, err
	}
	ntResp, err := extractNTLMField(msg, 20)
	if err != nil {
		return NTLMAuthenticate{}, err
	}
	domRaw, err := extractNTLMField(msg, 28)
	if err != nil {
		return NTLMAuthenticate{}, err
	}
	userRaw, err := extractNTLMField(msg, 36)
	if err != nil {
		return NTLMAuthenticate{}, err
	}
	wsRaw, err := extractNTLMField(msg, 44)
	if err != nil {
		return NTLMAuthenticate{}, err
	}

	var flags uint32
	if len(msg) >= 64 {
		flags = binary.LittleEndian.Uint32(msg[60:64])
	}

	decodeStr := func(b []byte) string {
		if len(b) == 0 {
			return ""
		}
		if flags&ntlmFlagUnicode != 0 {
			return decoy.Sanitize(decodeUTF16LE(b), maxNTLMField)
		}
		return decoy.Sanitize(string(b), maxNTLMField)
	}

	return NTLMAuthenticate{
		Flags:       flags,
		Domain:      decodeStr(domRaw),
		Username:    decodeStr(userRaw),
		Workstation: decodeStr(wsRaw),
		LMResponse:  append([]byte(nil), lmResp...),
		NTResponse:  append([]byte(nil), ntResp...),
	}, nil
}

func randomNTLMChallenge() ([8]byte, error) {
	var c [8]byte
	_, err := rand.Read(c[:])
	return c, err
}

func encodeUTF16LE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	out := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(out[i*2:], v)
	}
	return out
}

func decodeUTF16LE(b []byte) string {
	n := len(b) / 2
	if n == 0 {
		return ""
	}
	u16 := make([]uint16, n)
	for i := 0; i < n; i++ {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(u16))
}

// unwrapNTLMToken accepts either a raw NTLMSSP token or a GSS-API / SPNEGO
// NegTokenInit / NegTokenResp carrying an NTLMSSP token, parsed strictly via
// sdk/go/ber.
func unwrapNTLMToken(token []byte) (ntlmBytes []byte, spnego bool, err error) {
	if len(token) > maxNTLMMsgSize {
		return nil, false, errNTLMTooLarge
	}
	if bytes.HasPrefix(token, []byte(ntlmSignature)) {
		return token, false, nil
	}
	r, err := ber.NewReader(token, ber.Limits{MaxMessage: maxNTLMMsgSize, MaxDepth: 10})
	if err != nil {
		return nil, false, err
	}
	top, err := r.Next()
	if err != nil {
		return nil, false, err
	}

	// GSS-API InitialContextToken: [APPLICATION 0] { OID, innerToken }
	if top.Is(ber.Application, 0) && top.Constructed {
		ch, err := top.Children()
		if err != nil {
			return nil, false, err
		}
		oidEl, err := ch.Expect(ber.Universal, ber.TagOID)
		if err != nil {
			return nil, false, err
		}
		arcs, err := oidEl.OID(16)
		if err != nil {
			return nil, false, err
		}
		if equalOID(arcs, oidNTLMSSP) {
			// Direct NTLMSSP inside GSS-API wrapper (remaining bytes).
			if ch.Len() == 0 {
				return nil, false, errNTLMTruncated
			}
			// Read raw remainder or embedded element.
			inner, err := ch.Next()
			if err == nil && bytes.HasPrefix(inner.Value, []byte(ntlmSignature)) {
				return inner.Value, false, nil
			}
			return nil, false, errNTLMInvalid
		}
		if !equalOID(arcs, oidSPNEGO) {
			return nil, false, errNTLMInvalid
		}
		top, err = ch.Next()
		if err != nil {
			return nil, false, err
		}
	}

	// SPNEGO NegTokenInit ([0] SEQUENCE { [2] mechToken }) or
	// NegTokenResp ([1] SEQUENCE { [2] responseToken }).
	if (top.Is(ber.ContextSpecific, 0) || top.Is(ber.ContextSpecific, 1)) && top.Constructed {
		ch, err := top.Children()
		if err != nil {
			return nil, false, err
		}
		seq, err := ch.Expect(ber.Universal, ber.TagSequence)
		if err != nil {
			return nil, false, err
		}
		fields, err := seq.Children()
		if err != nil {
			return nil, false, err
		}
		for fields.Len() > 0 {
			f, err := fields.Next()
			if err != nil {
				return nil, false, err
			}
			if f.Is(ber.ContextSpecific, 2) && f.Constructed {
				fch, err := f.Children()
				if err != nil {
					return nil, false, err
				}
				osEl, err := fch.Expect(ber.Universal, ber.TagOctetString)
				if err != nil {
					return nil, false, err
				}
				if bytes.HasPrefix(osEl.Value, []byte(ntlmSignature)) {
					return osEl.Value, true, nil
				}
				return nil, false, errNTLMInvalid
			}
		}
	}
	return nil, false, errNTLMInvalid
}

// wrapSPNEGOChallenge wraps a Type 2 CHALLENGE_MESSAGE in a SPNEGO NegTokenResp
// (accept-incomplete, supportedMech=NTLMSSP) using sdk/go/ber.
func wrapSPNEGOChallenge(type2 []byte) []byte {
	negState := ber.Encode(ber.ContextSpecific, true, 0, ber.Enumerated(1)) // accept-incomplete
	supportedMech := ber.Encode(ber.ContextSpecific, true, 1, ber.OID(oidNTLMSSP))
	respToken := ber.Encode(ber.ContextSpecific, true, 2, ber.OctetString(type2))
	return ber.Encode(ber.ContextSpecific, true, 1, ber.Sequence(negState, supportedMech, respToken))
}

func equalOID(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
