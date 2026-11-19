// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/ber"
	"github.com/mahmoudahmed3132/Doppel/sdk/go/decoy"
	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

const (
	snmpMaxPacketSize  = 1472
	snmpMaxDepth       = 10
	snmpMaxOIDs        = 16
	snmpMaxOIDArcs     = 64
	snmpMaxReplyMargin = 64

	snmpVersion1  = 0
	snmpVersion2c = 1
	snmpVersion3  = 3

	snmpPDUGetRequest     uint32 = 0
	snmpPDUGetNextRequest uint32 = 1
	snmpPDUResponse       uint32 = 2
	snmpPDUSetRequest     uint32 = 3
	snmpPDUTrapV1         uint32 = 4
	snmpPDUGetBulkRequest uint32 = 5
	snmpPDUInformRequest  uint32 = 6
	snmpPDUTrapV2         uint32 = 7
	snmpPDUReport         uint32 = 8

	snmpSecurityModelUSM = 3
	snmpFlagAuth         = 0x01
	snmpFlagPriv         = 0x02
	snmpFlagReportable   = 0x04

	// RFC 2578 APPLICATION primitive tags.
	snmpTagCounter32 uint32 = 1
	snmpTagTimeTicks uint32 = 3

	// RFC 3416 exception tag (ContextSpecific primitive).
	snmpTagNoSuchObject uint32 = 0
)

var (
	oidSysGroupPrefix = []uint32{1, 3, 6, 1, 2, 1, 1}
	oidSysDescr       = []uint32{1, 3, 6, 1, 2, 1, 1, 1, 0}
	oidSysObjectID    = []uint32{1, 3, 6, 1, 2, 1, 1, 2, 0}
	oidSysUpTime      = []uint32{1, 3, 6, 1, 2, 1, 1, 3, 0}
	oidSysContact     = []uint32{1, 3, 6, 1, 2, 1, 1, 4, 0}
	oidSysName        = []uint32{1, 3, 6, 1, 2, 1, 1, 5, 0}
	oidSysLocation    = []uint32{1, 3, 6, 1, 2, 1, 1, 6, 0}
	oidUSMUnknownEng  = []uint32{1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0}
)

// snmpMessage is the parsed representation of an incoming SNMPv1/v2c/v3 packet.
type snmpMessage struct {
	Version    int64
	VersionStr string

	// v1 / v2c fields.
	Community string

	// v3 fields.
	MsgID         int64
	MsgMaxSize    int64
	MsgFlags      byte
	SecurityModel int64
	SecurityLevel string
	EngineID      []byte
	Username      string

	// PDU fields (when plaintext PDU is present).
	HasPDU    bool
	PDUTag    uint32
	PDUType   string
	RequestID int64
	OIDs      [][]uint32
}

// parseSNMPMessage parses an untrusted SNMPv1/v2c/v3 packet using sdk/go/ber.
func parseSNMPMessage(payload []byte) (*snmpMessage, error) {
	if len(payload) == 0 || len(payload) > snmpMaxPacketSize {
		return nil, errors.New("snmp: invalid packet length")
	}
	r, err := ber.NewReader(payload, ber.Limits{MaxMessage: snmpMaxPacketSize, MaxDepth: snmpMaxDepth})
	if err != nil {
		return nil, err
	}
	outer, err := r.Expect(ber.Universal, ber.TagSequence)
	if err != nil {
		return nil, err
	}
	body, err := outer.Children()
	if err != nil {
		return nil, err
	}
	verEl, err := body.Expect(ber.Universal, ber.TagInteger)
	if err != nil {
		return nil, err
	}
	ver, err := verEl.Int()
	if err != nil {
		return nil, err
	}

	switch ver {
	case snmpVersion1:
		return parseSNMPv1v2c(body, ver, "1")
	case snmpVersion2c:
		return parseSNMPv1v2c(body, ver, "2c")
	case snmpVersion3:
		return parseSNMPv3(body)
	default:
		return nil, fmt.Errorf("snmp: unsupported version %d", ver)
	}
}

func parseSNMPv1v2c(body *ber.Reader, ver int64, verStr string) (*snmpMessage, error) {
	commEl, err := body.Expect(ber.Universal, ber.TagOctetString)
	if err != nil {
		return nil, err
	}
	pduEl, err := body.Next()
	if err != nil {
		return nil, err
	}
	if pduEl.Class != ber.ContextSpecific || !pduEl.Constructed {
		return nil, errors.New("snmp: expected context-specific constructed PDU")
	}
	msg := &snmpMessage{
		Version:    ver,
		VersionStr: verStr,
		Community:  string(commEl.Value),
		HasPDU:     true,
		PDUTag:     pduEl.Number,
		PDUType:    snmpPDUTypeName(pduEl.Number),
	}
	// SNMPv1 Trap (tag 4) has a distinct header layout; report it without
	// parsing request-id / varbinds as a standard PDU.
	if pduEl.Number == snmpPDUTrapV1 {
		return msg, nil
	}
	reqID, oids, err := parseStandardPDU(pduEl)
	if err != nil {
		return nil, err
	}
	msg.RequestID = reqID
	msg.OIDs = oids
	return msg, nil
}

func parseSNMPv3(body *ber.Reader) (*snmpMessage, error) {
	globalEl, err := body.Expect(ber.Universal, ber.TagSequence)
	if err != nil {
		return nil, err
	}
	global, err := globalEl.Children()
	if err != nil {
		return nil, err
	}
	msgIDEl, err := global.Expect(ber.Universal, ber.TagInteger)
	if err != nil {
		return nil, err
	}
	msgID, err := msgIDEl.Int()
	if err != nil {
		return nil, err
	}
	maxSizeEl, err := global.Expect(ber.Universal, ber.TagInteger)
	if err != nil {
		return nil, err
	}
	maxSize, err := maxSizeEl.Int()
	if err != nil {
		return nil, err
	}
	flagsEl, err := global.Expect(ber.Universal, ber.TagOctetString)
	if err != nil {
		return nil, err
	}
	if len(flagsEl.Value) != 1 {
		return nil, errors.New("snmp: msgFlags must be 1 byte")
	}
	flags := flagsEl.Value[0]
	secModelEl, err := global.Expect(ber.Universal, ber.TagInteger)
	if err != nil {
		return nil, err
	}
	secModel, err := secModelEl.Int()
	if err != nil {
		return nil, err
	}

	secParamsEl, err := body.Expect(ber.Universal, ber.TagOctetString)
	if err != nil {
		return nil, err
	}

	msg := &snmpMessage{
		Version:       snmpVersion3,
		VersionStr:    "3",
		MsgID:         msgID,
		MsgMaxSize:    maxSize,
		MsgFlags:      flags,
		SecurityModel: secModel,
		SecurityLevel: snmpSecurityLevel(flags),
	}

	// Parse USM security parameters (RFC 3414 §2.4) when security model is USM (3).
	if secModel == snmpSecurityModelUSM && len(secParamsEl.Value) > 0 {
		usmReader, err := ber.NewReader(secParamsEl.Value, ber.Limits{MaxMessage: snmpMaxPacketSize, MaxDepth: snmpMaxDepth})
		if err != nil {
			return nil, err
		}
		usmSeq, err := usmReader.Expect(ber.Universal, ber.TagSequence)
		if err != nil {
			return nil, err
		}
		usm, err := usmSeq.Children()
		if err != nil {
			return nil, err
		}
		engEl, err := usm.Expect(ber.Universal, ber.TagOctetString)
		if err != nil {
			return nil, err
		}
		msg.EngineID = engEl.Value
		// msgAuthoritativeEngineBoots
		if _, err := usm.Expect(ber.Universal, ber.TagInteger); err != nil {
			return nil, err
		}
		// msgAuthoritativeEngineTime
		if _, err := usm.Expect(ber.Universal, ber.TagInteger); err != nil {
			return nil, err
		}
		userEl, err := usm.Expect(ber.Universal, ber.TagOctetString)
		if err != nil {
			return nil, err
		}
		msg.Username = decoy.Sanitize(string(userEl.Value), 128)
		// msgAuthenticationParameters & msgPrivacyParameters
		if _, err := usm.Expect(ber.Universal, ber.TagOctetString); err != nil {
			return nil, err
		}
		if _, err := usm.Expect(ber.Universal, ber.TagOctetString); err != nil {
			return nil, err
		}
	}

	// Parse msgData (ScopedPduData: SEQUENCE for plaintext, OCTET STRING for encrypted).
	if body.Len() == 0 {
		return nil, errors.New("snmp: missing msgData")
	}
	dataEl, err := body.Next()
	if err != nil {
		return nil, err
	}
	switch {
	case dataEl.Is(ber.Universal, ber.TagOctetString):
		msg.PDUType = "Encrypted"
	case dataEl.Is(ber.Universal, ber.TagSequence) && dataEl.Constructed:
		scoped, err := dataEl.Children()
		if err != nil {
			return nil, err
		}
		// contextEngineID, contextName
		if _, err := scoped.Expect(ber.Universal, ber.TagOctetString); err != nil {
			return nil, err
		}
		if _, err := scoped.Expect(ber.Universal, ber.TagOctetString); err != nil {
			return nil, err
		}
		pduEl, err := scoped.Next()
		if err != nil {
			return nil, err
		}
		if pduEl.Class != ber.ContextSpecific || !pduEl.Constructed {
			return nil, errors.New("snmp: expected constructed PDU inside ScopedPDU")
		}
		reqID, oids, err := parseStandardPDU(pduEl)
		if err != nil {
			return nil, err
		}
		msg.HasPDU = true
		msg.PDUTag = pduEl.Number
		msg.PDUType = snmpPDUTypeName(pduEl.Number)
		msg.RequestID = reqID
		msg.OIDs = oids
	default:
		return nil, errors.New("snmp: unexpected msgData element")
	}

	return msg, nil
}

func parseStandardPDU(pduEl ber.Element) (int64, [][]uint32, error) {
	pdu, err := pduEl.Children()
	if err != nil {
		return 0, nil, err
	}
	reqIDEl, err := pdu.Expect(ber.Universal, ber.TagInteger)
	if err != nil {
		return 0, nil, err
	}
	reqID, err := reqIDEl.Int()
	if err != nil {
		return 0, nil, err
	}
	// error-status / non-repeaters
	if _, err := pdu.Expect(ber.Universal, ber.TagInteger); err != nil {
		return 0, nil, err
	}
	// error-index / max-repetitions
	if _, err := pdu.Expect(ber.Universal, ber.TagInteger); err != nil {
		return 0, nil, err
	}
	vblEl, err := pdu.Expect(ber.Universal, ber.TagSequence)
	if err != nil {
		return 0, nil, err
	}
	vbl, err := vblEl.Children()
	if err != nil {
		return 0, nil, err
	}
	var oids [][]uint32
	for vbl.Len() > 0 && len(oids) < snmpMaxOIDs {
		vbEl, err := vbl.Expect(ber.Universal, ber.TagSequence)
		if err != nil {
			return 0, nil, err
		}
		vb, err := vbEl.Children()
		if err != nil {
			return 0, nil, err
		}
		oidEl, err := vb.Expect(ber.Universal, ber.TagOID)
		if err != nil {
			return 0, nil, err
		}
		arcs, err := oidEl.OID(snmpMaxOIDArcs)
		if err != nil {
			return 0, nil, err
		}
		// Ensure a value element exists in the varbind.
		if _, err := vb.Next(); err != nil {
			return 0, nil, err
		}
		oids = append(oids, arcs)
	}
	return reqID, oids, nil
}

func snmpPDUTypeName(tag uint32) string {
	switch tag {
	case snmpPDUGetRequest:
		return "GetRequest"
	case snmpPDUGetNextRequest:
		return "GetNextRequest"
	case snmpPDUResponse:
		return "Response"
	case snmpPDUSetRequest:
		return "SetRequest"
	case snmpPDUTrapV1:
		return "Trap"
	case snmpPDUGetBulkRequest:
		return "GetBulkRequest"
	case snmpPDUInformRequest:
		return "InformRequest"
	case snmpPDUTrapV2:
		return "SNMPv2-Trap"
	case snmpPDUReport:
		return "Report"
	default:
		return fmt.Sprintf("PDU(%d)", tag)
	}
}

func snmpSecurityLevel(flags byte) string {
	auth := flags&snmpFlagAuth != 0
	priv := flags&snmpFlagPriv != 0
	switch {
	case !auth && !priv:
		return "noAuthNoPriv"
	case auth && !priv:
		return "authNoPriv"
	case auth && priv:
		return "authPriv"
	default:
		return "invalid"
	}
}

// HandleSNMPPacket processes a single UDP SNMP datagram: parses it, emits an
// snmp_query event, and sends a bounded reply only when permitted by the spec
// and anti-amplification invariants.
func (d *Decoy) HandleSNMPPacket(pc net.PacketConn, from net.Addr, payload []byte, dstPort int) {
	ip := decoy.RemoteIP(from)
	reply := d.ProcessSNMP(ip, payload, dstPort)
	if len(reply) == 0 {
		return
	}
	// Hard anti-amplification guards right before transmit.
	if len(reply) > len(payload)+snmpMaxReplyMargin || len(reply) > snmpMaxPacketSize {
		return
	}
	if !d.allowReply(ip) {
		return
	}
	_, _ = pc.WriteTo(reply, from)
}

// ProcessSNMP parses payload, emits the snmp_query event, and returns an
// optional wire reply (guaranteed len(reply) <= len(payload)+64, or nil).
func (d *Decoy) ProcessSNMP(ip string, payload []byte, dstPort int) []byte {
	msg, err := parseSNMPMessage(payload)
	if err != nil {
		return nil
	}

	sev := sensor.SeverityMedium
	if msg.HasPDU && msg.PDUTag == snmpPDUSetRequest {
		sev = sensor.SeverityHigh
	}

	fields := sensor.Fields{
		sensor.F("protocol", "snmp"),
		sensor.F("dst_port", dstPort),
		sensor.F("version", msg.VersionStr),
	}
	if msg.PDUType != "" {
		fields = append(fields, sensor.F("pdu_type", msg.PDUType))
	}
	if len(msg.OIDs) > 0 {
		oidStrs := make([]string, len(msg.OIDs))
		for i, oid := range msg.OIDs {
			oidStrs[i] = formatOID(oid)
		}
		fields = append(fields, sensor.F("oids", oidStrs))
	}
	if msg.Version == snmpVersion3 {
		fields = append(fields, sensor.F("security_level", msg.SecurityLevel))
		if msg.Username != "" {
			fields = append(fields, sensor.F("username", msg.Username))
		}
		if len(msg.EngineID) == 0 {
			fields = append(fields, sensor.F("engine_discovery", true))
		}
	} else {
		fields = append(fields, d.capture.Secret("community", msg.Community)...)
	}

	d.emit(sev, TriggerSNMPQuery, ip, fmt.Sprintf("SNMP port %d", dstPort), fields)

	maxReply := len(payload) + snmpMaxReplyMargin
	if maxReply > snmpMaxPacketSize {
		maxReply = snmpMaxPacketSize
	}

	if msg.Version == snmpVersion3 {
		return d.buildSNMPv3Reply(msg, maxReply)
	}
	return d.buildSNMPv1v2cReply(msg, maxReply)
}

type sysGroupEntry struct {
	oid      []uint32
	isString bool
	strVal   string
	oidVal   []uint32
	ticksVal uint32
}

func (d *Decoy) sysGroupEntries() []sysGroupEntry {
	p := d.cfg.SNMPPersona
	return []sysGroupEntry{
		{oid: oidSysDescr, isString: true, strVal: p.SysDescr},
		{oid: oidSysObjectID, oidVal: p.SysObjectID},
		{oid: oidSysUpTime, ticksVal: d.uptimeTicks()},
		{oid: oidSysContact, isString: true, strVal: p.SysContact},
		{oid: oidSysName, isString: true, strVal: p.SysName},
		{oid: oidSysLocation, isString: true, strVal: p.SysLocation},
	}
}

func (e sysGroupEntry) encodeVarbind(maxStrLen int) []byte {
	var val []byte
	switch {
	case e.isString:
		s := e.strVal
		if maxStrLen >= 0 && len(s) > maxStrLen {
			s = s[:maxStrLen]
		}
		val = ber.OctetString([]byte(s))
	case e.oidVal != nil:
		val = ber.OID(e.oidVal)
	default:
		val = ber.Encode(ber.Application, false, snmpTagTimeTicks, uint32BERBytes(e.ticksVal))
	}
	return ber.Sequence(ber.OID(e.oid), val)
}

func (d *Decoy) buildSNMPv1v2cReply(msg *snmpMessage, maxReply int) []byte {
	// Stay silent unless a valid community is configured and matches in constant time.
	if d.cfg.SNMPCommunity == "" {
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(msg.Community), []byte(d.cfg.SNMPCommunity)) != 1 {
		return nil
	}
	if !msg.HasPDU || (msg.PDUTag != snmpPDUGetRequest && msg.PDUTag != snmpPDUGetNextRequest) {
		return nil
	}
	if len(msg.OIDs) == 0 {
		return nil
	}

	entries := d.sysGroupEntries()
	type resolvedVB struct {
		entry   *sysGroupEntry
		origOID []uint32
	}
	var resolved []resolvedVB
	matched := 0

	for _, reqOID := range msg.OIDs {
		var found *sysGroupEntry
		if msg.PDUTag == snmpPDUGetRequest {
			for i := range entries {
				if compareOID(entries[i].oid, reqOID) == 0 {
					found = &entries[i]
					break
				}
			}
		} else if hasOIDPrefix(reqOID, oidSysGroupPrefix) {
			for i := range entries {
				if compareOID(entries[i].oid, reqOID) > 0 {
					found = &entries[i]
					break
				}
			}
		}
		if found != nil {
			matched++
		}
		resolved = append(resolved, resolvedVB{entry: found, origOID: reqOID})
	}

	// Answer nothing outside the system group.
	if matched == 0 {
		return nil
	}

	encodeResp := func(maxStrLen int) []byte {
		var vbs [][]byte
		for _, r := range resolved {
			if r.entry != nil {
				vbs = append(vbs, r.entry.encodeVarbind(maxStrLen))
			} else if msg.Version == snmpVersion2c {
				vbs = append(vbs, ber.Sequence(ber.OID(r.origOID), ber.Encode(ber.ContextSpecific, false, snmpTagNoSuchObject, nil)))
			} else {
				// For v1, omit non-matching OIDs by dropping reply if any OID was outside system group.
				return nil
			}
		}
		pdu := ber.Encode(ber.ContextSpecific, true, snmpPDUResponse, ber.Cat(
			ber.Integer(msg.RequestID),
			ber.Integer(0),
			ber.Integer(0),
			ber.Sequence(vbs...),
		))
		return ber.Sequence(
			ber.Integer(msg.Version),
			ber.OctetString([]byte(msg.Community)),
			pdu,
		)
	}

	reply := encodeResp(-1)
	if len(reply) == 0 {
		return nil
	}
	if len(reply) <= maxReply {
		return reply
	}

	// If a long persona string pushed the reply past the anti-amplification
	// budget, trim string values to fit; if it still cannot fit, stay silent.
	excess := len(reply) - maxReply
	for _, limit := range []int{64, 48, 32, 16, 8, 0} {
		if excess > 0 {
			candidate := encodeResp(limit)
			if len(candidate) > 0 && len(candidate) <= maxReply {
				return candidate
			}
		}
	}
	return nil
}

func (d *Decoy) buildSNMPv3Reply(msg *snmpMessage, maxReply int) []byte {
	// Answer only USM unknown-engine-ID discovery (empty authoritative engine ID
	// with the reportable flag set).
	if msg.SecurityModel != snmpSecurityModelUSM || len(msg.EngineID) != 0 || msg.MsgFlags&snmpFlagReportable == 0 {
		return nil
	}
	count := d.unknownEngineCount.Add(1)
	engID := d.cfg.SNMPPersona.EngineID

	globalData := ber.Sequence(
		ber.Integer(msg.MsgID),
		ber.Integer(snmpMaxPacketSize),
		ber.OctetString([]byte{0x00}), // noAuthNoPriv, not reportable
		ber.Integer(snmpSecurityModelUSM),
	)
	usmParams := ber.Sequence(
		ber.OctetString(engID),
		ber.Integer(1),                 // msgAuthoritativeEngineBoots
		ber.Integer(d.uptimeSeconds()), // msgAuthoritativeEngineTime
		ber.OctetString(nil),           // msgUserName
		ber.OctetString(nil),           // msgAuthenticationParameters
		ber.OctetString(nil),           // msgPrivacyParameters
	)
	varbind := ber.Sequence(
		ber.OID(oidUSMUnknownEng),
		ber.Encode(ber.Application, false, snmpTagCounter32, uint32BERBytes(count)),
	)
	reportPDU := ber.Encode(ber.ContextSpecific, true, snmpPDUReport, ber.Cat(
		ber.Integer(msg.RequestID),
		ber.Integer(0),
		ber.Integer(0),
		ber.Sequence(varbind),
	))
	scopedPDU := ber.Sequence(
		ber.OctetString(engID),
		ber.OctetString(nil),
		reportPDU,
	)
	reply := ber.Sequence(
		ber.Integer(snmpVersion3),
		globalData,
		ber.OctetString(usmParams),
		scopedPDU,
	)
	if len(reply) > maxReply {
		return nil
	}
	return reply
}

// uint32BERBytes encodes an unsigned 32-bit integer as a minimal non-negative
// BER integer value (prepending 0x00 if the high bit is set).
func uint32BERBytes(v uint32) []byte {
	var tmp [5]byte
	i := len(tmp)
	for {
		i--
		tmp[i] = byte(v)
		v >>= 8
		if v == 0 {
			break
		}
	}
	if tmp[i]&0x80 != 0 {
		i--
		tmp[i] = 0
	}
	return append([]byte(nil), tmp[i:]...)
}

func parseOIDString(s string) ([]uint32, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "."))
	if s == "" {
		return nil, errors.New("empty OID")
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > snmpMaxOIDArcs {
		return nil, fmt.Errorf("OID must have 2..%d arcs", snmpMaxOIDArcs)
	}
	arcs := make([]uint32, len(parts))
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid OID arc %q", p)
		}
		arcs[i] = uint32(n)
	}
	if arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40) {
		return nil, errors.New("invalid leading OID arcs")
	}
	return arcs, nil
}

func formatOID(arcs []uint32) string {
	if len(arcs) == 0 {
		return ""
	}
	var b strings.Builder
	for i, a := range arcs {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.FormatUint(uint64(a), 10))
	}
	return b.String()
}

func compareOID(a, b []uint32) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

func hasOIDPrefix(oid, prefix []uint32) bool {
	if len(oid) < len(prefix) {
		return false
	}
	for i := range prefix {
		if oid[i] != prefix[i] {
			return false
		}
	}
	return true
}
