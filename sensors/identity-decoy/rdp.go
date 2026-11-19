// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/ber"
	"github.com/mahmoudahmed3132/Doppel/sdk/go/decoy"
	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

// MS-RDPBCGR & MS-CSSP constants.
const (
	tpktVersion      byte = 0x03
	maxTPKTSize           = 4096
	maxCredSSPSize        = 64 << 10
	maxCredSSPDepth       = 12
	maxCredSSPRounds      = 4
	maxCookieUser         = 128

	x224CodeConnReq     byte = 0xE0
	x224CodeConnConfirm byte = 0xD0

	rdpNegReqType  byte = 0x01
	rdpNegRspType  byte = 0x02
	rdpNegFailType byte = 0x03

	rdpProtoRDP      uint32 = 0x00000000
	rdpProtoSSL      uint32 = 0x00000001
	rdpProtoHybrid   uint32 = 0x00000002
	rdpProtoHybridEx uint32 = 0x00000008

	rdpFailHybridRequired uint32 = 0x00000005

	// STATUS_LOGON_FAILURE (0xC000006D as signed 32-bit integer for ASN.1 INTEGER).
	ntStatusLogonFailure int64 = -1073741715
)

var (
	credSSPBERLimits = ber.Limits{MaxMessage: maxCredSSPSize, MaxDepth: maxCredSSPDepth}

	errRDPBadTPKT = errors.New("rdp: invalid TPKT frame")
	errRDPBadX224 = errors.New("rdp: invalid X.224 TPDU")
)

type x224ConnReq struct {
	CookieUser         string
	HasNegReq          bool
	RequestedProtocols uint32
}

// readTPKT reads one RFC 1006 TPKT frame and returns its payload (without the
// 4-byte TPKT header).
func readTPKT(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != tpktVersion || hdr[1] != 0x00 {
		return nil, errRDPBadTPKT
	}
	totalLen := int(binary.BigEndian.Uint16(hdr[2:4]))
	if totalLen < 4 || totalLen > maxTPKTSize {
		return nil, errRDPBadTPKT
	}
	payload := make([]byte, totalLen-4)
	if len(payload) > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
	}
	return payload, nil
}

// parseX224ConnReq parses an X.224 Connection Request TPDU, extracting the
// optional mstshash= cookie and RDP_NEG_REQ structure.
func parseX224ConnReq(tpdu []byte) (x224ConnReq, error) {
	if len(tpdu) < 7 {
		return x224ConnReq{}, errRDPBadX224
	}
	li := int(tpdu[0])
	if li < 6 || li+1 > len(tpdu) {
		return x224ConnReq{}, errRDPBadX224
	}
	if tpdu[1]&0xF0 != x224CodeConnReq {
		return x224ConnReq{}, errRDPBadX224
	}

	var req x224ConnReq
	variable := tpdu[7 : li+1]

	// Optional "Cookie: mstshash=<user>\r\n" prefix.
	if len(variable) >= 7 && strings.EqualFold(string(variable[:7]), "cookie:") {
		if crlf := bytes.Index(variable, []byte("\r\n")); crlf >= 0 {
			line := string(variable[:crlf])
			if idx := strings.Index(strings.ToLower(line), "mstshash="); idx >= 0 {
				user := strings.TrimSpace(line[idx+len("mstshash="):])
				req.CookieUser = decoy.Sanitize(user, maxCookieUser)
			}
			variable = variable[crlf+2:]
		}
	}

	// Optional RDP_NEG_REQ (8 bytes: type=0x01, flags, length=8 LE, requestedProtocols LE).
	if len(variable) >= 8 && variable[0] == rdpNegReqType {
		negLen := binary.LittleEndian.Uint16(variable[2:4])
		if negLen == 8 {
			req.HasNegReq = true
			req.RequestedProtocols = binary.LittleEndian.Uint32(variable[4:8])
		}
	}

	return req, nil
}

func buildX224ConnConfirm(selectedProto uint32) []byte {
	// 4-byte TPKT + 7-byte X.224 CC + 8-byte RDP_NEG_RSP = 19 bytes.
	out := make([]byte, 19)
	out[0] = tpktVersion
	out[1] = 0x00
	binary.BigEndian.PutUint16(out[2:4], 19)
	out[4] = 14 // X.224 LI = 6 + 8
	out[5] = x224CodeConnConfirm
	// dstRef (2), srcRef (2), classOption (1) = 0
	out[11] = rdpNegRspType
	out[12] = 0x00
	binary.LittleEndian.PutUint16(out[13:15], 8)
	binary.LittleEndian.PutUint32(out[15:19], selectedProto)
	return out
}

func buildX224NegFailure(failureCode uint32) []byte {
	// 4-byte TPKT + 7-byte X.224 CC + 8-byte RDP_NEG_FAILURE = 19 bytes.
	out := make([]byte, 19)
	out[0] = tpktVersion
	out[1] = 0x00
	binary.BigEndian.PutUint16(out[2:4], 19)
	out[4] = 14 // X.224 LI = 6 + 8
	out[5] = x224CodeConnConfirm
	out[11] = rdpNegFailType
	out[12] = 0x00
	binary.LittleEndian.PutUint16(out[13:15], 8)
	binary.LittleEndian.PutUint32(out[15:19], failureCode)
	return out
}

type tsRequest struct {
	Version    int64
	NegoTokens [][]byte
}

// parseTSRequest decodes a CredSSP TSRequest (MS-CSSP §2.2.1) using sdk/go/ber.
func parseTSRequest(raw []byte) (tsRequest, error) {
	rd, err := ber.NewReader(raw, credSSPBERLimits)
	if err != nil {
		return tsRequest{}, err
	}
	seq, err := rd.Expect(ber.Universal, ber.TagSequence)
	if err != nil {
		return tsRequest{}, err
	}
	ch, err := seq.Children()
	if err != nil {
		return tsRequest{}, err
	}

	var req tsRequest
	for ch.Len() > 0 {
		el, err := ch.Next()
		if err != nil {
			return tsRequest{}, err
		}
		if el.Class != ber.ContextSpecific || !el.Constructed {
			continue
		}
		switch el.Number {
		case 0: // version [0] INTEGER
			fch, err := el.Children()
			if err != nil {
				return tsRequest{}, err
			}
			verEl, err := fch.Expect(ber.Universal, ber.TagInteger)
			if err != nil {
				return tsRequest{}, err
			}
			v, err := verEl.Int()
			if err != nil {
				return tsRequest{}, err
			}
			req.Version = v
		case 1: // negoTokens [1] NegoData (SEQUENCE OF SEQUENCE { [0] OCTET STRING })
			fch, err := el.Children()
			if err != nil {
				return tsRequest{}, err
			}
			outerSeq, err := fch.Expect(ber.Universal, ber.TagSequence)
			if err != nil {
				return tsRequest{}, err
			}
			items, err := outerSeq.Children()
			if err != nil {
				return tsRequest{}, err
			}
			for items.Len() > 0 && len(req.NegoTokens) < 4 {
				itemSeq, err := items.Expect(ber.Universal, ber.TagSequence)
				if err != nil {
					return tsRequest{}, err
				}
				ich, err := itemSeq.Children()
				if err != nil {
					return tsRequest{}, err
				}
				tokWrap, err := ich.Expect(ber.ContextSpecific, 0)
				if err != nil {
					return tsRequest{}, err
				}
				tch, err := tokWrap.Children()
				if err != nil {
					return tsRequest{}, err
				}
				osEl, err := tch.Expect(ber.Universal, ber.TagOctetString)
				if err != nil {
					return tsRequest{}, err
				}
				req.NegoTokens = append(req.NegoTokens, append([]byte(nil), osEl.Value...))
			}
		}
	}
	return req, nil
}

func buildTSRequestNego(version int64, token []byte) []byte {
	verField := ber.Encode(ber.ContextSpecific, true, 0, ber.Integer(version))
	tokItem := ber.Sequence(ber.Encode(ber.ContextSpecific, true, 0, ber.OctetString(token)))
	negoData := ber.Encode(ber.ContextSpecific, true, 1, ber.Sequence(tokItem))
	return ber.Sequence(verField, negoData)
}

func buildTSRequestError(version, errCode int64) []byte {
	verField := ber.Encode(ber.ContextSpecific, true, 0, ber.Integer(version))
	errField := ber.Encode(ber.ContextSpecific, true, 4, ber.Integer(errCode))
	return ber.Sequence(verField, errField)
}

func (d *Decoy) handleRDP(ctx context.Context, raw net.Conn, port int) {
	defer raw.Close()

	ip := decoy.RemoteIP(raw.RemoteAddr())
	bc := newBoundedConn(raw, d.idleTimeout, d.totalTimeout)

	emitted := false
	cookieUser := ""
	nlaOffered := false

	defer func() {
		if !emitted {
			d.emitRDPConnection(ip, port, cookieUser, nlaOffered)
		}
	}()

	// Step 1: X.224 Connection Request inside TPKT.
	tpdu, err := readTPKT(bc)
	if err != nil {
		return
	}
	cr, err := parseX224ConnReq(tpdu)
	if err != nil {
		return
	}
	cookieUser = cr.CookieUser
	nlaOffered = cr.HasNegReq && (cr.RequestedProtocols&rdpProtoHybrid != 0)

	if !nlaOffered {
		_, _ = bc.Write(buildX224NegFailure(rdpFailHybridRequired))
		return
	}

	// Step 2: X.224 Connection Confirm selecting TLS + CredSSP (PROTOCOL_HYBRID).
	if _, err := bc.Write(buildX224ConnConfirm(rdpProtoHybrid)); err != nil {
		return
	}

	// Step 3: Upgrade connection to TLS using the ephemeral persona cert.
	tlsConn := tls.Server(bc, d.tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return
	}

	// Step 4: CredSSP TSRequest loop carrying MS-NLMP (raw or SPNEGO-wrapped).
	var pendingChallenge [8]byte
	haveChallenge := false

	for round := 0; round < maxCredSSPRounds; round++ {
		if ctx.Err() != nil {
			return
		}
		rawReq, err := readBERSequence(tlsConn, maxCredSSPSize)
		if err != nil {
			return
		}
		tsReq, err := parseTSRequest(rawReq)
		if err != nil {
			return
		}
		if len(tsReq.NegoTokens) == 0 {
			return
		}

		ver := tsReq.Version
		if ver <= 0 || ver > 6 {
			ver = 6
		}

		ntlmBytes, spnego, err := unwrapNTLMToken(tsReq.NegoTokens[0])
		if err != nil {
			_, _ = tlsConn.Write(buildTSRequestError(ver, ntStatusLogonFailure))
			return
		}
		mt, err := ntlmMessageType(ntlmBytes)
		if err != nil {
			_, _ = tlsConn.Write(buildTSRequestError(ver, ntStatusLogonFailure))
			return
		}

		switch mt {
		case ntlmTypeNegotiate:
			if _, err := parseNTLMType1(ntlmBytes); err != nil {
				return
			}
			ch, err := randomNTLMChallenge()
			if err != nil {
				return
			}
			pendingChallenge = ch
			haveChallenge = true
			type2 := buildNTLMType2(d.cfg.Persona, ch, d.now())
			replyTok := type2
			if spnego {
				replyTok = wrapSPNEGOChallenge(type2)
			}
			if _, err := tlsConn.Write(buildTSRequestNego(ver, replyTok)); err != nil {
				return
			}

		case ntlmTypeAuthenticate:
			auth, err := parseNTLMType3(ntlmBytes)
			if err != nil {
				return
			}
			emitted = true
			d.emitRDPLogin(ip, port, cookieUser, auth, pendingChallenge, haveChallenge)
			if !d.pause(ctx, 150*time.Millisecond, 400*time.Millisecond) {
				return
			}
			_, _ = tlsConn.Write(buildTSRequestError(ver, ntStatusLogonFailure))
			return

		default:
			_, _ = tlsConn.Write(buildTSRequestError(ver, ntStatusLogonFailure))
			return
		}
	}
}

func (d *Decoy) emitRDPLogin(ip string, port int, cookieUser string, auth NTLMAuthenticate, challenge [8]byte, haveChallenge bool) {
	ok, suppressed := d.allowLogin(ip, "rdp")
	if !ok {
		return
	}
	user := auth.Username
	if user == "" {
		user = cookieUser
	}
	fields := sensor.Fields{
		sensor.F("protocol", "rdp"),
		sensor.F("dst_port", port),
		sensor.F("auth", "credssp_ntlm"),
		sensor.F("username", user),
	}
	if auth.Domain != "" {
		fields = append(fields, sensor.F("domain", auth.Domain))
	}
	if auth.Workstation != "" {
		fields = append(fields, sensor.F("workstation", auth.Workstation))
	}
	if cookieUser != "" {
		fields = append(fields, sensor.F("cookie_user", cookieUser))
	}
	if haveChallenge {
		fields = append(fields, sensor.F("ntlm_challenge", hex.EncodeToString(challenge[:])))
	}
	fields = append(fields, d.capture.Secret("ntlm_response", hex.EncodeToString(auth.NTResponse))...)
	if suppressed > 0 {
		fields = append(fields, sensor.F("suppressed_since_last", suppressed))
	}
	d.r.ReportSeverity(sensor.SeverityHigh, TriggerRDPLogin, ip, fmt.Sprintf("RDP port %d", port), fields)
}

func (d *Decoy) emitRDPConnection(ip string, port int, cookieUser string, nlaOffered bool) {
	ok, suppressed := d.allowConn(ip, "rdp")
	if !ok {
		return
	}
	fields := sensor.Fields{
		sensor.F("protocol", "rdp"),
		sensor.F("dst_port", port),
		sensor.F("nla_offered", nlaOffered),
	}
	if cookieUser != "" {
		fields = append(fields, sensor.F("username", cookieUser), sensor.F("cookie_user", cookieUser))
	}
	if suppressed > 0 {
		fields = append(fields, sensor.F("suppressed_since_last", suppressed))
	}
	d.r.ReportSeverity(sensor.SeverityMedium, TriggerRDPConnection, ip, fmt.Sprintf("RDP port %d", port), fields)
}
