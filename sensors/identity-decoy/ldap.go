// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"context"
	"crypto/tls"
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

const (
	maxLDAPMessageSize = 64 << 10
	maxLDAPDepth       = 16
	maxLDAPMessages    = 64
	maxLDAPFilterLen   = 256
	maxLDAPStringLen   = 256

	ldapOpBindRequest      uint32 = 0
	ldapOpBindResponse     uint32 = 1
	ldapOpUnbindRequest    uint32 = 2
	ldapOpSearchRequest    uint32 = 3
	ldapOpSearchEntry      uint32 = 4
	ldapOpSearchDone       uint32 = 5
	ldapOpModifyRequest    uint32 = 6
	ldapOpAddRequest       uint32 = 8
	ldapOpDelRequest       uint32 = 10
	ldapOpModifyDNRequest  uint32 = 12
	ldapOpCompareRequest   uint32 = 14
	ldapOpAbandonRequest   uint32 = 16
	ldapOpExtendedRequest  uint32 = 23
	ldapOpExtendedResponse uint32 = 24

	ldapResultSuccess              int64 = 0
	ldapResultAuthMethodNotSupport int64 = 7
	ldapResultSASLBindInProgress   int64 = 14
	ldapResultInvalidCredentials   int64 = 49
	ldapResultUnavailable          int64 = 52
	ldapResultUnwillingToPerform   int64 = 53

	adInvalidCredentialsDiag = "80090308: LdapErr: DSID-0C090447, comment: AcceptSecurityContext error, data 52e, v4563"
)

var (
	ldapBERLimits = ber.Limits{MaxMessage: maxLDAPMessageSize, MaxDepth: maxLDAPDepth}

	errLDAPBadFrame = errors.New("ldap: invalid BER frame")
)

// readBERSequence reads a single definite-length BER/DER SEQUENCE TLV from r,
// validating the total size against maxSize before allocating the payload.
// The returned slice contains the full TLV (tag + length + value) for strict
// decoding with sdk/go/ber.
func readBERSequence(r io.Reader, maxSize int) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0x30 { // Universal Constructed SEQUENCE
		return nil, errLDAPBadFrame
	}

	lb := hdr[1]
	var lenOctets []byte
	var bodyLen int
	switch {
	case lb < 0x80:
		bodyLen = int(lb)
	case lb == 0x80:
		return nil, ber.ErrIndefinite
	case lb == 0xff:
		return nil, ber.ErrLength
	default:
		nb := int(lb & 0x7f)
		if nb > 4 {
			return nil, ber.ErrLength
		}
		lenOctets = make([]byte, nb)
		if _, err := io.ReadFull(r, lenOctets); err != nil {
			return nil, err
		}
		var v uint64
		for _, c := range lenOctets {
			v = v<<8 | uint64(c)
		}
		if v > uint64(maxSize) {
			return nil, ber.ErrTooLarge
		}
		bodyLen = int(v)
	}

	hdrLen := 2 + len(lenOctets)
	if hdrLen+bodyLen > maxSize {
		return nil, ber.ErrTooLarge
	}

	buf := make([]byte, hdrLen+bodyLen)
	buf[0] = hdr[0]
	buf[1] = hdr[1]
	copy(buf[2:], lenOctets)
	if bodyLen > 0 {
		if _, err := io.ReadFull(r, buf[hdrLen:]); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

type ldapAuthKind int

const (
	ldapAuthUnknown ldapAuthKind = iota
	ldapAuthSimple
	ldapAuthSASL
	ldapAuthSicilyDiscovery
	ldapAuthSicilyNegotiate
	ldapAuthSicilyResponse
)

type ldapBindReq struct {
	Version  int64
	BindDN   string
	AuthKind ldapAuthKind
	Password []byte
	SASLMech string
	Creds    []byte
}

type ldapSearchReq struct {
	BaseDN string
	Scope  int64
	Filter string
}

type ldapMessage struct {
	MessageID int64
	Op        uint32
	Bind      *ldapBindReq
	Search    *ldapSearchReq
}

// parseLDAPMessage decodes one RFC 4511 LDAPMessage using sdk/go/ber.
func parseLDAPMessage(raw []byte) (ldapMessage, error) {
	rd, err := ber.NewReader(raw, ldapBERLimits)
	if err != nil {
		return ldapMessage{}, err
	}
	seq, err := rd.Expect(ber.Universal, ber.TagSequence)
	if err != nil {
		return ldapMessage{}, err
	}
	ch, err := seq.Children()
	if err != nil {
		return ldapMessage{}, err
	}
	idEl, err := ch.Expect(ber.Universal, ber.TagInteger)
	if err != nil {
		return ldapMessage{}, err
	}
	msgID, err := idEl.Int()
	if err != nil {
		return ldapMessage{}, err
	}
	opEl, err := ch.Next()
	if err != nil {
		return ldapMessage{}, err
	}
	if opEl.Class != ber.Application {
		return ldapMessage{}, ber.ErrType
	}

	msg := ldapMessage{
		MessageID: msgID,
		Op:        opEl.Number,
	}

	switch opEl.Number {
	case ldapOpBindRequest:
		b, err := parseLDAPBindRequest(opEl)
		if err != nil {
			return ldapMessage{}, err
		}
		msg.Bind = b
	case ldapOpSearchRequest:
		s, err := parseLDAPSearchRequest(opEl)
		if err != nil {
			return ldapMessage{}, err
		}
		msg.Search = s
	}
	return msg, nil
}

func parseLDAPBindRequest(el ber.Element) (*ldapBindReq, error) {
	ch, err := el.Children()
	if err != nil {
		return nil, err
	}
	verEl, err := ch.Expect(ber.Universal, ber.TagInteger)
	if err != nil {
		return nil, err
	}
	ver, err := verEl.Int()
	if err != nil {
		return nil, err
	}
	dnEl, err := ch.Expect(ber.Universal, ber.TagOctetString)
	if err != nil {
		return nil, err
	}
	authEl, err := ch.Next()
	if err != nil {
		return nil, err
	}

	req := &ldapBindReq{
		Version: ver,
		BindDN:  string(dnEl.Value),
	}

	if authEl.Class != ber.ContextSpecific {
		return nil, ber.ErrType
	}
	switch authEl.Number {
	case 0: // simple [0] OCTET STRING
		req.AuthKind = ldapAuthSimple
		req.Password = append([]byte(nil), authEl.Value...)
	case 3: // sasl [3] SaslCredentials
		req.AuthKind = ldapAuthSASL
		sch, err := authEl.Children()
		if err != nil {
			return nil, err
		}
		mechEl, err := sch.Expect(ber.Universal, ber.TagOctetString)
		if err != nil {
			return nil, err
		}
		req.SASLMech = string(mechEl.Value)
		if sch.Len() > 0 {
			credEl, err := sch.Expect(ber.Universal, ber.TagOctetString)
			if err != nil {
				return nil, err
			}
			req.Creds = append([]byte(nil), credEl.Value...)
		}
	case 9: // Sicily package discovery [9]
		req.AuthKind = ldapAuthSicilyDiscovery
	case 10: // Sicily negotiate [10]
		req.AuthKind = ldapAuthSicilyNegotiate
		req.Creds = append([]byte(nil), authEl.Value...)
	case 11: // Sicily response [11]
		req.AuthKind = ldapAuthSicilyResponse
		req.Creds = append([]byte(nil), authEl.Value...)
	default:
		req.AuthKind = ldapAuthUnknown
	}
	return req, nil
}

func parseLDAPSearchRequest(el ber.Element) (*ldapSearchReq, error) {
	ch, err := el.Children()
	if err != nil {
		return nil, err
	}
	baseEl, err := ch.Expect(ber.Universal, ber.TagOctetString)
	if err != nil {
		return nil, err
	}
	scopeEl, err := ch.Expect(ber.Universal, ber.TagEnumerated)
	if err != nil {
		return nil, err
	}
	scope, err := scopeEl.Int()
	if err != nil {
		return nil, err
	}
	// derefAliases (ENUMERATED), sizeLimit (INTEGER), timeLimit (INTEGER), typesOnly (BOOLEAN)
	if _, err := ch.Expect(ber.Universal, ber.TagEnumerated); err != nil {
		return nil, err
	}
	if _, err := ch.Expect(ber.Universal, ber.TagInteger); err != nil {
		return nil, err
	}
	if _, err := ch.Expect(ber.Universal, ber.TagInteger); err != nil {
		return nil, err
	}
	if _, err := ch.Expect(ber.Universal, ber.TagBoolean); err != nil {
		return nil, err
	}
	filterEl, err := ch.Next()
	if err != nil {
		return nil, err
	}
	var sb strings.Builder
	renderLDAPFilter(filterEl, &sb, maxLDAPFilterLen)

	return &ldapSearchReq{
		BaseDN: decoy.Sanitize(string(baseEl.Value), maxLDAPStringLen),
		Scope:  scope,
		Filter: decoy.Sanitize(sb.String(), maxLDAPFilterLen),
	}, nil
}

func renderLDAPFilter(el ber.Element, sb *strings.Builder, limit int) {
	if sb.Len() >= limit || el.Class != ber.ContextSpecific {
		return
	}
	writeLimited := func(s string) {
		rem := limit - sb.Len()
		if rem <= 0 {
			return
		}
		if len(s) > rem {
			s = s[:rem]
		}
		sb.WriteString(s)
	}

	switch el.Number {
	case 0, 1: // AND, OR
		op := "&"
		if el.Number == 1 {
			op = "|"
		}
		ch, err := el.Children()
		if err != nil {
			return
		}
		writeLimited("(" + op)
		for ch.Len() > 0 && sb.Len() < limit {
			sub, err := ch.Next()
			if err != nil {
				break
			}
			renderLDAPFilter(sub, sb, limit)
		}
		writeLimited(")")
	case 2: // NOT
		ch, err := el.Children()
		if err != nil {
			return
		}
		sub, err := ch.Next()
		if err != nil {
			return
		}
		writeLimited("(!")
		renderLDAPFilter(sub, sb, limit)
		writeLimited(")")
	case 3, 5, 6, 8: // equalityMatch, greaterOrEqual, lessOrEqual, approxMatch
		op := "="
		switch el.Number {
		case 5:
			op = ">="
		case 6:
			op = "<="
		case 8:
			op = "~="
		}
		ch, err := el.Children()
		if err != nil {
			return
		}
		attr, err := ch.Expect(ber.Universal, ber.TagOctetString)
		if err != nil {
			return
		}
		val, err := ch.Expect(ber.Universal, ber.TagOctetString)
		if err != nil {
			return
		}
		writeLimited("(" + decoy.Sanitize(string(attr.Value), 64) + op + decoy.Sanitize(string(val.Value), 128) + ")")
	case 4: // substrings
		ch, err := el.Children()
		if err != nil {
			return
		}
		attr, err := ch.Expect(ber.Universal, ber.TagOctetString)
		if err != nil {
			return
		}
		seq, err := ch.Expect(ber.Universal, ber.TagSequence)
		if err != nil {
			return
		}
		subs, err := seq.Children()
		if err != nil {
			return
		}
		writeLimited("(" + decoy.Sanitize(string(attr.Value), 64) + "=")
		first := true
		for subs.Len() > 0 && sb.Len() < limit {
			part, err := subs.Next()
			if err != nil {
				break
			}
			if part.Class != ber.ContextSpecific {
				continue
			}
			val := decoy.Sanitize(string(part.Value), 64)
			switch part.Number {
			case 0: // initial
				writeLimited(val + "*")
			case 1: // any
				if first {
					writeLimited("*")
				}
				writeLimited(val + "*")
			case 2: // final
				if first {
					writeLimited("*")
				}
				writeLimited(val)
			}
			first = false
		}
		writeLimited(")")
	case 7: // present
		writeLimited("(" + decoy.Sanitize(string(el.Value), 64) + "=*)")
	case 9: // extensibleMatch
		writeLimited("(extensible)")
	}
}

func ldapScopeName(scope int64) string {
	switch scope {
	case 0:
		return "base"
	case 1:
		return "one"
	case 2:
		return "sub"
	default:
		return "unknown"
	}
}

// deriveLDAPUsername extracts a user name (and optional domain) from an LDAP
// bind DN, UPN (user@domain), or down-level logon name (DOMAIN\user).
func deriveLDAPUsername(bindDN string) (username, domain string) {
	dn := strings.TrimSpace(bindDN)
	if dn == "" {
		return "", ""
	}
	if dom, usr, ok := strings.Cut(dn, `\`); ok && usr != "" {
		return decoy.Sanitize(usr, maxLDAPStringLen), decoy.Sanitize(dom, maxLDAPStringLen)
	}
	if !strings.Contains(dn, "=") {
		if usr, dom, ok := strings.Cut(dn, "@"); ok && usr != "" {
			return decoy.Sanitize(usr, maxLDAPStringLen), decoy.Sanitize(dom, maxLDAPStringLen)
		}
		return decoy.Sanitize(dn, maxLDAPStringLen), ""
	}

	var dcParts []string
	var foundUser string
	for _, rdn := range strings.Split(dn, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(rdn), "=")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		switch key {
		case "cn", "uid", "samaccountname":
			if foundUser == "" && val != "" {
				foundUser = val
			}
		case "dc":
			if val != "" {
				dcParts = append(dcParts, val)
			}
		}
	}
	if foundUser == "" {
		foundUser = dn
	}
	return decoy.Sanitize(foundUser, maxLDAPStringLen), decoy.Sanitize(strings.Join(dcParts, "."), maxLDAPStringLen)
}

func encodeLDAPMessage(msgID int64, op []byte) []byte {
	return ber.Sequence(ber.Integer(msgID), op)
}

func encodeLDAPBindResponse(msgID, resultCode int64, matchedDN, diag string, serverSaslCreds []byte) []byte {
	parts := [][]byte{
		ber.Enumerated(resultCode),
		ber.OctetString([]byte(matchedDN)),
		ber.OctetString([]byte(diag)),
	}
	if len(serverSaslCreds) > 0 {
		parts = append(parts, ber.Encode(ber.ContextSpecific, false, 7, serverSaslCreds))
	}
	return encodeLDAPMessage(msgID, ber.Encode(ber.Application, true, ldapOpBindResponse, ber.Cat(parts...)))
}

func encodeLDAPSicilyResponse(msgID, resultCode int64, serverCreds []byte, errMsg string) []byte {
	body := ber.Cat(
		ber.Enumerated(resultCode),
		ber.OctetString(serverCreds),
		ber.OctetString([]byte(errMsg)),
	)
	return encodeLDAPMessage(msgID, ber.Encode(ber.Application, true, ldapOpBindResponse, body))
}

func encodeLDAPSearchDone(msgID, resultCode int64) []byte {
	body := ber.Cat(
		ber.Enumerated(resultCode),
		ber.OctetString(nil),
		ber.OctetString(nil),
	)
	return encodeLDAPMessage(msgID, ber.Encode(ber.Application, true, ldapOpSearchDone, body))
}

func encodeLDAPRootDSEEntry(msgID int64, p Persona) []byte {
	defaultNC := p.DefaultNamingContext()
	configNC := "CN=Configuration," + defaultNC
	schemaNC := "CN=Schema," + configNC
	fqdn := p.FQDN()
	hostUpper := strings.ToUpper(p.Hostname)
	domLower := strings.ToLower(p.DomainDNS)
	domUpper := strings.ToUpper(p.DomainDNS)

	type attr struct {
		name string
		vals []string
	}
	attrs := []attr{
		{"defaultNamingContext", []string{defaultNC}},
		{"rootDomainNamingContext", []string{defaultNC}},
		{"configurationNamingContext", []string{configNC}},
		{"schemaNamingContext", []string{schemaNC}},
		{"namingContexts", []string{defaultNC, configNC, schemaNC}},
		{"dnsHostName", []string{fqdn}},
		{"serverName", []string{"CN=" + hostUpper + ",CN=Servers,CN=Default-First-Site-Name,CN=Sites," + configNC}},
		{"ldapServiceName", []string{domLower + ":" + strings.ToLower(p.Hostname) + "$@" + domUpper}},
		{"supportedLDAPVersion", []string{"3", "2"}},
		{"supportedSASLMechanisms", []string{"GSSAPI", "GSS-SPNEGO", "EXTERNAL", "DIGEST-MD5"}},
		{"supportedControl", []string{"1.2.840.113556.1.4.319", "1.2.840.113556.1.4.801", "1.2.840.113556.1.4.473"}},
		{"domainFunctionality", []string{"7"}},
		{"forestFunctionality", []string{"7"}},
		{"domainControllerFunctionality", []string{"7"}},
		{"isGlobalCatalogReady", []string{"TRUE"}},
		{"isSynchronized", []string{"TRUE"}},
	}

	encodedAttrs := make([][]byte, 0, len(attrs))
	for _, a := range attrs {
		valEls := make([][]byte, 0, len(a.vals))
		for _, v := range a.vals {
			valEls = append(valEls, ber.OctetString([]byte(v)))
		}
		set := ber.Encode(ber.Universal, true, ber.TagSet, ber.Cat(valEls...))
		encodedAttrs = append(encodedAttrs, ber.Sequence(ber.OctetString([]byte(a.name)), set))
	}

	entryBody := ber.Cat(
		ber.OctetString(nil), // RootDSE objectName is ""
		ber.Sequence(encodedAttrs...),
	)
	return encodeLDAPMessage(msgID, ber.Encode(ber.Application, true, ldapOpSearchEntry, entryBody))
}

func encodeLDAPResultOp(msgID int64, respTag uint32, resultCode int64, diag string) []byte {
	body := ber.Cat(
		ber.Enumerated(resultCode),
		ber.OctetString(nil),
		ber.OctetString([]byte(diag)),
	)
	return encodeLDAPMessage(msgID, ber.Encode(ber.Application, true, respTag, body))
}

func (d *Decoy) handleLDAP(ctx context.Context, raw net.Conn, port int, useTLS bool) {
	defer raw.Close()

	ip := decoy.RemoteIP(raw.RemoteAddr())
	bc := newBoundedConn(raw, d.idleTimeout, d.totalTimeout)

	proto := "ldap"
	loginTrigger := TriggerLDAPLogin
	queryTrigger := TriggerLDAPQuery
	connTrigger := TriggerLDAPConnection
	if useTLS {
		proto = "ldaps"
		loginTrigger = TriggerLDAPSLogin
		queryTrigger = TriggerLDAPSQuery
		connTrigger = TriggerLDAPSConnection
	}

	var conn net.Conn = bc
	if useTLS {
		tlsConn := tls.Server(bc, d.tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			d.emitLDAPConnection(ip, port, proto, connTrigger)
			return
		}
		conn = tlsConn
	}

	emitted := false
	defer func() {
		if !emitted {
			d.emitLDAPConnection(ip, port, proto, connTrigger)
		}
	}()

	var pendingChallenge [8]byte
	haveChallenge := false
	usedSPNEGO := false

	for i := 0; i < maxLDAPMessages; i++ {
		if ctx.Err() != nil {
			return
		}
		frame, err := readBERSequence(conn, maxLDAPMessageSize)
		if err != nil {
			return
		}
		msg, err := parseLDAPMessage(frame)
		if err != nil {
			return
		}

		switch msg.Op {
		case ldapOpUnbindRequest:
			return

		case ldapOpAbandonRequest:
			continue

		case ldapOpExtendedRequest:
			// StartTLS and all other extended operations are out of scope -> unavailable (52).
			if _, err := conn.Write(encodeLDAPResultOp(msg.MessageID, ldapOpExtendedResponse, ldapResultUnavailable, "operation unavailable")); err != nil {
				return
			}

		case ldapOpSearchRequest:
			s := msg.Search
			emitted = true
			d.emitLDAPQuery(ip, port, proto, queryTrigger, s)
			if s.BaseDN == "" && s.Scope == 0 {
				if _, err := conn.Write(encodeLDAPRootDSEEntry(msg.MessageID, d.cfg.Persona)); err != nil {
					return
				}
			}
			if _, err := conn.Write(encodeLDAPSearchDone(msg.MessageID, ldapResultSuccess)); err != nil {
				return
			}

		case ldapOpBindRequest:
			b := msg.Bind
			switch b.AuthKind {
			case ldapAuthSimple:
				if b.BindDN == "" && len(b.Password) == 0 {
					// Anonymous bind: succeed and report nothing until a search arrives.
					if _, err := conn.Write(encodeLDAPBindResponse(msg.MessageID, ldapResultSuccess, "", "", nil)); err != nil {
						return
					}
					continue
				}
				emitted = true
				pw := string(b.Password)
				clear(b.Password)
				user, dom := deriveLDAPUsername(b.BindDN)
				d.emitLDAPSimpleLogin(ip, port, proto, loginTrigger, b.BindDN, user, dom, pw)
				if !d.pause(ctx, 150*time.Millisecond, 400*time.Millisecond) {
					return
				}
				if _, err := conn.Write(encodeLDAPBindResponse(msg.MessageID, ldapResultInvalidCredentials, "", adInvalidCredentialsDiag, nil)); err != nil {
					return
				}

			case ldapAuthSASL:
				mech := decoy.Sanitize(b.SASLMech, 64)
				ntlmBytes, spnego, err := unwrapNTLMToken(b.Creds)
				if err != nil {
					if _, err := conn.Write(encodeLDAPBindResponse(msg.MessageID, ldapResultAuthMethodNotSupport, "", "authentication method not supported", nil)); err != nil {
						return
					}
					continue
				}
				mt, err := ntlmMessageType(ntlmBytes)
				if err != nil {
					if _, err := conn.Write(encodeLDAPBindResponse(msg.MessageID, ldapResultInvalidCredentials, "", adInvalidCredentialsDiag, nil)); err != nil {
						return
					}
					continue
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
					usedSPNEGO = spnego
					type2 := buildNTLMType2(d.cfg.Persona, ch, d.now())
					replyCreds := type2
					if spnego {
						replyCreds = wrapSPNEGOChallenge(type2)
					}
					if _, err := conn.Write(encodeLDAPBindResponse(msg.MessageID, ldapResultSASLBindInProgress, "", "", replyCreds)); err != nil {
						return
					}
				case ntlmTypeAuthenticate:
					auth, err := parseNTLMType3(ntlmBytes)
					if err != nil {
						return
					}
					emitted = true
					d.emitLDAPNTLMLogin(ip, port, proto, loginTrigger, mech, auth, pendingChallenge, haveChallenge)
					haveChallenge = false
					if !d.pause(ctx, 150*time.Millisecond, 400*time.Millisecond) {
						return
					}
					if _, err := conn.Write(encodeLDAPBindResponse(msg.MessageID, ldapResultInvalidCredentials, "", adInvalidCredentialsDiag, nil)); err != nil {
						return
					}
				default:
					if _, err := conn.Write(encodeLDAPBindResponse(msg.MessageID, ldapResultInvalidCredentials, "", adInvalidCredentialsDiag, nil)); err != nil {
						return
					}
				}

			case ldapAuthSicilyDiscovery:
				if _, err := conn.Write(encodeLDAPSicilyResponse(msg.MessageID, ldapResultSuccess, []byte("NTLM"), "")); err != nil {
					return
				}

			case ldapAuthSicilyNegotiate:
				ntlmBytes, spnego, err := unwrapNTLMToken(b.Creds)
				if err != nil {
					if _, err := conn.Write(encodeLDAPSicilyResponse(msg.MessageID, ldapResultInvalidCredentials, nil, adInvalidCredentialsDiag)); err != nil {
						return
					}
					continue
				}
				if _, err := parseNTLMType1(ntlmBytes); err != nil {
					return
				}
				ch, err := randomNTLMChallenge()
				if err != nil {
					return
				}
				pendingChallenge = ch
				haveChallenge = true
				usedSPNEGO = spnego
				type2 := buildNTLMType2(d.cfg.Persona, ch, d.now())
				replyCreds := type2
				if usedSPNEGO {
					replyCreds = wrapSPNEGOChallenge(type2)
				}
				if _, err := conn.Write(encodeLDAPSicilyResponse(msg.MessageID, ldapResultSuccess, replyCreds, "")); err != nil {
					return
				}

			case ldapAuthSicilyResponse:
				ntlmBytes, _, err := unwrapNTLMToken(b.Creds)
				if err != nil {
					return
				}
				auth, err := parseNTLMType3(ntlmBytes)
				if err != nil {
					return
				}
				emitted = true
				d.emitLDAPNTLMLogin(ip, port, proto, loginTrigger, "SICILY-NTLM", auth, pendingChallenge, haveChallenge)
				haveChallenge = false
				if !d.pause(ctx, 150*time.Millisecond, 400*time.Millisecond) {
					return
				}
				if _, err := conn.Write(encodeLDAPSicilyResponse(msg.MessageID, ldapResultInvalidCredentials, nil, adInvalidCredentialsDiag)); err != nil {
					return
				}

			default:
				if _, err := conn.Write(encodeLDAPBindResponse(msg.MessageID, ldapResultAuthMethodNotSupport, "", "authentication method not supported", nil)); err != nil {
					return
				}
			}

		case ldapOpModifyRequest, ldapOpAddRequest, ldapOpDelRequest, ldapOpModifyDNRequest, ldapOpCompareRequest:
			if _, err := conn.Write(encodeLDAPResultOp(msg.MessageID, msg.Op+1, ldapResultUnwillingToPerform, "unwilling to perform")); err != nil {
				return
			}

		default:
			// Unknown operation: ignore per RFC 4511.
			return
		}
	}
}

func (d *Decoy) emitLDAPSimpleLogin(ip string, port int, proto, trigger, bindDN, user, dom, password string) {
	ok, suppressed := d.allowLogin(ip, proto)
	if !ok {
		return
	}
	fields := sensor.Fields{
		sensor.F("protocol", proto),
		sensor.F("dst_port", port),
		sensor.F("auth", "simple"),
		sensor.F("bind_dn", decoy.Sanitize(bindDN, maxLDAPStringLen)),
		sensor.F("username", user),
	}
	if dom != "" {
		fields = append(fields, sensor.F("domain", dom))
	}
	fields = append(fields, d.capture.Password(password)...)
	if suppressed > 0 {
		fields = append(fields, sensor.F("suppressed_since_last", suppressed))
	}
	d.r.ReportSeverity(sensor.SeverityHigh, trigger, ip, fmt.Sprintf("%s port %d", strings.ToUpper(proto), port), fields)
}

func (d *Decoy) emitLDAPNTLMLogin(ip string, port int, proto, trigger, mech string, auth NTLMAuthenticate, challenge [8]byte, haveChallenge bool) {
	ok, suppressed := d.allowLogin(ip, proto)
	if !ok {
		return
	}
	fields := sensor.Fields{
		sensor.F("protocol", proto),
		sensor.F("dst_port", port),
		sensor.F("auth", "ntlm"),
		sensor.F("username", auth.Username),
	}
	if mech != "" {
		fields = append(fields, sensor.F("sasl_mechanism", mech))
	}
	if auth.Domain != "" {
		fields = append(fields, sensor.F("domain", auth.Domain))
	}
	if auth.Workstation != "" {
		fields = append(fields, sensor.F("workstation", auth.Workstation))
	}
	if haveChallenge {
		fields = append(fields, sensor.F("ntlm_challenge", hex.EncodeToString(challenge[:])))
	}
	fields = append(fields, d.capture.Secret("ntlm_response", hex.EncodeToString(auth.NTResponse))...)
	if suppressed > 0 {
		fields = append(fields, sensor.F("suppressed_since_last", suppressed))
	}
	d.r.ReportSeverity(sensor.SeverityHigh, trigger, ip, fmt.Sprintf("%s port %d", strings.ToUpper(proto), port), fields)
}

func (d *Decoy) emitLDAPQuery(ip string, port int, proto, trigger string, s *ldapSearchReq) {
	ok, suppressed := d.allowLogin(ip, proto+"_query")
	if !ok {
		return
	}
	fields := sensor.Fields{
		sensor.F("protocol", proto),
		sensor.F("dst_port", port),
		sensor.F("base_dn", s.BaseDN),
		sensor.F("scope", ldapScopeName(s.Scope)),
		sensor.F("filter", s.Filter),
	}
	if suppressed > 0 {
		fields = append(fields, sensor.F("suppressed_since_last", suppressed))
	}
	d.r.ReportSeverity(sensor.SeverityMedium, trigger, ip, fmt.Sprintf("%s port %d", strings.ToUpper(proto), port), fields)
}

func (d *Decoy) emitLDAPConnection(ip string, port int, proto, trigger string) {
	ok, suppressed := d.allowConn(ip, proto)
	if !ok {
		return
	}
	fields := sensor.Fields{
		sensor.F("protocol", proto),
		sensor.F("dst_port", port),
	}
	if suppressed > 0 {
		fields = append(fields, sensor.F("suppressed_since_last", suppressed))
	}
	d.r.ReportSeverity(sensor.SeverityMedium, trigger, ip, fmt.Sprintf("%s port %d", strings.ToUpper(proto), port), fields)
}
