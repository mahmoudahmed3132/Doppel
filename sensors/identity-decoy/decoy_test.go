// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/ber"
	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

const testCaptureKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

type recordedEvent struct {
	Severity sensor.Severity
	Trigger  string
	Source   string
	Target   string
	Details  sensor.Fields
}

type fakeReporter struct {
	mu       sync.Mutex
	settings map[string]string
	events   []recordedEvent
}

func newFakeReporter(overrides map[string]string) *fakeReporter {
	s := map[string]string{
		"TS_PASSWORD_CAPTURE":   "hash",
		"TS_CAPTURE_KEY":        testCaptureKeyHex,
		"TS_EVENT_COOLDOWN_SEC": "0",
	}
	for k, v := range overrides {
		s[k] = v
	}
	return &fakeReporter{settings: s}
}

func (f *fakeReporter) ReportSeverity(sev sensor.Severity, trigger, source, target string, details sensor.Details) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fields, _ := details.(sensor.Fields)
	f.events = append(f.events, recordedEvent{
		Severity: sev,
		Trigger:  trigger,
		Source:   source,
		Target:   target,
		Details:  fields,
	})
}

func (f *fakeReporter) Setting(name string) (string, bool) {
	v, ok := f.settings[name]
	return v, ok
}

func (f *fakeReporter) waitEvents(t *testing.T, n int) []recordedEvent {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		got := len(f.events)
		if got >= n {
			out := append([]recordedEvent(nil), f.events...)
			f.mu.Unlock()
			return out
		}
		f.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	t.Fatalf("timed out waiting for %d events, got %d: %+v", n, len(f.events), f.events)
	return nil
}

func fieldMap(fields sensor.Fields) map[string]any {
	m := make(map[string]any, len(fields))
	for _, f := range fields {
		m[f.Key] = f.Value
	}
	return m
}

func expectedHMAC(value string) string {
	key, _ := hex.DecodeString(testCaptureKeyHex)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func newTestDecoy(t *testing.T, overrides map[string]string) (*Decoy, *fakeReporter) {
	t.Helper()
	rep := newFakeReporter(overrides)
	cfg, err := LoadSettings(rep)
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	d, err := NewDecoy(cfg, rep)
	if err != nil {
		t.Fatalf("NewDecoy: %v", err)
	}
	d.authDelay = func(_, _ time.Duration) time.Duration { return 0 }
	return d, rep
}

func TestEphemeralCert(t *testing.T) {
	now := time.Now()
	c1, err := generateEphemeralTLSConfig("DC01", "corp.local", now)
	if err != nil {
		t.Fatalf("generateEphemeralTLSConfig: %v", err)
	}
	c2, err := generateEphemeralTLSConfig("DC01", "corp.local", now)
	if err != nil {
		t.Fatalf("generateEphemeralTLSConfig #2: %v", err)
	}

	leaf1 := c1.Certificates[0].Leaf
	leaf2 := c2.Certificates[0].Leaf
	if leaf1 == nil || leaf2 == nil {
		t.Fatal("expected parsed leaf certificates")
	}
	if leaf1.Subject.CommonName != "dc01.corp.local" {
		t.Fatalf("CN = %q, want dc01.corp.local", leaf1.Subject.CommonName)
	}
	if _, ok := c1.Certificates[0].PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected ECDSA private key, got %T", c1.Certificates[0].PrivateKey)
	}
	if leaf1.SerialNumber.Cmp(leaf2.SerialNumber) == 0 {
		t.Fatal("expected distinct ephemeral serial numbers across generations")
	}
}

func TestLoadSettings(t *testing.T) {
	rep := newFakeReporter(nil)
	cfg, err := LoadSettings(rep)
	if err != nil {
		t.Fatalf("default LoadSettings failed: %v", err)
	}
	if !cfg.EnableLDAP || !cfg.EnableLDAPS || !cfg.EnableRDP {
		t.Fatalf("expected all 3 protocols enabled by default")
	}
	if cfg.Persona.FQDN() != "dc01.corp.local" {
		t.Fatalf("FQDN = %q, want dc01.corp.local", cfg.Persona.FQDN())
	}
	if cfg.Persona.DefaultNamingContext() != "DC=corp,DC=local" {
		t.Fatalf("DefaultNamingContext = %q", cfg.Persona.DefaultNamingContext())
	}

	// All disabled must fail.
	if _, err := LoadSettings(newFakeReporter(map[string]string{
		"TS_ENABLE_LDAP":  "false",
		"TS_ENABLE_LDAPS": "false",
		"TS_ENABLE_RDP":   "false",
	})); err == nil {
		t.Fatal("expected error when all protocols disabled")
	}

	// Duplicate ports must fail.
	if _, err := LoadSettings(newFakeReporter(map[string]string{
		"TS_LDAP_PORT":  "1389",
		"TS_LDAPS_PORT": "1389",
	})); err == nil {
		t.Fatal("expected error on duplicate ports")
	}

	// Invalid OS build must fail.
	if _, err := LoadSettings(newFakeReporter(map[string]string{
		"TS_OS_BUILD": "not-a-version",
	})); err == nil {
		t.Fatal("expected error on invalid TS_OS_BUILD")
	}
}

// Helper to build a valid NTLM Type 1 (NEGOTIATE) message.
func makeTestNTLMType1() []byte {
	msg := make([]byte, 32)
	copy(msg[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], ntlmTypeNegotiate)
	binary.LittleEndian.PutUint32(msg[12:16], ntlmFlagUnicode|ntlmFlagNTLM|ntlmFlagExtendedSessionSecurity)
	return msg
}

// Helper to build a valid NTLM Type 3 (AUTHENTICATE) message.
func makeTestNTLMType3(domain, user, workstation string, ntResp []byte, unicode bool) []byte {
	var domB, usrB, wsB []byte
	var flags uint32 = ntlmFlagNTLM | ntlmFlagExtendedSessionSecurity
	if unicode {
		flags |= ntlmFlagUnicode
		domB = encodeUTF16LE(domain)
		usrB = encodeUTF16LE(user)
		wsB = encodeUTF16LE(workstation)
	} else {
		domB = []byte(domain)
		usrB = []byte(user)
		wsB = []byte(workstation)
	}

	const hdrLen = 64
	off := uint32(hdrLen)
	putDesc := func(buf []byte, descOff int, data []byte) {
		binary.LittleEndian.PutUint16(buf[descOff:descOff+2], uint16(len(data)))
		binary.LittleEndian.PutUint16(buf[descOff+2:descOff+4], uint16(len(data)))
		binary.LittleEndian.PutUint32(buf[descOff+4:descOff+8], off)
		off += uint32(len(data))
	}

	total := hdrLen + len(ntResp) + len(domB) + len(usrB) + len(wsB)
	msg := make([]byte, total)
	copy(msg[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], ntlmTypeAuthenticate)
	// LM response empty (offset 12..20)
	off = hdrLen
	putDesc(msg, 20, ntResp)
	putDesc(msg, 28, domB)
	putDesc(msg, 36, usrB)
	putDesc(msg, 44, wsB)
	binary.LittleEndian.PutUint32(msg[60:64], flags)

	p := hdrLen
	copy(msg[p:], ntResp)
	p += len(ntResp)
	copy(msg[p:], domB)
	p += len(domB)
	copy(msg[p:], usrB)
	p += len(usrB)
	copy(msg[p:], wsB)
	return msg
}

func makeSPNEGONegTokenInit(ntlmToken []byte) []byte {
	mechTypes := ber.Encode(ber.ContextSpecific, true, 0, ber.Sequence(ber.OID(oidNTLMSSP)))
	mechToken := ber.Encode(ber.ContextSpecific, true, 2, ber.OctetString(ntlmToken))
	negTokenInit := ber.Encode(ber.ContextSpecific, true, 0, ber.Sequence(mechTypes, mechToken))
	return ber.Encode(ber.Application, true, 0, ber.Cat(ber.OID(oidSPNEGO), negTokenInit))
}

func makeSPNEGONegTokenResp(ntlmToken []byte) []byte {
	respToken := ber.Encode(ber.ContextSpecific, true, 2, ber.OctetString(ntlmToken))
	return ber.Encode(ber.ContextSpecific, true, 1, ber.Sequence(respToken))
}

func TestNTLMUnit(t *testing.T) {
	// Type 1
	t1 := makeTestNTLMType1()
	neg, err := parseNTLMType1(t1)
	if err != nil {
		t.Fatalf("parseNTLMType1: %v", err)
	}
	if neg.Flags&ntlmFlagUnicode == 0 {
		t.Fatal("expected Unicode flag")
	}

	// Type 2
	p := Persona{DomainDNS: "corp.local", DomainNetBIOS: "CORP", Hostname: "DC01", OS: OSVersion{10, 0, 20348}}
	ch := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	t2 := buildNTLMType2(p, ch, time.Unix(1700000000, 0))
	if mt, err := ntlmMessageType(t2); err != nil || mt != ntlmTypeChallenge {
		t.Fatalf("Type 2 messageType = %d, err = %v", mt, err)
	}
	if !bytes.Equal(t2[24:32], ch[:]) {
		t.Fatalf("challenge mismatch")
	}
	if t2[48] != 10 || t2[49] != 0 || binary.LittleEndian.Uint16(t2[50:52]) != 20348 {
		t.Fatalf("OS version mismatch in Type 2")
	}

	// Type 3 Unicode & OEM
	ntResp := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	t3u := makeTestNTLMType3("CORP", "alice", "WKSTN01", ntResp, true)
	auth, err := parseNTLMType3(t3u)
	if err != nil {
		t.Fatalf("parseNTLMType3 unicode: %v", err)
	}
	if auth.Domain != "CORP" || auth.Username != "alice" || auth.Workstation != "WKSTN01" || !bytes.Equal(auth.NTResponse, ntResp) {
		t.Fatalf("unexpected Type 3 unicode: %+v", auth)
	}

	t3o := makeTestNTLMType3("CORP", "bob", "WKSTN02", ntResp, false)
	authO, err := parseNTLMType3(t3o)
	if err != nil {
		t.Fatalf("parseNTLMType3 oem: %v", err)
	}
	if authO.Domain != "CORP" || authO.Username != "bob" || authO.Workstation != "WKSTN02" {
		t.Fatalf("unexpected Type 3 oem: %+v", authO)
	}

	// SPNEGO unwrap + wrap round-trip
	wrapped1 := makeSPNEGONegTokenInit(t1)
	unwrapped, isSPNEGO, err := unwrapNTLMToken(wrapped1)
	if err != nil || !isSPNEGO || !bytes.Equal(unwrapped, t1) {
		t.Fatalf("unwrap SPNEGO Type 1 failed: spnego=%v err=%v", isSPNEGO, err)
	}
	wrapped2 := wrapSPNEGOChallenge(t2)
	unwrapped2, isSPNEGO2, err := unwrapNTLMToken(wrapped2)
	if err != nil || !isSPNEGO2 || !bytes.Equal(unwrapped2, t2) {
		t.Fatalf("unwrap SPNEGO Type 2 failed: spnego=%v err=%v", isSPNEGO2, err)
	}

	// Malformed/truncated Type 3 with out-of-bounds offset must fail cleanly.
	bad := make([]byte, 64)
	copy(bad[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(bad[8:12], ntlmTypeAuthenticate)
	binary.LittleEndian.PutUint16(bad[36:38], 100) // len 100
	binary.LittleEndian.PutUint32(bad[40:44], 60)  // offset 60 -> out of bounds
	if _, err := parseNTLMType3(bad); err == nil {
		t.Fatal("expected error for out-of-bounds Type 3 field")
	}
}

func TestDeriveLDAPUsername(t *testing.T) {
	cases := []struct {
		dn   string
		user string
		dom  string
	}{
		{"CN=Administrator,CN=Users,DC=corp,DC=local", "Administrator", "corp.local"},
		{"uid=alice,ou=people,dc=example,dc=com", "alice", "example.com"},
		{"CORP\\jdoe", "jdoe", "CORP"},
		{"jdoe@corp.local", "jdoe", "corp.local"},
		{"plainuser", "plainuser", ""},
	}
	for _, tc := range cases {
		u, d := deriveLDAPUsername(tc.dn)
		if u != tc.user || d != tc.dom {
			t.Errorf("deriveLDAPUsername(%q) = (%q, %q), want (%q, %q)", tc.dn, u, d, tc.user, tc.dom)
		}
	}
}

// LDAP client frame helpers using sdk/go/ber.
func makeLDAPSimpleBind(msgID int64, dn, pw string) []byte {
	body := ber.Cat(
		ber.Integer(3),
		ber.OctetString([]byte(dn)),
		ber.Encode(ber.ContextSpecific, false, 0, []byte(pw)),
	)
	return encodeLDAPMessage(msgID, ber.Encode(ber.Application, true, ldapOpBindRequest, body))
}

func makeLDAPSASLBind(msgID int64, mech string, creds []byte) []byte {
	sasl := ber.Encode(ber.ContextSpecific, true, 3, ber.Cat(ber.OctetString([]byte(mech)), ber.OctetString(creds)))
	body := ber.Cat(ber.Integer(3), ber.OctetString(nil), sasl)
	return encodeLDAPMessage(msgID, ber.Encode(ber.Application, true, ldapOpBindRequest, body))
}

func makeLDAPSicilyBind(msgID int64, tag uint32, creds []byte) []byte {
	body := ber.Cat(ber.Integer(3), ber.OctetString(nil), ber.Encode(ber.ContextSpecific, false, tag, creds))
	return encodeLDAPMessage(msgID, ber.Encode(ber.Application, true, ldapOpBindRequest, body))
}

func makeLDAPSearchPresent(msgID int64, baseDN string, scope int64, attr string) []byte {
	body := ber.Cat(
		ber.OctetString([]byte(baseDN)),
		ber.Enumerated(scope),
		ber.Enumerated(0),
		ber.Integer(0),
		ber.Integer(0),
		ber.Boolean(false),
		ber.Encode(ber.ContextSpecific, false, 7, []byte(attr)),
		ber.Sequence(),
	)
	return encodeLDAPMessage(msgID, ber.Encode(ber.Application, true, ldapOpSearchRequest, body))
}

func decodeLDAPResponse(t *testing.T, r io.Reader) (msgID int64, op uint32, resultCode int64, matchedDN, diag string, saslCreds []byte) {
	t.Helper()
	raw, err := readBERSequence(r, maxLDAPMessageSize)
	if err != nil {
		t.Fatalf("readBERSequence: %v", err)
	}
	rd, err := ber.NewReader(raw, ldapBERLimits)
	if err != nil {
		t.Fatalf("ber.NewReader: %v", err)
	}
	seq, err := rd.Expect(ber.Universal, ber.TagSequence)
	if err != nil {
		t.Fatalf("expect sequence: %v", err)
	}
	ch, _ := seq.Children()
	idEl, _ := ch.Expect(ber.Universal, ber.TagInteger)
	msgID, _ = idEl.Int()
	opEl, err := ch.Next()
	if err != nil {
		t.Fatalf("next op: %v", err)
	}
	op = opEl.Number
	if op == ldapOpSearchEntry {
		return msgID, op, 0, "", string(opEl.Value), nil
	}
	och, err := opEl.Children()
	if err != nil {
		t.Fatalf("op children: %v", err)
	}
	rcEl, err := och.Expect(ber.Universal, ber.TagEnumerated)
	if err != nil {
		t.Fatalf("resultCode: %v", err)
	}
	resultCode, _ = rcEl.Int()
	mdnEl, _ := och.Expect(ber.Universal, ber.TagOctetString)
	matchedDN = string(mdnEl.Value)
	diagEl, _ := och.Expect(ber.Universal, ber.TagOctetString)
	diag = string(diagEl.Value)
	if och.Len() > 0 {
		if sc, err := och.Next(); err == nil && sc.Is(ber.ContextSpecific, 7) {
			saslCreds = sc.Value
		}
	}
	return msgID, op, resultCode, matchedDN, diag, saslCreds
}

func TestLDAPSimpleBindAndRootDSEE2E(t *testing.T) {
	d, rep := newTestDecoy(t, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.ServeLDAP(ctx, ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// 1. Anonymous bind -> success, no event emitted yet.
	if _, err := conn.Write(makeLDAPSimpleBind(1, "", "")); err != nil {
		t.Fatalf("write anon bind: %v", err)
	}
	_, op, rc, _, _, _ := decodeLDAPResponse(t, conn)
	if op != ldapOpBindResponse || rc != ldapResultSuccess {
		t.Fatalf("anon bind got op=%d rc=%d, want 1/0", op, rc)
	}

	// 2. RootDSE search -> SearchResultEntry + SearchResultDone + ldap_query event.
	if _, err := conn.Write(makeLDAPSearchPresent(2, "", 0, "objectClass")); err != nil {
		t.Fatalf("write RootDSE search: %v", err)
	}
	_, op1, _, _, rawEntry, _ := decodeLDAPResponse(t, conn)
	if op1 != ldapOpSearchEntry || !strings.Contains(rawEntry, "DC=corp,DC=local") || !strings.Contains(rawEntry, "dc01.corp.local") {
		t.Fatalf("unexpected RootDSE entry: op=%d", op1)
	}
	_, op2, rc2, _, _, _ := decodeLDAPResponse(t, conn)
	if op2 != ldapOpSearchDone || rc2 != ldapResultSuccess {
		t.Fatalf("SearchDone got op=%d rc=%d", op2, rc2)
	}

	// 3. Simple bind with credentials -> invalidCredentials (49) + AD diagnostic + ldap_login.
	if _, err := conn.Write(makeLDAPSimpleBind(3, "CN=Administrator,CN=Users,DC=corp,DC=local", "Winter2026!")); err != nil {
		t.Fatalf("write simple bind: %v", err)
	}
	_, op3, rc3, _, diag3, _ := decodeLDAPResponse(t, conn)
	if op3 != ldapOpBindResponse || rc3 != ldapResultInvalidCredentials {
		t.Fatalf("simple bind got op=%d rc=%d, want 1/49", op3, rc3)
	}
	if !strings.Contains(diag3, "80090308") || !strings.Contains(diag3, "data 52e") {
		t.Fatalf("expected AD diagnostic message, got %q", diag3)
	}

	// 4. StartTLS ExtendedRequest -> unavailable (52).
	startTLS := encodeLDAPMessage(4, ber.Encode(ber.Application, true, ldapOpExtendedRequest,
		ber.Encode(ber.ContextSpecific, false, 0, []byte("1.3.6.1.4.1.1466.20037"))))
	if _, err := conn.Write(startTLS); err != nil {
		t.Fatalf("write StartTLS: %v", err)
	}
	_, op4, rc4, _, _, _ := decodeLDAPResponse(t, conn)
	if op4 != ldapOpExtendedResponse || rc4 != ldapResultUnavailable {
		t.Fatalf("StartTLS got op=%d rc=%d, want 24/52", op4, rc4)
	}

	// 5. Unbind.
	_, _ = conn.Write(encodeLDAPMessage(5, ber.Encode(ber.Application, false, ldapOpUnbindRequest, nil)))
	_ = conn.Close()

	events := rep.waitEvents(t, 2)
	if events[0].Trigger != TriggerLDAPQuery {
		t.Fatalf("event[0].Trigger = %q, want %q", events[0].Trigger, TriggerLDAPQuery)
	}
	q := fieldMap(events[0].Details)
	if q["scope"] != "base" || q["filter"] != "(objectClass=*)" {
		t.Fatalf("unexpected query details: %+v", q)
	}

	if events[1].Trigger != TriggerLDAPLogin {
		t.Fatalf("event[1].Trigger = %q, want %q", events[1].Trigger, TriggerLDAPLogin)
	}
	l := fieldMap(events[1].Details)
	if l["username"] != "Administrator" || l["auth"] != "simple" || l["password_hmac"] != expectedHMAC("Winter2026!") {
		t.Fatalf("unexpected login details: %+v", l)
	}
}

func TestLDAPSASLAndSicilyNTLME2E(t *testing.T) {
	d, rep := newTestDecoy(t, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.ServeLDAP(ctx, ln)

	// Part A: SASL GSS-SPNEGO NTLM
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(makeLDAPSASLBind(1, "GSS-SPNEGO", makeSPNEGONegTokenInit(makeTestNTLMType1()))); err != nil {
		t.Fatalf("write SASL Type 1: %v", err)
	}
	_, op, rc, _, _, saslCreds := decodeLDAPResponse(t, conn)
	if op != ldapOpBindResponse || rc != ldapResultSASLBindInProgress {
		t.Fatalf("SASL Type 1 got op=%d rc=%d, want 1/14", op, rc)
	}
	t2, wasSPNEGO, err := unwrapNTLMToken(saslCreds)
	if err != nil || !wasSPNEGO {
		t.Fatalf("expected SPNEGO-wrapped Type 2, got spnego=%v err=%v", wasSPNEGO, err)
	}
	if mt, _ := ntlmMessageType(t2); mt != ntlmTypeChallenge {
		t.Fatalf("expected NTLM Type 2, got %d", mt)
	}

	ntResp := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44}
	t3 := makeTestNTLMType3("CORP", "svc_backup", "JUMP01", ntResp, true)
	if _, err := conn.Write(makeLDAPSASLBind(2, "GSS-SPNEGO", makeSPNEGONegTokenResp(t3))); err != nil {
		t.Fatalf("write SASL Type 3: %v", err)
	}
	_, op2, rc2, _, _, _ := decodeLDAPResponse(t, conn)
	if op2 != ldapOpBindResponse || rc2 != ldapResultInvalidCredentials {
		t.Fatalf("SASL Type 3 got op=%d rc=%d, want 1/49", op2, rc2)
	}
	_ = conn.Close()

	// Part B: Sicily NTLM
	conn2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial sicily: %v", err)
	}
	defer conn2.Close()

	if _, err := conn2.Write(makeLDAPSicilyBind(1, 9, nil)); err != nil {
		t.Fatalf("write Sicily discovery: %v", err)
	}
	_, _, rcD, srvCredsD, _, _ := decodeLDAPResponse(t, conn2)
	if rcD != ldapResultSuccess || srvCredsD != "NTLM" {
		t.Fatalf("Sicily discovery got rc=%d creds=%q", rcD, srvCredsD)
	}
	if _, err := conn2.Write(makeLDAPSicilyBind(2, 10, makeTestNTLMType1())); err != nil {
		t.Fatalf("write Sicily negotiate: %v", err)
	}
	_, _, rcN, srvCredsN, _, _ := decodeLDAPResponse(t, conn2)
	if rcN != ldapResultSuccess || !strings.HasPrefix(srvCredsN, ntlmSignature) {
		t.Fatalf("Sicily negotiate got rc=%d", rcN)
	}
	if _, err := conn2.Write(makeLDAPSicilyBind(3, 11, t3)); err != nil {
		t.Fatalf("write Sicily response: %v", err)
	}
	_, _, rcR, _, _, _ := decodeLDAPResponse(t, conn2)
	if rcR != ldapResultInvalidCredentials {
		t.Fatalf("Sicily response got rc=%d, want 49", rcR)
	}
	_ = conn2.Close()

	events := rep.waitEvents(t, 2)
	for i, ev := range events {
		if ev.Trigger != TriggerLDAPLogin {
			t.Fatalf("event[%d].Trigger = %q", i, ev.Trigger)
		}
		m := fieldMap(ev.Details)
		if m["auth"] != "ntlm" || m["username"] != "svc_backup" || m["domain"] != "CORP" || m["workstation"] != "JUMP01" {
			t.Fatalf("event[%d] unexpected NTLM fields: %+v", i, m)
		}
		if m["ntlm_response_hmac"] != expectedHMAC(hex.EncodeToString(ntResp)) {
			t.Fatalf("event[%d] ntlm_response_hmac mismatch: %v", i, m["ntlm_response_hmac"])
		}
	}
}

func TestLDAPSE2E(t *testing.T) {
	d, rep := newTestDecoy(t, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.ServeLDAPS(ctx, ln)

	tlsConn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer tlsConn.Close()

	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 || certs[0].Subject.CommonName != "dc01.corp.local" {
		t.Fatalf("unexpected LDAPS cert: %+v", certs)
	}

	if _, err := tlsConn.Write(makeLDAPSimpleBind(1, "admin@corp.local", "SuperSecret!")); err != nil {
		t.Fatalf("write LDAPS bind: %v", err)
	}
	_, op, rc, _, _, _ := decodeLDAPResponse(t, tlsConn)
	if op != ldapOpBindResponse || rc != ldapResultInvalidCredentials {
		t.Fatalf("LDAPS bind got op=%d rc=%d, want 1/49", op, rc)
	}
	_ = tlsConn.Close()

	events := rep.waitEvents(t, 1)
	if events[0].Trigger != TriggerLDAPSLogin {
		t.Fatalf("Trigger = %q, want %q", events[0].Trigger, TriggerLDAPSLogin)
	}
	m := fieldMap(events[0].Details)
	if m["protocol"] != "ldaps" || m["username"] != "admin" || m["domain"] != "corp.local" || m["password_hmac"] != expectedHMAC("SuperSecret!") {
		t.Fatalf("unexpected LDAPS login fields: %+v", m)
	}
}

func makeX224ConnReqTPKT(cookieUser string, reqProto uint32) []byte {
	var body bytes.Buffer
	if cookieUser != "" {
		body.WriteString("Cookie: mstshash=" + cookieUser + "\r\n")
	}
	var neg [8]byte
	neg[0] = rdpNegReqType
	binary.LittleEndian.PutUint16(neg[2:4], 8)
	binary.LittleEndian.PutUint32(neg[4:8], reqProto)
	body.Write(neg[:])

	tpduLen := 7 + body.Len()
	totalLen := 4 + tpduLen
	out := make([]byte, 0, totalLen)
	var hdr [11]byte
	hdr[0] = tpktVersion
	hdr[1] = 0
	binary.BigEndian.PutUint16(hdr[2:4], uint16(totalLen))
	hdr[4] = byte(tpduLen - 1) // LI
	hdr[5] = x224CodeConnReq
	out = append(out, hdr[:]...)
	out = append(out, body.Bytes()...)
	return out
}

func TestRDPNLACredSSPE2E(t *testing.T) {
	d, rep := newTestDecoy(t, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.ServeRDP(ctx, ln)

	// 1. Full NLA + CredSSP + NTLM exchange.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial RDP: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(makeX224ConnReqTPKT("jdoe", rdpProtoSSL|rdpProtoHybrid)); err != nil {
		t.Fatalf("write X.224 CR: %v", err)
	}
	cc, err := readTPKT(conn)
	if err != nil {
		t.Fatalf("read X.224 CC: %v", err)
	}
	if len(cc) < 15 || cc[1] != x224CodeConnConfirm || cc[7] != rdpNegRspType || binary.LittleEndian.Uint32(cc[11:15]) != rdpProtoHybrid {
		t.Fatalf("unexpected X.224 CC: %x", cc)
	}

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("RDP TLS handshake: %v", err)
	}
	if cn := tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != "dc01.corp.local" {
		t.Fatalf("RDP TLS cert CN = %q", cn)
	}

	// Send CredSSP TSRequest with SPNEGO NTLM Type 1.
	if _, err := tlsConn.Write(buildTSRequestNego(6, makeSPNEGONegTokenInit(makeTestNTLMType1()))); err != nil {
		t.Fatalf("write TSRequest Type 1: %v", err)
	}
	rawResp1, err := readBERSequence(tlsConn, maxCredSSPSize)
	if err != nil {
		t.Fatalf("read TSRequest Type 2: %v", err)
	}
	tsResp1, err := parseTSRequest(rawResp1)
	if err != nil || len(tsResp1.NegoTokens) != 1 {
		t.Fatalf("parse TSRequest Type 2: err=%v tokens=%d", err, len(tsResp1.NegoTokens))
	}
	t2, wasSPNEGO, err := unwrapNTLMToken(tsResp1.NegoTokens[0])
	if err != nil || !wasSPNEGO {
		t.Fatalf("expected SPNEGO Type 2 in TSRequest: spnego=%v err=%v", wasSPNEGO, err)
	}
	if mt, _ := ntlmMessageType(t2); mt != ntlmTypeChallenge {
		t.Fatalf("expected Type 2, got %d", mt)
	}

	// Send CredSSP TSRequest with SPNEGO NTLM Type 3.
	ntResp := []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}
	t3 := makeTestNTLMType3("CORP", "administrator", "ATTACKER-PC", ntResp, true)
	if _, err := tlsConn.Write(buildTSRequestNego(6, makeSPNEGONegTokenResp(t3))); err != nil {
		t.Fatalf("write TSRequest Type 3: %v", err)
	}

	// Expect CredSSP TSRequest with errorCode = STATUS_LOGON_FAILURE.
	rawErr, err := readBERSequence(tlsConn, maxCredSSPSize)
	if err != nil {
		t.Fatalf("read TSRequest error: %v", err)
	}
	rd, err := ber.NewReader(rawErr, credSSPBERLimits)
	if err != nil {
		t.Fatalf("ber.NewReader error resp: %v", err)
	}
	seq, _ := rd.Expect(ber.Universal, ber.TagSequence)
	ch, _ := seq.Children()
	foundErr := false
	for ch.Len() > 0 {
		el, _ := ch.Next()
		if el.Is(ber.ContextSpecific, 4) {
			ech, _ := el.Children()
			ec, _ := ech.Expect(ber.Universal, ber.TagInteger)
			if v, _ := ec.Int(); v == ntStatusLogonFailure {
				foundErr = true
			}
		}
	}
	if !foundErr {
		t.Fatal("expected STATUS_LOGON_FAILURE in CredSSP error TSRequest")
	}
	_ = tlsConn.Close()

	// 2. Client refusing NLA -> RDP_NEG_FAILURE + rdp_connection.
	conn2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial RDP legacy: %v", err)
	}
	defer conn2.Close()

	if _, err := conn2.Write(makeX224ConnReqTPKT("legacyuser", rdpProtoRDP)); err != nil {
		t.Fatalf("write legacy X.224 CR: %v", err)
	}
	cc2, err := readTPKT(conn2)
	if err != nil {
		t.Fatalf("read legacy X.224 CC: %v", err)
	}
	if len(cc2) < 15 || cc2[7] != rdpNegFailType || binary.LittleEndian.Uint32(cc2[11:15]) != rdpFailHybridRequired {
		t.Fatalf("expected HYBRID_REQUIRED_BY_SERVER failure, got %x", cc2)
	}
	_ = conn2.Close()

	events := rep.waitEvents(t, 2)
	if events[0].Trigger != TriggerRDPLogin {
		t.Fatalf("event[0].Trigger = %q, want %q", events[0].Trigger, TriggerRDPLogin)
	}
	m := fieldMap(events[0].Details)
	if m["username"] != "administrator" || m["domain"] != "CORP" || m["workstation"] != "ATTACKER-PC" || m["cookie_user"] != "jdoe" {
		t.Fatalf("unexpected rdp_login details: %+v", m)
	}
	if m["ntlm_response_hmac"] != expectedHMAC(hex.EncodeToString(ntResp)) {
		t.Fatalf("ntlm_response_hmac mismatch: %v", m["ntlm_response_hmac"])
	}

	if events[1].Trigger != TriggerRDPConnection {
		t.Fatalf("event[1].Trigger = %q, want %q", events[1].Trigger, TriggerRDPConnection)
	}
	m2 := fieldMap(events[1].Details)
	if m2["nla_offered"] != false || m2["username"] != "legacyuser" {
		t.Fatalf("unexpected rdp_connection details: %+v", m2)
	}
}
