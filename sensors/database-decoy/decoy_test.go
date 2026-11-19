// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

const testCaptureKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type recordedEvent struct {
	Trigger  string
	Source   string
	Target   string
	Severity sensor.Severity
	Details  map[string]any
}

type fakeReporter struct {
	settings map[string]string
	mu       sync.Mutex
	events   []recordedEvent
	ch       chan recordedEvent
}

func newFakeReporter(settings map[string]string) *fakeReporter {
	s := map[string]string{
		"TS_PASSWORD_CAPTURE":   "hash",
		"TS_CAPTURE_KEY":        testCaptureKeyHex,
		"TS_EVENT_COOLDOWN_SEC": "0",
	}
	for k, v := range settings {
		s[k] = v
	}
	return &fakeReporter{
		settings: s,
		ch:       make(chan recordedEvent, 64),
	}
}

func (f *fakeReporter) ReportSeverity(severity sensor.Severity, trigger, source, target string, rawDetails sensor.Details) {
	details := map[string]any{}
	if flds, ok := rawDetails.(sensor.Fields); ok {
		for _, fld := range flds {
			details[fld.Key] = fld.Value
		}
	}
	ev := recordedEvent{
		Trigger:  trigger,
		Source:   source,
		Target:   target,
		Severity: severity,
		Details:  details,
	}
	f.mu.Lock()
	f.events = append(f.events, ev)
	f.mu.Unlock()
	select {
	case f.ch <- ev:
	default:
	}
}

func (f *fakeReporter) Setting(name string) (string, bool) {
	v, ok := f.settings[name]
	return v, ok
}

func (f *fakeReporter) waitEvent(t *testing.T) recordedEvent {
	t.Helper()
	select {
	case ev := <-f.ch:
		return ev
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for event")
		return recordedEvent{}
	}
}

func (f *fakeReporter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}

func expectedHMAC(t *testing.T, secret string) string {
	t.Helper()
	key, err := hex.DecodeString(testCaptureKeyHex)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(secret))
	return hex.EncodeToString(mac.Sum(nil))
}

func newTestDecoy(t *testing.T, settings map[string]string) (*Decoy, *fakeReporter) {
	t.Helper()
	rep := newFakeReporter(settings)
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

func TestLoadSettingsValidation(t *testing.T) {
	rep := newFakeReporter(nil)
	cfg, err := LoadSettings(rep)
	if err != nil {
		t.Fatalf("default settings failed: %v", err)
	}
	if !cfg.EnableMySQL || !cfg.EnablePostgres || !cfg.EnableMSSQL {
		t.Fatalf("expected all 3 protocols enabled by default: %+v", cfg)
	}
	if cfg.MySQLPort != 3306 || cfg.PostgresPort != 5432 || cfg.MSSQLPort != 1433 {
		t.Fatalf("unexpected default ports: %+v", cfg)
	}
	if cfg.MSSQLVer != (MSSQLVersion{Major: 16, Minor: 0, Build: 1000}) {
		t.Fatalf("unexpected default MSSQL version: %+v", cfg.MSSQLVer)
	}

	cases := []struct {
		name     string
		settings map[string]string
	}{
		{
			name: "all disabled",
			settings: map[string]string{
				"TS_ENABLE_MYSQL":    "false",
				"TS_ENABLE_POSTGRES": "false",
				"TS_ENABLE_MSSQL":    "false",
			},
		},
		{
			name: "duplicate ports",
			settings: map[string]string{
				"TS_MYSQL_PORT":    "5432",
				"TS_POSTGRES_PORT": "5432",
			},
		},
		{
			name: "privileged port rejected",
			settings: map[string]string{
				"TS_MYSQL_PORT": "330",
			},
		},
		{
			name: "invalid mssql version",
			settings: map[string]string{
				"TS_MSSQL_VERSION": "16.0",
			},
		},
		{
			name: "crlf in mysql version",
			settings: map[string]string{
				"TS_MYSQL_VERSION": "8.0.39\r\n",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadSettings(newFakeReporter(tc.settings)); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestTDSPasswordDeobfuscation(t *testing.T) {
	obfuscate := func(plain string) []byte {
		raw, _ := encodeUTF16LE(plain)
		for i, b := range raw {
			raw[i] = ((b << 4) | (b >> 4)) ^ 0xa5
		}
		return raw
	}

	for _, pw := range []string{"", "P@ssw0rd!", "sa12345", "hunter2-日本語"} {
		enc := obfuscate(pw)
		got := deobfuscateTDSPassword(enc)
		if got != pw {
			t.Fatalf("deobfuscateTDSPassword(%q) = %q, want %q", pw, got, pw)
		}
	}
}

func TestMySQLPacketFramingAndBounds(t *testing.T) {
	// Oversized packet (> 64 KiB) must be rejected without allocating huge memory.
	var hdr [4]byte
	oversize := mysqlMaxPacketLen + 1
	hdr[0] = byte(oversize)
	hdr[1] = byte(oversize >> 8)
	hdr[2] = byte(oversize >> 16)
	hdr[3] = 1
	if _, _, err := readMySQLPacket(bytes.NewReader(hdr[:])); err == nil {
		t.Fatal("expected error for oversized MySQL packet")
	}

	// Truncated handshake response.
	if _, _, err := parseMySQLHandshakeResponse([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for truncated handshake response")
	}
}

func TestPostgresBounds(t *testing.T) {
	// Oversized startup length (> 16 KiB).
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], pgMaxStartupLen+1)
	if _, _, err := readPostgresStartupFrame(bytes.NewReader(lenBuf[:])); err == nil {
		t.Fatal("expected error for oversized Postgres startup frame")
	}

	// Oversized password length (> 4 KiB).
	var pwHdr [5]byte
	pwHdr[0] = 'p'
	binary.BigEndian.PutUint32(pwHdr[1:5], pgMaxPasswordLen+1)
	if _, _, err := readPostgresPassword(bytes.NewReader(pwHdr[:])); err == nil {
		t.Fatal("expected error for oversized Postgres password frame")
	}

	// Terminate ('X') returns ok=false, err=nil.
	var term [5]byte
	term[0] = 'X'
	binary.BigEndian.PutUint32(term[1:5], 4)
	pw, ok, err := readPostgresPassword(bytes.NewReader(term[:]))
	if err != nil || ok || pw != "" {
		t.Fatalf("Terminate frame got (%q, %v, %v), want (\"\", false, nil)", pw, ok, err)
	}
}

func TestTDSMessageBoundsAndReassembly(t *testing.T) {
	// Multi-packet reassembly.
	pkt1 := make([]byte, tdsHeaderLen+4)
	pkt1[0] = tdsTypeLogin7
	pkt1[1] = 0x00 // not EOM
	binary.BigEndian.PutUint16(pkt1[2:4], uint16(len(pkt1)))
	copy(pkt1[tdsHeaderLen:], []byte("ABCD"))

	pkt2 := make([]byte, tdsHeaderLen+4)
	pkt2[0] = tdsTypeLogin7
	pkt2[1] = tdsStatusEOM
	binary.BigEndian.PutUint16(pkt2[2:4], uint16(len(pkt2)))
	copy(pkt2[tdsHeaderLen:], []byte("EFGH"))

	typ, payload, err := readTDSMessage(bytes.NewReader(append(pkt1, pkt2...)))
	if err != nil {
		t.Fatalf("readTDSMessage: %v", err)
	}
	if typ != tdsTypeLogin7 || string(payload) != "ABCDEFGH" {
		t.Fatalf("got type=0x%02x payload=%q", typ, string(payload))
	}

	// Oversized packet length (> 32 KiB).
	var hdr [tdsHeaderLen]byte
	hdr[0] = tdsTypeLogin7
	hdr[1] = tdsStatusEOM
	binary.BigEndian.PutUint16(hdr[2:4], tdsMaxPacketLen+1)
	if _, _, err := readTDSMessage(bytes.NewReader(hdr[:])); err == nil {
		t.Fatal("expected error for oversized TDS packet")
	}

	// Out-of-bounds LOGIN7 field.
	badLogin := make([]byte, 86)
	binary.LittleEndian.PutUint16(badLogin[40:42], 80)
	binary.LittleEndian.PutUint16(badLogin[42:44], 100) // exceeds payload
	if _, err := parseTDSLogin7(badLogin); err == nil {
		t.Fatal("expected error for out-of-bounds LOGIN7 username")
	}
}

// buildClientMySQLHandshakeResponse constructs a wire-valid HandshakeResponse41.
func buildClientMySQLHandshakeResponse(user string, authResp []byte, db, plugin string, attrs map[string]string) []byte {
	flags := mysqlClientProtocol41 | mysqlClientSecureConnection | mysqlClientPluginAuth | mysqlClientPluginAuthLenencClientData
	if db != "" {
		flags |= mysqlClientConnectWithDB
	}
	if len(attrs) > 0 {
		flags |= mysqlClientConnectAttrs
	}
	var p []byte
	p = binary.LittleEndian.AppendUint32(p, flags)
	p = binary.LittleEndian.AppendUint32(p, 16*1024*1024) // max_packet_size
	p = append(p, mysqlCharsetUTF8MB4)
	p = append(p, make([]byte, 23)...)
	p = append(p, user...)
	p = append(p, 0x00)
	p = append(p, byte(len(authResp)))
	p = append(p, authResp...)
	if db != "" {
		p = append(p, db...)
		p = append(p, 0x00)
	}
	p = append(p, plugin...)
	p = append(p, 0x00)
	if len(attrs) > 0 {
		var attrBuf []byte
		for k, v := range attrs {
			attrBuf = append(attrBuf, byte(len(k)))
			attrBuf = append(attrBuf, k...)
			attrBuf = append(attrBuf, byte(len(v)))
			attrBuf = append(attrBuf, v...)
		}
		p = append(p, byte(len(attrBuf)))
		p = append(p, attrBuf...)
	}
	return wrapMySQLPacket(1, p)
}

func TestMySQLE2E(t *testing.T) {
	d, rep := newTestDecoy(t, map[string]string{
		"TS_MYSQL_VERSION": "8.0.39-test",
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.ServeMySQL(ctx, ln)

	// 1. Full login attempt.
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	seq, hs, err := readMySQLPacket(conn)
	if err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	if seq != 0 || len(hs) < 30 || hs[0] != 0x0a {
		t.Fatalf("unexpected handshake header: seq=%d len=%d proto=0x%02x", seq, len(hs), hs[0])
	}
	ver, _, ok := readNullTerminated(hs, 1)
	if !ok || ver != "8.0.39-test" {
		t.Fatalf("unexpected server version %q", ver)
	}
	if !bytes.Contains(hs, []byte("mysql_native_password\x00")) {
		t.Fatal("handshake missing mysql_native_password plugin")
	}

	scrambleResp := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	req := buildClientMySQLHandshakeResponse("root", scrambleResp, "prod_db", "mysql_native_password", map[string]string{
		"_client_name":    "libmysql",
		"_client_version": "8.0.39",
		"program_name":    "mysql",
	})
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write response: %v", err)
	}

	errSeq, errPkt, err := readMySQLPacket(conn)
	if err != nil {
		t.Fatalf("read ERR: %v", err)
	}
	if errSeq != 2 || len(errPkt) < 9 || errPkt[0] != 0xff {
		t.Fatalf("unexpected ERR packet: seq=%d len=%d hdr=0x%02x", errSeq, len(errPkt), errPkt[0])
	}
	errCode := binary.LittleEndian.Uint16(errPkt[1:3])
	if errCode != 1045 {
		t.Fatalf("ERR code = %d, want 1045", errCode)
	}
	if string(errPkt[3:9]) != "#28000" {
		t.Fatalf("SQLSTATE = %q, want #28000", string(errPkt[3:9]))
	}
	if !strings.Contains(string(errPkt[9:]), "Access denied for user 'root'@'127.0.0.1' (using password: YES)") {
		t.Fatalf("unexpected ERR message: %q", string(errPkt[9:]))
	}

	ev := rep.waitEvent(t)
	if ev.Trigger != TriggerMySQLLogin || ev.Severity != sensor.SeverityHigh {
		t.Fatalf("unexpected event: %+v", ev)
	}
	if ev.Details["username"] != "root" || ev.Details["database"] != "prod_db" {
		t.Fatalf("unexpected details: %+v", ev.Details)
	}
	if ev.Details["client_name"] != "libmysql" || ev.Details["client_version"] != "8.0.39" || ev.Details["program_name"] != "mysql" {
		t.Fatalf("missing connect attrs: %+v", ev.Details)
	}
	if ev.Details["password_supplied"] != true {
		t.Fatalf("password_supplied = %v, want true", ev.Details["password_supplied"])
	}
	wantHMAC := expectedHMAC(t, hex.EncodeToString(scrambleResp))
	if ev.Details["auth_response_hmac"] != wantHMAC {
		t.Fatalf("auth_response_hmac = %v, want %s", ev.Details["auth_response_hmac"], wantHMAC)
	}

	// 2. SSLRequest closes cleanly and emits mysql_connection.
	sslConn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial ssl: %v", err)
	}
	defer sslConn.Close()
	if _, _, err := readMySQLPacket(sslConn); err != nil {
		t.Fatalf("read handshake for ssl: %v", err)
	}
	sslReq := make([]byte, 32)
	binary.LittleEndian.PutUint32(sslReq[0:4], mysqlClientProtocol41|mysqlClientSSL)
	if _, err := sslConn.Write(wrapMySQLPacket(1, sslReq)); err != nil {
		t.Fatalf("write ssl req: %v", err)
	}
	ev2 := rep.waitEvent(t)
	if ev2.Trigger != TriggerMySQLConnection || ev2.Severity != sensor.SeverityMedium || ev2.Details["ssl_requested"] != true {
		t.Fatalf("unexpected ssl connection event: %+v", ev2)
	}
}

func TestPostgresE2E(t *testing.T) {
	d, rep := newTestDecoy(t, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.ServePostgres(ctx, ln)

	// 1. SSLRequest -> 'N', GSSENCRequest -> 'N', StartupMessage -> CleartextAuth -> PasswordMessage -> ErrorResponse 28P01.
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	writePre := func(code uint32) {
		var buf [8]byte
		binary.BigEndian.PutUint32(buf[0:4], 8)
		binary.BigEndian.PutUint32(buf[4:8], code)
		if _, err := conn.Write(buf[:]); err != nil {
			t.Fatalf("write pre-startup: %v", err)
		}
		var reply [1]byte
		if _, err := io.ReadFull(conn, reply[:]); err != nil {
			t.Fatalf("read pre-startup reply: %v", err)
		}
		if reply[0] != 'N' {
			t.Fatalf("reply = %q, want 'N'", reply[0])
		}
	}
	writePre(pgCodeSSLRequest)
	writePre(pgCodeGSSENCRequest)

	var startupBody bytes.Buffer
	binary.Write(&startupBody, binary.BigEndian, pgProtocolV3)
	startupBody.WriteString("user\x00pgadmin\x00database\x00billing\x00application_name\x00psql\x00\x00")
	startupFrame := make([]byte, 4+startupBody.Len())
	binary.BigEndian.PutUint32(startupFrame[0:4], uint32(len(startupFrame)))
	copy(startupFrame[4:], startupBody.Bytes())
	if _, err := conn.Write(startupFrame); err != nil {
		t.Fatalf("write startup: %v", err)
	}

	var authReq [9]byte
	if _, err := io.ReadFull(conn, authReq[:]); err != nil {
		t.Fatalf("read auth req: %v", err)
	}
	if authReq[0] != 'R' || binary.BigEndian.Uint32(authReq[1:5]) != 8 || binary.BigEndian.Uint32(authReq[5:9]) != 3 {
		t.Fatalf("unexpected auth request: %x", authReq)
	}

	pw := "Sup3rSecret!"
	pwFrame := make([]byte, 5+len(pw)+1)
	pwFrame[0] = 'p'
	binary.BigEndian.PutUint32(pwFrame[1:5], uint32(4+len(pw)+1))
	copy(pwFrame[5:], pw)
	if _, err := conn.Write(pwFrame); err != nil {
		t.Fatalf("write password: %v", err)
	}

	var errHdr [5]byte
	if _, err := io.ReadFull(conn, errHdr[:]); err != nil {
		t.Fatalf("read ErrorResponse hdr: %v", err)
	}
	if errHdr[0] != 'E' {
		t.Fatalf("expected 'E', got 0x%02x", errHdr[0])
	}
	errLen := binary.BigEndian.Uint32(errHdr[1:5])
	errBody := make([]byte, errLen-4)
	if _, err := io.ReadFull(conn, errBody); err != nil {
		t.Fatalf("read ErrorResponse body: %v", err)
	}
	if !bytes.Contains(errBody, []byte("SFATAL\x00")) ||
		!bytes.Contains(errBody, []byte("C28P01\x00")) ||
		!bytes.Contains(errBody, []byte("Mpassword authentication failed for user \"pgadmin\"\x00")) {
		t.Fatalf("unexpected ErrorResponse body: %q", errBody)
	}

	ev := rep.waitEvent(t)
	if ev.Trigger != TriggerPostgresLogin || ev.Severity != sensor.SeverityHigh {
		t.Fatalf("unexpected event: %+v", ev)
	}
	if ev.Details["username"] != "pgadmin" || ev.Details["database"] != "billing" || ev.Details["application_name"] != "psql" {
		t.Fatalf("unexpected details: %+v", ev.Details)
	}
	if ev.Details["password_hmac"] != expectedHMAC(t, pw) || ev.Details["password_length"] != len(pw) {
		t.Fatalf("unexpected password capture: %+v", ev.Details)
	}
	if _, leaked := ev.Details["password"]; leaked {
		t.Fatal("plaintext password leaked in hash mode")
	}

	// 2. CancelRequest closes silently without reply or event.
	before := rep.count()
	cancelConn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial cancel: %v", err)
	}
	defer cancelConn.Close()
	var cancelPkt [16]byte
	binary.BigEndian.PutUint32(cancelPkt[0:4], 16)
	binary.BigEndian.PutUint32(cancelPkt[4:8], pgCodeCancelRequest)
	binary.BigEndian.PutUint32(cancelPkt[8:12], 1234)
	binary.BigEndian.PutUint32(cancelPkt[12:16], 5678)
	if _, err := cancelConn.Write(cancelPkt[:]); err != nil {
		t.Fatalf("write cancel: %v", err)
	}
	var eofBuf [1]byte
	n, err := cancelConn.Read(eofBuf[:])
	if n != 0 || err != io.EOF {
		t.Fatalf("CancelRequest expected silent EOF, got n=%d err=%v", n, err)
	}
	time.Sleep(50 * time.Millisecond)
	if rep.count() != before {
		t.Fatalf("CancelRequest emitted unexpected event (count %d -> %d)", before, rep.count())
	}
}

func buildClientTDSLogin7(host, user, pass, app, server, lib, db string) []byte {
	// 86-byte fixed+offset header followed by variable UTF-16LE data.
	hdr := make([]byte, 86)
	binary.LittleEndian.PutUint32(hdr[4:8], 0x74000004) // TDS 7.4

	var data []byte
	addField := func(offPos int, val string, obfuscate bool) {
		raw, chars := encodeUTF16LE(val)
		if obfuscate {
			for i, b := range raw {
				raw[i] = ((b << 4) | (b >> 4)) ^ 0xa5
			}
		}
		offset := len(hdr) + len(data)
		binary.LittleEndian.PutUint16(hdr[offPos:offPos+2], uint16(offset))
		binary.LittleEndian.PutUint16(hdr[offPos+2:offPos+4], uint16(chars))
		data = append(data, raw...)
	}

	addField(36, host, false)
	addField(40, user, false)
	addField(44, pass, true)
	addField(48, app, false)
	addField(52, server, false)
	addField(60, lib, false)
	addField(68, db, false)

	payload := append(hdr, data...)
	binary.LittleEndian.PutUint32(payload[0:4], uint32(len(payload)))
	return payload
}

func TestMSSQLE2E(t *testing.T) {
	d, rep := newTestDecoy(t, map[string]string{
		"TS_MSSQL_SERVER_NAME": "SQL-FIN-01",
		"TS_MSSQL_VERSION":     "16.0.1000",
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.ServeMSSQL(ctx, ln)

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// 1. Send PRELOGIN.
	preloginReq := wrapTDSPacket(tdsTypePrelogin, []byte{tdsPreloginTerminator})
	if _, err := conn.Write(preloginReq); err != nil {
		t.Fatalf("write prelogin: %v", err)
	}
	typ, preResp, err := readTDSMessage(conn)
	if err != nil {
		t.Fatalf("read prelogin response: %v", err)
	}
	if typ != tdsTypeTabularResult || len(preResp) < 18 {
		t.Fatalf("unexpected prelogin response: type=0x%02x len=%d", typ, len(preResp))
	}
	if preResp[11] != 16 || preResp[12] != 0 || binary.BigEndian.Uint16(preResp[13:15]) != 1000 || preResp[17] != tdsEncryptNotSup {
		t.Fatalf("unexpected prelogin data: %x", preResp)
	}

	// 2. Send LOGIN7 split across two TDS packets to test reassembly.
	pw := "SqlAdmin#2026"
	loginPayload := buildClientTDSLogin7("WS-ATTACKER", "sa", pw, "sqlcmd", "SQL-FIN-01", "ODBC", "master")
	mid := len(loginPayload) / 2
	p1 := make([]byte, tdsHeaderLen+mid)
	p1[0] = tdsTypeLogin7
	p1[1] = 0x00 // continuation
	binary.BigEndian.PutUint16(p1[2:4], uint16(len(p1)))
	copy(p1[tdsHeaderLen:], loginPayload[:mid])
	p2 := wrapTDSPacket(tdsTypeLogin7, loginPayload[mid:])
	if _, err := conn.Write(append(p1, p2...)); err != nil {
		t.Fatalf("write login7: %v", err)
	}

	// 3. Read ERROR 18456 + DONE response.
	errTyp, errResp, err := readTDSMessage(conn)
	if err != nil {
		t.Fatalf("read error response: %v", err)
	}
	if errTyp != tdsTypeTabularResult || len(errResp) < 20 {
		t.Fatalf("unexpected error response: type=0x%02x len=%d", errTyp, len(errResp))
	}
	if errResp[0] != tdsTokenError {
		t.Fatalf("first token = 0x%02x, want ERROR (0xAA)", errResp[0])
	}
	tokLen := int(binary.LittleEndian.Uint16(errResp[1:3]))
	errNum := int32(binary.LittleEndian.Uint32(errResp[3:7]))
	if errNum != 18456 || errResp[7] != 1 || errResp[8] != 14 {
		t.Fatalf("unexpected error header: num=%d state=%d class=%d", errNum, errResp[7], errResp[8])
	}
	msgChars := int(binary.LittleEndian.Uint16(errResp[9:11]))
	msg := decodeUTF16LE(errResp[11 : 11+msgChars*2])
	if msg != "Login failed for user 'sa'." {
		t.Fatalf("error message = %q", msg)
	}
	doneOff := 3 + tokLen
	if len(errResp) < doneOff+13 || errResp[doneOff] != tdsTokenDone {
		t.Fatalf("missing DONE token at offset %d (len %d)", doneOff, len(errResp))
	}
	if binary.LittleEndian.Uint16(errResp[doneOff+1:doneOff+3]) != tdsDoneError {
		t.Fatalf("DONE status = 0x%04x, want 0x0002", binary.LittleEndian.Uint16(errResp[doneOff+1:doneOff+3]))
	}

	ev := rep.waitEvent(t)
	if ev.Trigger != TriggerMSSQLLogin || ev.Severity != sensor.SeverityHigh {
		t.Fatalf("unexpected event: %+v", ev)
	}
	if ev.Details["username"] != "sa" ||
		ev.Details["hostname"] != "WS-ATTACKER" ||
		ev.Details["app_name"] != "sqlcmd" ||
		ev.Details["server_name"] != "SQL-FIN-01" ||
		ev.Details["library_name"] != "ODBC" ||
		ev.Details["database"] != "master" {
		t.Fatalf("unexpected details: %+v", ev.Details)
	}
	if ev.Details["password_hmac"] != expectedHMAC(t, pw) || ev.Details["password_length"] != len(pw) {
		t.Fatalf("unexpected password capture: %+v", ev.Details)
	}

	// 4. Connection closing right after PRELOGIN emits mssql_connection.
	c2, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	_, _ = c2.Write(wrapTDSPacket(tdsTypePrelogin, []byte{tdsPreloginTerminator}))
	_, _, _ = readTDSMessage(c2)
	c2.Close()

	ev2 := rep.waitEvent(t)
	if ev2.Trigger != TriggerMSSQLConnection || ev2.Severity != sensor.SeverityMedium {
		t.Fatalf("unexpected mssql_connection event: %+v", ev2)
	}
}

func TestPlainPasswordCaptureAndCooldown(t *testing.T) {
	d, rep := newTestDecoy(t, map[string]string{
		"TS_PASSWORD_CAPTURE":   "plain",
		"TS_EVENT_COOLDOWN_SEC": "60",
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.ServeMSSQL(ctx, ln)

	// Send loginLimiterBurst + 2 logins; first 6 should emit, remaining 2 suppressed.
	for i := 0; i < loginLimiterBurst+2; i++ {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		payload := buildClientTDSLogin7("H", "admin", "clearpass", "app", "srv", "lib", "db")
		_, _ = conn.Write(wrapTDSPacket(tdsTypeLogin7, payload))
		_, _, _ = readTDSMessage(conn)
		conn.Close()
	}

	ev := rep.waitEvent(t)
	if ev.Details["password"] != "clearpass" {
		t.Fatalf("expected plaintext password in plain mode, got %+v", ev.Details)
	}
	// Drain remaining allowed events.
	for i := 1; i < loginLimiterBurst; i++ {
		rep.waitEvent(t)
	}
	time.Sleep(50 * time.Millisecond)
	if rep.count() != loginLimiterBurst {
		t.Fatalf("expected %d events (burst cap), got %d", loginLimiterBurst, rep.count())
	}
}
