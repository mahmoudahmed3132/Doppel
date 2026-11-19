// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/decoy"
	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

const (
	pgMaxStartupLen       = 16 * 1024
	pgMaxPasswordLen      = 4 * 1024
	pgMaxPreStartupFrames = 3
	pgMaxParams           = 64
	pgMaxFieldLen         = 128

	pgCodeCancelRequest uint32 = 80877102
	pgCodeSSLRequest    uint32 = 80877103
	pgCodeGSSENCRequest uint32 = 80877104
	pgProtocolV3        uint32 = 0x00030000

	pgAuthCleartextPassword uint32 = 3
)

type pgStartupInfo struct {
	Username        string
	Database        string
	ApplicationName string
}

// parsePostgresStartupParams parses the NUL-terminated key/value pairs in a
// PostgreSQL v3 StartupMessage body (after the 4-byte protocol version).
func parsePostgresStartupParams(body []byte) pgStartupInfo {
	var info pgStartupInfo
	pos := 0
	for count := 0; pos < len(body) && count < pgMaxParams; count++ {
		if body[pos] == 0x00 {
			break
		}
		kEnd := bytes.IndexByte(body[pos:], 0x00)
		if kEnd < 0 {
			break
		}
		key := string(body[pos : pos+kEnd])
		pos += kEnd + 1
		if pos >= len(body) {
			break
		}
		vEnd := bytes.IndexByte(body[pos:], 0x00)
		if vEnd < 0 {
			break
		}
		val := decoy.Sanitize(string(body[pos:pos+vEnd]), pgMaxFieldLen)
		pos += vEnd + 1

		switch key {
		case "user":
			info.Username = val
		case "database":
			info.Database = val
		case "application_name":
			info.ApplicationName = val
		}
	}
	return info
}

func buildPostgresAuthCleartext() []byte {
	pkt := make([]byte, 9)
	pkt[0] = 'R'
	binary.BigEndian.PutUint32(pkt[1:5], 8)
	binary.BigEndian.PutUint32(pkt[5:9], pgAuthCleartextPassword)
	return pkt
}

func buildPostgresErrorResponse(user string) []byte {
	msg := fmt.Sprintf("password authentication failed for user %q", user)
	var body bytes.Buffer
	writeField := func(code byte, val string) {
		body.WriteByte(code)
		body.WriteString(val)
		body.WriteByte(0x00)
	}
	writeField('S', "FATAL")
	writeField('V', "FATAL")
	writeField('C', "28P01")
	writeField('M', msg)
	body.WriteByte(0x00)

	out := make([]byte, 5+body.Len())
	out[0] = 'E'
	binary.BigEndian.PutUint32(out[1:5], uint32(4+body.Len()))
	copy(out[5:], body.Bytes())
	return out
}

func readPostgresStartupFrame(r io.Reader) (uint32, []byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, nil, err
	}
	msgLen := binary.BigEndian.Uint32(lenBuf[:])
	if msgLen < 8 || msgLen > pgMaxStartupLen {
		return 0, nil, fmt.Errorf("postgres startup length %d out of range", msgLen)
	}
	body := make([]byte, msgLen-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	code := binary.BigEndian.Uint32(body[:4])
	return code, body[4:], nil
}

// readPostgresPassword reads a PasswordMessage ('p'). Returns (password, gotPassword, err).
// If the client sends Terminate ('X'), returns ("", false, nil).
func readPostgresPassword(r io.Reader) (string, bool, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", false, err
	}
	msgType := hdr[0]
	msgLen := binary.BigEndian.Uint32(hdr[1:5])
	if msgType == 'X' {
		return "", false, nil
	}
	if msgType != 'p' {
		return "", false, fmt.Errorf("unexpected postgres message type 0x%02x", msgType)
	}
	if msgLen < 5 || msgLen > pgMaxPasswordLen {
		return "", false, fmt.Errorf("postgres password message length %d out of range", msgLen)
	}
	buf := make([]byte, msgLen-4)
	defer clear(buf)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", false, err
	}
	// Trim trailing NUL terminator if present.
	if n := len(buf); n > 0 && buf[n-1] == 0x00 {
		buf = buf[:n-1]
	}
	return string(buf), true, nil
}

func (d *Decoy) handlePostgres(ctx context.Context, raw net.Conn, port int) {
	conn := newBoundedConn(raw, d.idleTimeout, d.totalTimeout)
	defer conn.Close()

	ip := decoy.RemoteIP(raw.RemoteAddr())

	var (
		startup      pgStartupInfo
		gotStartup   bool
		sslRequested bool
		gssRequested bool
	)

	for i := 0; i <= pgMaxPreStartupFrames; i++ {
		code, rest, err := readPostgresStartupFrame(conn)
		if err != nil {
			d.emitPostgresConnection(ip, port, startup, sslRequested, gssRequested)
			return
		}
		switch code {
		case pgCodeSSLRequest:
			if len(rest) != 0 || i == pgMaxPreStartupFrames {
				d.emitPostgresConnection(ip, port, startup, sslRequested, gssRequested)
				return
			}
			sslRequested = true
			if _, err := conn.Write([]byte{'N'}); err != nil {
				d.emitPostgresConnection(ip, port, startup, sslRequested, gssRequested)
				return
			}
		case pgCodeGSSENCRequest:
			if len(rest) != 0 || i == pgMaxPreStartupFrames {
				d.emitPostgresConnection(ip, port, startup, sslRequested, gssRequested)
				return
			}
			gssRequested = true
			if _, err := conn.Write([]byte{'N'}); err != nil {
				d.emitPostgresConnection(ip, port, startup, sslRequested, gssRequested)
				return
			}
		case pgCodeCancelRequest:
			// Spec: CancelRequest closes silently.
			if len(rest) == 8 {
				return
			}
			d.emitPostgresConnection(ip, port, startup, sslRequested, gssRequested)
			return
		case pgProtocolV3:
			startup = parsePostgresStartupParams(rest)
			gotStartup = true
		default:
			d.emitPostgresConnection(ip, port, startup, sslRequested, gssRequested)
			return
		}
		if gotStartup {
			break
		}
	}

	if !gotStartup {
		d.emitPostgresConnection(ip, port, startup, sslRequested, gssRequested)
		return
	}

	if _, err := conn.Write(buildPostgresAuthCleartext()); err != nil {
		d.emitPostgresConnection(ip, port, startup, sslRequested, gssRequested)
		return
	}

	pw, ok, err := readPostgresPassword(conn)
	if err != nil || !ok {
		d.emitPostgresConnection(ip, port, startup, sslRequested, gssRequested)
		return
	}

	if !d.pause(ctx, 100*time.Millisecond, 300*time.Millisecond) {
		return
	}

	_, _ = conn.Write(buildPostgresErrorResponse(startup.Username))
	d.emitPostgresLogin(ip, port, startup, pw)
}

func (d *Decoy) emitPostgresLogin(ip string, port int, info pgStartupInfo, password string) {
	allowed, suppressed := d.allowLogin(ip, "postgres")
	if !allowed {
		return
	}
	fields := sensor.Fields{
		sensor.F("protocol", "postgres"),
		sensor.F("dst_port", port),
		sensor.F("username", info.Username),
	}
	if info.Database != "" {
		fields = append(fields, sensor.F("database", info.Database))
	}
	if info.ApplicationName != "" {
		fields = append(fields, sensor.F("application_name", info.ApplicationName))
	}
	fields = append(fields, d.capture.Password(password)...)
	if suppressed > 0 {
		fields = append(fields, sensor.F("suppressed_since_last", suppressed))
	}
	d.r.ReportSeverity(sensor.SeverityHigh, TriggerPostgresLogin, ip, fmt.Sprintf("PostgreSQL port %d", port), fields)
}

func (d *Decoy) emitPostgresConnection(ip string, port int, info pgStartupInfo, sslReq, gssReq bool) {
	allowed, suppressed := d.allowConn(ip, "postgres")
	if !allowed {
		return
	}
	fields := sensor.Fields{
		sensor.F("protocol", "postgres"),
		sensor.F("dst_port", port),
	}
	if info.Username != "" {
		fields = append(fields, sensor.F("username", info.Username))
	}
	if info.Database != "" {
		fields = append(fields, sensor.F("database", info.Database))
	}
	if info.ApplicationName != "" {
		fields = append(fields, sensor.F("application_name", info.ApplicationName))
	}
	if sslReq {
		fields = append(fields, sensor.F("ssl_requested", true))
	}
	if gssReq {
		fields = append(fields, sensor.F("gss_requested", true))
	}
	if suppressed > 0 {
		fields = append(fields, sensor.F("suppressed_since_last", suppressed))
	}
	d.r.ReportSeverity(sensor.SeverityMedium, TriggerPostgresConnection, ip, fmt.Sprintf("PostgreSQL port %d", port), fields)
}

// parsePostgresWireMessage is used by tests/fuzzers to validate startup+password
// parsing without a network socket.
func parsePostgresWireMessage(data []byte) error {
	r := bytes.NewReader(data)
	for i := 0; i <= pgMaxPreStartupFrames; i++ {
		code, rest, err := readPostgresStartupFrame(r)
		if err != nil {
			return err
		}
		switch code {
		case pgCodeSSLRequest, pgCodeGSSENCRequest:
			if len(rest) != 0 {
				return errors.New("invalid pre-startup length")
			}
		case pgCodeCancelRequest:
			return nil
		case pgProtocolV3:
			_ = parsePostgresStartupParams(rest)
			_, _, err = readPostgresPassword(r)
			return err
		default:
			return errors.New("unknown startup code")
		}
	}
	return errors.New("too many pre-startup frames")
}
