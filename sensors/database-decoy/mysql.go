// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/decoy"
	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

const (
	mysqlProtocolVersion = 0x0a
	mysqlCharsetUTF8MB4  = 0x2d
	mysqlStatusAutocomit = 0x0002
	mysqlErrAccessDenied = 1045
	mysqlDefaultPlugin   = "mysql_native_password"

	mysqlMaxPacketLen = 64 * 1024
	mysqlMaxAttrCount = 64
	mysqlMaxFieldLen  = 128

	mysqlClientLongPassword               uint32 = 0x00000001
	mysqlClientFoundRows                  uint32 = 0x00000002
	mysqlClientLongFlag                   uint32 = 0x00000004
	mysqlClientConnectWithDB              uint32 = 0x00000008
	mysqlClientProtocol41                 uint32 = 0x00000200
	mysqlClientSSL                        uint32 = 0x00000800
	mysqlClientTransactions               uint32 = 0x00002000
	mysqlClientSecureConnection           uint32 = 0x00008000
	mysqlClientPluginAuth                 uint32 = 0x00080000
	mysqlClientConnectAttrs               uint32 = 0x00100000
	mysqlClientPluginAuthLenencClientData uint32 = 0x00200000
)

const mysqlServerCaps = mysqlClientLongPassword |
	mysqlClientFoundRows |
	mysqlClientLongFlag |
	mysqlClientConnectWithDB |
	mysqlClientProtocol41 |
	mysqlClientTransactions |
	mysqlClientSecureConnection |
	mysqlClientPluginAuth |
	mysqlClientConnectAttrs |
	mysqlClientPluginAuthLenencClientData

type mysqlAuthInfo struct {
	Username      string
	Database      string
	AuthPlugin    string
	AuthResponse  []byte
	ClientName    string
	ClientVersion string
	ProgramName   string
}

func randomMySQLScramble() ([]byte, uint32, error) {
	var raw [24]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return nil, 0, err
	}
	scramble := make([]byte, 20)
	// Avoid NUL bytes in the scramble so C-string client parsers never truncate it.
	for i := 0; i < 20; i++ {
		scramble[i] = 0x21 + (raw[i] % 0x5e)
	}
	connID := binary.LittleEndian.Uint32(raw[20:24])
	if connID == 0 {
		connID = 1
	}
	return scramble, connID, nil
}

func wrapMySQLPacket(seq byte, payload []byte) []byte {
	n := len(payload)
	pkt := make([]byte, 4+n)
	pkt[0] = byte(n)
	pkt[1] = byte(n >> 8)
	pkt[2] = byte(n >> 16)
	pkt[3] = seq
	copy(pkt[4:], payload)
	return pkt
}

// buildMySQLHandshake builds a MySQL Protocol 10 Initial Handshake Packet (seq 0).
func buildMySQLHandshake(version string, connID uint32, scramble []byte) []byte {
	if len(scramble) < 20 {
		padded := make([]byte, 20)
		copy(padded, scramble)
		for i := len(scramble); i < 20; i++ {
			padded[i] = 'a'
		}
		scramble = padded
	}
	payload := make([]byte, 0, 64+len(version)+len(mysqlDefaultPlugin))
	payload = append(payload, mysqlProtocolVersion)
	payload = append(payload, version...)
	payload = append(payload, 0x00)
	payload = binary.LittleEndian.AppendUint32(payload, connID)
	payload = append(payload, scramble[:8]...)
	payload = append(payload, 0x00)
	payload = binary.LittleEndian.AppendUint16(payload, uint16(mysqlServerCaps&0xffff))
	payload = append(payload, mysqlCharsetUTF8MB4)
	payload = binary.LittleEndian.AppendUint16(payload, mysqlStatusAutocomit)
	payload = binary.LittleEndian.AppendUint16(payload, uint16(mysqlServerCaps>>16))
	payload = append(payload, 21) // auth_plugin_data_len (20 + NUL)
	payload = append(payload, make([]byte, 10)...)
	payload = append(payload, scramble[8:20]...)
	payload = append(payload, 0x00)
	payload = append(payload, mysqlDefaultPlugin...)
	payload = append(payload, 0x00)
	return wrapMySQLPacket(0, payload)
}

// buildMySQLErrPacket builds a MySQL ERR packet with SQLSTATE marker '#'.
func buildMySQLErrPacket(seq byte, code uint16, sqlState, message string) []byte {
	if len(sqlState) != 5 {
		sqlState = "HY000"
	}
	payload := make([]byte, 0, 9+len(message))
	payload = append(payload, 0xff)
	payload = binary.LittleEndian.AppendUint16(payload, code)
	payload = append(payload, '#')
	payload = append(payload, sqlState...)
	payload = append(payload, message...)
	return wrapMySQLPacket(seq, payload)
}

func readMySQLPacket(r io.Reader) (byte, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if length > mysqlMaxPacketLen {
		return 0, nil, fmt.Errorf("mysql packet length %d exceeds cap %d", length, mysqlMaxPacketLen)
	}
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return hdr[3], payload, nil
}

func readNullTerminated(b []byte, pos int) (string, int, bool) {
	if pos > len(b) {
		return "", pos, false
	}
	for i := pos; i < len(b); i++ {
		if b[i] == 0x00 {
			return string(b[pos:i]), i + 1, true
		}
	}
	return "", pos, false
}

func readLenencInt(b []byte, pos int) (uint64, int, bool) {
	if pos >= len(b) {
		return 0, pos, false
	}
	first := b[pos]
	switch {
	case first < 0xfb:
		return uint64(first), pos + 1, true
	case first == 0xfc:
		if pos+3 > len(b) {
			return 0, pos, false
		}
		return uint64(binary.LittleEndian.Uint16(b[pos+1 : pos+3])), pos + 3, true
	case first == 0xfd:
		if pos+4 > len(b) {
			return 0, pos, false
		}
		v := uint64(b[pos+1]) | uint64(b[pos+2])<<8 | uint64(b[pos+3])<<16
		return v, pos + 4, true
	case first == 0xfe:
		if pos+9 > len(b) {
			return 0, pos, false
		}
		return binary.LittleEndian.Uint64(b[pos+1 : pos+9]), pos + 9, true
	default:
		return 0, pos, false
	}
}

// parseMySQLHandshakeResponse parses a client HandshakeResponse41 (or SSLRequest).
// Returns (info, isSSLRequest, err).
func parseMySQLHandshakeResponse(payload []byte) (*mysqlAuthInfo, bool, error) {
	if len(payload) < 32 {
		return nil, false, errors.New("mysql handshake response truncated")
	}
	flags := binary.LittleEndian.Uint32(payload[0:4])
	if len(payload) == 32 && (flags&mysqlClientSSL) != 0 {
		return nil, true, nil
	}

	pos := 32
	user, next, ok := readNullTerminated(payload, pos)
	if !ok {
		return nil, false, errors.New("mysql handshake response missing username terminator")
	}
	pos = next

	var authResp []byte
	switch {
	case (flags & mysqlClientPluginAuthLenencClientData) != 0:
		n, nextPos, ok := readLenencInt(payload, pos)
		if !ok || n > uint64(len(payload)-nextPos) {
			return nil, false, errors.New("mysql handshake response invalid lenenc auth_response")
		}
		authResp = append([]byte(nil), payload[nextPos:nextPos+int(n)]...)
		pos = nextPos + int(n)
	case (flags & mysqlClientSecureConnection) != 0:
		if pos >= len(payload) {
			return nil, false, errors.New("mysql handshake response truncated auth_response length")
		}
		n := int(payload[pos])
		pos++
		if n > len(payload)-pos {
			return nil, false, errors.New("mysql handshake response truncated auth_response")
		}
		authResp = append([]byte(nil), payload[pos:pos+n]...)
		pos += n
	default:
		s, nextPos, ok := readNullTerminated(payload, pos)
		if !ok {
			return nil, false, errors.New("mysql handshake response missing auth_response terminator")
		}
		authResp = []byte(s)
		pos = nextPos
	}

	info := &mysqlAuthInfo{
		Username:     decoy.Sanitize(user, mysqlMaxFieldLen),
		AuthResponse: authResp,
	}

	if (flags&mysqlClientConnectWithDB) != 0 && pos < len(payload) {
		if db, nextPos, ok := readNullTerminated(payload, pos); ok {
			info.Database = decoy.Sanitize(db, mysqlMaxFieldLen)
			pos = nextPos
		}
	}

	if (flags&mysqlClientPluginAuth) != 0 && pos < len(payload) {
		if plugin, nextPos, ok := readNullTerminated(payload, pos); ok {
			info.AuthPlugin = decoy.Sanitize(plugin, mysqlMaxFieldLen)
			pos = nextPos
		}
	}

	if (flags&mysqlClientConnectAttrs) != 0 && pos < len(payload) {
		attrLen, nextPos, ok := readLenencInt(payload, pos)
		if ok && attrLen <= uint64(len(payload)-nextPos) {
			end := nextPos + int(attrLen)
			p := nextPos
			for count := 0; p < end && count < mysqlMaxAttrCount; count++ {
				kLen, kp, ok := readLenencInt(payload[:end], p)
				if !ok || kLen > uint64(end-kp) {
					break
				}
				k := string(payload[kp : kp+int(kLen)])
				p = kp + int(kLen)

				vLen, vp, ok := readLenencInt(payload[:end], p)
				if !ok || vLen > uint64(end-vp) {
					break
				}
				v := decoy.Sanitize(string(payload[vp:vp+int(vLen)]), mysqlMaxFieldLen)
				p = vp + int(vLen)

				switch k {
				case "_client_name":
					info.ClientName = v
				case "_client_version":
					info.ClientVersion = v
				case "program_name":
					info.ProgramName = v
				}
			}
		}
	}

	return info, false, nil
}

func (d *Decoy) handleMySQL(ctx context.Context, raw net.Conn, port int) {
	conn := newBoundedConn(raw, d.idleTimeout, d.totalTimeout)
	defer conn.Close()

	ip := decoy.RemoteIP(raw.RemoteAddr())

	scramble, connID, err := randomMySQLScramble()
	if err != nil {
		return
	}
	handshake := buildMySQLHandshake(d.cfg.MySQLVersion, connID, scramble)
	if _, err := conn.Write(handshake); err != nil {
		return
	}

	seq, payload, err := readMySQLPacket(conn)
	if err != nil {
		d.emitMySQLConnection(ip, port, false)
		return
	}

	info, isSSL, err := parseMySQLHandshakeResponse(payload)
	if err != nil || isSSL {
		d.emitMySQLConnection(ip, port, isSSL)
		return
	}

	if !d.pause(ctx, 100*time.Millisecond, 300*time.Millisecond) {
		return
	}

	yesNo := "NO"
	if len(info.AuthResponse) > 0 {
		yesNo = "YES"
	}
	errMsg := fmt.Sprintf("Access denied for user '%s'@'%s' (using password: %s)", info.Username, ip, yesNo)
	_, _ = conn.Write(buildMySQLErrPacket(seq+1, mysqlErrAccessDenied, "28000", errMsg))

	d.emitMySQLLogin(ip, port, info)
}

func (d *Decoy) emitMySQLLogin(ip string, port int, info *mysqlAuthInfo) {
	allowed, suppressed := d.allowLogin(ip, "mysql")
	if !allowed {
		return
	}
	fields := sensor.Fields{
		sensor.F("protocol", "mysql"),
		sensor.F("dst_port", port),
		sensor.F("username", info.Username),
		sensor.F("password_supplied", len(info.AuthResponse) > 0),
	}
	if info.Database != "" {
		fields = append(fields, sensor.F("database", info.Database))
	}
	if info.AuthPlugin != "" {
		fields = append(fields, sensor.F("auth_plugin", info.AuthPlugin))
	}
	if info.ClientName != "" {
		fields = append(fields, sensor.F("client_name", info.ClientName))
	}
	if info.ClientVersion != "" {
		fields = append(fields, sensor.F("client_version", info.ClientVersion))
	}
	if info.ProgramName != "" {
		fields = append(fields, sensor.F("program_name", info.ProgramName))
	}
	if len(info.AuthResponse) > 0 {
		fields = append(fields, d.capture.Secret("auth_response", hex.EncodeToString(info.AuthResponse))...)
	}
	if suppressed > 0 {
		fields = append(fields, sensor.F("suppressed_since_last", suppressed))
	}
	d.r.ReportSeverity(sensor.SeverityHigh, TriggerMySQLLogin, ip, fmt.Sprintf("MySQL port %d", port), fields)
}

func (d *Decoy) emitMySQLConnection(ip string, port int, sslRequested bool) {
	allowed, suppressed := d.allowConn(ip, "mysql")
	if !allowed {
		return
	}
	fields := sensor.Fields{
		sensor.F("protocol", "mysql"),
		sensor.F("dst_port", port),
	}
	if sslRequested {
		fields = append(fields, sensor.F("ssl_requested", true))
	}
	if suppressed > 0 {
		fields = append(fields, sensor.F("suppressed_since_last", suppressed))
	}
	d.r.ReportSeverity(sensor.SeverityMedium, TriggerMySQLConnection, ip, fmt.Sprintf("MySQL port %d", port), fields)
}
