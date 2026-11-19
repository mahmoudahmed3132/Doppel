// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
	"unicode/utf16"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/decoy"
	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

const (
	tdsHeaderLen     = 8
	tdsMaxPacketLen  = 32 * 1024
	tdsMaxMessageLen = 64 * 1024
	tdsMaxPackets    = 64
	tdsMaxFieldLen   = 128
	tdsMaxPassBytes  = 512

	tdsTypeTabularResult byte = 0x04
	tdsTypeLogin7        byte = 0x10
	tdsTypePrelogin      byte = 0x12

	tdsStatusEOM byte = 0x01

	tdsPreloginVersion    byte = 0x00
	tdsPreloginEncryption byte = 0x01
	tdsPreloginTerminator byte = 0xff
	tdsEncryptNotSup      byte = 0x02

	tdsTokenError byte   = 0xaa
	tdsTokenDone  byte   = 0xfd
	tdsDoneError  uint16 = 0x0002

	tdsErrLoginFailed int32  = 18456
	tdsVersion72      uint32 = 0x72000000
)

type tdsLoginInfo struct {
	TDSVersion  uint32
	Hostname    string
	Username    string
	Password    string
	AppName     string
	ServerName  string
	LibraryName string
	Database    string
}

func wrapTDSPacket(pktType byte, payload []byte) []byte {
	totalLen := tdsHeaderLen + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = pktType
	pkt[1] = tdsStatusEOM
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	// SPID = 0, PacketID = 1, Window = 0
	pkt[6] = 1
	copy(pkt[tdsHeaderLen:], payload)
	return pkt
}

// readTDSMessage reads and reassembles a single (possibly multi-packet) TDS
// message with strict per-packet (32 KiB) and total (64 KiB) length caps.
func readTDSMessage(r io.Reader) (byte, []byte, error) {
	var (
		pktType byte
		payload []byte
	)
	for i := 0; i < tdsMaxPackets; i++ {
		var hdr [tdsHeaderLen]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return 0, nil, err
		}
		length := int(binary.BigEndian.Uint16(hdr[2:4]))
		if length < tdsHeaderLen || length > tdsMaxPacketLen {
			return 0, nil, fmt.Errorf("tds packet length %d out of range", length)
		}
		if i == 0 {
			pktType = hdr[0]
		} else if hdr[0] != pktType {
			return 0, nil, fmt.Errorf("tds continuation packet type mismatch: 0x%02x != 0x%02x", hdr[0], pktType)
		}
		bodyLen := length - tdsHeaderLen
		if len(payload)+bodyLen > tdsMaxMessageLen {
			return 0, nil, fmt.Errorf("tds reassembled message exceeds %d bytes", tdsMaxMessageLen)
		}
		if bodyLen > 0 {
			chunk := make([]byte, bodyLen)
			if _, err := io.ReadFull(r, chunk); err != nil {
				return 0, nil, err
			}
			payload = append(payload, chunk...)
		}
		if (hdr[1] & tdsStatusEOM) != 0 {
			return pktType, payload, nil
		}
	}
	return 0, nil, errors.New("tds message exceeded maximum packet count")
}

// buildTDSPreloginResponse builds a Tabular Result packet carrying VERSION and
// ENCRYPTION = ENCRYPT_NOT_SUP (0x02).
func buildTDSPreloginResponse(ver MSSQLVersion) []byte {
	// Header: 2 options (5 bytes each) + 1 terminator = 11 bytes.
	// Data: 6 bytes VERSION (at offset 11) + 1 byte ENCRYPTION (at offset 17).
	payload := make([]byte, 18)
	// Option 0: VERSION
	payload[0] = tdsPreloginVersion
	binary.BigEndian.PutUint16(payload[1:3], 11)
	binary.BigEndian.PutUint16(payload[3:5], 6)
	// Option 1: ENCRYPTION
	payload[5] = tdsPreloginEncryption
	binary.BigEndian.PutUint16(payload[6:8], 17)
	binary.BigEndian.PutUint16(payload[8:10], 1)
	// Terminator
	payload[10] = tdsPreloginTerminator
	// VERSION data
	payload[11] = ver.Major
	payload[12] = ver.Minor
	binary.BigEndian.PutUint16(payload[13:15], ver.Build)
	binary.BigEndian.PutUint16(payload[15:17], 0) // subbuild
	// ENCRYPTION data
	payload[17] = tdsEncryptNotSup
	return wrapTDSPacket(tdsTypeTabularResult, payload)
}

func decodeUTF16LE(b []byte) string {
	n := len(b) / 2
	if n == 0 {
		return ""
	}
	u := make([]uint16, n)
	for i := 0; i < n; i++ {
		u[i] = binary.LittleEndian.Uint16(b[2*i : 2*i+2])
	}
	return string(utf16.Decode(u))
}

func encodeUTF16LE(s string) ([]byte, int) {
	u := utf16.Encode([]rune(s))
	out := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(out[2*i:2*i+2], c)
	}
	return out, len(u)
}

// deobfuscateTDSPassword reverses MS-TDS LOGIN7 password obfuscation:
// XOR each byte with 0xA5, swap high/low nibbles, then decode UTF-16LE.
// The temporary plaintext buffer is zeroed before returning.
func deobfuscateTDSPassword(enc []byte) string {
	if len(enc) == 0 {
		return ""
	}
	if len(enc) > tdsMaxPassBytes {
		enc = enc[:tdsMaxPassBytes]
	}
	buf := make([]byte, len(enc))
	defer clear(buf)
	for i, b := range enc {
		b ^= 0xa5
		buf[i] = (b << 4) | (b >> 4)
	}
	return decodeUTF16LE(buf)
}

// parseTDSLogin7 parses a MS-TDS 7.x LOGIN7 message payload.
func parseTDSLogin7(payload []byte) (*tdsLoginInfo, error) {
	// Minimum size covers the 36-byte fixed header + offset/length pairs through
	// ibDatabase/cchDatabase (bytes 36..71).
	if len(payload) < 72 {
		return nil, errors.New("tds login7 payload too short")
	}

	readField := func(offPos int) (string, error) {
		ib := int(binary.LittleEndian.Uint16(payload[offPos : offPos+2]))
		cch := int(binary.LittleEndian.Uint16(payload[offPos+2 : offPos+4]))
		if cch == 0 {
			return "", nil
		}
		byteLen := cch * 2
		if ib < 36 || ib+byteLen > len(payload) {
			return "", fmt.Errorf("tds login7 field at %d out of bounds (off=%d, chars=%d, len=%d)", offPos, ib, cch, len(payload))
		}
		return decoy.Sanitize(decodeUTF16LE(payload[ib:ib+byteLen]), tdsMaxFieldLen), nil
	}

	var (
		info = &tdsLoginInfo{
			TDSVersion: binary.LittleEndian.Uint32(payload[4:8]),
		}
		err error
	)
	if info.Hostname, err = readField(36); err != nil {
		return nil, err
	}
	if info.Username, err = readField(40); err != nil {
		return nil, err
	}
	// Password at offset 44: bounds-checked and de-obfuscated.
	passOff := int(binary.LittleEndian.Uint16(payload[44:46]))
	passChars := int(binary.LittleEndian.Uint16(payload[46:48]))
	if passChars > 0 {
		passBytes := passChars * 2
		if passOff < 36 || passOff+passBytes > len(payload) {
			return nil, fmt.Errorf("tds login7 password out of bounds (off=%d, chars=%d, len=%d)", passOff, passChars, len(payload))
		}
		info.Password = deobfuscateTDSPassword(payload[passOff : passOff+passBytes])
	}
	if info.AppName, err = readField(48); err != nil {
		return nil, err
	}
	if info.ServerName, err = readField(52); err != nil {
		return nil, err
	}
	if info.LibraryName, err = readField(60); err != nil {
		return nil, err
	}
	if info.Database, err = readField(68); err != nil {
		return nil, err
	}
	return info, nil
}

// buildTDSErrorDoneResponse builds a Tabular Result packet containing an ERROR
// token (18456, state 1, class 14) followed by a DONE token (DONE_ERROR).
func buildTDSErrorDoneResponse(user, serverName string, tdsVersion uint32) []byte {
	msg := fmt.Sprintf("Login failed for user '%s'.", user)
	msgBytes, msgChars := encodeUTF16LE(msg)
	srvBytes, srvChars := encodeUTF16LE(serverName)
	if srvChars > 128 {
		srvChars = 128
		srvBytes = srvBytes[:256]
	}

	tds72Plus := tdsVersion == 0 || tdsVersion >= tdsVersion72

	// ERROR token body:
	// Number(4) + State(1) + Class(1) + MsgLen(2) + Msg + SrvLen(1) + Srv + ProcLen(1) + Line(4 or 2)
	lineBytes := 2
	if tds72Plus {
		lineBytes = 4
	}
	errBodyLen := 4 + 1 + 1 + 2 + len(msgBytes) + 1 + len(srvBytes) + 1 + lineBytes
	errTok := make([]byte, 0, 3+errBodyLen)
	errTok = append(errTok, tdsTokenError)
	errTok = binary.LittleEndian.AppendUint16(errTok, uint16(errBodyLen))
	errTok = binary.LittleEndian.AppendUint32(errTok, uint32(tdsErrLoginFailed))
	errTok = append(errTok, 1)  // State
	errTok = append(errTok, 14) // Class (severity)
	errTok = binary.LittleEndian.AppendUint16(errTok, uint16(msgChars))
	errTok = append(errTok, msgBytes...)
	errTok = append(errTok, uint8(srvChars))
	errTok = append(errTok, srvBytes...)
	errTok = append(errTok, 0) // ProcName length = 0
	if tds72Plus {
		errTok = binary.LittleEndian.AppendUint32(errTok, 1) // LineNumber
	} else {
		errTok = binary.LittleEndian.AppendUint16(errTok, 1)
	}

	// DONE token:
	// Type(1) + Status(2) + CurCmd(2) + DoneRowCount(8 for TDS 7.2+, 4 for < 7.2)
	doneTok := make([]byte, 0, 13)
	doneTok = append(doneTok, tdsTokenDone)
	doneTok = binary.LittleEndian.AppendUint16(doneTok, tdsDoneError)
	doneTok = binary.LittleEndian.AppendUint16(doneTok, 0)
	if tds72Plus {
		doneTok = binary.LittleEndian.AppendUint64(doneTok, 0)
	} else {
		doneTok = binary.LittleEndian.AppendUint32(doneTok, 0)
	}

	payload := append(errTok, doneTok...)
	return wrapTDSPacket(tdsTypeTabularResult, payload)
}

func (d *Decoy) handleMSSQL(ctx context.Context, raw net.Conn, port int) {
	conn := newBoundedConn(raw, d.idleTimeout, d.totalTimeout)
	defer conn.Close()

	ip := decoy.RemoteIP(raw.RemoteAddr())

	pktType, payload, err := readTDSMessage(conn)
	if err != nil {
		d.emitMSSQLConnection(ip, port)
		return
	}

	if pktType == tdsTypePrelogin {
		if _, err := conn.Write(buildTDSPreloginResponse(d.cfg.MSSQLVer)); err != nil {
			d.emitMSSQLConnection(ip, port)
			return
		}
		pktType, payload, err = readTDSMessage(conn)
		if err != nil {
			d.emitMSSQLConnection(ip, port)
			return
		}
	}

	if pktType != tdsTypeLogin7 {
		d.emitMSSQLConnection(ip, port)
		return
	}

	info, err := parseTDSLogin7(payload)
	if err != nil {
		d.emitMSSQLConnection(ip, port)
		return
	}

	if !d.pause(ctx, 100*time.Millisecond, 300*time.Millisecond) {
		return
	}

	_, _ = conn.Write(buildTDSErrorDoneResponse(info.Username, d.cfg.MSSQLServerName, info.TDSVersion))
	d.emitMSSQLLogin(ip, port, info)
}

func (d *Decoy) emitMSSQLLogin(ip string, port int, info *tdsLoginInfo) {
	allowed, suppressed := d.allowLogin(ip, "mssql")
	if !allowed {
		return
	}
	fields := sensor.Fields{
		sensor.F("protocol", "mssql"),
		sensor.F("dst_port", port),
		sensor.F("username", info.Username),
	}
	if info.Hostname != "" {
		fields = append(fields, sensor.F("hostname", info.Hostname))
	}
	if info.AppName != "" {
		fields = append(fields, sensor.F("app_name", info.AppName))
	}
	if info.ServerName != "" {
		fields = append(fields, sensor.F("server_name", info.ServerName))
	}
	if info.LibraryName != "" {
		fields = append(fields, sensor.F("library_name", info.LibraryName))
	}
	if info.Database != "" {
		fields = append(fields, sensor.F("database", info.Database))
	}
	fields = append(fields, d.capture.Password(info.Password)...)
	if suppressed > 0 {
		fields = append(fields, sensor.F("suppressed_since_last", suppressed))
	}
	d.r.ReportSeverity(sensor.SeverityHigh, TriggerMSSQLLogin, ip, fmt.Sprintf("MSSQL port %d", port), fields)
}

func (d *Decoy) emitMSSQLConnection(ip string, port int) {
	allowed, suppressed := d.allowConn(ip, "mssql")
	if !allowed {
		return
	}
	fields := sensor.Fields{
		sensor.F("protocol", "mssql"),
		sensor.F("dst_port", port),
	}
	if suppressed > 0 {
		fields = append(fields, sensor.F("suppressed_since_last", suppressed))
	}
	d.r.ReportSeverity(sensor.SeverityMedium, TriggerMSSQLConnection, ip, fmt.Sprintf("MSSQL port %d", port), fields)
}
