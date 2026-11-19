// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func FuzzMySQL(f *testing.F) {
	f.Add(buildClientMySQLHandshakeResponse("root", []byte("scramble"), "appdb", "mysql_native_password", map[string]string{
		"_client_name": "libmysql",
		"program_name": "mysql",
	}))
	sslReq := make([]byte, 32)
	binary.LittleEndian.PutUint32(sslReq[0:4], mysqlClientProtocol41|mysqlClientSSL)
	f.Add(wrapMySQLPacket(1, sslReq))
	f.Add([]byte{0xff, 0xff, 0xff, 0x01})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, payload, err := readMySQLPacket(bytes.NewReader(data))
		if err == nil {
			_, _, _ = parseMySQLHandshakeResponse(payload)
		}
		_, _, _ = parseMySQLHandshakeResponse(data)
	})
}

func FuzzPostgres(f *testing.F) {
	var startup bytes.Buffer
	binary.Write(&startup, binary.BigEndian, pgCodeSSLRequest)
	var sslFrame [8]byte
	binary.BigEndian.PutUint32(sslFrame[0:4], 8)
	binary.BigEndian.PutUint32(sslFrame[4:8], pgCodeSSLRequest)
	f.Add(sslFrame[:])

	var body bytes.Buffer
	binary.Write(&body, binary.BigEndian, pgProtocolV3)
	body.WriteString("user\x00postgres\x00database\x00prod\x00application_name\x00psql\x00\x00")
	frame := make([]byte, 4+body.Len())
	binary.BigEndian.PutUint32(frame[0:4], uint32(len(frame)))
	copy(frame[4:], body.Bytes())
	pw := []byte{'p', 0, 0, 0, 11, 's', 'e', 'c', 'r', 'e', 't', 0}
	f.Add(append(frame, pw...))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = parsePostgresWireMessage(data)
		_ = parsePostgresStartupParams(data)
	})
}

func FuzzTDS(f *testing.F) {
	f.Add(wrapTDSPacket(tdsTypePrelogin, []byte{tdsPreloginTerminator}))
	f.Add(wrapTDSPacket(tdsTypeLogin7, buildClientTDSLogin7("HOST", "sa", "pass", "app", "srv", "lib", "master")))
	f.Add([]byte{tdsTypeLogin7, tdsStatusEOM, 0xff, 0xff, 0, 0, 1, 0})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, payload, err := readTDSMessage(bytes.NewReader(data))
		if err == nil {
			_, _ = parseTDSLogin7(payload)
		}
		_, _ = parseTDSLogin7(data)
		_ = deobfuscateTDSPassword(data)
	})
}
