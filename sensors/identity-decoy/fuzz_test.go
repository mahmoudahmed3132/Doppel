// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"bytes"
	"testing"
)

func FuzzLDAP(f *testing.F) {
	f.Add(makeLDAPSimpleBind(1, "CN=admin,DC=corp,DC=local", "secret"))
	f.Add(makeLDAPSimpleBind(1, "", ""))
	f.Add(makeLDAPSASLBind(2, "GSS-SPNEGO", makeSPNEGONegTokenInit(makeTestNTLMType1())))
	f.Add(makeLDAPSicilyBind(3, 10, makeTestNTLMType1()))
	f.Add(makeLDAPSearchPresent(4, "", 0, "objectClass"))
	f.Add([]byte{0x30, 0x80, 0x00, 0x00}) // indefinite length
	f.Add([]byte{0x30, 0xff})             // invalid length
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseLDAPMessage(data)
		if frame, err := readBERSequence(bytes.NewReader(data), maxLDAPMessageSize); err == nil {
			_, _ = parseLDAPMessage(frame)
		}
	})
}

func FuzzNTLM(f *testing.F) {
	t1 := makeTestNTLMType1()
	t3 := makeTestNTLMType3("CORP", "alice", "WKSTN01", []byte{1, 2, 3, 4, 5, 6, 7, 8}, true)
	f.Add(t1)
	f.Add(t3)
	f.Add(makeSPNEGONegTokenInit(t1))
	f.Add(makeSPNEGONegTokenResp(t3))
	f.Add([]byte("NTLMSSP\x00\x03\x00\x00\x00"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseNTLMType1(data)
		_, _ = parseNTLMType3(data)
		if inner, _, err := unwrapNTLMToken(data); err == nil {
			_, _ = parseNTLMType1(inner)
			_, _ = parseNTLMType3(inner)
		}
	})
}

func FuzzRDP(f *testing.F) {
	f.Add(makeX224ConnReqTPKT("jdoe", rdpProtoSSL|rdpProtoHybrid))
	f.Add(makeX224ConnReqTPKT("", rdpProtoRDP))
	f.Add(buildTSRequestNego(6, makeSPNEGONegTokenInit(makeTestNTLMType1())))
	f.Add(buildTSRequestError(6, ntStatusLogonFailure))
	f.Add([]byte{0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if tpdu, err := readTPKT(bytes.NewReader(data)); err == nil {
			_, _ = parseX224ConnReq(tpdu)
		}
		_, _ = parseX224ConnReq(data)
		_, _ = parseTSRequest(data)
		if frame, err := readBERSequence(bytes.NewReader(data), maxCredSSPSize); err == nil {
			_, _ = parseTSRequest(frame)
		}
	})
}
