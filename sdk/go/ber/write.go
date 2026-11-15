// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package ber

// Encode returns one TLV with a definite length. Tag numbers above 30 are
// not needed by LDAP or SNMP and are encoded in the high-tag-number form.
func Encode(c Class, constructed bool, number uint32, content []byte) []byte {
	id := byte(c) << 6
	if constructed {
		id |= 0x20
	}
	out := make([]byte, 0, len(content)+8)
	if number < 0x1f {
		out = append(out, id|byte(number))
	} else {
		out = append(out, id|0x1f)
		var tmp [5]byte
		i := len(tmp)
		for n := number; ; n >>= 7 {
			i--
			tmp[i] = byte(n & 0x7f)
			if n < 0x80 {
				break
			}
		}
		for k := i; k < len(tmp)-1; k++ {
			tmp[k] |= 0x80
		}
		out = append(out, tmp[i:]...)
	}
	switch l := len(content); {
	case l < 0x80:
		out = append(out, byte(l))
	case l < 1<<8:
		out = append(out, 0x81, byte(l))
	case l < 1<<16:
		out = append(out, 0x82, byte(l>>8), byte(l))
	case l < 1<<24:
		out = append(out, 0x83, byte(l>>16), byte(l>>8), byte(l))
	default:
		out = append(out, 0x84, byte(l>>24), byte(l>>16), byte(l>>8), byte(l))
	}
	return append(out, content...)
}

// Cat concatenates encoded elements.
func Cat(parts ...[]byte) []byte {
	var n int
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// Sequence encodes a universal SEQUENCE.
func Sequence(parts ...[]byte) []byte {
	return Encode(Universal, true, TagSequence, Cat(parts...))
}

// OctetString encodes an OCTET STRING.
func OctetString(b []byte) []byte { return Encode(Universal, false, TagOctetString, b) }

// Null encodes NULL.
func Null() []byte { return Encode(Universal, false, TagNull, nil) }

// Boolean encodes a BOOLEAN (0xff for true).
func Boolean(v bool) []byte {
	b := byte(0)
	if v {
		b = 0xff
	}
	return Encode(Universal, false, TagBoolean, []byte{b})
}

func intBytes(v int64) []byte {
	var b []byte
	for {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
		if (v == 0 && b[0]&0x80 == 0) || (v == -1 && b[0]&0x80 != 0) {
			return b
		}
	}
}

// Integer encodes an INTEGER.
func Integer(v int64) []byte { return Encode(Universal, false, TagInteger, intBytes(v)) }

// Enumerated encodes an ENUMERATED.
func Enumerated(v int64) []byte { return Encode(Universal, false, TagEnumerated, intBytes(v)) }

// OID encodes an OBJECT IDENTIFIER from arcs (at least two, first arc 0-2).
func OID(arcs []uint32) []byte {
	if len(arcs) < 2 {
		return Encode(Universal, false, TagOID, nil)
	}
	var out []byte
	put := func(v uint64) {
		var tmp [10]byte
		i := len(tmp)
		for ; ; v >>= 7 {
			i--
			tmp[i] = byte(v & 0x7f)
			if v < 0x80 {
				break
			}
		}
		for k := i; k < len(tmp)-1; k++ {
			tmp[k] |= 0x80
		}
		out = append(out, tmp[i:]...)
	}
	put(uint64(arcs[0])*40 + uint64(arcs[1]))
	for _, a := range arcs[2:] {
		put(uint64(a))
	}
	return Encode(Universal, false, TagOID, out)
}
