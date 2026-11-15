// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package ber is a strict reader and a small writer for the BER subset used
// by LDAP (RFC 4511) and SNMP (RFC 3416), per ITU-T X.690.
//
// The reader is built for untrusted input: only definite lengths are
// accepted, a length is checked against the bytes actually present before
// anything is sliced or allocated, tag numbers and length fields have fixed
// maxima, and nesting depth is bounded. It never panics and never allocates
// in proportion to a length the peer claims.
package ber

import (
	"errors"
	"fmt"
)

// Class is the tag class (X.690 8.1.2.2).
type Class byte

// Tag classes.
const (
	Universal       Class = 0
	Application     Class = 1
	ContextSpecific Class = 2
	Private         Class = 3
)

// Universal tag numbers used by LDAP and SNMP.
const (
	TagBoolean     = 1
	TagInteger     = 2
	TagOctetString = 4
	TagNull        = 5
	TagOID         = 6
	TagEnumerated  = 10
	TagSequence    = 16
	TagSet         = 17
)

// Limits bound what the reader accepts.
type Limits struct {
	MaxMessage int // total bytes of the outermost element (default 65536)
	MaxDepth   int // nesting depth of constructed elements (default 8)
}

// DefaultLimits are used when a field is zero.
var DefaultLimits = Limits{MaxMessage: 64 << 10, MaxDepth: 8}

// Errors returned by the reader.
var (
	ErrTruncated  = errors.New("ber: truncated")
	ErrIndefinite = errors.New("ber: indefinite length not accepted")
	ErrLength     = errors.New("ber: bad length")
	ErrTag        = errors.New("ber: bad tag")
	ErrTooLarge   = errors.New("ber: message too large")
	ErrDepth      = errors.New("ber: nesting too deep")
	ErrType       = errors.New("ber: unexpected type")
	ErrValue      = errors.New("ber: bad value")
)

// Element is one decoded TLV. Value aliases the input buffer.
type Element struct {
	Class       Class
	Constructed bool
	Number      uint32
	Value       []byte
	depth       int
	limits      Limits
}

// Is reports whether the element has the given class and tag number.
func (e Element) Is(c Class, n uint32) bool { return e.Class == c && e.Number == n }

// Reader iterates over consecutive elements of a buffer.
type Reader struct {
	b      []byte
	depth  int
	limits Limits
}

// NewReader returns a reader over b. Zero limit fields take their defaults.
// The whole buffer must not exceed MaxMessage.
func NewReader(b []byte, l Limits) (*Reader, error) {
	if l.MaxMessage <= 0 {
		l.MaxMessage = DefaultLimits.MaxMessage
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = DefaultLimits.MaxDepth
	}
	if len(b) > l.MaxMessage {
		return nil, ErrTooLarge
	}
	return &Reader{b: b, limits: l}, nil
}

// Len is the number of unread bytes.
func (r *Reader) Len() int { return len(r.b) }

// Next decodes the next element. It returns ErrTruncated at end of input; use
// Len to test for the end first.
func (r *Reader) Next() (Element, error) {
	b := r.b
	if len(b) == 0 {
		return Element{}, ErrTruncated
	}
	id := b[0]
	e := Element{Class: Class(id >> 6), Constructed: id&0x20 != 0, depth: r.depth, limits: r.limits}
	n := uint32(id & 0x1f)
	i := 1
	if n == 0x1f { // high-tag-number form
		n = 0
		for k := 0; ; k++ {
			if i >= len(b) {
				return Element{}, ErrTruncated
			}
			c := b[i]
			i++
			if k == 0 && c == 0x80 || k >= 4 {
				return Element{}, ErrTag // non-minimal or too long
			}
			n = n<<7 | uint32(c&0x7f)
			if c&0x80 == 0 {
				break
			}
		}
		if n < 0x1f {
			return Element{}, ErrTag
		}
	}
	e.Number = n
	if i >= len(b) {
		return Element{}, ErrTruncated
	}
	lb := b[i]
	i++
	var length int
	switch {
	case lb < 0x80:
		length = int(lb)
	case lb == 0x80:
		return Element{}, ErrIndefinite
	case lb == 0xff:
		return Element{}, ErrLength
	default:
		nb := int(lb & 0x7f)
		if nb > 4 || i+nb > len(b) {
			if nb > 4 {
				return Element{}, ErrLength
			}
			return Element{}, ErrTruncated
		}
		var v uint64
		for k := 0; k < nb; k++ {
			v = v<<8 | uint64(b[i+k])
		}
		i += nb
		if v > uint64(r.limits.MaxMessage) {
			return Element{}, ErrTooLarge
		}
		length = int(v)
	}
	if length > len(b)-i {
		return Element{}, ErrTruncated
	}
	e.Value = b[i : i+length]
	r.b = b[i+length:]
	return e, nil
}

// Children returns a reader over the contents of a constructed element.
func (e Element) Children() (*Reader, error) {
	if !e.Constructed {
		return nil, ErrType
	}
	if e.depth+1 > e.limits.MaxDepth {
		return nil, ErrDepth
	}
	return &Reader{b: e.Value, depth: e.depth + 1, limits: e.limits}, nil
}

// Expect reads the next element and checks its class and number.
func (r *Reader) Expect(c Class, n uint32) (Element, error) {
	e, err := r.Next()
	if err != nil {
		return e, err
	}
	if !e.Is(c, n) {
		return e, fmt.Errorf("%w: got class %d number %d", ErrType, e.Class, e.Number)
	}
	return e, nil
}

// Int decodes an INTEGER or ENUMERATED value of up to 8 bytes.
func (e Element) Int() (int64, error) {
	v := e.Value
	if len(v) == 0 || len(v) > 8 {
		return 0, ErrValue
	}
	if len(v) > 1 && (v[0] == 0x00 && v[1]&0x80 == 0 || v[0] == 0xff && v[1]&0x80 != 0) {
		return 0, ErrValue // non-minimal encoding
	}
	n := int64(int8(v[0]))
	for _, c := range v[1:] {
		n = n<<8 | int64(c)
	}
	return n, nil
}

// Bool decodes a BOOLEAN (DER requires 0xff for true; BER allows any non-zero).
func (e Element) Bool() (bool, error) {
	if len(e.Value) != 1 {
		return false, ErrValue
	}
	return e.Value[0] != 0, nil
}

// OID decodes an OBJECT IDENTIFIER into its arcs (at most maxArcs).
func (e Element) OID(maxArcs int) ([]uint32, error) {
	v := e.Value
	if len(v) == 0 {
		return nil, ErrValue
	}
	var arcs []uint32
	var cur uint64
	started := false
	for _, c := range v {
		if !started && c == 0x80 {
			return nil, ErrValue
		}
		started = true
		cur = cur<<7 | uint64(c&0x7f)
		if cur > 0xffffffff {
			return nil, ErrValue
		}
		if c&0x80 != 0 {
			continue
		}
		if len(arcs) == 0 { // first sub-identifier carries two arcs
			switch {
			case cur < 40:
				arcs = append(arcs, 0, uint32(cur))
			case cur < 80:
				arcs = append(arcs, 1, uint32(cur-40))
			default:
				arcs = append(arcs, 2, uint32(cur-80))
			}
		} else {
			arcs = append(arcs, uint32(cur))
		}
		if len(arcs) > maxArcs {
			return nil, ErrValue
		}
		cur, started = 0, false
	}
	if started {
		return nil, ErrTruncated
	}
	return arcs, nil
}
