// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package ber

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	for _, v := range []int64{0, 1, 127, 128, 255, 256, -1, -128, -129, 1 << 31, -(1 << 40), 1<<63 - 1, -1 << 63} {
		r, _ := NewReader(Integer(v), Limits{})
		e, err := r.Expect(Universal, TagInteger)
		if err != nil {
			t.Fatal(v, err)
		}
		if got, err := e.Int(); err != nil || got != v {
			t.Errorf("int %d -> %d, %v", v, got, err)
		}
	}
	arcs := []uint32{1, 3, 6, 1, 2, 1, 1, 1, 0}
	r, _ := NewReader(OID(arcs), Limits{})
	e, _ := r.Next()
	if got, err := e.OID(32); err != nil || !reflect.DeepEqual(got, arcs) {
		t.Errorf("oid %v, %v", got, err)
	}
	long := bytes.Repeat([]byte{'a'}, 70000)
	r, err := NewReader(OctetString(long), Limits{MaxMessage: 80000})
	if err != nil {
		t.Fatal(err)
	}
	if e, err := r.Next(); err != nil || len(e.Value) != 70000 {
		t.Errorf("long string: %v", err)
	}
}

func TestStructure(t *testing.T) {
	msg := Sequence(Integer(1), Encode(Application, true, 0, Cat(Integer(3), OctetString(nil), Encode(ContextSpecific, false, 0, []byte("pw")))))
	r, _ := NewReader(msg, Limits{})
	seq, err := r.Expect(Universal, TagSequence)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := seq.Children()
	if id, _ := c.Next(); id.Number != TagInteger {
		t.Fatal("id")
	}
	op, _ := c.Expect(Application, 0)
	oc, _ := op.Children()
	oc.Next()
	oc.Next()
	pw, _ := oc.Expect(ContextSpecific, 0)
	if string(pw.Value) != "pw" || r.Len() != 0 || c.Len() != 0 {
		t.Error("walk")
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]struct {
		in   []byte
		want error
	}{
		"indefinite":     {[]byte{0x30, 0x80, 0, 0}, ErrIndefinite},
		"truncated body": {[]byte{0x04, 0x05, 'a'}, ErrTruncated},
		"truncated len":  {[]byte{0x04, 0x82, 0x01}, ErrTruncated},
		"len 5 bytes":    {[]byte{0x04, 0x85, 0, 0, 0, 0, 1, 'a'}, ErrLength},
		"len 0xff":       {[]byte{0x04, 0xff}, ErrLength},
		"huge length":    {[]byte{0x04, 0x84, 0xff, 0xff, 0xff, 0xff}, ErrTooLarge},
		"empty tag":      {[]byte{}, ErrTruncated},
		"long tag cut":   {[]byte{0x1f, 0x81}, ErrTruncated},
		"nonminimal tag": {[]byte{0x1f, 0x80, 0x01, 0x00}, ErrTag},
		"low high-form":  {[]byte{0x1f, 0x05, 0x00}, ErrTag},
	}
	for name, c := range cases {
		r, err := NewReader(c.in, Limits{})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if _, err := r.Next(); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", name, err, c.want)
		}
	}
	if _, err := NewReader(make([]byte, 100), Limits{MaxMessage: 50}); !errors.Is(err, ErrTooLarge) {
		t.Error("max message")
	}
	// depth
	msg := Null()
	for i := 0; i < 20; i++ {
		msg = Sequence(msg)
	}
	r, _ := NewReader(msg, Limits{MaxDepth: 4})
	e, _ := r.Next()
	var err error
	for i := 0; i < 10 && err == nil; i++ {
		var c *Reader
		if c, err = e.Children(); err == nil {
			e, err = c.Next()
		}
	}
	if !errors.Is(err, ErrDepth) {
		t.Errorf("depth: %v", err)
	}
	if _, err := (Element{Value: []byte{1}}).Children(); !errors.Is(err, ErrType) {
		t.Error("primitive children")
	}
	for _, v := range [][]byte{nil, {0, 0}, {0xff, 0x80}, make([]byte, 9)} {
		if _, err := (Element{Value: v}).Int(); err == nil {
			t.Errorf("int %x accepted", v)
		}
	}
	for _, v := range [][]byte{nil, {0x80, 0x01}, {0x81}, {0xff, 0xff, 0xff, 0xff, 0x7f}} {
		if _, err := (Element{Value: v}).OID(32); err == nil {
			t.Errorf("oid %x accepted", v)
		}
	}
	if _, err := (Element{Value: []byte{0x2b, 1, 1, 1, 1}}).OID(3); err == nil {
		t.Error("oid arc cap")
	}
}

func FuzzReader(f *testing.F) {
	f.Add(Sequence(Integer(1), OctetString([]byte("x")), OID([]uint32{1, 3, 6, 1})))
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{0x1f, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := NewReader(b, Limits{MaxMessage: 4096, MaxDepth: 6})
		if err != nil {
			return
		}
		var walk func(*Reader, int)
		walk = func(r *Reader, n int) {
			for r.Len() > 0 && n < 1000 {
				e, err := r.Next()
				if err != nil {
					return
				}
				e.Int()
				e.OID(16)
				e.Bool()
				if e.Constructed {
					if c, err := e.Children(); err == nil {
						walk(c, n+1)
					}
				}
			}
		}
		walk(r, 0)
	})
}
