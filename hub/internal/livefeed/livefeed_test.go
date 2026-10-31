// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package livefeed

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
)

// dial performs a client handshake and returns the raw connection.
func dial(t *testing.T, url string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(url, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 16)
	rand.Read(key)
	k := base64.StdEncoding.EncodeToString(key)
	io.WriteString(c, "GET /live HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "+k+"\r\nSec-WebSocket-Version: 13\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 || resp.Header.Get("Sec-WebSocket-Accept") == "" {
		t.Fatalf("handshake: %v %v", resp, err)
	}
	return c, br
}

func readFrame(t *testing.T, br *bufio.Reader) (byte, []byte) {
	t.Helper()
	var h [2]byte
	if _, err := io.ReadFull(br, h[:]); err != nil {
		t.Fatal(err)
	}
	n := int(h[1] & 0x7f)
	if n == 126 {
		var e [2]byte
		io.ReadFull(br, e[:])
		n = int(binary.BigEndian.Uint16(e[:]))
	} else if n == 127 {
		var e [8]byte
		io.ReadFull(br, e[:])
		n = int(binary.BigEndian.Uint64(e[:]))
	}
	p := make([]byte, n)
	io.ReadFull(br, p)
	return h[0] & 0x0f, p
}

func clientFrame(op byte, payload []byte, masked bool) []byte {
	b := []byte{0x80 | op}
	if masked {
		b = append(b, 0x80|byte(len(payload)), 1, 2, 3, 4)
		for i, c := range payload {
			b = append(b, c^[]byte{1, 2, 3, 4}[i%4])
		}
		return b
	}
	return append(append(b, byte(len(payload))), payload...)
}

func server(t *testing.T, b *Broker) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := Upgrade(w, r)
		if err != nil {
			http.Error(w, "bad", 400)
			return
		}
		ch, cancel := b.Subscribe()
		defer cancel()
		for {
			select {
			case m, ok := <-ch:
				if !ok {
					c.Close(1008)
					return
				}
				if c.WriteText(m) != nil {
					return
				}
			case <-c.Done():
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func waitClients(t *testing.T, b *Broker, n int) {
	deadline := time.Now().Add(2 * time.Second)
	for b.Clients() != n {
		if time.Now().After(deadline) {
			t.Fatalf("clients %d, want %d", b.Clients(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPushEventStatusRefresh(t *testing.T) {
	b := NewBroker()
	b.Debounce = 20 * time.Millisecond
	srv := server(t, b)
	c, br := dial(t, srv.URL)
	defer c.Close()
	waitClients(t, b, 1)

	b.PublishEvent(domain.EnrichedEvent{Event: domain.Event{EventID: "e1", Trigger: "tcp_connection", Details: []byte("{}")}})
	b.PublishStatus("node-1", "ts-sensor-a", domain.StatusOffline, time.Now())
	var types []string
	for i := 0; i < 3; i++ {
		op, p := readFrame(t, br)
		if op != opText {
			t.Fatalf("opcode %d", op)
		}
		var m Message
		json.Unmarshal(p, &m)
		types = append(types, m.Type)
	}
	if strings.Join(types, ",") != "event,status,refresh" {
		t.Fatalf("%v (refresh must be debounced into one)", types)
	}
	// Ping is answered with pong.
	c.Write(clientFrame(opPing, []byte("hi"), true))
	if op, p := readFrame(t, br); op != opPong || string(p) != "hi" {
		t.Fatalf("pong %d %q", op, p)
	}
}

func TestUnmaskedOrOversizedClientFramesClose(t *testing.T) {
	b := NewBroker()
	srv := server(t, b)
	c, br := dial(t, srv.URL)
	c.Write(clientFrame(opText, []byte("x"), false))
	if op, p := readFrame(t, br); op != opClose || binary.BigEndian.Uint16(p) != 1002 {
		t.Fatalf("%d %v", op, p)
	}
	c.Close()

	c, br = dial(t, srv.URL)
	defer c.Close()
	big := []byte{0x81, 0x80 | 126, 0x20, 0x00, 1, 2, 3, 4} // 8192-byte masked frame header
	c.Write(big)
	if op, p := readFrame(t, br); op != opClose || binary.BigEndian.Uint16(p) != 1009 {
		t.Fatalf("%d %v", op, p)
	}
}

func TestSlowClientDropped(t *testing.T) {
	b := NewBroker()
	ch, cancel := b.Subscribe()
	defer cancel()
	for i := 0; i < clientBuffer+5; i++ {
		b.Tick(time.Now())
	}
	if b.Clients() != 0 {
		t.Fatal("slow client kept")
	}
	n := 0
	for range ch {
		n++
	}
	if n != clientBuffer {
		t.Fatalf("buffered %d", n)
	}
}

func TestHandshakeValidation(t *testing.T) {
	srv := server(t, NewBroker())
	resp, _ := http.Get(srv.URL)
	if resp.StatusCode != 400 {
		t.Fatal("plain GET upgraded")
	}
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "short")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 400 {
		t.Fatal("bad key accepted")
	}
}

func TestAcceptKeyRFC6455Example(t *testing.T) {
	// RFC 6455 §1.3 worked example.
	if got := acceptKey("dGhlIHNhbXBsZSBub25jZQ=="); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("%s", got)
	}
}
