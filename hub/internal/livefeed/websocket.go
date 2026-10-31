// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package livefeed

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RFC 6455 constants.
const (
	wsGUID       = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	opText       = 0x1
	opClose      = 0x8
	opPing       = 0x9
	opPong       = 0xA
	maxClientMsg = 4096
	writeWait    = 10 * time.Second
)

// ErrHandshake is returned for a request that is not a valid upgrade.
var ErrHandshake = errors.New("not a websocket upgrade")

func headerHas(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, p := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(p), token) {
				return true
			}
		}
	}
	return false
}

// acceptKey computes Sec-WebSocket-Accept (RFC 6455 §4.2.2).
func acceptKey(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// Conn is a server-side WebSocket that only sends text frames.
type Conn struct {
	nc     net.Conn
	br     *bufio.Reader
	wmu    sync.Mutex
	closed chan struct{}
	once   sync.Once
}

// Upgrade completes the handshake and hijacks the connection. The caller
// must have authenticated the request and checked its Origin.
func Upgrade(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if r.Method != http.MethodGet || !headerHas(r.Header, "Connection", "upgrade") ||
		!headerHas(r.Header, "Upgrade", "websocket") || r.Header.Get("Sec-WebSocket-Version") != "13" {
		return nil, ErrHandshake
	}
	if raw, err := base64.StdEncoding.DecodeString(key); err != nil || len(raw) != 16 {
		return nil, ErrHandshake
	}
	nc, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return nil, err
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey(key) + "\r\n\r\n"
	nc.SetWriteDeadline(time.Now().Add(writeWait))
	if _, err := nc.Write([]byte(resp)); err != nil {
		nc.Close()
		return nil, err
	}
	c := &Conn{nc: nc, br: brw.Reader, closed: make(chan struct{})}
	go c.readLoop()
	return c, nil
}

// Done is closed when the connection ends.
func (c *Conn) Done() <-chan struct{} { return c.closed }

func (c *Conn) frame(op byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	hdr := []byte{0x80 | op}
	switch n := len(payload); {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n <= 0xffff:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	c.nc.SetWriteDeadline(time.Now().Add(writeWait))
	if _, err := c.nc.Write(append(hdr, payload...)); err != nil {
		return err
	}
	return nil
}

// WriteText sends one text message.
func (c *Conn) WriteText(b []byte) error { return c.frame(opText, b) }

// Close sends a close frame and closes the connection.
func (c *Conn) Close(code uint16) {
	c.once.Do(func() {
		c.frame(opClose, []byte{byte(code >> 8), byte(code)})
		c.nc.Close()
		close(c.closed)
	})
}

// readLoop handles client frames: they must be masked; ping is answered,
// close ends the connection, data frames are ignored; oversized or
// malformed frames close the connection (1002/1009).
func (c *Conn) readLoop() {
	defer c.Close(1000)
	for {
		c.nc.SetReadDeadline(time.Now().Add(90 * time.Second))
		var h [2]byte
		if _, err := io.ReadFull(c.br, h[:]); err != nil {
			return
		}
		op, masked, n := h[0]&0x0f, h[1]&0x80 != 0, int(h[1]&0x7f)
		if !masked {
			c.Close(1002)
			return
		}
		switch n {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(c.br, ext[:]); err != nil {
				return
			}
			n = int(binary.BigEndian.Uint16(ext[:]))
		case 127:
			c.Close(1009) // never needed by this feed
			return
		}
		if n > maxClientMsg {
			c.Close(1009)
			return
		}
		var mask [4]byte
		if _, err := io.ReadFull(c.br, mask[:]); err != nil {
			return
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(c.br, payload); err != nil {
			return
		}
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
		switch op {
		case opClose:
			return
		case opPing:
			if c.frame(opPong, payload) != nil {
				return
			}
		}
	}
}
