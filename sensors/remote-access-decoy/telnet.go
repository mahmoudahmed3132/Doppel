// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/decoy"
	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

// Telnet protocol constants (RFC 854, RFC 857, RFC 858, RFC 1572).
const (
	telnetSE   byte = 240
	telnetSB   byte = 250
	telnetWILL byte = 251
	telnetWONT byte = 252
	telnetDO   byte = 253
	telnetDONT byte = 254
	telnetIAC  byte = 255

	optEcho       byte = 1
	optSGA        byte = 3
	optNewEnviron byte = 39

	envIS      byte = 0
	envSEND    byte = 1
	envVAR     byte = 0
	envVALUE   byte = 1
	envESC     byte = 2
	envUSERVAR byte = 3

	maxTelnetLine       = 256
	maxTelnetRawPerLine = 2048
	maxTelnetSubneg     = 512
	maxTelnetNegReplies = 64
	maxTelnetAttempts   = 3
)

type telnetState int

const (
	tStateData telnetState = iota
	tStateIAC
	tStateOpt
	tStateSB
	tStateSBIAC
)

var errTelnetLineTooLong = errors.New("telnet line exceeds maximum length")

// telnetParser is a strict, bounded byte-by-byte RFC 854 / RFC 1572 state
// machine. All IAC sequences and non-printable control bytes are stripped from
// returned lines; NEW-ENVIRON USER is extracted if sent by the peer.
type telnetParser struct {
	state      telnetState
	cmd        byte
	sb         []byte
	envUser    string
	negReplies int
	sentEnvReq bool
	lastCR     bool
	writeReply func([]byte)
}

func newTelnetParser(writeReply func([]byte)) *telnetParser {
	return &telnetParser{writeReply: writeReply}
}

func (p *telnetParser) reply(b ...byte) {
	if p.writeReply == nil || p.negReplies >= maxTelnetNegReplies {
		return
	}
	p.negReplies++
	p.writeReply(b)
}

func (p *telnetParser) handleOption(cmd, opt byte) {
	switch cmd {
	case telnetDO:
		switch opt {
		case optEcho, optSGA:
			// Offered explicitly by the server; no extra reply needed to avoid loops.
		default:
			p.reply(telnetIAC, telnetWONT, opt)
		}
	case telnetWILL:
		switch opt {
		case optSGA:
			p.reply(telnetIAC, telnetDO, optSGA)
		case optNewEnviron:
			if !p.sentEnvReq {
				p.sentEnvReq = true
				p.reply(telnetIAC, telnetDO, optNewEnviron,
					telnetIAC, telnetSB, optNewEnviron, envSEND, envVAR, 'U', 'S', 'E', 'R', telnetIAC, telnetSE)
			}
		default:
			p.reply(telnetIAC, telnetDONT, opt)
		}
	case telnetWONT, telnetDONT:
		// RFC 854: never reply to WONT/DONT to prevent negotiation loops.
	}
}

// parseNewEnviron extracts the USER variable from an RFC 1572 NEW-ENVIRON IS
// subnegotiation payload (after the leading option byte 39 and IS byte 0).
func (p *telnetParser) parseNewEnviron(payload []byte) {
	if len(payload) < 2 || payload[0] != optNewEnviron || payload[1] != envIS {
		return
	}
	data := payload[2:]
	var (
		inVar   bool
		inVal   bool
		escaped bool
		curName []byte
		curVal  []byte
	)
	flush := func() {
		name := strings.ToUpper(string(curName))
		if (name == "USER" || name == "LOGNAME") && len(curVal) > 0 && p.envUser == "" {
			p.envUser = sensor.Clean(string(curVal), 128)
		}
		curName = curName[:0]
		curVal = curVal[:0]
	}
	for _, b := range data {
		if escaped {
			escaped = false
			if inVal {
				if len(curVal) < 128 {
					curVal = append(curVal, b)
				}
			} else if inVar {
				if len(curName) < 64 {
					curName = append(curName, b)
				}
			}
			continue
		}
		switch b {
		case envESC:
			escaped = true
		case envVAR, envUSERVAR:
			if inVar || inVal {
				flush()
			}
			inVar = true
			inVal = false
		case envVALUE:
			if inVar {
				inVar = false
				inVal = true
			}
		default:
			if inVal {
				if len(curVal) < 128 {
					curVal = append(curVal, b)
				}
			} else if inVar {
				if len(curName) < 64 {
					curName = append(curName, b)
				}
			}
		}
	}
	if inVar || inVal {
		flush()
	}
}

// readLine reads one NVT line from r, stripping all IAC sequences and control
// bytes. Returns the cleaned line and whether a line terminator was seen.
func (p *telnetParser) readLine(r *bufio.Reader) (string, error) {
	line := make([]byte, 0, 64)
	rawCount := 0
	for {
		b, err := r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return decoy.Sanitize(string(line), maxTelnetLine), nil
			}
			return "", err
		}
		rawCount++
		if rawCount > maxTelnetRawPerLine {
			return "", errTelnetLineTooLong
		}

		switch p.state {
		case tStateData:
			if b == telnetIAC {
				p.state = tStateIAC
				continue
			}
			if p.lastCR {
				p.lastCR = false
				if b == '\n' || b == 0 {
					return decoy.Sanitize(string(line), maxTelnetLine), nil
				}
				// Bare CR followed by data: treat CR as line terminator? RFC 854
				// specifies CR LF or CR NUL; if a client sends bare CR, ignore
				// and process b below.
			}
			if b == '\r' {
				p.lastCR = true
				continue
			}
			if b == '\n' {
				return decoy.Sanitize(string(line), maxTelnetLine), nil
			}
			// Strip all other non-printable control bytes (< 0x20 or DEL 0x7f).
			if b < 0x20 || b == 0x7f {
				continue
			}
			if len(line) >= maxTelnetLine {
				return "", errTelnetLineTooLong
			}
			line = append(line, b)

		case tStateIAC:
			switch b {
			case telnetWILL, telnetWONT, telnetDO, telnetDONT:
				p.cmd = b
				p.state = tStateOpt
			case telnetSB:
				p.sb = p.sb[:0]
				p.state = tStateSB
			default:
				// Escaped IAC (0xFF) or 2-byte command (NOP, AYT, etc.): strip.
				p.state = tStateData
			}

		case tStateOpt:
			p.handleOption(p.cmd, b)
			p.state = tStateData

		case tStateSB:
			if b == telnetIAC {
				p.state = tStateSBIAC
			} else if len(p.sb) < maxTelnetSubneg {
				p.sb = append(p.sb, b)
			}

		case tStateSBIAC:
			switch b {
			case telnetSE:
				p.parseNewEnviron(p.sb)
				p.sb = p.sb[:0]
				p.state = tStateData
			case telnetIAC:
				if len(p.sb) < maxTelnetSubneg {
					p.sb = append(p.sb, telnetIAC)
				}
				p.state = tStateSB
			default:
				p.sb = p.sb[:0]
				p.state = tStateData
			}
		}
	}
}

func telnetTarget(port int) string { return "Telnet port " + strconv.Itoa(port) }

func (d *Decoy) handleTelnet(ctx context.Context, raw net.Conn, port int) {
	defer raw.Close()

	stop := context.AfterFunc(ctx, func() { _ = raw.SetDeadline(time.Now()) })
	defer stop()

	conn := newBoundedConn(raw, d.idleTimeout, d.totalTimeout)
	src := raw.RemoteAddr().String()
	ip := decoy.RemoteIP(raw.RemoteAddr())
	target := telnetTarget(port)

	writeBytes := func(b []byte) bool {
		_, err := conn.Write(b)
		return err == nil
	}

	// Offer SGA and request NEW-ENVIRON for realistic login negotiation.
	if !writeBytes([]byte{
		telnetIAC, telnetWILL, optSGA,
		telnetIAC, telnetDO, optNewEnviron,
	}) {
		return
	}
	if d.cfg.TelnetBanner != "" {
		if !writeBytes([]byte(d.cfg.TelnetBanner + "\r\n")) {
			return
		}
	}

	br := bufio.NewReaderSize(conn, 1024)
	parser := newTelnetParser(func(b []byte) { _, _ = conn.Write(b) })
	loggedInAttempt := false

	for attempt := 0; attempt < maxTelnetAttempts; attempt++ {
		if !writeBytes([]byte("login: ")) {
			break
		}
		user, err := parser.readLine(br)
		if err != nil {
			break
		}
		user = strings.TrimSpace(sensor.Clean(user, 128))
		if user == "" && parser.envUser != "" {
			user = parser.envUser
		}
		if user == "" {
			continue
		}

		// Suppress remote echo for the password prompt.
		if !writeBytes([]byte{telnetIAC, telnetWILL, optEcho}) {
			break
		}
		if !writeBytes([]byte("Password: ")) {
			break
		}
		pass, err := parser.readLine(br)
		if err != nil {
			break
		}
		_, _ = conn.Write([]byte{'\r', '\n', telnetIAC, telnetWONT, optEcho})

		loggedInAttempt = true
		if ok, sup := d.allowLogin(ip, "telnet"); ok {
			fields := sensor.Fields{
				sensor.F("protocol", "telnet"),
				sensor.F("dst_port", port),
				sensor.F("username", user),
			}
			if parser.envUser != "" && parser.envUser != user {
				fields = append(fields, sensor.F("env_user", parser.envUser))
			}
			fields = append(fields, d.capture.Password(pass)...)
			fields = append(fields, sensor.F("suppressed_since_last", sup))
			d.r.ReportSeverity(sensor.SeverityHigh, TriggerTelnetLogin, src, target, fields)
		}

		if !d.pause(ctx, 400*time.Millisecond, 800*time.Millisecond) {
			break
		}
		if !writeBytes([]byte("Login incorrect\r\n")) {
			break
		}
	}

	if !loggedInAttempt {
		if ok, sup := d.allowConn(ip, "telnet"); ok {
			fields := sensor.Fields{
				sensor.F("protocol", "telnet"),
				sensor.F("dst_port", port),
			}
			if parser.envUser != "" {
				fields = append(fields, sensor.F("env_user", parser.envUser))
			}
			fields = append(fields, sensor.F("suppressed_since_last", sup))
			d.r.ReportSeverity(sensor.SeverityMedium, TriggerTelnetConnection, src, target, fields)
		}
	}
}
