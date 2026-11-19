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

const (
	maxFTPLine          = 512
	maxFTPCommands      = 32
	maxFTPLoginAttempts = 5
)

var errFTPLineTooLong = errors.New("ftp command line exceeds 512 bytes")

// readFTPLine reads a single CRLF- or LF-terminated line of at most maxFTPLine
// bytes (including line ending). If the line exceeds maxFTPLine bytes, it
// returns errFTPLineTooLong immediately without allocating unbounded memory.
func readFTPLine(r *bufio.Reader) (string, error) {
	buf := make([]byte, 0, 64)
	for {
		b, err := r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && len(buf) > 0 {
				return strings.TrimRight(string(buf), "\r\n"), nil
			}
			return "", err
		}
		if len(buf)+1 > maxFTPLine {
			return "", errFTPLineTooLong
		}
		buf = append(buf, b)
		if b == '\n' {
			return strings.TrimRight(string(buf), "\r\n"), nil
		}
	}
}

// parseFTPCommand splits an FTP command line into its uppercase verb and
// optional argument.
func parseFTPCommand(line string) (verb, arg string) {
	line = strings.TrimLeft(line, " \t")
	v, a, found := strings.Cut(line, " ")
	verb = strings.ToUpper(strings.TrimSpace(v))
	if found {
		arg = a
	}
	return verb, arg
}

func ftpTarget(port int) string { return "FTP port " + strconv.Itoa(port) }

func (d *Decoy) handleFTP(ctx context.Context, raw net.Conn, port int) {
	defer raw.Close()

	stop := context.AfterFunc(ctx, func() { _ = raw.SetDeadline(time.Now()) })
	defer stop()

	conn := newBoundedConn(raw, d.idleTimeout, d.totalTimeout)
	src := raw.RemoteAddr().String()
	ip := decoy.RemoteIP(raw.RemoteAddr())
	target := ftpTarget(port)

	writeLine := func(s string) bool {
		_, err := conn.Write([]byte(s))
		return err == nil
	}

	banner := "220 " + d.cfg.FTPBanner + "\r\n"
	if !writeLine(banner) {
		return
	}

	br := bufio.NewReaderSize(conn, 1024)
	var (
		pendingUser   string
		hasPending    bool
		loginAttempts int
	)

loop:
	for cmds := 0; cmds < maxFTPCommands; cmds++ {
		line, err := readFTPLine(br)
		if err != nil {
			break
		}
		verb, arg := parseFTPCommand(line)
		if verb == "" {
			if !writeLine("500 Unknown command.\r\n") {
				break
			}
			continue
		}

		switch verb {
		case "USER":
			pendingUser = sensor.Clean(strings.TrimSpace(arg), 128)
			hasPending = true
			if !writeLine("331 Please specify the password.\r\n") {
				break loop
			}

		case "PASS":
			if !hasPending {
				if !writeLine("503 Login with USER first.\r\n") {
					break loop
				}
				continue
			}
			user := pendingUser
			pendingUser = ""
			hasPending = false
			loginAttempts++

			anon := strings.EqualFold(user, "anonymous") || strings.EqualFold(user, "ftp")
			if ok, sup := d.allowLogin(ip, "ftp"); ok {
				fields := sensor.Fields{
					sensor.F("protocol", "ftp"),
					sensor.F("dst_port", port),
					sensor.F("username", user),
					sensor.F("anonymous", anon),
				}
				fields = append(fields, d.capture.Password(arg)...)
				fields = append(fields, sensor.F("suppressed_since_last", sup))
				d.r.ReportSeverity(sensor.SeverityHigh, TriggerFTPLogin, src, target, fields)
			}

			if !d.pause(ctx, 300*time.Millisecond, 600*time.Millisecond) {
				break loop
			}
			if !writeLine("530 Login incorrect.\r\n") {
				break loop
			}
			if loginAttempts >= maxFTPLoginAttempts {
				break loop
			}

		case "AUTH":
			mech := strings.ToUpper(strings.TrimSpace(arg))
			if mech == "TLS" || mech == "SSL" {
				if !writeLine("534 Policy requires plain authentication.\r\n") {
					break loop
				}
			} else {
				if !writeLine("504 Command not implemented for that parameter.\r\n") {
					break loop
				}
			}

		case "SYST":
			if !writeLine("215 UNIX Type: L8\r\n") {
				break loop
			}

		case "FEAT":
			if !writeLine("211-Features:\r\n211 End\r\n") {
				break loop
			}

		case "NOOP":
			if !writeLine("200 NOOP ok.\r\n") {
				break loop
			}

		case "QUIT":
			_ = writeLine("221 Goodbye.\r\n")
			break loop

		default:
			if !writeLine("530 Please login with USER and PASS.\r\n") {
				break loop
			}
		}
	}

	if loginAttempts == 0 {
		if ok, sup := d.allowConn(ip, "ftp"); ok {
			fields := sensor.Fields{
				sensor.F("protocol", "ftp"),
				sensor.F("dst_port", port),
			}
			if pendingUser != "" {
				fields = append(fields, sensor.F("username", pendingUser))
			}
			fields = append(fields, sensor.F("suppressed_since_last", sup))
			d.r.ReportSeverity(sensor.SeverityMedium, TriggerFTPConnection, src, target, fields)
		}
	}
}
