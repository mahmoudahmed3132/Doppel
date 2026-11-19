// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func FuzzTelnet(f *testing.F) {
	f.Add([]byte("root\r\npassword\r\n"))
	f.Add([]byte{telnetIAC, telnetWILL, optNewEnviron, telnetIAC, telnetSB, optNewEnviron, envIS, envVAR, 'U', 'S', 'E', 'R', envVALUE, 'a', 'd', 'm', 'i', 'n', telnetIAC, telnetSE, '\r', '\n'})
	f.Add([]byte{telnetIAC, telnetDO, optEcho, telnetIAC, telnetDONT, 99, telnetIAC, telnetWONT, 1, 0x00, 0x07, 0x7f, '\n'})
	f.Add(bytes.Repeat([]byte{telnetIAC, telnetSB}, 200))
	f.Add(bytes.Repeat([]byte("A"), 1024))

	rep := newFakeReporter(map[string]string{"TS_ENABLE_TELNET": "true"})
	cfg, err := LoadSettings(rep)
	if err != nil {
		f.Fatal(err)
	}
	d, err := NewDecoy(cfg, rep, "ts-sensor-fuzz")
	if err != nil {
		f.Fatal(err)
	}
	d.authDelay = func(_, _ time.Duration) time.Duration { return 0 }
	d.idleTimeout = 100 * time.Millisecond
	d.totalTimeout = 200 * time.Millisecond

	f.Fuzz(func(t *testing.T, data []byte) {
		// Cap per-iteration input so fuzzing stays fast and bounded.
		if len(data) > 4096 {
			data = data[:4096]
		}
		// 1. Direct parser fuzzing.
		p := newTelnetParser(nil)
		br := bufio.NewReader(bytes.NewReader(data))
		for i := 0; i < 8; i++ {
			if _, err := p.readLine(br); err != nil {
				break
			}
		}

		// 2. Full handler over net.Pipe.
		srv, cli := net.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		go func() {
			go func() { _, _ = io.Copy(io.Discard, cli) }()
			_, _ = cli.Write(data)
			_ = cli.Close()
		}()
		d.handleTelnet(ctx, srv, 23)
	})
}

func FuzzFTP(f *testing.F) {
	f.Add([]byte("USER admin\r\nPASS secret\r\nQUIT\r\n"))
	f.Add([]byte("AUTH TLS\r\nSYST\r\nFEAT\r\nNOOP\r\nLIST\r\n"))
	f.Add([]byte("USER anonymous\r\nPASS a@b.c\r\n"))
	f.Add(bytes.Repeat([]byte("X"), 600))
	f.Add([]byte("\x00\xff\xfe\r\n\r\n"))

	rep := newFakeReporter(map[string]string{"TS_ENABLE_FTP": "true"})
	cfg, err := LoadSettings(rep)
	if err != nil {
		f.Fatal(err)
	}
	d, err := NewDecoy(cfg, rep, "ts-sensor-fuzz")
	if err != nil {
		f.Fatal(err)
	}
	d.authDelay = func(_, _ time.Duration) time.Duration { return 0 }
	d.idleTimeout = 100 * time.Millisecond
	d.totalTimeout = 200 * time.Millisecond

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			data = data[:4096]
		}
		// 1. Direct line reader + parser fuzzing.
		br := bufio.NewReader(bytes.NewReader(data))
		for i := 0; i < 16; i++ {
			line, err := readFTPLine(br)
			if err != nil {
				break
			}
			_, _ = parseFTPCommand(line)
		}

		// 2. Full handler over net.Pipe.
		srv, cli := net.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		go func() {
			go func() { _, _ = io.Copy(io.Discard, cli) }()
			_, _ = cli.Write(data)
			_ = cli.Close()
		}()
		d.handleFTP(ctx, srv, 21)
	})
}
