// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package sensor

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"unicode/utf8"
)

// Printable renders untrusted bytes as printable ASCII: printable
// characters are kept, \n \r \t become their escapes, everything else
// becomes \xHH. At most max input bytes are rendered.
func Printable(b []byte, max int) string {
	if max >= 0 && len(b) > max {
		b = b[:max]
	}
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c == '\\':
			sb.WriteString(`\\`)
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\r':
			sb.WriteString(`\r`)
		case c == '\t':
			sb.WriteString(`\t`)
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		default:
			fmt.Fprintf(&sb, `\x%02x`, c)
		}
	}
	return sb.String()
}

// Clean bounds an untrusted string for event details: valid UTF-8, no
// control characters, at most max bytes.
func Clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, "�"))
	if len(s) > max {
		cut := max
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return s
}

// LogPrivileges logs the process uid and effective capabilities, so a
// sensor states honestly what it runs with (§11.3).
func LogPrivileges(log *slog.Logger) {
	capEff := "unknown"
	if f, err := os.Open("/proc/self/status"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "CapEff:"); ok {
				capEff = strings.TrimSpace(v)
			}
		}
		f.Close()
	}
	log.Info("running with privileges", "uid", os.Getuid(), "gid", os.Getgid(), "cap_eff", capEff)
}
