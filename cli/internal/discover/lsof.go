// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package discover

import (
	"bufio"
	"bytes"
	"context"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Runner runs a command (argv, never a shell) and returns its stdout.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// LsofSource names the source of a Host built by ScanCommands.
const LsofSource = "lsof+ps"

// ScanCommands builds a Host without /proc (macOS, BSD) from lsof and ps.
// Like Scan, it is passive: it only lists local sockets and processes.
// Without root, lsof sees only the caller's own sockets.
func ScanCommands(ctx context.Context, r Runner) (*Host, error) {
	h := &Host{root: LsofSource}
	seen := map[string]bool{}
	add := func(s Socket) {
		key := s.Proto + "/" + strconv.Itoa(s.Port) + "/" + s.Process
		if !seen[key] {
			seen[key] = true
			h.Sockets = append(h.Sockets, s)
		}
	}
	// lsof exits 1 when nothing matches; the output is still authoritative.
	tcp, _ := r.Run(ctx, "lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcn")
	parseLsof(tcp, "tcp", add)
	udp, _ := r.Run(ctx, "lsof", "-nP", "-iUDP", "-F", "pcn")
	parseLsof(udp, "udp", add)
	sort.Slice(h.Sockets, func(i, j int) bool {
		if h.Sockets[i].Port != h.Sockets[j].Port {
			return h.Sockets[i].Port < h.Sockets[j].Port
		}
		return h.Sockets[i].Proto < h.Sockets[j].Proto
	})
	ps, err := r.Run(ctx, "ps", "-axo", "comm=")
	if err == nil {
		h.Processes = parsePs(ps)
	}
	return h, nil
}

// parseLsof reads `lsof -F pcn` output: "p<pid>", "c<command>", then per
// file "f<fd>" and "n<addr:port>" (e.g. "*:22", "[::1]:631", "a:1->b:2").
func parseLsof(out []byte, proto string, add func(Socket)) {
	var comm string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			comm = ""
		case 'c':
			comm = line[1:]
		case 'n':
			name := line[1:]
			if strings.Contains(name, "->") {
				continue // connected, not listening/bound
			}
			i := strings.LastIndexByte(name, ':')
			if i < 0 {
				continue
			}
			port, err := strconv.Atoi(name[i+1:])
			if err != nil || port <= 0 || port > 65535 {
				continue
			}
			add(Socket{Proto: proto, Port: port, Process: comm})
		}
	}
}

// parsePs returns distinct process base names from `ps -axo comm=`.
func parsePs(out []byte) []string {
	set := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if c := path.Base(strings.TrimSpace(sc.Text())); c != "" && c != "." && c != "/" {
			set[c] = true
		}
	}
	res := make([]string, 0, len(set))
	for c := range set {
		res = append(res, c)
	}
	sort.Strings(res)
	return res
}

// Source names where the snapshot came from (a /proc root or LsofSource).
func (h *Host) Source() string { return h.root }
