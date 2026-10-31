// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

// Package discover inspects the host passively (§8): it reads /proc for
// listening sockets and process names, checks file existence, and matches
// the result against manifest discovery heuristics. It never probes the
// network; the only active step is a local bind test on a candidate port.
package discover

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Socket is one listening socket.
type Socket struct {
	Proto   string // tcp | udp
	Port    int
	Process string // comm of the owning process, "" if unknown
}

// Host is a snapshot of the host.
type Host struct {
	Sockets   []Socket
	Processes []string // distinct process names
	root      string
}

// Scan reads procRoot (normally "/proc").
func Scan(procRoot string) (*Host, error) {
	h := &Host{root: procRoot}
	inodes := map[string]Socket{}
	for _, f := range []struct{ file, proto, state string }{
		{"net/tcp", "tcp", "0A"}, {"net/tcp6", "tcp", "0A"}, // LISTEN
		{"net/udp", "udp", "07"}, {"net/udp6", "udp", "07"}, // unconnected (bound)
	} {
		readSockets(filepath.Join(procRoot, f.file), f.proto, f.state, inodes)
	}
	owners := socketOwners(procRoot)
	seen := map[string]bool{}
	for inode, s := range inodes {
		s.Process = owners[inode]
		key := s.Proto + "/" + strconv.Itoa(s.Port) + "/" + s.Process
		if !seen[key] {
			seen[key] = true
			h.Sockets = append(h.Sockets, s)
		}
	}
	sort.Slice(h.Sockets, func(i, j int) bool {
		if h.Sockets[i].Port != h.Sockets[j].Port {
			return h.Sockets[i].Port < h.Sockets[j].Port
		}
		return h.Sockets[i].Proto < h.Sockets[j].Proto
	})
	h.Processes = processNames(procRoot)
	return h, nil
}

// readSockets parses /proc/net/{tcp,udp}[6]: "sl local rem st ... inode".
func readSockets(path, proto, wantState string, out map[string]Socket) {
	f, err := os.Open(path)
	if err != nil {
		return // e.g. no IPv6
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 10 || fs[3] != wantState {
			continue
		}
		i := strings.LastIndexByte(fs[1], ':')
		if i < 0 {
			continue
		}
		port, err := strconv.ParseUint(fs[1][i+1:], 16, 16)
		if err != nil || port == 0 {
			continue
		}
		out[fs[9]] = Socket{Proto: proto, Port: int(port)}
	}
}

// socketOwners maps socket inodes to process names via /proc/<pid>/fd.
func socketOwners(procRoot string) map[string]string {
	out := map[string]string{}
	pids, _ := os.ReadDir(procRoot)
	for _, p := range pids {
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		fdDir := filepath.Join(procRoot, p.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		var comm string
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			if comm == "" {
				comm = readComm(procRoot, p.Name())
			}
			out[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = comm
		}
	}
	return out
}

func readComm(procRoot, pid string) string {
	b, err := os.ReadFile(filepath.Join(procRoot, pid, "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func processNames(procRoot string) []string {
	set := map[string]bool{}
	pids, _ := os.ReadDir(procRoot)
	for _, p := range pids {
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		if c := readComm(procRoot, p.Name()); c != "" {
			set[c] = true
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Listening reports whether any socket uses port (any protocol).
func (h *Host) Listening(port int) bool {
	for _, s := range h.Sockets {
		if s.Port == port {
			return true
		}
	}
	return false
}
