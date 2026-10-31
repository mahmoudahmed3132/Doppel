// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package discover

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Manifest is the subset of a sensor manifest discovery uses.
type Manifest struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Version     string `json:"version"`
	Runtime     struct {
		ListenPorts []struct {
			ConfigKey string `json:"config_key"`
			Protocol  string `json:"protocol"`
		} `json:"listen_ports"`
	} `json:"runtime"`
	Config []struct {
		Name        string  `json:"name"`
		Type        string  `json:"type"`
		Default     *string `json:"default"`
		Required    bool    `json:"required"`
		HubReserved bool    `json:"hub_reserved"`
		Secret      bool    `json:"secret"`
	} `json:"config"`
	Discovery *struct {
		ProcessNames   []string          `json:"process_names"`
		ListeningPorts []int             `json:"listening_ports"`
		Files          []string          `json:"files"`
		Defaults       map[string]string `json:"defaults"`
	} `json:"discovery"`
}

// Proposal is a sensor suggested for this host.
type Proposal struct {
	Name    string
	Version string
	Display string
	Reasons []string
	Config  map[string]string
	Missing []string // required keys without a value
}

// Env abstracts host checks for tests.
type Env struct {
	FileExists func(string) bool
	BindFree   func(proto string, port int) bool
	Hostname   func() (string, error)
}

// DefaultEnv uses the real host. The bind test listens on the port and
// closes it immediately (local only; no packets are sent).
func DefaultEnv() Env {
	return Env{
		FileExists: func(p string) bool { _, err := os.Stat(p); return err == nil },
		BindFree: func(proto string, port int) bool {
			addr := net.JoinHostPort("", strconv.Itoa(port))
			if proto == "udp" {
				c, err := net.ListenPacket("udp", addr)
				if err != nil {
					return false
				}
				c.Close()
				return true
			}
			l, err := net.Listen("tcp", addr)
			if err != nil {
				return false
			}
			l.Close()
			return true
		},
		Hostname: os.Hostname,
	}
}

// Match reports why a manifest fits the host (empty: it does not).
func Match(m *Manifest, h *Host, env Env) []string {
	if m.Discovery == nil {
		return nil
	}
	var reasons []string
	for _, pat := range m.Discovery.ProcessNames {
		for _, p := range h.Processes {
			if ok, _ := path.Match(pat, p); ok {
				reasons = append(reasons, "process "+p)
			}
		}
	}
	for _, port := range m.Discovery.ListeningPorts {
		if h.Listening(port) {
			reasons = append(reasons, "port "+strconv.Itoa(port)+" in use")
		}
	}
	for _, f := range m.Discovery.Files {
		if env.FileExists(f) {
			reasons = append(reasons, "file "+f)
		}
	}
	sort.Strings(reasons)
	return reasons
}

var (
	freePortRE = regexp.MustCompile(`^free_port\(([0-9]{1,5})\)$`)
	choiceRE   = regexp.MustCompile(`^random_choice\(([^()]*)\)$`)
)

// ErrNoFreePort is returned when free_port finds nothing in its range.
var ErrNoFreePort = errors.New("no free port")

// Evaluate renders a default: templates use only free_port, random_choice
// and hostname; anything else is returned verbatim.
func Evaluate(tpl, proto string, h *Host, env Env, taken map[int]bool) (string, error) {
	switch {
	case freePortRE.MatchString(tpl):
		start, _ := strconv.Atoi(freePortRE.FindStringSubmatch(tpl)[1])
		if start < 1 || start > 65535 {
			return "", fmt.Errorf("free_port(%d): out of range", start)
		}
		for p := start; p <= 65535 && p < start+200; p++ {
			if taken[p] || h.Listening(p) || !env.BindFree(proto, p) {
				continue
			}
			taken[p] = true
			return strconv.Itoa(p), nil
		}
		return "", fmt.Errorf("%w from %d", ErrNoFreePort, start)
	case choiceRE.MatchString(tpl):
		var opts []string
		for _, o := range strings.Split(choiceRE.FindStringSubmatch(tpl)[1], ",") {
			if o = strings.TrimSpace(o); o != "" {
				opts = append(opts, o)
			}
		}
		if len(opts) == 0 {
			return "", errors.New("random_choice() needs options")
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(opts))))
		if err != nil {
			return "", err
		}
		return opts[n.Int64()], nil
	case tpl == "hostname()":
		return env.Hostname()
	}
	return tpl, nil
}

// Propose builds a proposal with rendered defaults. taken tracks ports
// already assigned in this discovery run.
func Propose(m *Manifest, reasons []string, h *Host, env Env, taken map[int]bool) Proposal {
	p := Proposal{Name: m.Name, Version: m.Version, Display: m.DisplayName, Reasons: reasons, Config: map[string]string{}}
	proto := map[string]string{}
	for _, lp := range m.Runtime.ListenPorts {
		proto[lp.ConfigKey] = lp.Protocol
	}
	for _, k := range m.Config {
		if k.HubReserved || k.Secret {
			continue
		}
		tpl := ""
		if k.Default != nil {
			tpl = *k.Default
		}
		if m.Discovery != nil {
			if d, ok := m.Discovery.Defaults[k.Name]; ok {
				tpl = d
			}
		}
		if tpl == "" {
			if k.Required {
				p.Missing = append(p.Missing, k.Name)
			}
			continue
		}
		v, err := Evaluate(tpl, proto[k.Name], h, env, taken)
		if err != nil {
			p.Missing = append(p.Missing, k.Name+" ("+err.Error()+")")
			continue
		}
		p.Config[k.Name] = v
	}
	return p
}
