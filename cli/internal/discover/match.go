// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

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
			ConfigKey  string `json:"config_key"`
			Protocol   string `json:"protocol"`
			EnabledKey string `json:"enabled_key"`
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

// PortBinding is one conflict-free host port assigned to a proposed decoy.
type PortBinding struct {
	ConfigKey string `json:"config_key"`
	Protocol  string `json:"protocol"`
	Port      int    `json:"port"`
}

// Proposal is a sensor suggested for this host.
type Proposal struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Display string            `json:"display_name"`
	Score   int               `json:"score"`
	Reasons []string          `json:"reasons"`
	Ports   []PortBinding     `json:"ports,omitempty"`
	Config  map[string]string `json:"config"`
	Missing []string          `json:"missing,omitempty"` // required keys without a value
}

// HostSummary is the passive /proc inspection summary included in a Plan.
type HostSummary struct {
	ProcRoot  string   `json:"proc_root"`
	Sockets   []Socket `json:"sockets"`
	Processes []string `json:"processes"`
}

// Plan is the conflict-free decoy mix proposed for a host.
type Plan struct {
	Host      HostSummary `json:"host"`
	Proposals []Proposal  `json:"proposals"`
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
		if env.FileExists != nil && env.FileExists(f) {
			reasons = append(reasons, "file "+f)
		}
	}
	sort.Strings(reasons)
	return reasons
}

// Score ranks how well a manifest blends into the host based on passive /proc
// observations. In addition to matching running processes, active ports, and
// host files, it scores unoccupied standard ports declared in discovery so a
// host without e.g. postgres can be recommended database-decoy on port 5432.
func Score(m *Manifest, h *Host, env Env) (int, []string) {
	if m == nil || m.Discovery == nil {
		return 0, nil
	}
	if len(m.Discovery.ProcessNames) == 0 && len(m.Discovery.ListeningPorts) == 0 && len(m.Discovery.Files) == 0 {
		return 0, nil
	}
	score := 0
	var reasons []string
	for _, pat := range m.Discovery.ProcessNames {
		for _, p := range h.Processes {
			if ok, _ := path.Match(pat, p); ok {
				score += 30
				reasons = append(reasons, "process "+p)
			}
		}
	}
	portProto := map[int]string{}
	for _, lp := range m.Runtime.ListenPorts {
		for _, k := range m.Config {
			if k.Name == lp.ConfigKey && k.Default != nil {
				if p, err := strconv.Atoi(strings.TrimSpace(*k.Default)); err == nil && p > 0 {
					portProto[p] = lp.Protocol
				}
			}
		}
	}
	for _, port := range m.Discovery.ListeningPorts {
		if h.Listening(port) {
			score += 20
			reasons = append(reasons, "port "+strconv.Itoa(port)+" in use")
			continue
		}
		proto := portProto[port]
		if proto == "" {
			proto = "tcp"
		}
		if env.BindFree != nil && env.BindFree(proto, port) {
			score += 15
			reasons = append(reasons, "port "+strconv.Itoa(port)+" available")
		}
	}
	for _, f := range m.Discovery.Files {
		if env.FileExists != nil && env.FileExists(f) {
			score += 10
			reasons = append(reasons, "file "+f)
		}
	}
	sort.Strings(reasons)
	return score, reasons
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
			if taken[p] || h.Listening(p) || (env.BindFree != nil && !env.BindFree(proto, p)) {
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
	if taken == nil {
		taken = map[int]bool{}
	}
	proto := map[string]string{}
	enabledKey := map[string]string{}
	for _, lp := range m.Runtime.ListenPorts {
		proto[lp.ConfigKey] = lp.Protocol
		if lp.EnabledKey != "" {
			enabledKey[lp.ConfigKey] = lp.EnabledKey
		}
	}
	// Resolve non-port settings first so enabled_key values are known before
	// allocating ports for listen_ports.
	isListenPort := map[string]bool{}
	for _, lp := range m.Runtime.ListenPorts {
		isListenPort[lp.ConfigKey] = true
	}
	evalKey := func(k struct {
		Name        string  `json:"name"`
		Type        string  `json:"type"`
		Default     *string `json:"default"`
		Required    bool    `json:"required"`
		HubReserved bool    `json:"hub_reserved"`
		Secret      bool    `json:"secret"`
	}) {
		if k.HubReserved || k.Secret {
			return
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
			return
		}
		// Skip port allocation for disabled optional protocols so they do not
		// reserve or conflict on ports they will not bind.
		if ek := enabledKey[k.Name]; ek != "" {
			if v, ok := p.Config[ek]; ok && (strings.EqualFold(v, "false") || v == "0") {
				if k.Default != nil {
					p.Config[k.Name] = *k.Default
				}
				return
			}
		}
		v, err := Evaluate(tpl, proto[k.Name], h, env, taken)
		if err != nil {
			p.Missing = append(p.Missing, k.Name+" ("+err.Error()+")")
			return
		}
		p.Config[k.Name] = v
	}
	for _, k := range m.Config {
		if !isListenPort[k.Name] {
			evalKey(k)
		}
	}
	for _, k := range m.Config {
		if isListenPort[k.Name] {
			evalKey(k)
		}
	}
	seenBinding := map[string]bool{}
	for _, lp := range m.Runtime.ListenPorts {
		if lp.EnabledKey != "" {
			if v, ok := p.Config[lp.EnabledKey]; ok && (strings.EqualFold(v, "false") || v == "0") {
				continue
			}
		}
		raw := p.Config[lp.ConfigKey]
		if raw == "" {
			continue
		}
		lpProto := lp.Protocol
		if lpProto == "" {
			lpProto = "tcp"
		}
		for _, part := range strings.Split(raw, ",") {
			port, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil || port < 1 || port > 65535 {
				continue
			}
			taken[port] = true
			bk := lp.ConfigKey + "/" + lpProto + "/" + strconv.Itoa(port)
			if !seenBinding[bk] {
				seenBinding[bk] = true
				p.Ports = append(p.Ports, PortBinding{ConfigKey: lp.ConfigKey, Protocol: lpProto, Port: port})
			}
		}
	}
	return p
}

// BuildPlan scores manifests against host h, skips already deployed sensors,
// and proposes a conflict-free decoy mix ordered by score descending.
func BuildPlan(manifests []*Manifest, h *Host, env Env, deployed map[string]bool, taken map[int]bool) Plan {
	if taken == nil {
		taken = map[int]bool{}
	}
	type candidate struct {
		manifest *Manifest
		score    int
		reasons  []string
	}
	var cands []candidate
	for _, m := range manifests {
		if m == nil || deployed[m.Name] {
			continue
		}
		score, reasons := Score(m, h, env)
		if score <= 0 {
			continue
		}
		cands = append(cands, candidate{manifest: m, score: score, reasons: reasons})
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		return cands[i].manifest.Name < cands[j].manifest.Name
	})
	proposals := make([]Proposal, 0, len(cands))
	for _, c := range cands {
		prop := Propose(c.manifest, c.reasons, h, env, taken)
		prop.Score = c.score
		proposals = append(proposals, prop)
	}
	sockets := h.Sockets
	if sockets == nil {
		sockets = []Socket{}
	}
	procs := h.Processes
	if procs == nil {
		procs = []string{}
	}
	return Plan{
		Host: HostSummary{
			ProcRoot:  h.root,
			Sockets:   sockets,
			Processes: procs,
		},
		Proposals: proposals,
	}
}
