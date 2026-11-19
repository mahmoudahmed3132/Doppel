// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package discover

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeProc builds a minimal /proc: sshd listening on tcp 22, named on udp 53.
func fakeProc(t *testing.T) string {
	root := t.TempDir()
	w := func(p, s string) {
		os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte(s), 0o644)
	}
	hdr := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	w("net/tcp", hdr+
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0\n"+
		"   1: 0100007F:1F90 0100007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 1002 1 0\n") // established, ignored
	w("net/udp", hdr+"   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 2001 2 0\n")
	w("100/comm", "sshd\n")
	w("200/comm", "named\n")
	os.MkdirAll(filepath.Join(root, "100/fd"), 0o755)
	os.MkdirAll(filepath.Join(root, "200/fd"), 0o755)
	os.Symlink("socket:[1001]", filepath.Join(root, "100/fd/3"))
	os.Symlink("socket:[2001]", filepath.Join(root, "200/fd/4"))
	os.Symlink("/dev/null", filepath.Join(root, "200/fd/0"))
	return root
}

func TestScan(t *testing.T) {
	h, err := Scan(fakeProc(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Sockets) != 2 || h.Sockets[0] != (Socket{"tcp", 22, "sshd"}) || h.Sockets[1] != (Socket{"udp", 53, "named"}) {
		t.Fatalf("%+v", h.Sockets)
	}
	if strings.Join(h.Processes, ",") != "named,sshd" || h.Listening(8080) {
		t.Fatalf("%v", h.Processes)
	}
}

func manifest(t *testing.T, s string) *Manifest {
	var m Manifest
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return &m
}

func TestMatchAndPropose(t *testing.T) {
	h, _ := Scan(fakeProc(t))
	env := Env{
		FileExists: func(p string) bool { return p == "/etc/ssh/sshd_config" },
		BindFree:   func(_ string, port int) bool { return port != 2222 }, // 2222 taken by something unseen
		Hostname:   func() (string, error) { return "web01", nil },
	}
	ssh := manifest(t, `{"name":"tcp-tarpit","display_name":"Tarpit","version":"1.1.0",
	 "runtime":{"listen_ports":[{"config_key":"TS_PORTS","protocol":"tcp"}]},
	 "config":[{"name":"TS_PORTS","type":"list","required":true},{"name":"TS_MODE","type":"enum","default":"hold"},
	   {"name":"TS_BANNER","type":"string","default":"random_choice(OpenSSH_8.9, OpenSSH_9.6)"},
	   {"name":"TS_HOST","type":"string","default":"hostname()"},{"name":"TS_TOKEN","type":"string","secret":true,"default":"x"},
	   {"name":"TS_CAPTURE_KEY","type":"string","hub_reserved":true}],
	 "discovery":{"process_names":["ssh*"],"listening_ports":[22],"files":["/etc/ssh/sshd_config"],"defaults":{"TS_PORTS":"free_port(2222)"}}}`)
	reasons := Match(ssh, h, env)
	if strings.Join(reasons, ";") != "file /etc/ssh/sshd_config;port 22 in use;process sshd" {
		t.Fatalf("%v", reasons)
	}
	p := Propose(ssh, reasons, h, env, map[int]bool{})
	if p.Config["TS_PORTS"] != "2223" || p.Config["TS_MODE"] != "hold" || p.Config["TS_HOST"] != "web01" || len(p.Missing) != 0 {
		t.Fatalf("%+v", p)
	}
	if b := p.Config["TS_BANNER"]; b != "OpenSSH_8.9" && b != "OpenSSH_9.6" {
		t.Fatalf("banner %q", b)
	}
	if _, has := p.Config["TS_TOKEN"]; has {
		t.Fatal("secret default proposed")
	}
	if _, has := p.Config["TS_CAPTURE_KEY"]; has {
		t.Fatal("hub-reserved key proposed")
	}

	other := manifest(t, `{"name":"x","discovery":{"process_names":["nginx"],"listening_ports":[443]}}`)
	if len(Match(other, h, env)) != 0 {
		t.Fatal("false match")
	}
	if len(Match(manifest(t, `{"name":"y"}`), h, env)) != 0 {
		t.Fatal("manifest without discovery matched")
	}
}

func TestFreePortTracksAssignments(t *testing.T) {
	h := &Host{}
	env := Env{BindFree: func(string, int) bool { return true }}
	taken := map[int]bool{}
	a, _ := Evaluate("free_port(8080)", "tcp", h, env, taken)
	b, _ := Evaluate("free_port(8080)", "tcp", h, env, taken)
	if a != "8080" || b != "8081" {
		t.Fatalf("%s %s", a, b)
	}
	if v, _ := Evaluate("$(rm -rf /)", "", h, env, taken); v != "$(rm -rf /)" {
		t.Fatal("non-template must be returned verbatim (never evaluated)")
	}
	if _, err := Evaluate("free_port(9)", "tcp", h, Env{BindFree: func(string, int) bool { return false }}, taken); err == nil {
		t.Fatal("exhausted range not reported")
	}
}

func TestBuildPlanConflictFreeMix(t *testing.T) {
	// fakeProc has sshd on tcp/22 and named on udp/53; postgres is NOT running.
	h, err := Scan(fakeProc(t))
	if err != nil {
		t.Fatal(err)
	}
	env := Env{
		FileExists: func(string) bool { return false },
		BindFree:   func(_ string, port int) bool { return port != 22 && port != 53 },
		Hostname:   func() (string, error) { return "app01", nil },
	}
	remoteAccess := manifest(t, `{
		"name":"remote-access-decoy","display_name":"Remote access decoy","version":"1.0.0",
		"runtime":{"listen_ports":[
			{"config_key":"TS_SSH_PORT","protocol":"tcp","enabled_key":"TS_ENABLE_SSH"},
			{"config_key":"TS_TELNET_PORT","protocol":"tcp","enabled_key":"TS_ENABLE_TELNET"}
		]},
		"config":[
			{"name":"TS_ENABLE_SSH","type":"bool","default":"true"},
			{"name":"TS_SSH_PORT","type":"port","default":"22"},
			{"name":"TS_ENABLE_TELNET","type":"bool","default":"false"},
			{"name":"TS_TELNET_PORT","type":"port","default":"23"}
		],
		"discovery":{"process_names":["sshd"],"listening_ports":[22],"defaults":{"TS_SSH_PORT":"free_port(2222)"}}
	}`)
	tarpit := manifest(t, `{
		"name":"tcp-tarpit","display_name":"TCP tarpit","version":"1.0.0",
		"runtime":{"listen_ports":[{"config_key":"TS_PORTS","protocol":"tcp"}]},
		"config":[{"name":"TS_PORTS","type":"list","required":true}],
		"discovery":{"process_names":["sshd"],"listening_ports":[22],"defaults":{"TS_PORTS":"free_port(2222)"}}
	}`)
	db := manifest(t, `{
		"name":"database-decoy","display_name":"Database decoy","version":"1.0.0",
		"runtime":{"listen_ports":[
			{"config_key":"TS_POSTGRES_PORT","protocol":"tcp","enabled_key":"TS_ENABLE_POSTGRES"}
		]},
		"config":[
			{"name":"TS_ENABLE_POSTGRES","type":"bool","default":"true"},
			{"name":"TS_POSTGRES_PORT","type":"port","default":"5432"}
		],
		"discovery":{"process_names":["postgres"],"listening_ports":[5432],"defaults":{"TS_POSTGRES_PORT":"free_port(5432)"}}
	}`)
	template := manifest(t, `{
		"name":"template","display_name":"Template","version":"1.0.0",
		"discovery":{"defaults":{"TS_TEMPLATE_PORT":"free_port(9099)"}}
	}`)

	plan := BuildPlan([]*Manifest{tarpit, db, template, remoteAccess}, h, env, map[string]bool{}, nil)
	if len(plan.Proposals) != 3 {
		t.Fatalf("got %d proposals, want 3: %+v", len(plan.Proposals), plan.Proposals)
	}
	// remote-access-decoy and tcp-tarpit tie on score (50); alphabetical order puts remote-access-decoy first.
	if plan.Proposals[0].Name != "remote-access-decoy" || plan.Proposals[0].Config["TS_SSH_PORT"] != "2222" {
		t.Fatalf("first proposal = %+v, want remote-access-decoy on 2222", plan.Proposals[0])
	}
	// Disabled telnet port 23 must NOT appear in active Ports bindings.
	if len(plan.Proposals[0].Ports) != 1 || plan.Proposals[0].Ports[0].Port != 2222 {
		t.Fatalf("unexpected remote-access-decoy ports: %+v", plan.Proposals[0].Ports)
	}
	// tcp-tarpit must automatically shift to 2223 to stay conflict-free.
	if plan.Proposals[1].Name != "tcp-tarpit" || plan.Proposals[1].Config["TS_PORTS"] != "2223" {
		t.Fatalf("second proposal = %+v, want tcp-tarpit on 2223", plan.Proposals[1])
	}
	// database-decoy is proposed on unoccupied standard port 5432 even though postgres is not running.
	if plan.Proposals[2].Name != "database-decoy" || plan.Proposals[2].Config["TS_POSTGRES_PORT"] != "5432" {
		t.Fatalf("third proposal = %+v, want database-decoy on 5432", plan.Proposals[2])
	}
	if !strings.Contains(strings.Join(plan.Proposals[2].Reasons, ","), "port 5432 available") {
		t.Fatalf("database-decoy reasons = %v, want port 5432 available", plan.Proposals[2].Reasons)
	}
}
