// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package manifest

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../../sensors/template/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTemplateManifestValid(t *testing.T) {
	// The committed manifest has no digest yet (filled by CI at publish).
	if _, err := Decode(load(t), Options{}); err == nil || !strings.Contains(err.Error(), "image_not_pinned") {
		t.Fatalf("unpinned manifest accepted in production mode: %v", err)
	}
	m, err := Decode(load(t), Options{AllowUnpinned: true})
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "template" || m.Key("TS_TEMPLATE_PORT") == nil {
		t.Fatalf("%+v", m)
	}
	pinned := strings.Replace(string(load(t)), `"digest": ""`, `"digest": "sha256:`+strings.Repeat("a", 64)+`"`, 1)
	if _, err := Decode([]byte(pinned), Options{}); err != nil {
		t.Fatalf("pinned manifest refused: %v", err)
	}
}

func TestDecodeStrict(t *testing.T) {
	b := strings.Replace(string(load(t)), `"schema_version": 3,`, `"schema_version": 3, "privileged": true,`, 1)
	if _, err := Decode([]byte(b), Options{AllowUnpinned: true}); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := Decode(append(load(t), []byte("{}")...), Options{AllowUnpinned: true}); err == nil {
		t.Fatal("trailing data accepted")
	}
	if _, err := Decode(make([]byte, MaxSize+1), Options{}); err == nil {
		t.Fatal("oversized manifest accepted")
	}
}

func valid() *Manifest {
	m, _ := Decode([]byte(strings.Replace(string(mustRead()), `"digest": ""`, `"digest": "sha256:`+strings.Repeat("b", 64)+`"`, 1)), Options{})
	return m
}

func mustRead() []byte { b, _ := os.ReadFile("../../../sensors/template/manifest.json"); return b }

func TestValidateRules(t *testing.T) {
	cases := map[string]func(*Manifest){
		"cap":       func(m *Manifest) { m.Runtime.CapAdd = []string{"SYS_ADMIN"} },
		"network":   func(m *Manifest) { m.Runtime.NetworkMode = "container:x" },
		"user":      func(m *Manifest) { m.Runtime.User = "root" },
		"hub major": func(m *Manifest) { m.Compatibility.HubMajor = 2 },
		"schema":    func(m *Manifest) { m.SchemaVersion = 2 },
		"name":      func(m *Manifest) { m.Name = "Bad_Name" },
		"reserved key": func(m *Manifest) {
			m.Config = append(m.Config, ConfigKey{Name: "TS_HUB_ENDPOINT", Type: "string", Description: "x"})
		},
		"bad reserved": func(m *Manifest) {
			m.Config = append(m.Config, ConfigKey{Name: "TS_OTHER", Type: "string", HubReserved: true, Description: "x"})
		},
		"bad default":  func(m *Manifest) { d := "70000"; m.Config[0].Default = &d },
		"bad port key": func(m *Manifest) { m.Runtime.ListenPorts[0].ConfigKey = "TS_TEMPLATE_COOLDOWN_SEC" },
		"no triggers":  func(m *Manifest) { m.Triggers = nil },
		"bad severity": func(m *Manifest) { m.Triggers[0].DefaultSeverity = "urgent" },
		"bad pattern":  func(m *Manifest) { m.Config[1].Validation.Pattern = "(" },
		"image $":      func(m *Manifest) { m.Image.Repository = "ghcr.io/x/$y" },
		"platform":     func(m *Manifest) { m.Image.Platforms = []string{"windows/amd64"} },
		"init interp":  func(m *Manifest) { m.Init = &Init{Image: m.Image, Command: []string{"sh", "-c", "{{x}}"}} },
		"init hostpath": func(m *Manifest) {
			m.Init = &Init{Image: m.Image, Command: []string{"/i"}, WritableHostPaths: []string{"TS_X"}}
		},
		"discovery": func(m *Manifest) { m.Discovery.Defaults["TS_TEMPLATE_PORT"] = "$(curl evil)" },
	}
	if err := valid().Validate(Options{}); err != nil {
		t.Fatalf("baseline invalid: %v", err)
	}
	for name, mut := range cases {
		m := valid()
		mut(m)
		if err := m.Validate(Options{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	m := valid()
	m.Runtime.CapAdd = []string{"NET_ADMIN"}
	var re *RuleError
	if err := m.Validate(Options{}); !errors.As(err, &re) || re.Code != "capability_not_allowed" {
		t.Fatalf("rule code: %v", err)
	}
}

func TestCheckValue(t *testing.T) {
	min, max := int64(10), int64(20)
	cases := []struct {
		k  ConfigKey
		v  string
		ok bool
	}{
		{ConfigKey{Type: "port"}, "443", true},
		{ConfigKey{Type: "port"}, "0", false},
		{ConfigKey{Type: "int", Validation: &Validation{Min: &min, Max: &max}}, "15", true},
		{ConfigKey{Type: "int", Validation: &Validation{Min: &min, Max: &max}}, "21", false},
		{ConfigKey{Type: "bool"}, "yes", false},
		{ConfigKey{Type: "string", Validation: &Validation{Pattern: "[a-z]+"}}, "abc", true},
		{ConfigKey{Type: "string", Validation: &Validation{Pattern: "[a-z]+"}}, "abc1", false},
		{ConfigKey{Type: "string"}, "line1\nline2", false},
		{ConfigKey{Type: "list", ItemType: "port"}, "22, 80,443", true},
		{ConfigKey{Type: "list", ItemType: "port", Validation: &Validation{MaxItems: 2}}, "1,2,3", false},
		{ConfigKey{Type: "list", ItemType: "path"}, "/srv/a,relative", false},
		{ConfigKey{Type: "path"}, "/srv/a/../b", false},
	}
	for i, c := range cases {
		if err := CheckValue(&c.k, c.v); (err == nil) != c.ok {
			t.Errorf("case %d (%s %q): err=%v", i, c.k.Type, c.v, err)
		}
	}
}

func TestMountSources(t *testing.T) {
	for _, p := range []string{"/srv/lures", "/home/ops/.aws", "/opt/app/conf", "/var/www/html"} {
		if err := CheckMountSource(p); err != nil {
			t.Errorf("%s refused: %v", p, err)
		}
	}
	for _, p := range []string{"/", "/etc", "/etc/ssh", "/run/docker.sock", "/var/run/docker.sock", "/var", "/var/lib",
		"/var/lib/docker", "/var/lib/kubelet/pods", "/lib64", "/usr/local", "/root/.ssh", "/proc/self", "/sys/fs", "/dev/sda", "/boot"} {
		if err := CheckMountSource(p); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
}

// TestAllSensorManifests validates every manifest in the repository (§9: CI
// validates official manifests against the schema and §6.12 rules).
func TestAllSensorManifests(t *testing.T) {
	paths, _ := filepath.Glob("../../../sensors/*/manifest.json")
	paths = append(paths, "../../../sdk/python/template/manifest.json")
	if len(paths) < 2 {
		t.Fatal("no manifests found")
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		m, err := Decode(b, Options{AllowUnpinned: true}) // digests are filled at publish
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if dir := filepath.Base(filepath.Dir(p)); dir != m.Name && !(dir == "template" && m.Name == "python-template") {
			t.Errorf("%s: name %q does not match its directory", p, m.Name)
		}
	}
}
