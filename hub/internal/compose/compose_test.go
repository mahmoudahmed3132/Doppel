// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package compose

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/fleet"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/manifest"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ported/stub"
)

const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func str(s string) *string { return &s }

// tarpit returns a valid manifest; tests mutate copies of it.
func tarpit() *manifest.Manifest {
	return &manifest.Manifest{
		SchemaVersion: 3, Name: "tcp-tarpit", DisplayName: "TCP tarpit", Version: "1.0.0",
		Description: "Holds TCP connections", Category: "network", Author: "TrueSignal",
		Image: manifest.Image{Repository: "ghcr.io/example/truesignal-tcp-tarpit", Tag: "1.0.0", Digest: digest, Platforms: []string{"linux/amd64"}},
		Runtime: manifest.Runtime{NetworkMode: "host", CapAdd: []string{"NET_BIND_SERVICE"},
			ListenPorts: []manifest.ListenPort{{ConfigKey: "TS_PORTS", Protocol: "tcp"}}},
		Config: []manifest.ConfigKey{
			{Name: "TS_PORTS", Type: "list", ItemType: "port", Required: true, Description: "ports"},
			{Name: "TS_MODE", Type: "enum", Default: str("hold"), Description: "mode", Validation: &manifest.Validation{Enum: []string{"hold", "echo", "close"}}},
			{Name: "TS_CAPTURE_KEY", Type: "string", HubReserved: true, Description: "capture key"},
		},
		Triggers:      []manifest.Trigger{{Name: "tcp_connection", DefaultSeverity: "medium", Description: "connect"}},
		Compatibility: manifest.Compatibility{HubMajor: 3},
	}
}

func dnsSensor() *manifest.Manifest {
	m := tarpit()
	m.Name, m.Runtime.ListenPorts = "dns-decoy", []manifest.ListenPort{{ConfigKey: "TS_PORTS", Protocol: "udp"}}
	return m
}

func fileCanary() *manifest.Manifest {
	m := tarpit()
	m.Name, m.Runtime.NetworkMode, m.Runtime.CapAdd, m.Runtime.ListenPorts = "file-canary", "none", nil, nil
	m.Runtime.HostPaths = []manifest.HostPath{{ConfigKey: "TS_LURES", Mount: "parent", ReadOnly: true}}
	m.Config = []manifest.ConfigKey{
		{Name: "TS_LURES", Type: "list", ItemType: "path", Required: true, Description: "lure files"},
		{Name: "TS_HONEYTOKEN", Type: "string", HubReserved: true, Description: "credential"},
	}
	m.Init = &manifest.Init{Image: manifest.Image{Repository: "ghcr.io/example/truesignal-file-canary-init", Digest: digest, Platforms: []string{"linux/amd64"}},
		Command: []string{"/init", "--create"}, WritableHostPaths: []string{"TS_LURES"}}
	return m
}

type source map[string]*manifest.Manifest

func (s source) Manifest(_ context.Context, name, version string) (*manifest.Manifest, error) {
	if m, ok := s[name+"@"+version]; ok {
		return m, nil
	}
	return nil, ErrManifestUnavailable
}

type settings map[string]string

func (s settings) Setting(_ context.Context, k string) (string, bool, error) {
	v, ok := s[k]
	return v, ok, nil
}

type keys struct{}

func (keys) CaptureMasterKey(context.Context) ([]byte, error) {
	return []byte("capture-master-key-0123456789abc"), nil
}
func (keys) BeaconMasterKey(context.Context) ([]byte, error) {
	return []byte("beacon-master-key-0123456789abcd"), nil
}

func compiler(ms ...*manifest.Manifest) *Compiler {
	src := source{}
	for _, m := range ms {
		src[m.Name+"@"+m.Version] = m
	}
	return &Compiler{Manifests: src, Settings: settings{SettingEndpoint: "https://hub.example.com"}, Keys: keys{},
		Honeytokens: &stub.Honeytokens{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

var node = domain.Node{ID: "node-0000000a"}

func sensor(id, name string, cfg map[string]string) domain.Sensor {
	return domain.Sensor{ID: id, CatalogueName: name, Version: "1.0.0", Config: cfg}
}

func render(t *testing.T, c *Compiler, redact bool, sensors ...domain.Sensor) (*Document, fleet.Rendered, error) {
	t.Helper()
	r, err := c.Render(context.Background(), node, sensors, fleet.RenderOptions{Redact: redact})
	if err != nil {
		return nil, r, err
	}
	var d Document
	if err := json.Unmarshal(r.Compose, &d); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	return &d, r, nil
}

func wantCode(t *testing.T, err error, status int, code string) {
	t.Helper()
	var re *fleet.RenderError
	if !errors.As(err, &re) || re.Status != status || re.Code != code {
		t.Fatalf("want %d %s, got %v", status, code, err)
	}
}

func TestPassingRenderHardening(t *testing.T) {
	d, r, err := render(t, compiler(tarpit()), false, sensor("ts-sensor-ssh", "tcp-tarpit", map[string]string{"TS_PORTS": "22,2222"}))
	if err != nil {
		t.Fatal(err)
	}
	s := d.Services["ts-sensor-ssh"]
	if s == nil || len(d.Services) != 1 {
		t.Fatalf("services %v", d.Services)
	}
	// Rules 1, 2, 3, 8.
	if s.Image != "ghcr.io/example/truesignal-tcp-tarpit:1.0.0@"+digest || !s.ReadOnly || strings.Join(s.CapDrop, ",") != "ALL" ||
		strings.Join(s.SecurityOpt, ",") != "no-new-privileges:true" || strings.Join(s.CapAdd, ",") != "NET_BIND_SERVICE" ||
		s.User != DefaultUser || s.ContainerName != "ts-sensor-ssh" || s.NetworkMode != "host" {
		t.Fatalf("hardening %+v", s)
	}
	env := s.Environment
	if env["TS_HUB_ENDPOINT"] != "https://hub.example.com" || env["TS_SENSOR_ID"] != "ts-sensor-ssh" || env["TS_TEST_MODE"] != "false" ||
		env["TS_CONFIG_REVISION"] != r.Revision || env["TS_MODE"] != "hold" || env["TS_PORTS"] != "22,2222" {
		t.Fatalf("env %v", env)
	}
	if _, has := env["TS_NODE_KEY"]; has || d.Meta.NodeKeyEnv != "TS_NODE_KEY" {
		t.Fatal("node key handling: the Hub cannot know the key; the CLI injects it")
	}
	want := hex.EncodeToString(CaptureKey([]byte("capture-master-key-0123456789abc"), node.ID))
	if env["TS_CAPTURE_KEY"] != want {
		t.Fatal("capture key is not HMAC(master, node id)")
	}
	if strings.Contains(string(r.Compose), "capture-master-key") {
		t.Fatal("master key leaked into compose")
	}
}

// Rule 1.
func TestRuleDigest(t *testing.T) {
	m := tarpit()
	m.Image.Digest = ""
	_, _, err := render(t, compiler(m), true, sensor("ts-sensor-a", "tcp-tarpit", map[string]string{"TS_PORTS": "22"}))
	wantCode(t, err, 422, "image_not_pinned")

	c := compiler(m)
	c.Options.AllowUnpinned = true
	d, _, err := render(t, c, true, sensor("ts-sensor-a", "tcp-tarpit", map[string]string{"TS_PORTS": "22"}))
	if err != nil || d.Services["ts-sensor-a"].Image != "ghcr.io/example/truesignal-tcp-tarpit:1.0.0" {
		t.Fatalf("dev unpinned: %v", err)
	}
	m.Image.Digest = "sha256:abc"
	_, _, err = render(t, compiler(m), true, sensor("ts-sensor-a", "tcp-tarpit", map[string]string{"TS_PORTS": "22"}))
	wantCode(t, err, 422, "image_not_pinned")
}

// Rule 3.
func TestRuleCapabilitiesAndNetwork(t *testing.T) {
	m := tarpit()
	m.Runtime.CapAdd = []string{"NET_ADMIN"}
	_, _, err := render(t, compiler(m), true, sensor("ts-sensor-a", "tcp-tarpit", map[string]string{"TS_PORTS": "22"}))
	wantCode(t, err, 422, "capability_not_allowed")

	m = tarpit()
	m.Runtime.CapAdd = []string{"NET_RAW", "DAC_OVERRIDE", "NET_BIND_SERVICE"}
	if _, _, err := render(t, compiler(m), true, sensor("ts-sensor-a", "tcp-tarpit", map[string]string{"TS_PORTS": "22"})); err != nil {
		t.Fatalf("allowed caps refused: %v", err)
	}
	m.Runtime.NetworkMode = "container:other"
	_, _, err = render(t, compiler(m), true, sensor("ts-sensor-a", "tcp-tarpit", map[string]string{"TS_PORTS": "22"}))
	wantCode(t, err, 422, "network_mode_not_allowed")
}

// Rule 4.
func TestRuleMounts(t *testing.T) {
	c := compiler(fileCanary())
	bad := []string{"/run/docker.sock", "/var/run/docker.sock", "/etc/shadow", "/proc/1/root", "/var/lib/docker/x",
		"/", "relative/path", "/srv/../etc/passwd", "/srv//x", "/srv/x/", "/srv/$HOME", "/srv/{{x}}", "/srv/a:b", "/x"}
	for _, p := range bad {
		_, _, err := render(t, c, true, sensor("ts-sensor-f", "file-canary", map[string]string{"TS_LURES": p}))
		var re *fleet.RenderError
		if !errors.As(err, &re) || re.Status != 422 {
			t.Errorf("mount %q accepted: %v", p, err)
		}
	}
	// "/x" is fine itself but its parent "/" is not; "/var/x" exposes /var/lib/docker.
	for _, p := range []string{"/var/lure.txt", "/x"} {
		if _, _, err := render(t, c, true, sensor("ts-sensor-f", "file-canary", map[string]string{"TS_LURES": p})); err == nil {
			t.Errorf("%q: parent mount should be refused", p)
		}
	}

	d, _, err := render(t, c, true, sensor("ts-sensor-f", "file-canary", map[string]string{"TS_LURES": "/srv/finance/q3.xlsx,/srv/finance/keys.txt,/home/ops/.aws/credentials"}))
	if err != nil {
		t.Fatal(err)
	}
	main, init := d.Services["ts-sensor-f"], d.Services["ts-sensor-f-init"]
	var srcs []string
	for _, v := range main.Volumes {
		if v.Type == "bind" {
			if !v.ReadOnly || v.Bind == nil || v.Bind.CreateHostPath {
				t.Fatalf("main bind mount not read-only/no-create: %+v", v)
			}
			srcs = append(srcs, v.Source)
		}
	}
	if strings.Join(srcs, ",") != "/srv/finance,/home/ops/.aws" {
		t.Fatalf("parent mounts %v", srcs)
	}
	// Rule 2 for init: no network; writable lure dirs; main waits for it.
	if init.NetworkMode != "none" || !init.ReadOnly || init.CapDrop[0] != "ALL" || init.Restart != "no" ||
		main.DependsOn["ts-sensor-f-init"].Condition != "service_completed_successfully" {
		t.Fatalf("init %+v", init)
	}
	rw := 0
	for _, v := range init.Volumes {
		if v.Type == "bind" && !v.ReadOnly {
			rw++
		}
	}
	if rw != 2 {
		t.Fatalf("init writable mounts %d", rw)
	}
}

// Rule 5.
func TestRuleInterpolation(t *testing.T) {
	m := tarpit()
	m.Image.Repository = "ghcr.io/example/${EVIL}"
	_, _, err := render(t, compiler(m), true, sensor("ts-sensor-a", "tcp-tarpit", map[string]string{"TS_PORTS": "22"}))
	if err == nil {
		t.Fatal("$ in image accepted")
	}
	fc := fileCanary()
	fc.Init.Command = []string{"/init", "$(id)"}
	_, _, err = render(t, compiler(fc), true, sensor("ts-sensor-f", "file-canary", map[string]string{"TS_LURES": "/srv/a"}))
	wantCode(t, err, 422, "interpolation")

	// $ in environment values is escaped, not interpreted.
	m = tarpit()
	m.Config = append(m.Config, manifest.ConfigKey{Name: "TS_BANNER", Type: "string", Description: "banner"})
	d, _, err := render(t, compiler(m), true, sensor("ts-sensor-a", "tcp-tarpit", map[string]string{"TS_PORTS": "22", "TS_BANNER": "SSH-2.0 $HOME ${PATH}"}))
	if err != nil || d.Services["ts-sensor-a"].Environment["TS_BANNER"] != "SSH-2.0 $$HOME $${PATH}" {
		t.Fatalf("env escaping: %v %v", err, d)
	}
}

// Rule 6.
func TestRuleConfigDeclaredAndReserved(t *testing.T) {
	d, r, err := render(t, compiler(tarpit()), true, sensor("ts-sensor-a", "tcp-tarpit", map[string]string{
		"TS_PORTS": "22", "TS_UNDECLARED": "x", "TS_HUB_ENDPOINT": "https://attacker.example", "TS_SENSOR_ID": "ts-sensor-other",
		"TS_TEST_MODE": "true", "TS_CAPTURE_KEY": "chosen", "TS_NODE_KEY": "tsk_x"}))
	if err != nil {
		t.Fatal(err)
	}
	env := d.Services["ts-sensor-a"].Environment
	if _, has := env["TS_UNDECLARED"]; has {
		t.Fatal("undeclared key not dropped")
	}
	if env["TS_HUB_ENDPOINT"] != "https://hub.example.com" || env["TS_SENSOR_ID"] != "ts-sensor-a" || env["TS_TEST_MODE"] != "false" ||
		env["TS_CAPTURE_KEY"] != Redacted {
		t.Fatalf("reserved overridden: %v", env)
	}
	if _, has := env["TS_NODE_KEY"]; has {
		t.Fatal("user-supplied node key passed through")
	}
	if len(r.Warnings) != 6 {
		t.Fatalf("warnings %v", r.Warnings)
	}
	_, _, err = render(t, compiler(tarpit()), true, sensor("ts-sensor-a", "tcp-tarpit", map[string]string{}))
	wantCode(t, err, 422, "missing_config")
	_, _, err = render(t, compiler(tarpit()), true, sensor("ts-sensor-a", "tcp-tarpit", map[string]string{"TS_PORTS": "22", "TS_MODE": "explode"}))
	wantCode(t, err, 422, "invalid_config")
	_, _, err = render(t, compiler(tarpit()), true, sensor("ts-sensor-a", "tcp-tarpit", map[string]string{"TS_PORTS": "70000"}))
	wantCode(t, err, 422, "invalid_config")
}

// Rule 7, incl. UDP vs TCP on the same number.
func TestRulePortConflict(t *testing.T) {
	c := compiler(tarpit(), dnsSensor())
	_, _, err := render(t, c, true,
		sensor("ts-sensor-a", "tcp-tarpit", map[string]string{"TS_PORTS": "53,80"}),
		sensor("ts-sensor-b", "dns-decoy", map[string]string{"TS_PORTS": "53"}))
	wantCode(t, err, 409, "port_conflict")
	_, _, err = render(t, c, true,
		sensor("ts-sensor-a", "tcp-tarpit", map[string]string{"TS_PORTS": "22"}),
		sensor("ts-sensor-b", "tcp-tarpit", map[string]string{"TS_PORTS": "2222,22"}))
	wantCode(t, err, 409, "port_conflict")
	if _, _, err := render(t, c, true,
		sensor("ts-sensor-a", "tcp-tarpit", map[string]string{"TS_PORTS": "22"}),
		sensor("ts-sensor-b", "dns-decoy", map[string]string{"TS_PORTS": "53"})); err != nil {
		t.Fatalf("distinct ports refused: %v", err)
	}
}

func TestBridgePublishesPorts(t *testing.T) {
	m := tarpit()
	m.Runtime.NetworkMode = "bridge"
	d, _, err := render(t, compiler(m), true, sensor("ts-sensor-a", "tcp-tarpit", map[string]string{"TS_PORTS": "8080"}))
	if err != nil {
		t.Fatal(err)
	}
	p := d.Services["ts-sensor-a"].Ports
	if len(p) != 1 || p[0].Target != 8080 || p[0].Published != "8080" || p[0].Protocol != "tcp" {
		t.Fatalf("ports %+v", p)
	}
}

func TestContainerPortMapping(t *testing.T) {
	m := tarpit()
	m.Runtime.NetworkMode, m.Runtime.CapAdd = "bridge", nil
	m.Runtime.ListenPorts = []manifest.ListenPort{{ConfigKey: "TS_PORT", Protocol: "tcp", ContainerPort: 8080}}
	m.Config = []manifest.ConfigKey{{Name: "TS_PORT", Type: "port", Default: str("8080"), Description: "port"}}
	d, _, err := render(t, compiler(m), true, sensor("ts-sensor-web", "tcp-tarpit", map[string]string{"TS_PORT": "80"}))
	if err != nil {
		t.Fatal(err)
	}
	p := d.Services["ts-sensor-web"].Ports
	if len(p) != 1 || p[0].Target != 8080 || p[0].Published != "80" {
		t.Fatalf("%+v", p)
	}
	m.Runtime.NetworkMode = "host"
	_, _, err = render(t, compiler(m), true, sensor("ts-sensor-web", "tcp-tarpit", map[string]string{"TS_PORT": "80"}))
	if err == nil {
		t.Fatal("container_port accepted with host networking")
	}
}

// Rule 10.
func TestRevisionDeterministic(t *testing.T) {
	a := sensor("ts-sensor-a", "tcp-tarpit", map[string]string{"TS_PORTS": "22", "TS_MODE": "echo"})
	b := sensor("ts-sensor-b", "tcp-tarpit", map[string]string{"TS_PORTS": "80"})
	r1 := Revision([]domain.Sensor{a, b})
	r2 := Revision([]domain.Sensor{b, a})
	if r1 != r2 || !strings.HasPrefix(r1, "rev_") || len(r1) != 12 {
		t.Fatalf("%s %s", r1, r2)
	}
	b.Config["TS_PORTS"] = "81"
	if Revision([]domain.Sensor{a, b}) == r1 {
		t.Fatal("revision ignores config")
	}
	c := compiler(tarpit())
	_, x, _ := render(t, c, true, a)
	_, y, _ := render(t, c, false, a)
	_, z, _ := render(t, c, true, a)
	if x.Revision != y.Revision || string(x.Compose) != string(z.Compose) {
		t.Fatal("render not deterministic or revision depends on redaction")
	}
}

func TestSecretsAndRedaction(t *testing.T) {
	ht := &stub.Honeytokens{}
	c := compiler(fileCanary())
	c.Honeytokens = ht
	s := sensor("ts-sensor-f", "file-canary", map[string]string{"TS_LURES": "/srv/finance/q3.xlsx"})

	d, r, _ := render(t, c, true, s)
	if d.Services["ts-sensor-f"].Environment["TS_HONEYTOKEN"] != Redacted || strings.Contains(string(r.Compose), "stub-secret") {
		t.Fatal("redacted render contains the honeytoken")
	}
	if l, _ := ht.List(context.Background()); len(l) != 0 {
		t.Fatal("redacted (admin) render created a honeytoken")
	}
	d, _, _ = render(t, c, false, s)
	var tok map[string]string
	json.Unmarshal([]byte(d.Services["ts-sensor-f"].Environment["TS_HONEYTOKEN"]), &tok)
	if tok["secret"] != "stub-secret" || tok["username"] == "" {
		t.Fatalf("honeytoken not injected: %v", tok)
	}
	if d.Services["ts-sensor-f-init"].Environment["TS_HONEYTOKEN"] == "" {
		t.Fatal("init container has no honeytoken for lure content")
	}
	c.Honeytokens = nil
	_, _, err := render(t, c, false, s)
	wantCode(t, err, 422, "honeytoken_unavailable")
}

func TestManifestProblems(t *testing.T) {
	_, _, err := render(t, compiler(), true, sensor("ts-sensor-a", "tcp-tarpit", map[string]string{"TS_PORTS": "22"}))
	wantCode(t, err, 422, "manifest_unavailable")
	m := tarpit()
	m.Compatibility.HubMajor = 4
	_, _, err = render(t, compiler(m), true, sensor("ts-sensor-a", "tcp-tarpit", map[string]string{"TS_PORTS": "22"}))
	wantCode(t, err, 422, "incompatible_manifest")
	c := compiler(tarpit())
	c.Settings = settings{}
	_, _, err = render(t, c, true)
	wantCode(t, err, 422, "hub_endpoint_unset")
	// Empty node renders an empty, valid document.
	d, _, err := render(t, compiler(), true)
	if err != nil || len(d.Services) != 0 {
		t.Fatal(err)
	}
}

// TestRealManifestsRender renders every sensor manifest in the repository
// with plausible configuration through the real compiler.
func TestRealManifestsRender(t *testing.T) {
	paths, _ := filepath.Glob("../../../sensors/*/manifest.json")
	if len(paths) < 6 {
		t.Fatalf("expected the template and five sensors, found %d manifests", len(paths))
	}
	src := source{}
	var sensors []domain.Sensor
	lureDir := "/srv/truesignal-lures"
	for i, p := range paths {
		b, _ := os.ReadFile(p)
		m, err := manifest.Decode(b, manifest.Options{AllowUnpinned: true})
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		m.Image.Digest = digest
		if m.Init != nil {
			m.Init.Image.Digest = digest
		}
		src[m.Name+"@"+m.Version] = m
		cfg := map[string]string{}
		for _, k := range m.Config {
			if !k.Required {
				continue
			}
			switch {
			case k.Type == "port" || k.ItemType == "port":
				cfg[k.Name] = strconv.Itoa(30000 + i)
			case k.ItemType == "path" || k.Type == "path":
				cfg[k.Name] = lureDir + "/passwords.txt"
			}
		}
		sensors = append(sensors, domain.Sensor{ID: "ts-sensor-" + m.Name, CatalogueName: m.Name, Version: m.Version, Config: cfg})
	}
	c := &Compiler{Manifests: src, Settings: settings{SettingEndpoint: "https://hub.example.com"}, Keys: keys{},
		Honeytokens: &stub.Honeytokens{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	r, err := c.Render(context.Background(), node, sensors, fleet.RenderOptions{Redact: false})
	if err != nil {
		t.Fatal(err)
	}
	var d Document
	json.Unmarshal(r.Compose, &d)
	// §10 compose guard, compiler side: rendered files never build images.
	var generic struct {
		Services map[string]map[string]json.RawMessage `json:"services"`
	}
	json.Unmarshal(r.Compose, &generic)
	for name, svc := range generic.Services {
		if _, ok := svc["build"]; ok {
			t.Errorf("%s: rendered compose contains build:", name)
		}
	}
	want := map[string]struct {
		user string
		caps string
		net  string
	}{
		"ts-sensor-tcp-tarpit":            {"0:0", "NET_BIND_SERVICE", "host"},
		"ts-sensor-icmp-canary":           {"0:0", "NET_RAW", "host"},
		"ts-sensor-network-scan-detector": {"0:0", "NET_RAW", "host"},
		"ts-sensor-file-canary":           {"0:0", "DAC_OVERRIDE", "bridge"},
		"ts-sensor-file-canary-init":      {"0:0", "DAC_OVERRIDE", "none"},
		"ts-sensor-web-router-decoy":      {DefaultUser, "", "bridge"},
		"ts-sensor-template":              {DefaultUser, "", "host"},
	}
	for name, w := range want {
		s := d.Services[name]
		if s == nil {
			t.Errorf("%s missing", name)
			continue
		}
		if s.User != w.user || strings.Join(s.CapAdd, ",") != w.caps || s.NetworkMode != w.net || !s.ReadOnly || s.CapDrop[0] != "ALL" {
			t.Errorf("%s: user %s caps %v net %s", name, s.User, s.CapAdd, s.NetworkMode)
		}
	}
	if d.Services["ts-sensor-web-router-decoy"].Environment["TS_CAPTURE_KEY"] == "" ||
		d.Services["ts-sensor-file-canary-init"].Environment["TS_HONEYTOKEN"] == "" {
		t.Fatal("hub secrets not injected")
	}
	if len(d.Meta.HostPaths) != 1 || d.Meta.HostPaths[0] != lureDir+"/passwords.txt" {
		t.Fatalf("host paths %v", d.Meta.HostPaths)
	}
}
