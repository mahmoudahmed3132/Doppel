// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package apply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/cli/internal/config"
	"github.com/mahmoudahmed3132/Doppel/cli/internal/docker"
	"github.com/mahmoudahmed3132/Doppel/cli/internal/hub"
)

const key = "tsk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type fakeHub struct {
	compose  string
	revision string
	reports  []string
}

func (f *fakeHub) Compose(context.Context) (*hub.Rendered, error) {
	return &hub.Rendered{Revision: f.revision, Compose: json.RawMessage(f.compose)}, nil
}

func (f *fakeHub) ReportApplied(_ context.Context, rev, result, msg string) error {
	f.reports = append(f.reports, result)
	return nil
}

type fakeDocker struct {
	calls   []string
	pullErr error
	upErr   []error // per call
	states  [][]docker.Container
	upFiles []string
}

func (d *fakeDocker) Pull(_ context.Context, f string) error {
	d.calls = append(d.calls, "pull")
	return d.pullErr
}
func (d *fakeDocker) Up(_ context.Context, f string) error {
	d.calls = append(d.calls, "up")
	b, _ := os.ReadFile(f)
	d.upFiles = append(d.upFiles, string(b))
	if len(d.upErr) > 0 {
		e := d.upErr[0]
		d.upErr = d.upErr[1:]
		return e
	}
	return nil
}
func (d *fakeDocker) Down(context.Context, string) error {
	d.calls = append(d.calls, "down")
	return nil
}
func (d *fakeDocker) PS(context.Context, string) ([]docker.Container, error) {
	d.calls = append(d.calls, "ps")
	if len(d.states) == 0 {
		return []docker.Container{{Service: "ts-sensor-a", State: "running"}}, nil
	}
	s := d.states[0]
	d.states = d.states[1:]
	return s, nil
}

func composeDoc(nodeID, port, bindSrc string) string {
	vols := `[{"type":"tmpfs","target":"/tmp"}]`
	if bindSrc != "" {
		vols = fmt.Sprintf(`[{"type":"bind","source":%q,"target":%q,"read_only":true}]`, bindSrc, bindSrc)
	}
	return fmt.Sprintf(`{"name":"truesignal","x-truesignal":{"node_id":%q,"revision":"rev_0000000%s","node_key_env":"TS_NODE_KEY","host_paths":[]},
	"services":{"ts-sensor-a":{"container_name":"ts-sensor-a","image":"x@sha256:00","environment":{"TS_PORTS":%q},"volumes":%s},
	"ts-sensor-a-init":{"container_name":"ts-sensor-a-init","image":"y@sha256:00","environment":{}}}}`, nodeID, port[:1], port, vols)
}

func newApplier(t *testing.T, h *fakeHub, d *fakeDocker) *Applier {
	t.Helper()
	dir := t.TempDir()
	return &Applier{
		Paths:  config.Paths{ConfigFile: filepath.Join(dir, "etc", "config.json"), WorkDir: filepath.Join(dir, "opt")},
		Config: &config.Config{HubEndpoint: "https://hub", NodeID: "node-0000000a", NodeKey: key},
		Hub:    h, Docker: d, Settle: time.Millisecond,
		Sleep: func(context.Context, time.Duration) error { return nil },
		Warn:  func(string, ...any) {},
	}
}

func TestFirstApplyInjectsKeyAndWrites0600(t *testing.T) {
	h := &fakeHub{compose: composeDoc("node-0000000a", "22", ""), revision: "rev_00000001"}
	d := &fakeDocker{}
	a := newApplier(t, h, d)
	res, err := a.Run(context.Background())
	if err != nil || res.Outcome != ResultApplied {
		t.Fatalf("%+v %v", res, err)
	}
	st, _ := os.Stat(a.Paths.Compose())
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("compose file mode %v", st.Mode().Perm())
	}
	var doc map[string]any
	b, _ := os.ReadFile(a.Paths.Compose())
	json.Unmarshal(b, &doc)
	for _, svc := range []string{"ts-sensor-a", "ts-sensor-a-init"} {
		env := doc["services"].(map[string]any)[svc].(map[string]any)["environment"].(map[string]any)
		if env["TS_NODE_KEY"] != key {
			t.Fatalf("%s: node key not injected", svc)
		}
	}
	if strings.Join(d.calls, ",") != "pull,up,ps" || strings.Join(h.reports, ",") != "applied" {
		t.Fatalf("calls %v reports %v", d.calls, h.reports)
	}
}

func TestApplyNoOpWhenUnchanged(t *testing.T) {
	h := &fakeHub{compose: composeDoc("node-0000000a", "22", ""), revision: "rev_00000001"}
	d := &fakeDocker{}
	a := newApplier(t, h, d)
	a.Run(context.Background())
	d.calls = nil
	// Same content, different formatting and key order from the Hub.
	var v any
	json.Unmarshal([]byte(h.compose), &v)
	re, _ := json.Marshal(v)
	h.compose = string(re)
	res, err := a.Run(context.Background())
	if err != nil || res.Outcome != ResultUnchanged || len(d.calls) != 0 {
		t.Fatalf("not a no-op: %+v %v calls %v", res, err, d.calls)
	}
	if h.reports[len(h.reports)-1] != ResultUnchanged {
		t.Fatal("unchanged not reported")
	}
}

func TestRollbackOnExitedService(t *testing.T) {
	h := &fakeHub{compose: composeDoc("node-0000000a", "22", ""), revision: "rev_00000001"}
	d := &fakeDocker{}
	a := newApplier(t, h, d)
	a.Run(context.Background())
	good, _ := os.ReadFile(a.Paths.Compose())

	h.compose, h.revision = composeDoc("node-0000000a", "80", ""), "rev_00000008"
	d.calls = nil
	d.states = [][]docker.Container{{
		{Service: "ts-sensor-a", State: "exited", ExitCode: 1},
		{Service: "ts-sensor-a-init", State: "exited", ExitCode: 0},
	}}
	res, err := a.Run(context.Background())
	if err == nil || res.Outcome != ResultRolledBack || !strings.Contains(err.Error(), "ts-sensor-a (exited, exit 1)") {
		t.Fatalf("%+v %v", res, err)
	}
	if strings.Contains(err.Error(), "ts-sensor-a-init") {
		t.Fatal("init container exiting 0 counted as a failure")
	}
	now, _ := os.ReadFile(a.Paths.Compose())
	if string(now) != string(good) {
		t.Fatal("previous compose file not restored")
	}
	if strings.Join(d.calls, ",") != "pull,up,ps,up" || !strings.Contains(d.upFiles[len(d.upFiles)-1], `"TS_PORTS": "22"`) {
		t.Fatalf("rollback did not bring the previous config back up: %v", d.calls)
	}
}

func TestRestartingAndUpFailureRollBack(t *testing.T) {
	for name, d := range map[string]*fakeDocker{
		"restarting": {states: [][]docker.Container{{{Service: "ts-sensor-a", State: "restarting"}}}},
		"up error":   {upErr: []error{errors.New("port is already allocated")}},
		"init fails": {states: [][]docker.Container{{{Service: "ts-sensor-a", State: "created"}, {Service: "ts-sensor-a-init", State: "exited", ExitCode: 2}}}},
	} {
		h := &fakeHub{compose: composeDoc("node-0000000a", "22", ""), revision: "rev_00000001"}
		a := newApplier(t, h, &fakeDocker{})
		a.Run(context.Background())
		h.compose = composeDoc("node-0000000a", "80", "")
		a.Docker = d
		if res, err := a.Run(context.Background()); err == nil || res.Outcome != ResultRolledBack {
			t.Errorf("%s: %+v %v", name, res, err)
		}
	}
}

func TestFirstDeployFailureTearsDown(t *testing.T) {
	h := &fakeHub{compose: composeDoc("node-0000000a", "22", ""), revision: "rev_00000001"}
	d := &fakeDocker{states: [][]docker.Container{{{Service: "ts-sensor-a", State: "exited", ExitCode: 1}}}}
	a := newApplier(t, h, d)
	res, err := a.Run(context.Background())
	if err == nil || res.Outcome != ResultRolledBack || d.calls[len(d.calls)-1] != "down" {
		t.Fatalf("%+v %v %v", res, err, d.calls)
	}
	if _, err := os.Stat(a.Paths.Compose()); !os.IsNotExist(err) {
		t.Fatal("failed first compose file left in place")
	}
}

func TestPullFailureChangesNothing(t *testing.T) {
	h := &fakeHub{compose: composeDoc("node-0000000a", "22", ""), revision: "rev_00000001"}
	d := &fakeDocker{}
	a := newApplier(t, h, d)
	a.Run(context.Background())
	good, _ := os.ReadFile(a.Paths.Compose())
	h.compose = composeDoc("node-0000000a", "80", "")
	d.pullErr, d.calls = errors.New("manifest unknown"), nil
	res, err := a.Run(context.Background())
	if err == nil || res.Outcome != ResultFailed || strings.Join(d.calls, ",") != "pull" {
		t.Fatalf("%+v %v %v", res, err, d.calls)
	}
	if now, _ := os.ReadFile(a.Paths.Compose()); string(now) != string(good) {
		t.Fatal("compose file changed after a failed pull")
	}
}

func TestHostPathChecks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "lures")
	os.Mkdir(real, 0o755)
	link := filepath.Join(dir, "link")
	os.Symlink("/etc", link)

	cases := map[string]string{
		"missing": filepath.Join(dir, "nope"),
		"symlink": link,
		"etc":     "/etc",
		"dotdot":  real + "/../lures",
	}
	for name, src := range cases {
		h := &fakeHub{compose: composeDoc("node-0000000a", "22", src), revision: "rev_00000001"}
		d := &fakeDocker{}
		a := newApplier(t, h, d)
		res, err := a.Run(context.Background())
		if err == nil || res.Outcome != ResultFailed || len(d.calls) != 0 {
			t.Errorf("%s (%s): %+v %v %v", name, src, res, err, d.calls)
		}
	}
	h := &fakeHub{compose: composeDoc("node-0000000a", "22", real), revision: "rev_00000001"}
	if res, err := newApplier(t, h, &fakeDocker{}).Run(context.Background()); err != nil || res.Outcome != ResultApplied {
		t.Fatalf("valid path refused: %v", err)
	}
}

func TestRefusesForeignOrMalformedCompose(t *testing.T) {
	for name, doc := range map[string]string{
		"other node":  composeDoc("node-0000000b", "22", ""),
		"bad service": `{"x-truesignal":{"node_id":"node-0000000a"},"services":{"evil":{"container_name":"evil","image":"x"}}}`,
		"not json":    `"nope"`,
	} {
		h := &fakeHub{compose: doc, revision: "rev_00000001"}
		d := &fakeDocker{}
		if _, err := newApplier(t, h, d).Run(context.Background()); err == nil || len(d.calls) != 0 {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestLockExclusive(t *testing.T) {
	p := config.Paths{WorkDir: t.TempDir()}
	unlock, err := Lock(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(p); err == nil {
		t.Fatal("second lock acquired")
	}
	unlock()
	if u, err := Lock(p); err != nil {
		t.Fatal(err)
	} else {
		u()
	}
}
