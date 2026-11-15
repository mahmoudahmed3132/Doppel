// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package fleet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/nodekey"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

// FakeCompiler models the rules fleet relies on: TS_BAD is undeclared
// (422), equal TS_PORT values conflict (409), revision is deterministic.
type FakeCompiler struct {
	mu      sync.Mutex
	redacts []bool
}

func (f *FakeCompiler) Render(_ context.Context, n domain.Node, sensors []domain.Sensor, o RenderOptions) (Rendered, error) {
	f.mu.Lock()
	f.redacts = append(f.redacts, o.Redact)
	f.mu.Unlock()
	ports := map[string]string{}
	h := sha256.New()
	var b strings.Builder
	for _, s := range sensors {
		if _, bad := s.Config["TS_BAD"]; bad {
			return Rendered{}, &RenderError{Status: 422, Code: "undeclared_config", Message: "TS_BAD", SensorID: s.ID}
		}
		if p, ok := s.Config["TS_PORT"]; ok {
			if other, dup := ports[p]; dup {
				return Rendered{}, &RenderError{Status: 409, Code: "port_conflict", Message: other + " and " + s.ID}
			}
			ports[p] = s.ID
		}
		keys := make([]string, 0, len(s.Config))
		for k := range s.Config {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(h, "%s|%s|", s.ID, s.Version)
		for _, k := range keys {
			fmt.Fprintf(h, "%s=%s;", k, s.Config[k])
		}
		fmt.Fprintf(&b, "%s:%s\n", s.ID, s.Version)
	}
	return Rendered{Compose: []byte(b.String()), Revision: "rev_" + hex.EncodeToString(h.Sum(nil))[:8]}, nil
}

type fakeCatalogue struct{}

func (fakeCatalogue) Latest(_ context.Context, name string) (string, bool) {
	if name == "tcp-tarpit" {
		return "1.2.0", true
	}
	return "", false
}

func (fakeCatalogue) SecretKeys(_ context.Context, name, _ string) ([]string, bool) {
	if name == "tcp-tarpit" {
		return []string{"TS_SECRET"}, true
	}
	return nil, false
}

type keyCache struct{ invalidated []string }

func (k *keyCache) Invalidate(id string) { k.invalidated = append(k.invalidated, id) }

func newService(t *testing.T, withCompiler bool) (*Service, *store.DB, *keyCache) {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "ts.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	kc := &keyCache{}
	s := &Service{Store: db, Catalogue: fakeCatalogue{}, Keys: kc, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: time.Now}
	if withCompiler {
		s.Compiler = &FakeCompiler{}
	}
	return s, db, kc
}

func TestNodeLifecycle(t *testing.T) {
	s, db, kc := newService(t, true)
	ctx := context.Background()

	if _, _, err := s.CreateNode(ctx, "  ", nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty alias accepted")
	}
	if _, _, err := s.CreateNode(ctx, "dmz\n1", nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("control character accepted")
	}
	if _, _, err := s.CreateNode(ctx, "dmz", []string{"bad tag"}); !errors.Is(err, ErrInvalid) {
		t.Fatal("bad tag accepted")
	}
	n, key, err := s.CreateNode(ctx, " DMZ web 1 ", []string{"pci", "dmz", "pci"})
	if err != nil {
		t.Fatal(err)
	}
	if !domain.ValidNodeID(n.ID) || n.Alias != "DMZ web 1" || strings.Join(n.Tags, ",") != "dmz,pci" {
		t.Fatalf("%+v", n)
	}
	h, _ := nodekey.Hash(key)
	stored, _ := db.Node(ctx, n.ID)
	if string(stored.KeyHash) != string(h) {
		t.Fatal("stored key hash does not match the returned key")
	}

	alias := "dmz-web-01"
	if n2, err := s.UpdateNode(ctx, n.ID, &alias, nil); err != nil || n2.Alias != alias || len(n2.Tags) != 2 {
		t.Fatalf("%+v %v", n2, err)
	}
	newKey, err := s.RotateKey(ctx, n.ID)
	if err != nil || newKey == key {
		t.Fatal(err)
	}
	if len(kc.invalidated) != 1 {
		t.Fatal("rotation did not invalidate the key cache")
	}
	if _, err := s.RotateKey(ctx, "node-ffffffff"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("rotate unknown: %v", err)
	}
	if err := s.DeleteNode(ctx, n.ID); err != nil || len(kc.invalidated) != 2 {
		t.Fatal("delete did not invalidate the key cache")
	}
	if _, err := s.GetNode(ctx, n.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("node not deleted")
	}
}

func spec(name, port string) SensorSpec {
	return SensorSpec{Name: name, CatalogueName: "tcp-tarpit", Version: "1.0.0", Config: map[string]string{"TS_PORT": port, "TS_SECRET": "s3cret"}}
}

func TestSensorAddRendersBeforeSaving(t *testing.T) {
	s, db, _ := newService(t, true)
	ctx := context.Background()
	n, _, _ := s.CreateNode(ctx, "n1", nil)

	v, r, err := s.AddSensor(ctx, n.ID, spec("ssh", "22"))
	if err != nil {
		t.Fatal(err)
	}
	if v.ID != "ts-sensor-ssh" || v.Config["TS_SECRET"] != MaskedValue || v.Config["TS_PORT"] != "22" || !v.UpdateAvailable || v.LatestVersion != "1.2.0" {
		t.Fatalf("view %+v", v)
	}
	node, _ := db.Node(ctx, n.ID)
	if node.DesiredRevision != r.Revision || r.Revision == "" {
		t.Fatal("desired revision not stored with the sensor")
	}

	// Port conflict: refused, nothing stored, revision unchanged.
	var re *RenderError
	if _, _, err := s.AddSensor(ctx, n.ID, spec("ssh2", "22")); !errors.As(err, &re) || re.Status != 409 || re.Code != "port_conflict" {
		t.Fatalf("port conflict: %v", err)
	}
	bad := spec("bad", "23")
	bad.Config["TS_BAD"] = "x"
	if _, _, err := s.AddSensor(ctx, n.ID, bad); !errors.As(err, &re) || re.Status != 422 {
		t.Fatalf("invalid config: %v", err)
	}
	if list, _ := db.Sensors(ctx, n.ID); len(list) != 1 {
		t.Fatalf("refused sensors were stored: %d", len(list))
	}
	if node2, _ := db.Node(ctx, n.ID); node2.DesiredRevision != r.Revision {
		t.Fatal("refused change altered the revision")
	}
	if _, _, err := s.AddSensor(ctx, n.ID, spec("ssh", "2222")); !errors.Is(err, ErrSensorExists) {
		t.Fatalf("duplicate id: %v", err)
	}
	for _, sp := range []SensorSpec{
		{CatalogueName: "Bad_Name", Version: "1.0.0"},
		{CatalogueName: "tcp-tarpit", Version: "latest"},
		{CatalogueName: "tcp-tarpit", Version: "1.0.0", Config: map[string]string{"PATH": "/x"}},
		{Name: "../x", CatalogueName: "tcp-tarpit", Version: "1.0.0"},
	} {
		if _, _, err := s.AddSensor(ctx, n.ID, sp); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted %+v: %v", sp, err)
		}
	}
}

func TestSensorEditUpgradeDelete(t *testing.T) {
	s, db, _ := newService(t, true)
	ctx := context.Background()
	n, _, _ := s.CreateNode(ctx, "n1", nil)
	s.AddSensor(ctx, n.ID, spec("ssh", "22"))
	_, r0, _ := s.AddSensor(ctx, n.ID, spec("web", "80"))

	// Liveness state must survive edits.
	now := time.Now()
	db.SaveSensorLiveness(ctx, n.ID, "ts-sensor-ssh", store.SensorLiveness{Status: domain.StatusOnline, StatusChanged: true, LastHeartbeatAt: &now, EverOnline: true}, now)

	// Keep the masked secret with null, change the port.
	port := "2222"
	v, r1, err := s.UpdateSensorConfig(ctx, n.ID, "ts-sensor-ssh", ConfigPatch{"TS_PORT": &port, "TS_SECRET": nil})
	if err != nil {
		t.Fatal(err)
	}
	if r1.Revision == r0.Revision {
		t.Fatal("revision unchanged after config edit")
	}
	stored, _ := db.Sensor(ctx, n.ID, "ts-sensor-ssh")
	if stored.Config["TS_SECRET"] != "s3cret" || stored.Config["TS_PORT"] != "2222" || stored.Status != domain.StatusOnline {
		t.Fatalf("stored %+v", stored)
	}
	if v.Config["TS_SECRET"] != MaskedValue {
		t.Fatal("secret returned in clear")
	}
	if _, _, err := s.UpdateSensorConfig(ctx, n.ID, "ts-sensor-ssh", ConfigPatch{"TS_NEW": nil}); !errors.Is(err, ErrInvalid) {
		t.Fatal("keep of a non-existent key accepted")
	}
	clash := "80"
	if _, _, err := s.UpdateSensorConfig(ctx, n.ID, "ts-sensor-ssh", ConfigPatch{"TS_PORT": &clash}); err == nil {
		t.Fatal("conflicting edit saved")
	}
	if stored, _ := db.Sensor(ctx, n.ID, "ts-sensor-ssh"); stored.Config["TS_PORT"] != "2222" {
		t.Fatal("refused edit was stored")
	}

	// Upgrades.
	if v, _, err := s.UpgradeSensor(ctx, n.ID, "ts-sensor-ssh", "1.1.0"); err != nil || v.Version != "1.1.0" {
		t.Fatal(err)
	}
	changed, _, err := s.UpgradeNode(ctx, n.ID)
	if err != nil || strings.Join(changed, ",") != "ts-sensor-ssh,ts-sensor-web" {
		t.Fatalf("%v %v", changed, err)
	}
	if again, _, _ := s.UpgradeNode(ctx, n.ID); len(again) != 0 {
		t.Fatal("upgrade not idempotent")
	}

	// Delete keeps events.
	db.InsertEvent(ctx, &domain.Event{EventID: "e", NodeID: n.ID, SensorID: "ts-sensor-web", Trigger: "x", Severity: "low",
		OccurredAt: now, ReceivedAt: now, Source: "s", Target: "t", Details: []byte("{}")})
	if _, err := s.DeleteSensor(ctx, n.ID, "ts-sensor-web"); err != nil {
		t.Fatal(err)
	}
	if ev, _ := db.Events(ctx, store.EventFilter{}); len(ev) != 1 {
		t.Fatal("sensor deletion removed events")
	}
	if _, err := s.DeleteSensor(ctx, n.ID, "ts-sensor-web"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("double delete")
	}
}

func TestFailClosedWithoutCompiler(t *testing.T) {
	s, db, _ := newService(t, false)
	ctx := context.Background()
	n, _, _ := s.CreateNode(ctx, "n1", nil)
	if _, _, err := s.AddSensor(ctx, n.ID, spec("ssh", "22")); !errors.Is(err, ErrCompilerUnavailable) {
		t.Fatalf("add without compiler: %v", err)
	}
	if _, err := s.Compose(ctx, n.ID); !errors.Is(err, ErrCompilerUnavailable) {
		t.Fatal("compose without compiler")
	}
	// Deletion is never blocked.
	db.ApplySensorChanges(ctx, n.ID, store.SensorChanges{Create: []domain.Sensor{{ID: "ts-sensor-x", CatalogueName: "x", Version: "1.0.0", CreatedAt: time.Now()}}})
	if _, err := s.DeleteSensor(ctx, n.ID, "ts-sensor-x"); err != nil {
		t.Fatalf("delete without compiler: %v", err)
	}
}

func TestPreviewDoesNotSaveAndIsRedacted(t *testing.T) {
	s, db, _ := newService(t, true)
	ctx := context.Background()
	n, _, _ := s.CreateNode(ctx, "n1", nil)
	sp := spec("ssh", "22")
	r, err := s.PreviewChange(ctx, n.ID, &sp, "", nil)
	if err != nil || !strings.Contains(string(r.Compose), "ts-sensor-ssh") {
		t.Fatal(err)
	}
	if list, _ := db.Sensors(ctx, n.ID); len(list) != 0 {
		t.Fatal("preview saved a sensor")
	}
	for _, red := range s.Compiler.(*FakeCompiler).redacts {
		if !red {
			t.Fatal("admin render without redaction")
		}
	}
}

func TestConcurrentAddsCannotBothClaimAPort(t *testing.T) {
	s, db, _ := newService(t, true)
	ctx := context.Background()
	n, _, _ := s.CreateNode(ctx, "n1", nil)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.AddSensor(ctx, n.ID, spec(fmt.Sprintf("s%d", i), "443"))
		}(i)
	}
	wg.Wait()
	if list, _ := db.Sensors(ctx, n.ID); len(list) != 1 {
		t.Fatalf("%d sensors share port 443", len(list))
	}
}

func TestHealthAndSemver(t *testing.T) {
	s, db, _ := newService(t, true)
	ctx := context.Background()
	n, _, _ := s.CreateNode(ctx, "n1", nil)
	s.AddSensor(ctx, n.ID, spec("a", "1"))
	s.AddSensor(ctx, n.ID, spec("b", "2"))
	now := time.Now()
	db.TouchNode(ctx, n.ID, now)
	db.SaveSensorLiveness(ctx, n.ID, "ts-sensor-a", store.SensorLiveness{Status: domain.StatusOnline, StatusChanged: true}, now)
	list, _ := s.ListNodes(ctx)
	h := list[0].Health
	if !h.Online || h.InSync || h.SensorsTotal != 2 || h.SensorsOnline != 1 || h.SensorsPending != 1 {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct {
		a, b string
		less bool
	}{{"1.0.0", "1.0.1", true}, {"1.10.0", "1.9.0", false}, {"2.0.0-rc.1", "2.0.0", true}, {"2.0.0", "2.0.0-rc.1", false}, {"1.0.0", "1.0.0", false}} {
		if semverLess(c.a, c.b) != c.less {
			t.Errorf("%s < %s", c.a, c.b)
		}
	}
}
