// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/fleet"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ingest"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/liveness"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/nodekey"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ratelimit"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

// jsonCompiler wraps portCompiler's text output in a JSON document, as the
// real compiler emits JSON.
type jsonCompiler struct{ portCompiler }

func (j jsonCompiler) Render(ctx context.Context, n domain.Node, s []domain.Sensor, o fleet.RenderOptions) (fleet.Rendered, error) {
	r, err := j.portCompiler.Render(ctx, n, s, o)
	if err == nil {
		r.Compose, _ = json.Marshal(map[string]string{"text": string(r.Compose)})
	}
	return r, err
}

func composeText(out map[string]any) string {
	m, _ := out["compose"].(map[string]any)
	s, _ := m["text"].(string)
	return s
}

func TestNodeAPI(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "ts.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	keys := nodekey.NewAuthenticator(db)
	fs := &fleet.Service{Store: db, Compiler: jsonCompiler{}, Keys: keys, Log: log, Now: time.Now}
	n1, key1, _ := fs.CreateNode(ctx, "one", nil)
	n2, key2, _ := fs.CreateNode(ctx, "two", nil)
	fs.AddSensor(ctx, n1.ID, fleet.SensorSpec{CatalogueName: "tcp-tarpit", Version: "1.0.0", Config: map[string]string{"TS_PORT": "22"}})

	pipe := &ingest.Pipeline{Store: db, Log: log, Now: time.Now}
	ing := &Ingest{Auth: keys, Limiter: ratelimit.NewKeyed(100, 100), Store: db, Pipeline: pipe,
		Liveness: &liveness.Service{Store: db, Raiser: pipe, Log: log, Now: time.Now}, Version: Version{"truesignal-hub", "3.0.0", 3}, Log: log, Now: time.Now}
	mux := http.NewServeMux()
	(&NodeAPI{Ingest: ing, Fleet: fs, Store: db, Raiser: pipe, HubMajor: 3}).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	call := func(method, path, key, version, body string) (int, map[string]any) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		if version != "" {
			req.Header.Set(CLIVersionHeader, version)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	for _, v := range []string{"", "2.9.0", "4.0.0", "three"} {
		code, out := call("GET", "/v3/node/identity", key1, v, "")
		if code != 426 || out["error"] != "version_mismatch" || out["required_major"] != 3.0 {
			t.Fatalf("version %q: %d %v", v, code, out)
		}
	}
	if code, _ := call("GET", "/v3/node/identity", "tsk_"+strings.Repeat("a", 64), "3.1.0", ""); code != 401 {
		t.Fatal("bad key accepted")
	}
	code, out := call("GET", "/v3/node/identity", key1, "3.0.0", "")
	if code != 200 || out["node_id"] != n1.ID || out["alias"] != "one" {
		t.Fatalf("%d %v", code, out)
	}

	// The node gets its own unredacted compose; nobody else's.
	code, out = call("GET", "/v3/node/compose", key1, "3.0.0", "")
	if code != 200 || !strings.Contains(composeText(out), "tsk_REAL_SECRET") || !strings.Contains(composeText(out), "ts-sensor-tcp-tarpit") {
		t.Fatalf("%d %v", code, out)
	}
	rev := out["revision"].(string)
	code, out = call("GET", "/v3/node/compose", key2, "3.0.0", "")
	if code != 200 || strings.Contains(composeText(out), "ts-sensor-tcp-tarpit") {
		t.Fatalf("node 2 sees node 1's sensors: %v", out)
	}
	_ = n2

	if code, _ := call("POST", "/v3/node/applied", key1, "3.0.0", `{"revision":"`+rev+`","result":"applied"}`); code != 200 {
		t.Fatal("applied refused")
	}
	node, _ := db.Node(ctx, n1.ID)
	if node.AppliedRevision != rev {
		t.Fatalf("revisions %+v", node)
	}
	if code, _ := call("POST", "/v3/node/applied", key1, "3.0.0", `{"revision":"rev_zz","result":"applied"}`); code != 400 {
		t.Fatal("bad revision accepted")
	}
	if code, _ := call("POST", "/v3/node/applied", key1, "3.0.0", `{"revision":"rev_00000000","result":"failed","message":"service exited"}`); code != 200 {
		t.Fatal("failure report refused")
	}
	if node, _ := db.Node(ctx, n1.ID); node.AppliedRevision != rev {
		t.Fatal("failed apply overwrote the applied revision")
	}

	// node_apply_failed: raised once per node and revision, re-armed by success.
	failed := func() []domain.Event {
		ev, _ := db.Events(ctx, store.EventFilter{Trigger: domain.TriggerNodeApplyFailed})
		return ev
	}
	ev := failed()
	if len(ev) != 1 || ev[0].Severity != domain.SeverityHigh || ev[0].NodeID != n1.ID || ev[0].Target != n1.ID || ev[0].Source != domain.HubSource {
		t.Fatalf("%+v", ev)
	}
	var d map[string]any
	json.Unmarshal(ev[0].Details, &d)
	if d["result"] != "failed" || d["message"] != "service exited" || d["revision"] != "rev_00000000" {
		t.Fatalf("details %v", d)
	}
	call("POST", "/v3/node/applied", key1, "3.0.0", `{"revision":"rev_00000000","result":"rolled_back","message":"again"}`)
	if len(failed()) != 1 {
		t.Fatal("same revision alerted twice")
	}
	call("POST", "/v3/node/applied", key1, "3.0.0", `{"revision":"`+rev+`","result":"applied"}`)
	call("POST", "/v3/node/applied", key1, "3.0.0", `{"revision":"rev_00000000","result":"failed","message":"x"}`)
	if len(failed()) != 2 {
		t.Fatal("failure after a success not alerted")
	}
	// Sensors cannot forge it.
	if !domain.IsReservedTrigger(domain.TriggerNodeApplyFailed) {
		t.Fatal("node_apply_failed must be reserved")
	}
	_ = domain.StatusPending
}
