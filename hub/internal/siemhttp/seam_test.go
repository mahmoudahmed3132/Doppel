// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package siemhttp_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ecs"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/siem"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/siemhttp"
)

// The real transport behind ported.HTTPSIEMTransport, driven by the SIEM
// service with the real ECS renderer: an elastic output delivers an audit
// record as one bulk create.
func TestTransportThroughSIEMService(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, r.URL.Path+"\n"+string(b))
		mu.Unlock()
		w.Write([]byte(`{"errors":false,"items":[{"create":{"status":201}}]}`))
	}))
	defer ts.Close()
	tr, err := siemhttp.New("")
	if err != nil {
		t.Fatal(err)
	}
	tr.Client.Transport = ts.Client().Transport
	svc := &siem.Service{HTTP: tr, Renderer: ecs.Renderer{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	cfg, err := siem.Config{Protocol: siem.ProtoElastic, Address: ts.URL + "/logs-truesignal-default", Token: "k", Format: siem.FormatECS}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(cfg); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		svc.Shutdown(ctx)
	}()
	rec := domain.Record{Kind: domain.RecordAudit, Audit: &domain.AuditRecord{Time: time.Now(), Action: "siem.test", Method: "POST", Path: "/api/v3/outputs/siem/test", Status: 200, Outcome: "success", ActorIP: "10.0.0.2"}}
	if err := svc.DeliverNow(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 || !strings.HasPrefix(bodies[0], "/logs-truesignal-default/_bulk\n{\"create\":{}}\n") {
		t.Fatalf("bodies %q", bodies)
	}
	var doc map[string]any
	line := strings.Split(bodies[0], "\n")[2]
	if err := json.Unmarshal([]byte(line), &doc); err != nil || doc["event"].(map[string]any)["dataset"] != "truesignal.audit" {
		t.Fatalf("doc %s %v", line, err)
	}
}
