// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/projections"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

type failingFleetReader struct{ err error }

func (f failingFleetReader) Nodes(context.Context) ([]domain.Node, error) { return nil, f.err }
func (f failingFleetReader) Sensors(context.Context, string) ([]domain.Sensor, error) {
	return nil, f.err
}

type staticHoneytokens struct{ list []ported.Honeytoken }

func (s staticHoneytokens) List(context.Context) ([]ported.Honeytoken, error) { return s.list, nil }

type staticBeacons struct{ list []ported.Beacon }

func (s staticBeacons) List(context.Context) ([]ported.Beacon, error) { return s.list, nil }

// The real projections (merge import H11 + WP-2A insights) mounted on the
// Hub's projection route: the status lists them and each builds from the window.
func TestRealProjectionModules(t *testing.T) {
	h := newInsightHubWith(t, func(in *Insights) {
		in.Projections = map[string]ported.Projection{}
		for _, p := range []ported.Projection{
			projections.NewInsights(in.Store, nil, nil),
			projections.Sources{},
			projections.GeoMap{},
			projections.AttackPath{},
			projections.Report{},
		} {
			in.Projections[p.Name()] = p
		}
	})
	_, out, _ := h.c.do("GET", "/api/v3/system/status", nil)
	if mods := out["status"].(map[string]any)["modules"].(map[string]any); len(mods["projections"].([]any)) != 5 {
		t.Fatalf("modules %v", mods)
	}
	for _, name := range []string{"insights", "sources", "geo_map", "attack_path?source=s", "report"} {
		code, out, _ := h.c.do("GET", "/api/v3/analytics/projections/"+name, nil)
		if code != 200 || out["data"] == nil {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	if code, _, _ := h.c.do("GET", "/api/v3/analytics/projections/report?from=nonsense", nil); code != 400 {
		t.Fatalf("bad report range: %d", code)
	}
}

func TestInsightsProjectionRoute(t *testing.T) {
	var db *store.DB
	h := newInsightHubWith(t, func(in *Insights) {
		db = in.Store.(*store.DB)
		in.Projections = map[string]ported.Projection{
			"insights": projections.NewInsights(
				in.Store,
				staticHoneytokens{list: []ported.Honeytoken{{ID: "ht_1", Username: "svc_secret_user", Secret: "HT_SECRET_VALUE", Status: "active"}}},
				staticBeacons{list: []ported.Beacon{{ID: "bc_1", Token: "BC_SECRET_TOKEN", Type: "dns"}}},
			),
		}
	})

	ctx := context.Background()
	now := time.Now().UTC()
	// Add a second node with no decoys, and a whitelisted + Hub-liveness event.
	if err := db.CreateNode(ctx, &domain.Node{ID: "node-0000000b", Alias: "b", KeyHash: []byte("k2"), CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertEvent(ctx, &domain.Event{
		EventID: "wl-1", NodeID: "node-0000000a", SensorID: "ts-sensor-a", Trigger: "x",
		Severity: domain.SeverityHigh, OccurredAt: now, ReceivedAt: now, Source: "10.0.0.1",
		Target: "t", Details: []byte(`{"password":"DO_NOT_LEAK_EVENT_DETAIL"}`), Whitelisted: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertEvent(ctx, &domain.Event{
		EventID: "hub-1", NodeID: "node-0000000a", SensorID: "ts-sensor-a", Trigger: domain.TriggerSensorHeartbeatLost,
		Severity: domain.SeverityHigh, OccurredAt: now, ReceivedAt: now, Source: domain.HubSource,
		Target: "t", Details: []byte(`{}`),
	}); err != nil {
		t.Fatal(err)
	}

	code, out, _ := h.c.do("GET", "/api/v3/analytics/projections/insights?days=30&ignored=1", nil)
	if code != 200 || out["projection"] != "insights" || out["days"] != 30.0 {
		t.Fatalf("unexpected response: %d %v", code, out)
	}
	rawData, err := json.Marshal(out["data"])
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"HT_SECRET_VALUE", "svc_secret_user", "BC_SECRET_TOKEN", "DO_NOT_LEAK_EVENT_DETAIL"} {
		if strings.Contains(string(rawData), secret) {
			t.Fatalf("insights response leaked %q: %s", secret, string(rawData))
		}
	}

	var dto projections.InsightsDTO
	if err := json.Unmarshal(rawData, &dto); err != nil {
		t.Fatalf("unmarshal insights dto: %v", err)
	}
	if dto.Window != 30 {
		t.Fatalf("window = %d, want 30", dto.Window)
	}
	if dto.Coverage.DecoysDeployed != 1 || dto.Coverage.NodesWithDecoy != 1 || dto.Coverage.NodesWithoutDecoy != 1 ||
		dto.Coverage.SensorsOnline != 1 || dto.Coverage.HoneytokensPlanted != 1 || dto.Coverage.BeaconsActive != 1 {
		t.Fatalf("coverage = %+v", dto.Coverage)
	}
	if dto.Touched.Instances != 1 || dto.Touched.Total != 1 || dto.Touched.Ratio != 1 {
		t.Fatalf("touched = %+v", dto.Touched)
	}
	if dto.AllowedEvents != 1 {
		t.Fatalf("allowed_events = %d, want 1", dto.AllowedEvents)
	}
	if len(dto.ByType) != 1 || dto.ByType[0].SensorType != "x" || dto.ByType[0].Events != 4 || dto.ByType[0].HighestSeverity != "critical" {
		t.Fatalf("by_type = %+v", dto.ByType)
	}
	if len(dto.TopTriggers) != 1 || dto.TopTriggers[0].Trigger != "x" || dto.TopTriggers[0].Count != 4 {
		t.Fatalf("top_triggers = %+v", dto.TopTriggers)
	}

	// Custom days parameter flows into dto.Window.
	code, out, _ = h.c.do("GET", "/api/v3/analytics/projections/insights?days=7", nil)
	if code != 200 || out["data"].(map[string]any)["window"] != 7.0 {
		t.Fatalf("days=7 response: %d %v", code, out)
	}

	// Fleet read error surfaces as 400 with the error message.
	errHub := newInsightHubWith(t, func(in *Insights) {
		in.Projections = map[string]ported.Projection{
			"insights": projections.NewInsights(failingFleetReader{err: errors.New("fleet read failed")}, nil, nil),
		}
	})
	if code, out, _ := errHub.c.do("GET", "/api/v3/analytics/projections/insights", nil); code != 400 {
		t.Fatalf("fleet error: %d %v", code, out)
	}
}
