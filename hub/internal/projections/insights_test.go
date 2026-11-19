// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

type stubFleet struct {
	nodes      []domain.Node
	sensors    []domain.Sensor
	nodesErr   error
	sensorsErr error
}

func (f stubFleet) Nodes(context.Context) ([]domain.Node, error) {
	if f.nodesErr != nil {
		return nil, f.nodesErr
	}
	return f.nodes, nil
}

func (f stubFleet) Sensors(context.Context, string) ([]domain.Sensor, error) {
	if f.sensorsErr != nil {
		return nil, f.sensorsErr
	}
	return f.sensors, nil
}

type stubHoneytokens struct {
	tokens []ported.Honeytoken
	err    error
}

func (h stubHoneytokens) List(context.Context) ([]ported.Honeytoken, error) {
	if h.err != nil {
		return nil, h.err
	}
	return h.tokens, nil
}

type stubBeacons struct {
	beacons []ported.Beacon
	err     error
}

func (b stubBeacons) List(context.Context) ([]ported.Beacon, error) {
	if b.err != nil {
		return nil, b.err
	}
	return b.beacons, nil
}

func TestInsightsTable(t *testing.T) {
	cet := time.FixedZone("CET", 2*3600)
	base := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

	mkEv := func(min int, node, sensor, trigger string, sev domain.Severity, source string) domain.EnrichedEvent {
		return domain.EnrichedEvent{
			Event: domain.Event{
				NodeID:     node,
				SensorID:   sensor,
				Trigger:    trigger,
				Severity:   sev,
				Source:     source,
				OccurredAt: base.Add(time.Duration(min) * time.Minute),
				Details:    json.RawMessage(`{"password":"SUPER_SECRET_DETAIL_VALUE"}`),
			},
		}
	}

	whitelistedEv := mkEv(10, "node-00000001", "ts-sensor-ssh", "ssh_login", domain.SeverityHigh, "10.0.0.99")
	whitelistedEv.Whitelisted = true

	scannerEv := mkEv(11, "node-00000002", "ts-sensor-web", "web_path_probe", domain.SeverityLow, "198.51.100.42")
	scannerEv.KnownScanner = true

	applyFailEv := mkEv(12, "node-00000001", "", domain.TriggerNodeApplyFailed, domain.SeverityHigh, domain.HubSource)
	livenessEv := mkEv(13, "node-00000001", "ts-sensor-ssh", domain.TriggerSensorHeartbeatLost, domain.SeverityHigh, domain.HubSource)
	recoveredEv := mkEv(14, "node-00000001", "ts-sensor-ssh", domain.TriggerSensorRecovered, domain.SeverityInfo, "node-agent")

	tzEv := mkEv(25, "node-00000001", "ts-sensor-web", "web_login_attempt", domain.SeverityHigh, "203.0.113.8")
	tzEv.OccurredAt = base.Add(25 * time.Minute).In(cet)

	twelveTriggerEvents := make([]domain.EnrichedEvent, 0, 30)
	for i := 1; i <= 12; i++ {
		trig := fmt.Sprintf("trig_%02d", i)
		for j := 0; j < i; j++ {
			twelveTriggerEvents = append(twelveTriggerEvents, mkEv(i*10+j, "node-00000001", "ts-sensor-web", trig, domain.SeverityMedium, "10.0.0.1"))
		}
	}

	tests := []struct {
		name   string
		proj   *Insights
		ctx    context.Context
		events []domain.EnrichedEvent
		params map[string]string
		check  func(t *testing.T, dto *InsightsDTO, rawJSON string)
	}{
		{
			name: "empty fleet and no events",
			proj: NewInsights(stubFleet{}, stubHoneytokens{}, stubBeacons{}),
			ctx:  context.Background(),
			check: func(t *testing.T, dto *InsightsDTO, _ string) {
				if dto.Window != 30 {
					t.Fatalf("window = %d, want 30", dto.Window)
				}
				if dto.Coverage != (InsightsCoverage{}) {
					t.Fatalf("coverage = %+v, want zero", dto.Coverage)
				}
				if dto.ByType == nil || len(dto.ByType) != 0 {
					t.Fatalf("by_type = %#v, want empty non-nil slice", dto.ByType)
				}
				if dto.Touched != (InsightsTouched{}) {
					t.Fatalf("touched = %+v, want zero", dto.Touched)
				}
				if dto.TopTriggers == nil || len(dto.TopTriggers) != 0 {
					t.Fatalf("top_triggers = %#v, want empty non-nil slice", dto.TopTriggers)
				}
				if dto.AllowedEvents != 0 {
					t.Fatalf("allowed_events = %d, want 0", dto.AllowedEvents)
				}
			},
		},
		{
			name: "mixed attacker, allowed, liveness, and multi-node fleet",
			proj: NewInsights(
				stubFleet{
					nodes: []domain.Node{
						{ID: "node-00000001", Alias: "edge-1"},
						{ID: "node-00000002", Alias: "app-2"},
						{ID: "node-00000003", Alias: "bare-3"},
					},
					sensors: []domain.Sensor{
						{NodeID: "node-00000001", ID: "ts-sensor-web", CatalogueName: "web-router-decoy", Status: domain.StatusOnline, Config: map[string]string{"SECRET_CFG": "DO_NOT_LEAK_CFG"}},
						{NodeID: "node-00000001", ID: "ts-sensor-ssh", CatalogueName: "remote-access-decoy", Status: domain.StatusOffline},
						{NodeID: "node-00000002", ID: "ts-sensor-web", CatalogueName: "web-router-decoy", Status: domain.StatusOnline},
						{NodeID: "node-00000002", ID: "ts-sensor-files", CatalogueName: "file-canary", Status: domain.StatusPending},
					},
				},
				stubHoneytokens{
					tokens: []ported.Honeytoken{
						{ID: "ht_1", Username: "svc_backup", Secret: "HONEYTOKEN_SECRET_1", Status: "active"},
						{ID: "ht_2", Username: "svc_deploy", Secret: "HONEYTOKEN_SECRET_2", Status: ""},
						{ID: "ht_3", Username: "svc_old", Secret: "HONEYTOKEN_SECRET_3", Status: "retired"},
					},
				},
				stubBeacons{
					beacons: []ported.Beacon{
						{ID: "bc_1", Token: "BEACON_SECRET_TOKEN_1", Type: "dns"},
						{ID: "bc_2", Token: "BEACON_SECRET_TOKEN_2", Type: "web-bug"},
					},
				},
			),
			ctx:    ported.WithWindowDays(context.Background(), 7),
			params: map[string]string{"unknown_param": "ignored"},
			events: []domain.EnrichedEvent{
				mkEv(0, "node-00000001", "ts-sensor-web", "web_path_probe", domain.SeverityLow, "203.0.113.7"),
				tzEv,
				mkEv(5, "node-00000002", "ts-sensor-files", "decoy_file_accessed", domain.SeverityCritical, "10.0.0.5"),
				mkEv(6, "node-00000001", "ts-sensor-old-decoy", "tcp_connect", domain.SeverityMedium, "10.0.0.6"),
				whitelistedEv,
				scannerEv,
				applyFailEv,
				livenessEv,
				recoveredEv,
			},
			check: func(t *testing.T, dto *InsightsDTO, rawJSON string) {
				if dto.Window != 7 {
					t.Fatalf("window = %d, want 7", dto.Window)
				}
				wantCov := InsightsCoverage{
					DecoysDeployed:     4,
					NodesWithDecoy:     2,
					NodesWithoutDecoy:  1,
					SensorsOnline:      2,
					HoneytokensPlanted: 2,
					BeaconsActive:      2,
				}
				if dto.Coverage != wantCov {
					t.Fatalf("coverage = %+v, want %+v", dto.Coverage, wantCov)
				}
				wantTouched := InsightsTouched{Instances: 2, Total: 4, Ratio: 0.5}
				if dto.Touched != wantTouched {
					t.Fatalf("touched = %+v, want %+v", dto.Touched, wantTouched)
				}
				if dto.AllowedEvents != 2 {
					t.Fatalf("allowed_events = %d, want 2", dto.AllowedEvents)
				}
				if len(dto.ByType) != 4 {
					t.Fatalf("len(by_type) = %d, want 4: %+v", len(dto.ByType), dto.ByType)
				}
				// Sorted by events desc, then instances_deployed desc, then sensor_type asc.
				if dto.ByType[0] != (InsightsByType{
					SensorType:        "web-router-decoy",
					InstancesDeployed: 2,
					InstancesOnline:   2,
					Events:            2,
					DistinctSources:   2,
					HighestSeverity:   "high",
					LastEventAt:       "2026-11-10T12:25:00Z",
				}) {
					t.Fatalf("by_type[0] = %+v", dto.ByType[0])
				}
				if dto.ByType[1].SensorType != "file-canary" || dto.ByType[1].Events != 1 || dto.ByType[1].HighestSeverity != "critical" || dto.ByType[1].LastEventAt != "2026-11-10T12:05:00Z" {
					t.Fatalf("by_type[1] = %+v", dto.ByType[1])
				}
				if dto.ByType[2].SensorType != "old-decoy" || dto.ByType[2].InstancesDeployed != 0 || dto.ByType[2].Events != 1 {
					t.Fatalf("by_type[2] = %+v", dto.ByType[2])
				}
				if dto.ByType[3].SensorType != "remote-access-decoy" || dto.ByType[3].InstancesDeployed != 1 || dto.ByType[3].Events != 0 || dto.ByType[3].HighestSeverity != "" || dto.ByType[3].LastEventAt != "" {
					t.Fatalf("by_type[3] = %+v", dto.ByType[3])
				}
				if len(dto.TopTriggers) != 4 {
					t.Fatalf("top_triggers = %+v", dto.TopTriggers)
				}
				// Verify no secrets or event details leak into JSON output.
				for _, secret := range []string{
					"SUPER_SECRET_DETAIL_VALUE",
					"DO_NOT_LEAK_CFG",
					"HONEYTOKEN_SECRET_1",
					"HONEYTOKEN_SECRET_2",
					"svc_backup",
					"BEACON_SECRET_TOKEN_1",
				} {
					if strings.Contains(rawJSON, secret) {
						t.Fatalf("output leaked %q: %s", secret, rawJSON)
					}
				}
			},
		},
		{
			name: "top_triggers capped at 10",
			proj: NewInsights(stubFleet{
				nodes:   []domain.Node{{ID: "node-00000001"}},
				sensors: []domain.Sensor{{NodeID: "node-00000001", ID: "ts-sensor-web", CatalogueName: "web-router-decoy", Status: domain.StatusOnline}},
			}, nil, nil),
			ctx:    context.Background(),
			params: map[string]string{"days": "14"},
			events: twelveTriggerEvents,
			check: func(t *testing.T, dto *InsightsDTO, _ string) {
				if dto.Window != 14 {
					t.Fatalf("window = %d, want 14", dto.Window)
				}
				if len(dto.TopTriggers) != 10 {
					t.Fatalf("len(top_triggers) = %d, want 10", len(dto.TopTriggers))
				}
				if dto.TopTriggers[0] != (InsightsTriggerCount{Trigger: "trig_12", Count: 12}) {
					t.Fatalf("top_triggers[0] = %+v", dto.TopTriggers[0])
				}
				if dto.TopTriggers[9] != (InsightsTriggerCount{Trigger: "trig_03", Count: 3}) {
					t.Fatalf("top_triggers[9] = %+v", dto.TopTriggers[9])
				}
			},
		},
		{
			name:   "nil dependencies still aggregate attacker events",
			proj:   NewInsights(nil, nil, nil),
			ctx:    context.Background(),
			events: []domain.EnrichedEvent{mkEv(0, "node-00000001", "ts-sensor-ssh", "ssh_login", domain.SeverityHigh, "192.0.2.1")},
			check: func(t *testing.T, dto *InsightsDTO, _ string) {
				if dto.Coverage != (InsightsCoverage{}) || dto.Touched != (InsightsTouched{}) {
					t.Fatalf("unexpected coverage/touched: %+v %+v", dto.Coverage, dto.Touched)
				}
				if len(dto.ByType) != 1 || dto.ByType[0].SensorType != "ssh" || dto.ByType[0].Events != 1 {
					t.Fatalf("by_type = %+v", dto.ByType)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.proj.Name() != "insights" {
				t.Fatalf("Name() = %q, want insights", tc.proj.Name())
			}
			out, err := tc.proj.Build(tc.ctx, tc.events, tc.params)
			if err != nil {
				t.Fatalf("Build error: %v", err)
			}
			dto, ok := out.(*InsightsDTO)
			if !ok {
				t.Fatalf("unexpected type %T", out)
			}
			raw, err := json.Marshal(dto)
			if err != nil {
				t.Fatalf("marshal error: %v", err)
			}
			tc.check(t, dto, string(raw))
		})
	}
}

func TestInsightsErrors(t *testing.T) {
	boom := errors.New("db unavailable")
	cases := []struct {
		name string
		proj *Insights
	}{
		{"nodes error", NewInsights(stubFleet{nodesErr: boom}, nil, nil)},
		{"sensors error", NewInsights(stubFleet{sensorsErr: boom}, nil, nil)},
		{"honeytokens error", NewInsights(stubFleet{}, stubHoneytokens{err: boom}, nil)},
		{"beacons error", NewInsights(stubFleet{}, nil, stubBeacons{err: boom})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.proj.Build(context.Background(), nil, nil); !errors.Is(err, boom) {
				t.Fatalf("err = %v, want %v", err, boom)
			}
		})
	}
}

func TestInsightsConcurrent(t *testing.T) {
	p := NewInsights(
		stubFleet{
			nodes:   []domain.Node{{ID: "node-00000001"}},
			sensors: []domain.Sensor{{NodeID: "node-00000001", ID: "ts-sensor-web", CatalogueName: "web-router-decoy", Status: domain.StatusOnline}},
		},
		stubHoneytokens{tokens: []ported.Honeytoken{{ID: "ht_1", Status: "active"}}},
		stubBeacons{beacons: []ported.Beacon{{ID: "bc_1"}}},
	)
	evs := []domain.EnrichedEvent{{Event: domain.Event{
		NodeID: "node-00000001", SensorID: "ts-sensor-web", Trigger: "web_login_attempt",
		Severity: domain.SeverityHigh, Source: "10.0.0.5", OccurredAt: t0, Details: json.RawMessage(`{}`),
	}}}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(days int) {
			defer wg.Done()
			out, err := p.Build(ported.WithWindowDays(context.Background(), days), evs, nil)
			if err != nil {
				t.Errorf("Build: %v", err)
				return
			}
			if dto := out.(*InsightsDTO); dto.Window != days || dto.Coverage.DecoysDeployed != 1 {
				t.Errorf("unexpected dto: %+v", dto)
			}
		}(i + 1)
	}
	wg.Wait()
}
