// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPrometheusExposition(t *testing.T) {
	reg := New("3.0.0-rc.1", 8)
	reg.SIEM = func() SIEMSnapshot { return SIEMSnapshot{Output: "elastic", QueueDepth: 7} }
	reg.LegacyDrills = func() uint64 { return 2 }
	reg.Fleet = func(context.Context) (FleetSnapshot, error) {
		return FleetSnapshot{
			NodesOnline:     3,
			NodesOffline:    1,
			SensorsOnline:   5,
			SensorsOffline:  2,
			SensorsPending:  1,
			SensorsSilenced: 1,
			SensorDropped:   []SensorDropped{{NodeID: "node-01", SensorID: "ts-sensor-ssh", Dropped: 4}},
		}, nil
	}

	reg.RecordEventIngested("node-01", "ts-sensor-ssh", "high", false)
	reg.RecordEventIngested("node-01", "ts-sensor-ssh", "info", true)
	reg.RecordIngestRejected("overloaded")
	reg.RecordSIEMSent("elastic")
	reg.RecordSIEMDropped("elastic")
	reg.RecordNotifySent("slack")
	reg.RecordNotifyFailed("slack")
	reg.ObserveHeartbeatLag(30 * time.Second)
	reg.ObserveDBQuery(2 * time.Millisecond)

	// Instrument an HTTP handler with nested SetRoute.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v3/events", func(w http.ResponseWriter, r *http.Request) {
		SetRoute(r.Context(), "GET /api/v3/events")
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	reg.Instrument(mux).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v3/events", nil))

	// Scrape /metrics.
	mrec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(mrec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if mrec.Code != http.StatusOK {
		t.Fatalf("/metrics status = %d", mrec.Code)
	}
	if ct := mrec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("Content-Type = %q", ct)
	}
	body := mrec.Body.String()

	wantLines := []string{
		`doppel_build_info{schema="8",version="3.0.0-rc.1"} 1`,
		`doppel_events_ingested_total{drill="false",node="node-01",sensor="ts-sensor-ssh",severity="high"} 1`,
		`doppel_events_ingested_total{drill="true",node="node-01",sensor="ts-sensor-ssh",severity="info"} 1`,
		`doppel_ingest_rejected_total{code="overloaded"} 1`,
		`doppel_siem_queue_depth{output="elastic"} 7`,
		`doppel_siem_sent_total{output="elastic"} 1`,
		`doppel_siem_dropped_total{output="elastic"} 1`,
		`doppel_notify_sent_total{route="slack"} 1`,
		`doppel_notify_failed_total{route="slack"} 1`,
		`doppel_nodes{state="online"} 3`,
		`doppel_nodes{state="offline"} 1`,
		`doppel_sensors{state="online"} 5`,
		`doppel_sensors{state="offline"} 2`,
		`doppel_sensors{state="pending"} 1`,
		`doppel_sensors{state="silenced"} 1`,
		`doppel_sensor_dropped_events{node="node-01",sensor="ts-sensor-ssh"} 4`,
		`doppel_legacy_drills_total 2`,
		`doppel_heartbeat_lag_seconds_count 1`,
		`doppel_http_requests_total{code="200",route="GET /api/v3/events"} 1`,
		`doppel_http_request_seconds_count 1`,
		`doppel_db_query_seconds_count 1`,
	}
	for _, want := range wantLines {
		if !strings.Contains(body, want) {
			t.Errorf("missing metric line %q in:\n%s", want, body)
		}
	}

	// Non-GET methods and other paths must be rejected.
	mrec = httptest.NewRecorder()
	reg.Handler().ServeHTTP(mrec, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if mrec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /metrics status = %d want 405", mrec.Code)
	}
	mrec = httptest.NewRecorder()
	reg.Handler().ServeHTTP(mrec, httptest.NewRequest(http.MethodGet, "/other", nil))
	if mrec.Code != http.StatusNotFound {
		t.Fatalf("GET /other status = %d want 404", mrec.Code)
	}
}
