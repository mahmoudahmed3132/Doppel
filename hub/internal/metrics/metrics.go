// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package metrics exposes Doppel Hub Prometheus metrics in text exposition
// format (0.0.4) on a dedicated loopback listener (TS_METRICS_ADDR, default
// 127.0.0.1:9090, never on the public Hub port; F-003 item 2).
//
// Implemented with the Go standard library only (zero third-party metrics
// dependencies).
package metrics

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Default histogram bucket upper bounds (seconds).
var (
	HeartbeatLagBuckets = []float64{0.5, 1, 5, 15, 30, 45, 60, 120, 300}
	HTTPRequestBuckets  = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	DBQueryBuckets      = []float64{0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1}
)

// FleetSnapshot holds point-in-time fleet counts scraped on each /metrics request.
type FleetSnapshot struct {
	NodesOnline     int
	NodesOffline    int
	SensorsOnline   int
	SensorsOffline  int
	SensorsPending  int
	SensorsSilenced int
	SensorDropped   []SensorDropped
}

// SensorDropped is a per-sensor cumulative dropped event counter (Q88).
type SensorDropped struct {
	NodeID   string
	SensorID string
	Dropped  int64
}

// SIEMSnapshot holds point-in-time SIEM queue depth for the active output.
type SIEMSnapshot struct {
	Output     string
	QueueDepth int
}

// Registry collects all Doppel Hub metrics and renders Prometheus text format.
type Registry struct {
	Version string
	Schema  int

	// Optional scrape-time providers (wired in main.go).
	Fleet        func(context.Context) (FleetSnapshot, error)
	SIEM         func() SIEMSnapshot
	LegacyDrills func() uint64

	mu             sync.Mutex
	eventsIngested map[eventKey]uint64
	ingestRejected map[string]uint64
	siemSent       map[string]uint64
	siemDropped    map[string]uint64
	notifySent     map[string]uint64
	notifyFailed   map[string]uint64
	httpRequests   map[httpReqKey]uint64

	heartbeatLag *histogram
	httpDuration *histogram
	dbDuration   *histogram
}

type eventKey struct {
	node     string
	sensor   string
	severity string
	drill    string
}

type httpReqKey struct {
	route string
	code  string
}

// New constructs a Registry with build metadata.
func New(version string, schema int) *Registry {
	return &Registry{
		Version:        version,
		Schema:         schema,
		eventsIngested: map[eventKey]uint64{},
		ingestRejected: map[string]uint64{},
		siemSent:       map[string]uint64{},
		siemDropped:    map[string]uint64{},
		notifySent:     map[string]uint64{},
		notifyFailed:   map[string]uint64{},
		httpRequests:   map[httpReqKey]uint64{},
		heartbeatLag:   newHistogram(HeartbeatLagBuckets),
		httpDuration:   newHistogram(HTTPRequestBuckets),
		dbDuration:     newHistogram(DBQueryBuckets),
	}
}

// RecordEventIngested increments doppel_events_ingested_total.
func (r *Registry) RecordEventIngested(node, sensor, severity string, drill bool) {
	if r == nil {
		return
	}
	d := "false"
	if drill {
		d = "true"
	}
	r.mu.Lock()
	r.eventsIngested[eventKey{node: node, sensor: sensor, severity: severity, drill: d}]++
	r.mu.Unlock()
}

// RecordIngestRejected increments doppel_ingest_rejected_total{code}.
func (r *Registry) RecordIngestRejected(code string) {
	if r == nil || code == "" {
		return
	}
	r.mu.Lock()
	r.ingestRejected[code]++
	r.mu.Unlock()
}

// RecordSIEMSent increments doppel_siem_sent_total{output}.
func (r *Registry) RecordSIEMSent(output string) {
	if r == nil {
		return
	}
	if output == "" {
		output = "none"
	}
	r.mu.Lock()
	r.siemSent[output]++
	r.mu.Unlock()
}

// RecordSIEMDropped increments doppel_siem_dropped_total{output}.
func (r *Registry) RecordSIEMDropped(output string) {
	if r == nil {
		return
	}
	if output == "" {
		output = "none"
	}
	r.mu.Lock()
	r.siemDropped[output]++
	r.mu.Unlock()
}

// RecordNotifySent increments doppel_notify_sent_total{route}.
func (r *Registry) RecordNotifySent(route string) {
	if r == nil {
		return
	}
	if route == "" {
		route = "default"
	}
	r.mu.Lock()
	r.notifySent[route]++
	r.mu.Unlock()
}

// RecordNotifyFailed increments doppel_notify_failed_total{route}.
func (r *Registry) RecordNotifyFailed(route string) {
	if r == nil {
		return
	}
	if route == "" {
		route = "default"
	}
	r.mu.Lock()
	r.notifyFailed[route]++
	r.mu.Unlock()
}

// ObserveHeartbeatLag records one heartbeat lag sample in seconds.
func (r *Registry) ObserveHeartbeatLag(d time.Duration) {
	if r == nil {
		return
	}
	s := d.Seconds()
	if s < 0 {
		s = 0
	}
	r.heartbeatLag.observe(s)
}

// ObserveDBQuery records one SQLite query duration in seconds.
func (r *Registry) ObserveDBQuery(d time.Duration) {
	if r == nil {
		return
	}
	s := d.Seconds()
	if s < 0 {
		s = 0
	}
	r.dbDuration.observe(s)
}

// ObserveHTTPRequest records one completed HTTP request.
func (r *Registry) ObserveHTTPRequest(route string, code int, d time.Duration) {
	if r == nil {
		return
	}
	if route == "" {
		route = "other"
	}
	if code == 0 {
		code = http.StatusOK
	}
	r.mu.Lock()
	r.httpRequests[httpReqKey{route: route, code: strconv.Itoa(code)}]++
	r.mu.Unlock()
	s := d.Seconds()
	if s < 0 {
		s = 0
	}
	r.httpDuration.observe(s)
}

type routeCtxKey struct{}

// SetRoute records the matched low-cardinality route template on the request
// context so nested muxes (e.g. /api/v3/*) report their exact pattern instead
// of the mount prefix.
func SetRoute(ctx context.Context, route string) {
	if p, ok := ctx.Value(routeCtxKey{}).(*string); ok && p != nil {
		*p = route
	}
}

// Instrument wraps next to record doppel_http_requests_total and
// doppel_http_request_seconds for every request.
func (r *Registry) Instrument(next http.Handler) http.Handler {
	if r == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		var route string
		req = req.WithContext(context.WithValue(req.Context(), routeCtxKey{}, &route))
		sw := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(sw, req)
		if route == "" {
			if req.Pattern != "" {
				route = req.Pattern
			} else {
				route = "other"
			}
		}
		r.ObserveHTTPRequest(route, sw.status, time.Since(start))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Hijack preserves WebSocket upgrades (/api/v3/live) through the middleware.
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("metrics: underlying ResponseWriter does not implement http.Hijacker")
	}
	return h.Hijack()
}

// Handler returns an http.Handler for the dedicated metrics listener. Only
// GET/HEAD /metrics is served; all other paths return 404.
func (r *Registry) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if req.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		r.WritePrometheus(req.Context(), w)
	})
	return mux
}

// WritePrometheus writes all metrics in Prometheus text exposition format 0.0.4.
func (r *Registry) WritePrometheus(ctx context.Context, w io.Writer) {
	var b strings.Builder

	// 1. doppel_build_info{version,schema}
	writeHeader(&b, "doppel_build_info", "Build and schema metadata for this Doppel Hub.", "gauge")
	fmt.Fprintf(&b, "doppel_build_info{schema=%q,version=%q} 1\n", strconv.Itoa(r.Schema), r.Version)

	// Snapshot in-memory counters under lock.
	r.mu.Lock()
	events := make(map[eventKey]uint64, len(r.eventsIngested))
	for k, v := range r.eventsIngested {
		events[k] = v
	}
	rejected := copyStringUint64(r.ingestRejected)
	siemSent := copyStringUint64(r.siemSent)
	siemDropped := copyStringUint64(r.siemDropped)
	notifySent := copyStringUint64(r.notifySent)
	notifyFailed := copyStringUint64(r.notifyFailed)
	httpReqs := make(map[httpReqKey]uint64, len(r.httpRequests))
	for k, v := range r.httpRequests {
		httpReqs[k] = v
	}
	r.mu.Unlock()

	// 2. doppel_events_ingested_total{node,sensor,severity,drill}
	writeHeader(&b, "doppel_events_ingested_total", "Total events stored by the Hub ingest pipeline.", "counter")
	evKeys := make([]eventKey, 0, len(events))
	for k := range events {
		evKeys = append(evKeys, k)
	}
	sort.Slice(evKeys, func(i, j int) bool {
		if evKeys[i].node != evKeys[j].node {
			return evKeys[i].node < evKeys[j].node
		}
		if evKeys[i].sensor != evKeys[j].sensor {
			return evKeys[i].sensor < evKeys[j].sensor
		}
		if evKeys[i].severity != evKeys[j].severity {
			return evKeys[i].severity < evKeys[j].severity
		}
		return evKeys[i].drill < evKeys[j].drill
	})
	for _, k := range evKeys {
		fmt.Fprintf(&b, "doppel_events_ingested_total{drill=%s,node=%s,sensor=%s,severity=%s} %d\n",
			quoteLabel(k.drill), quoteLabel(k.node), quoteLabel(k.sensor), quoteLabel(k.severity), events[k])
	}

	// 3. doppel_ingest_rejected_total{code}
	writeHeader(&b, "doppel_ingest_rejected_total", "Total ingest requests or events rejected, by error code.", "counter")
	writeSingleLabelCounters(&b, "doppel_ingest_rejected_total", "code", rejected)

	// 4. doppel_siem_queue_depth{output}
	writeHeader(&b, "doppel_siem_queue_depth", "Current number of records queued for SIEM delivery.", "gauge")
	if r.SIEM != nil {
		snap := r.SIEM()
		out := snap.Output
		if out == "" {
			out = "none"
		}
		fmt.Fprintf(&b, "doppel_siem_queue_depth{output=%s} %d\n", quoteLabel(out), snap.QueueDepth)
	}

	// 5. doppel_siem_sent_total{output}
	writeHeader(&b, "doppel_siem_sent_total", "Total records delivered to the SIEM output.", "counter")
	writeSingleLabelCounters(&b, "doppel_siem_sent_total", "output", siemSent)

	// 6. doppel_siem_dropped_total{output}
	writeHeader(&b, "doppel_siem_dropped_total", "Total SIEM records dropped due to queue overflow or delivery failure.", "counter")
	writeSingleLabelCounters(&b, "doppel_siem_dropped_total", "output", siemDropped)

	// 7. doppel_notify_sent_total{route}
	writeHeader(&b, "doppel_notify_sent_total", "Total notifications delivered successfully.", "counter")
	writeSingleLabelCounters(&b, "doppel_notify_sent_total", "route", notifySent)

	// 8. doppel_notify_failed_total{route}
	writeHeader(&b, "doppel_notify_failed_total", "Total notifications that failed delivery or were dropped.", "counter")
	writeSingleLabelCounters(&b, "doppel_notify_failed_total", "route", notifyFailed)

	// 9. doppel_nodes{state} & 10. doppel_sensors{state} & doppel_sensor_dropped_events{node,sensor}
	writeHeader(&b, "doppel_nodes", "Current number of registered nodes by state.", "gauge")
	var fleet FleetSnapshot
	haveFleet := false
	if r.Fleet != nil {
		if f, err := r.Fleet(ctx); err == nil {
			fleet = f
			haveFleet = true
		}
	}
	if haveFleet {
		fmt.Fprintf(&b, "doppel_nodes{state=\"offline\"} %d\n", fleet.NodesOffline)
		fmt.Fprintf(&b, "doppel_nodes{state=\"online\"} %d\n", fleet.NodesOnline)
	}

	writeHeader(&b, "doppel_sensors", "Current number of registered sensors by state.", "gauge")
	if haveFleet {
		fmt.Fprintf(&b, "doppel_sensors{state=\"offline\"} %d\n", fleet.SensorsOffline)
		fmt.Fprintf(&b, "doppel_sensors{state=\"online\"} %d\n", fleet.SensorsOnline)
		fmt.Fprintf(&b, "doppel_sensors{state=\"pending\"} %d\n", fleet.SensorsPending)
		fmt.Fprintf(&b, "doppel_sensors{state=\"silenced\"} %d\n", fleet.SensorsSilenced)
	}

	// Q88: sensor-reported dropped events.
	writeHeader(&b, "doppel_sensor_dropped_events", "Cumulative events reported dropped by sensors in heartbeats.", "counter")
	if haveFleet {
		drops := append([]SensorDropped(nil), fleet.SensorDropped...)
		sort.Slice(drops, func(i, j int) bool {
			if drops[i].NodeID != drops[j].NodeID {
				return drops[i].NodeID < drops[j].NodeID
			}
			return drops[i].SensorID < drops[j].SensorID
		})
		for _, d := range drops {
			fmt.Fprintf(&b, "doppel_sensor_dropped_events{node=%s,sensor=%s} %d\n",
				quoteLabel(d.NodeID), quoteLabel(d.SensorID), d.Dropped)
		}
	}

	// Q92: deprecated legacy drill shim uses.
	writeHeader(&b, "doppel_legacy_drills_total", "Total fire drills classified via the deprecated legacy source shim.", "counter")
	var legacyDrills uint64
	if r.LegacyDrills != nil {
		legacyDrills = r.LegacyDrills()
	}
	fmt.Fprintf(&b, "doppel_legacy_drills_total %d\n", legacyDrills)

	// 11. doppel_heartbeat_lag_seconds (histogram)
	r.heartbeatLag.write(&b, "doppel_heartbeat_lag_seconds", "Time elapsed between consecutive sensor heartbeats in seconds.")

	// 12. doppel_http_requests_total{route,code}
	writeHeader(&b, "doppel_http_requests_total", "Total HTTP requests handled by the Hub.", "counter")
	reqKeys := make([]httpReqKey, 0, len(httpReqs))
	for k := range httpReqs {
		reqKeys = append(reqKeys, k)
	}
	sort.Slice(reqKeys, func(i, j int) bool {
		if reqKeys[i].route != reqKeys[j].route {
			return reqKeys[i].route < reqKeys[j].route
		}
		return reqKeys[i].code < reqKeys[j].code
	})
	for _, k := range reqKeys {
		fmt.Fprintf(&b, "doppel_http_requests_total{code=%s,route=%s} %d\n",
			quoteLabel(k.code), quoteLabel(k.route), httpReqs[k])
	}

	// 13. doppel_http_request_seconds (histogram)
	r.httpDuration.write(&b, "doppel_http_request_seconds", "HTTP request handling duration in seconds.")

	// 14. doppel_db_query_seconds (histogram)
	r.dbDuration.write(&b, "doppel_db_query_seconds", "SQLite query execution duration in seconds.")

	_, _ = io.WriteString(w, b.String())
}

func writeHeader(b *strings.Builder, name, help, typ string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func copyStringUint64(m map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func writeSingleLabelCounters(b *strings.Builder, name, label string, m map[string]uint64) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(b, "%s{%s=%s} %d\n", name, label, quoteLabel(k), m[k])
	}
}

func quoteLabel(v string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteByte(v[i])
		}
	}
	b.WriteByte('"')
	return b.String()
}

type histogram struct {
	mu     sync.Mutex
	bounds []float64
	counts []uint64 // len == len(bounds), non-cumulative per bucket
	sum    float64
	total  uint64
}

func newHistogram(bounds []float64) *histogram {
	cp := append([]float64(nil), bounds...)
	sort.Float64s(cp)
	return &histogram{bounds: cp, counts: make([]uint64, len(cp))}
}

func (h *histogram) observe(v float64) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return
	}
	h.mu.Lock()
	h.sum += v
	h.total++
	for i, bound := range h.bounds {
		if v <= bound {
			h.counts[i]++
			break
		}
	}
	h.mu.Unlock()
}

func (h *histogram) write(b *strings.Builder, name, help string) {
	h.mu.Lock()
	counts := append([]uint64(nil), h.counts...)
	sum := h.sum
	total := h.total
	h.mu.Unlock()

	writeHeader(b, name, help, "histogram")
	var cum uint64
	for i, bound := range h.bounds {
		cum += counts[i]
		fmt.Fprintf(b, "%s_bucket{le=%q} %d\n", name, strconv.FormatFloat(bound, 'g', -1, 64), cum)
	}
	fmt.Fprintf(b, "%s_bucket{le=\"+Inf\"} %d\n", name, total)
	fmt.Fprintf(b, "%s_sum %s\n", name, strconv.FormatFloat(sum, 'g', -1, 64))
	fmt.Fprintf(b, "%s_count %d\n", name, total)
}
