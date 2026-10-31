// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package httpapi

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/auth"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/hubsettings"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/livefeed"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ported"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ported/stub"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/store"
)

type insightHub struct {
	srv    *httptest.Server
	c      *client
	broker *livefeed.Broker
	jar    http.CookieJar
}

func newInsightHub(t *testing.T) *insightHub { return newInsightHubWith(t, nil) }

// newInsightHubWith lets a test install PORTED stubs before registration.
func newInsightHubWith(t *testing.T, mod func(*Insights)) *insightHub {
	t.Helper()
	ctx := context.Background()
	db, _ := store.Open(ctx, filepath.Join(t.TempDir(), "ts.db"), store.Options{})
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, _ := auth.New(auth.Options{Store: db, Hasher: auth.NewHasher(auth.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1}, 4),
		TOTP: stub.TOTP{}, Log: log, Now: time.Now, SessionTTL: time.Hour, SessionIdle: time.Hour})
	tok, _ := svc.Init(ctx)
	settings := &hubsettings.Service{Store: db, Log: log}
	broker := livefeed.NewBroker()
	admin := &Admin{Auth: svc, Settings: db, Audit: &auditLog{}, Log: log, Now: time.Now, Development: true}
	in := &Insights{Store: db, Settings: settings, Auth: svc, Live: broker, Armed: func() bool { return true },
		SIEMStats: func() (int, uint64) { return 3, 1 }, Version: "3.0.0", Schema: 2, StartedAt: time.Now(),
		Development: true, Log: log, Now: time.Now, Origin: admin.ExpectedOrigin, TickEvery: 50 * time.Millisecond}
	if mod != nil {
		mod(in)
	}
	in.Register(admin)
	srv := httptest.NewServer(admin.Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, http: &http.Client{Jar: jar}, base: srv.URL, origin: srv.URL}
	c.do("POST", "/api/v3/setup", map[string]string{"setup_token": tok, "password": adminPW, "public_endpoint": srv.URL})
	c.do("POST", "/api/v3/session/login", map[string]string{"password": adminPW})

	now := time.Now()
	db.CreateNode(ctx, &domain.Node{ID: "node-0000000a", Alias: "a", KeyHash: []byte("k"), CreatedAt: now, LastSeenAt: &now})
	db.TouchNode(ctx, "node-0000000a", now)
	db.CreateSensor(ctx, &domain.Sensor{NodeID: "node-0000000a", ID: "ts-sensor-a", CatalogueName: "x", Version: "1.0.0", CreatedAt: now.Add(-48 * time.Hour)})
	db.SaveSensorLiveness(ctx, "node-0000000a", "ts-sensor-a", store.SensorLiveness{Status: domain.StatusOnline, StatusChanged: true}, now.Add(-47*time.Hour))
	for i, sev := range []domain.Severity{"critical", "high", "high", "low"} {
		db.InsertEvent(ctx, &domain.Event{EventID: string(rune('a' + i)), NodeID: "node-0000000a", SensorID: "ts-sensor-a", Trigger: "x",
			Severity: sev, OccurredAt: now, ReceivedAt: now.Add(-time.Duration(i) * time.Hour), Source: "s", Target: "t", Details: []byte("{}")})
	}
	return &insightHub{srv: srv, c: c, broker: broker, jar: jar}
}

func TestAnalyticsEndpoints(t *testing.T) {
	h := newInsightHub(t)
	_, out, _ := h.c.do("GET", "/api/v3/analytics/summary", nil)
	s := out["summary"].(map[string]any)
	if s["events_total"] != 4.0 || s["critical_24h"] != 1.0 || s["nodes_online"] != 1.0 || s["sensors_online"] != 1.0 {
		t.Fatalf("%v", s)
	}
	_, out, _ = h.c.do("GET", "/api/v3/analytics/severity?days=1", nil)
	sev := out["severity"].(map[string]any)
	if sev["high"] != 2.0 || sev["medium"] != 0.0 {
		t.Fatalf("%v", sev)
	}
	_, out, _ = h.c.do("GET", "/api/v3/analytics/velocity?hours=6&bucket=3600", nil)
	var sum float64
	for _, p := range out["series"].([]any) {
		sum += p.(map[string]any)["count"].(float64)
	}
	if sum != 4 || len(out["series"].([]any)) < 6 {
		t.Fatalf("%v", out)
	}
	if code, _, _ := h.c.do("GET", "/api/v3/analytics/velocity?hours=2000&bucket=60", nil); code != 400 {
		t.Fatal("too many buckets accepted")
	}
	_, out, _ = h.c.do("GET", "/api/v3/analytics/uptime?days=2", nil)
	row := out["sensors"].([]any)[0].(map[string]any)
	if len(row["percent"].([]any)) != 2 {
		t.Fatalf("%v", row)
	}
	_, out, _ = h.c.do("GET", "/api/v3/system/status", nil)
	st := out["status"].(map[string]any)
	if st["version"] != "3.0.0" || st["armed"] != true || st["siem_queue"].(map[string]any)["depth"] != 3.0 {
		t.Fatalf("%v", st)
	}
	if code, _, _ := h.c.do("GET", "/api/v3/analytics/projections/insights", nil); code != 404 {
		t.Fatal("projection without module")
	}
	if code, _, _ := h.c.do("GET", "/api/v3/analytics/attack/navigator", nil); code != 503 {
		t.Fatal("navigator without module")
	}
}

func (h *insightHub) dialLive(t *testing.T, origin string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	u, _ := url.Parse(h.srv.URL)
	c, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	var cookie string
	for _, ck := range h.jar.Cookies(u) {
		cookie = ck.Name + "=" + ck.Value
	}
	req := "GET /api/v3/live HTTP/1.1\r\nHost: " + u.Host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nCookie: " + cookie + "\r\n"
	if origin != "" {
		req += "Origin: " + origin + "\r\n"
	}
	io.WriteString(c, req+"\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, br, resp.StatusCode
}

func TestLiveFeedEndsWithSession(t *testing.T) {
	h := newInsightHub(t)
	c, br, code := h.dialLive(t, h.srv.URL)
	defer c.Close()
	if code != 101 {
		t.Fatalf("upgrade %d", code)
	}
	h.broker.PublishEvent(domain.EnrichedEvent{Event: domain.Event{EventID: "x", Details: []byte("{}")}})
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	hdr := make([]byte, 2)
	io.ReadFull(br, hdr)
	if hdr[0] != 0x81 {
		t.Fatalf("frame %x", hdr)
	}
	// Logout: the next tick sees the invalid session and closes the feed.
	h.c.do("POST", "/api/v3/session/logout", nil)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	all, _ := io.ReadAll(br)
	closeAt := strings.LastIndex(string(all), "\x88")
	if closeAt < 0 {
		t.Fatalf("feed not closed after logout (%d bytes)", len(all))
	}
}

func TestLiveFeedOriginChecked(t *testing.T) {
	in := &Insights{Development: false, Origin: func(*http.Request) string { return "https://hub.example.com" }}
	for _, origin := range []string{"", "https://evil.example"} {
		r := httptest.NewRequest("GET", "/api/v3/live", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		in.live(w, r)
		if w.Code != 403 {
			t.Fatalf("origin %q: %d", origin, w.Code)
		}
	}
	h := newInsightHub(t)
	anon := &client{t: t, http: &http.Client{}, base: h.srv.URL}
	if code, _, _ := anon.do("GET", "/api/v3/live", nil); code != 401 {
		t.Fatal("live feed without session")
	}
}

// With the PORTED modules installed (stubs), projections are mounted with
// their window and bounded parameter pass-through, the status lists them,
// and the ATT&CK Navigator layer downloads as an attachment.
func TestProjectionsAndNavigatorWithModules(t *testing.T) {
	attack := stub.Attack{Map: map[string]domain.AttackMapping{"x": {Primary: domain.Technique{ID: "T1046", Name: "Network Service Discovery", Tactics: []string{"discovery"}}}}}
	h := newInsightHubWith(t, func(in *Insights) {
		in.Projections = map[string]ported.Projection{"sources": stub.Projection{N: "sources"}}
		in.Attack = attack
	})
	_, out, _ := h.c.do("GET", "/api/v3/system/status", nil)
	mods := out["status"].(map[string]any)["modules"].(map[string]any)
	if mods["attack"] != true || len(mods["projections"].([]any)) != 1 || mods["projections"].([]any)[0] != "sources" {
		t.Fatalf("modules %v", mods)
	}
	code, out, _ := h.c.do("GET", "/api/v3/analytics/projections/sources?days=1&top=5", nil)
	data, _ := out["data"].(map[string]any)
	if code != 200 || out["projection"] != "sources" || data["events"] != 4.0 || data["params"].(map[string]any)["top"] != "5" {
		t.Fatalf("%d %v", code, out)
	}
	if _, ok := data["params"].(map[string]any)["days"]; ok {
		t.Fatal("days must not be passed through as a projection parameter")
	}
	if code, _, _ := h.c.do("GET", "/api/v3/analytics/projections/Bad%20Name", nil); code != 404 {
		t.Fatalf("invalid projection name: %d", code)
	}
	code, _, resp := h.c.do("GET", "/api/v3/analytics/attack/navigator?days=1", nil)
	if code != 200 || !strings.HasPrefix(resp.Header.Get("Content-Disposition"), "attachment;") || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("navigator %d %v", code, resp.Header)
	}
}
