// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package webhook

import (
	"bytes"
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

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
)

type memSettings struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *memSettings) Setting(_ context.Context, k string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	return v, ok, nil
}

func (s *memSettings) PutSettings(_ context.Context, kv map[string]*string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range kv {
		if v == nil {
			delete(s.m, k)
		} else {
			s.m[k] = *v
		}
	}
	return nil
}

type hit struct {
	header http.Header
	body   []byte
}

type receiver struct {
	mu     sync.Mutex
	hits   []hit
	status []int
	srv    *httptest.Server
}

func newReceiver(t *testing.T) *receiver {
	r := &receiver{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.hits = append(r.hits, hit{req.Header.Clone(), b})
		code := 200
		if len(r.status) > 0 {
			code, r.status = r.status[0], r.status[1:]
		}
		r.mu.Unlock()
		if code == http.StatusFound {
			http.Redirect(w, req, "https://evil.example/steal", code)
			return
		}
		w.WriteHeader(code)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.hits) }
func (r *receiver) last() hit  { r.mu.Lock(); defer r.mu.Unlock(); return r.hits[len(r.hits)-1] }

func newNotifier(t *testing.T, typ, url string, log *slog.Logger) *Notifier {
	t.Helper()
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	n := &Notifier{Store: &memSettings{m: map[string]string{}}, AllowHTTP: true, Log: log, Now: time.Now, Backoff: time.Millisecond}
	if err := n.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Update(context.Background(), Config{Type: typ, URL: url}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.Start(ctx)
	t.Cleanup(func() { cancel(); n.Wait() })
	return n
}

func hostile(sev domain.Severity) domain.EnrichedEvent {
	return domain.EnrichedEvent{NodeAlias: "dmz-1", Event: domain.Event{
		EventID: "e1", NodeID: "node-0000000a", SensorID: "ts-sensor-web", Trigger: "web_login_attempt", Severity: sev,
		ReceivedAt: time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC),
		Source:     "@everyone <!channel> [click](https://evil.example)\r\nX-Injected: 1",
		Target:     "Router login *bold* `code` <https://evil.example|bank>",
	}}
}

func waitCount(t *testing.T, r *receiver, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for r.count() < n {
		if time.Now().After(deadline) {
			t.Fatalf("got %d requests, want %d", r.count(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestDiscordNeutralisesMentionsAndMarkdown(t *testing.T) {
	r := newReceiver(t)
	n := newNotifier(t, TypeDiscord, r.srv.URL, nil)
	n.Notify(hostile(domain.SeverityCritical))
	waitCount(t, r, 1)
	var msg struct {
		AllowedMentions struct{ Parse []string } `json:"allowed_mentions"`
		Embeds          []struct {
			Title  string
			Color  int
			Fields []struct{ Name, Value string }
		}
	}
	if err := json.Unmarshal(r.last().body, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.AllowedMentions.Parse == nil || len(msg.AllowedMentions.Parse) != 0 {
		t.Fatal("mentions not disabled")
	}
	if msg.Embeds[0].Color != 0x8B0000 {
		t.Fatal("severity colour")
	}
	var src string
	for _, f := range msg.Embeds[0].Fields {
		if f.Name == "Source" {
			src = f.Value
		}
	}
	for _, raw := range []string{"](", "[click]", "\r", "\n"} {
		if strings.Contains(src, raw) {
			t.Fatalf("unescaped %q in %q", raw, src)
		}
	}
	if !strings.Contains(src, `\@everyone`) || !strings.Contains(src, `\[click\]`) {
		t.Fatalf("escaping: %q", src)
	}
}

func TestSlackEscapesControlSequences(t *testing.T) {
	r := newReceiver(t)
	n := newNotifier(t, TypeSlack, r.srv.URL, nil)
	n.Notify(hostile(domain.SeverityHigh))
	waitCount(t, r, 1)
	var msg struct {
		Text        string
		Attachments []struct {
			Color  string
			Fields []struct{ Title, Value string }
		}
	}
	if err := json.Unmarshal(r.last().body, &msg); err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	for _, f := range msg.Attachments[0].Fields {
		all.WriteString(f.Value + "\n")
	}
	decoded := all.String()
	if strings.Contains(decoded, "<!channel>") || strings.Contains(decoded, "<https://evil") {
		t.Fatalf("slack control sequence not escaped: %s", decoded)
	}
	if !strings.Contains(decoded, "&lt;!channel&gt;") || msg.Attachments[0].Color != "#E53935" {
		t.Fatalf("%s", decoded)
	}
}

func TestNtfyHeadersCarryNoAttackerData(t *testing.T) {
	r := newReceiver(t)
	n := newNotifier(t, TypeNtfy, r.srv.URL, nil)
	n.Notify(hostile(domain.SeverityHigh))
	waitCount(t, r, 1)
	h := r.last()
	if h.header.Get("X-Injected") != "" {
		t.Fatal("header injection")
	}
	if h.header.Get("Title") != "TrueSignal [HIGH] web_login_attempt" || h.header.Get("Priority") != "4" {
		t.Fatalf("headers %v", h.header)
	}
	if !bytes.Contains(h.body, []byte("Source: @everyone")) || bytes.Contains(h.body, []byte("\r")) {
		t.Fatalf("body %q", h.body)
	}
}

func TestGotifyFormat(t *testing.T) {
	r := newReceiver(t)
	n := newNotifier(t, TypeGotify, r.srv.URL+"/message?token=SECRET", nil)
	n.Notify(hostile(domain.SeverityCritical))
	waitCount(t, r, 1)
	var m map[string]any
	json.Unmarshal(r.last().body, &m)
	if m["priority"] != 10.0 || !strings.Contains(m["message"].(string), "Node: dmz-1 (node-0000000a)") {
		t.Fatalf("%v", m)
	}
}

func TestGating(t *testing.T) {
	r := newReceiver(t)
	n := newNotifier(t, TypeSlack, r.srv.URL, nil)
	n.Notify(hostile(domain.SeverityInfo)) // info not selected by default
	n.SetArmed(context.Background(), false)
	n.Notify(hostile(domain.SeverityCritical)) // disarmed
	time.Sleep(50 * time.Millisecond)
	if r.count() != 0 {
		t.Fatalf("sent %d", r.count())
	}
	n.SetArmed(context.Background(), true)
	n.Notify(hostile(domain.SeverityCritical))
	waitCount(t, r, 1)

	// Armed state persists; default is armed.
	n2 := &Notifier{Store: n.Store, Log: n.Log, Now: time.Now}
	n2.Load(context.Background())
	if !n2.Armed() {
		t.Fatal("armed state not persisted")
	}
	fresh := &Notifier{Store: &memSettings{m: map[string]string{}}, Log: n.Log, Now: time.Now}
	fresh.Load(context.Background())
	if !fresh.Armed() {
		t.Fatal("default must be armed")
	}
}

func TestRetriesAndRedirects(t *testing.T) {
	r := newReceiver(t)
	n := newNotifier(t, TypeSlack, r.srv.URL, nil)
	r.mu.Lock()
	r.status = []int{500, 503, 502, 500} // 1 attempt + 3 retries, all failing
	r.mu.Unlock()
	if err := n.deliver(context.Background(), n.Config(), hostile(domain.SeverityHigh)); err == nil {
		t.Fatal("expected failure")
	}
	if r.count() != 4 {
		t.Fatalf("attempts %d, want 4", r.count())
	}
	r.mu.Lock()
	r.hits, r.status = nil, []int{400}
	r.mu.Unlock()
	n.deliver(context.Background(), n.Config(), hostile(domain.SeverityHigh))
	if r.count() != 1 {
		t.Fatalf("4xx retried: %d", r.count())
	}
	r.mu.Lock()
	r.hits, r.status = nil, []int{302}
	r.mu.Unlock()
	if err := n.deliver(context.Background(), n.Config(), hostile(domain.SeverityHigh)); err == nil {
		t.Fatal("redirect treated as success")
	}
	if r.count() != 1 {
		t.Fatalf("redirect followed: %d requests", r.count())
	}
}

// syncBuf is a goroutine-safe log sink.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func TestURLNeverLogged(t *testing.T) {
	buf := &syncBuf{}
	log := slog.New(slog.NewTextHandler(buf, nil))
	secret := "http://127.0.0.1:1/hooks/T000/B000/SUPERSECRETTOKEN"
	n := newNotifier(t, TypeSlack, secret, log)
	n.Notify(hostile(domain.SeverityCritical))
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(buf.String(), "webhook notification failed") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(buf.String(), "webhook notification failed") {
		t.Fatal("failure not logged")
	}
	if strings.Contains(buf.String(), "SUPERSECRETTOKEN") || strings.Contains(buf.String(), "/hooks/") {
		t.Fatalf("URL leaked into logs: %s", buf.String())
	}
	if err := n.Test(context.Background()); err == nil || strings.Contains(err.Error(), "SUPERSECRETTOKEN") {
		t.Fatalf("test error leaks URL: %v", err)
	}
	if n.Config().Public().URLSet != true {
		t.Fatal("url_set")
	}
	b, _ := json.Marshal(n.Config().Public())
	if strings.Contains(string(b), "SUPERSECRET") {
		t.Fatal("public config contains the URL")
	}
}

func TestValidation(t *testing.T) {
	for _, c := range []Config{
		{Type: "teams", URL: "https://x"},
		{Type: TypeSlack, URL: "http://hooks.slack.com/x"},
		{Type: TypeSlack, URL: "not a url"},
		{Type: TypeSlack, URL: "https://x", Severities: []domain.Severity{"urgent"}},
	} {
		if _, err := c.Normalize(false); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
	c, err := Config{Type: "Discord", URL: "https://discord.com/api/webhooks/1/x"}.Normalize(false)
	if err != nil || len(c.Severities) != 4 {
		t.Fatalf("%+v %v", c, err)
	}
}
