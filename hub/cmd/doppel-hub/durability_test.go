// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/config"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ids"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/nodekey"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

const childEnv = "DOPPEL_TEST_HUB_CHILD"

// TestMain lets the test binary act as the real Hub (`doppel-hub serve`)
// when re-executed with childEnv set, so the crash test kills the real
// serve path, not a test double.
func TestMain(m *testing.M) {
	if os.Getenv(childEnv) == "1" {
		os.Args = []string{"doppel-hub", "serve"}
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type hubProc struct {
	cmd  *exec.Cmd
	base string
	log  *os.File
}

func startHub(t *testing.T, dir, dbPath string) *hubProc {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	logf, err := os.OpenFile(filepath.Join(dir, "hub.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(),
		childEnv+"=1",
		config.EnvEnvironment+"=development",
		config.EnvDevAllowPlaintext+"=true",
		config.EnvDBPath+"="+dbPath,
		config.EnvListenPort+"="+strconv.Itoa(port),
		config.EnvUpdateCheckURL+"=https://127.0.0.1:1/none",
		config.EnvRegistryURL+"=http://127.0.0.1:1/",
	)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &hubProc{cmd: cmd, base: "http://127.0.0.1:" + strconv.Itoa(port), log: logf}
	t.Cleanup(func() {
		p.cmd.Process.Kill()
		p.cmd.Wait()
		logf.Close()
		if t.Failed() {
			b, _ := os.ReadFile(logf.Name())
			t.Logf("hub log:\n%s", tail(b, 4000))
		}
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := http.Get(p.base + "/v3/version")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return p
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("hub did not start: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func tail(b []byte, n int) []byte {
	if len(b) > n {
		return b[len(b)-n:]
	}
	return b
}

// TestKill9DuringBurstLosesNoAcknowledgedEvent is the F-603 acceptance test:
// SIGKILL the Hub while several clients post event batches, then count the
// events the Hub acknowledged (200 with every event accepted or duplicate)
// against the events in the database. Every acknowledged event must be
// stored. Unacknowledged batches may or may not be stored; the SDK resends
// them and the Hub deduplicates by event_id.
func TestKill9DuringBurstLosesNoAcknowledgedEvent(t *testing.T) {
	if testing.Short() {
		t.Skip("starts the real Hub")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "doppel.db")
	ctx := context.Background()

	// Seed one node and sensor through the store, as enrolment would.
	key, hash := nodekey.Generate()
	db, err := store.Open(ctx, dbPath, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	const nodeID, sensorID = "node-0000c0de", "ts-sensor-burst"
	if err := db.CreateNode(ctx, &domain.Node{ID: nodeID, Alias: "burst", KeyHash: hash, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSensor(ctx, &domain.Sensor{NodeID: nodeID, ID: sensorID, CatalogueName: "tcp-tarpit", Version: "1.0.0", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	hub := startHub(t, dir, dbPath)

	const (
		workers   = 8
		batchSize = 50
		killAfter = 1500 // acknowledged events before SIGKILL
	)
	var (
		mu      sync.Mutex
		acked   = map[string]bool{}
		sent    atomic.Int64
		failed  atomic.Int64 // requests that ended without an acknowledgement
		killed  = make(chan struct{})
		once    sync.Once
		wg      sync.WaitGroup
		client  = &http.Client{Timeout: 10 * time.Second}
		badResp atomic.Value
	)
	kill := func() {
		once.Do(func() {
			hub.cmd.Process.Signal(syscall.SIGKILL)
			close(killed)
		})
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for {
				batchIDs := make([]string, batchSize)
				evs := make([]map[string]any, batchSize)
				for i := range evs {
					id := ids.UUIDv7(time.Now())
					batchIDs[i] = id
					evs[i] = map[string]any{
						"event_id": id, "sensor_id": sensorID, "trigger": "tcp_connection", "severity": "medium",
						"occurred_at": time.Now().Format(time.RFC3339Nano), "source": "192.0.2.10:40000",
						"target": "port 22", "details": map[string]any{"worker": w, "i": i},
					}
				}
				body, _ := json.Marshal(map[string]any{"events": evs})
			retry:
				req, _ := http.NewRequest(http.MethodPost, hub.base+"/v3/ingest/events", bytes.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+key)
				req.Header.Set("Content-Type", "application/json")
				sent.Add(batchSize)
				resp, err := client.Do(req)
				if err != nil {
					failed.Add(1)
					return // the Hub is gone
				}
				var out struct {
					OK         bool  `json:"ok"`
					Accepted   int   `json:"accepted"`
					Duplicates int   `json:"duplicates"`
					Rejected   []any `json:"rejected"`
				}
				derr := json.NewDecoder(resp.Body).Decode(&out)
				resp.Body.Close()
				if resp.StatusCode == http.StatusTooManyRequests {
					failed.Add(1)
					select {
					case <-killed:
						return
					case <-time.After(100 * time.Millisecond):
					}
					goto retry
				}
				if derr != nil {
					failed.Add(1) // connection cut mid-response: not acknowledged
					return
				}
				if resp.StatusCode != 200 || !out.OK || out.Accepted+out.Duplicates != batchSize || len(out.Rejected) != 0 {
					badResp.Store(fmt.Sprintf("status %d %+v", resp.StatusCode, out))
					kill()
					return
				}
				mu.Lock()
				for _, id := range batchIDs {
					acked[id] = true
				}
				n := len(acked)
				mu.Unlock()
				if n >= killAfter {
					kill()
				}
			}
		}(w)
	}
	wg.Wait()
	hub.cmd.Wait()
	if v := badResp.Load(); v != nil {
		t.Fatalf("unexpected ingest reply: %v", v)
	}
	if ps := hub.cmd.ProcessState; ps == nil || ps.Success() {
		t.Fatalf("hub was not killed: %v", ps)
	}
	if failed.Load() == 0 {
		t.Fatal("no request was cut by the kill; the crash did not land mid-burst")
	}

	// Count what survived. Opening the database replays the WAL, as the next
	// Hub start would.
	sqldb, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer sqldb.Close()
	rows, err := sqldb.Query(`SELECT event_id FROM events WHERE node_id = ? AND sensor_id = ?`, nodeID, sensorID)
	if err != nil {
		t.Fatal(err)
	}
	stored := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		stored[id] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	lost := 0
	for id := range acked {
		if !stored[id] {
			lost++
		}
	}
	t.Logf("sent %d events, acknowledged %d, stored %d, lost acknowledged %d", sent.Load(), len(acked), len(stored), lost)
	if len(acked) < killAfter {
		t.Fatalf("only %d events acknowledged before the kill", len(acked))
	}
	if lost != 0 {
		t.Fatalf("%d acknowledged events lost after kill -9", lost)
	}

	// The Hub restarts on the crashed database and keeps serving ingest.
	hub2 := startHub(t, dir, dbPath)
	body := fmt.Sprintf(`{"events":[{"event_id":%q,"sensor_id":%q,"trigger":"tcp_connection","severity":"low","occurred_at":%q,"source":"192.0.2.11","target":"port 22","details":{}}]}`,
		ids.UUIDv7(time.Now()), sensorID, time.Now().Format(time.RFC3339))
	req, _ := http.NewRequest(http.MethodPost, hub2.base+"/v3/ingest/events", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("ingest after restart: %d", resp.StatusCode)
	}
	hub2.cmd.Process.Signal(syscall.SIGTERM)
}
