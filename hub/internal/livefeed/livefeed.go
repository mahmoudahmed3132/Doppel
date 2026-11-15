// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package livefeed pushes typed messages to connected admin UIs over
// WebSocket (§6.4 Live feed): new events, sensor status changes, a periodic
// tick and a debounced chart-refresh hint. The Hub only sends; clients may
// send only control frames.
package livefeed

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

// Message is one pushed message.
type Message struct {
	Type string `json:"type"` // event | status | tick | refresh
	Data any    `json:"data"`
}

const clientBuffer = 64

// Broker fans messages out to clients. A client that falls behind is
// disconnected instead of buffered without bound.
type Broker struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}

	refreshMu sync.Mutex
	refresh   *time.Timer
	Debounce  time.Duration
}

// NewBroker returns an empty broker.
func NewBroker() *Broker {
	return &Broker{clients: map[chan []byte]struct{}{}, Debounce: 2 * time.Second}
}

// Subscribe registers a client; cancel must be called when it leaves.
// The channel is closed when the client is dropped for being slow.
func (b *Broker) Subscribe() (<-chan []byte, func()) {
	ch := make(chan []byte, clientBuffer)
	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		if _, ok := b.clients[ch]; ok {
			delete(b.clients, ch)
			close(ch)
		}
		b.mu.Unlock()
	}
}

// Clients returns the number of connected clients.
func (b *Broker) Clients() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.clients)
}

// Publish sends a message to every client without blocking.
func (b *Broker) Publish(m Message) {
	raw, err := json.Marshal(m)
	if err != nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.clients {
		select {
		case ch <- raw:
		default:
			delete(b.clients, ch) // too slow: drop
			close(ch)
		}
	}
}

// PublishEvent implements ingest.LiveFeed.
func (b *Broker) PublishEvent(ev domain.EnrichedEvent) {
	b.Publish(Message{Type: "event", Data: ev})
	b.hintRefresh()
}

// PublishStatus implements liveness.StatusPublisher.
func (b *Broker) PublishStatus(nodeID, sensorID string, status domain.SensorStatus, at time.Time) {
	b.Publish(Message{Type: "status", Data: map[string]any{"node_id": nodeID, "sensor_id": sensorID, "status": status, "at": at}})
	b.hintRefresh()
}

// hintRefresh sends one "refresh" message after a burst settles.
func (b *Broker) hintRefresh() {
	b.refreshMu.Lock()
	defer b.refreshMu.Unlock()
	if b.refresh != nil {
		return
	}
	b.refresh = time.AfterFunc(b.Debounce, func() {
		b.refreshMu.Lock()
		b.refresh = nil
		b.refreshMu.Unlock()
		b.Publish(Message{Type: "refresh", Data: map[string]bool{"charts": true}})
	})
}

// Tick publishes the periodic heartbeat tick.
func (b *Broker) Tick(now time.Time) {
	b.Publish(Message{Type: "tick", Data: map[string]any{"time": now.UTC()}})
}
