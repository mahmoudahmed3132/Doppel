// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package honeytoken

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

// StatusActive is the status of every planted token.
const StatusActive = "active"

// Service implements ported.HoneytokenService.
type Service struct {
	Store      ported.HoneytokenStore
	CaptureKey ported.CaptureKeyFunc // nil or nil result: passwords are not compared
	Now        func() time.Time

	mu sync.Mutex // serialises Ensure, so one sensor never gets two tokens
}

var _ ported.HoneytokenService = (*Service)(nil)

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Ensure returns the honeytoken a File Canary instance plants, creating it
// on first use. It is stable: lures are written once, so the token must not
// change between deployments.
func (s *Service) Ensure(ctx context.Context, nodeID, sensorID string) (ported.Honeytoken, error) {
	if nodeID == "" || sensorID == "" {
		return ported.Honeytoken{}, errors.New("honeytoken: node and sensor required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if h, err := s.Store.HoneytokenForSensor(ctx, nodeID, sensorID); err != nil {
		return ported.Honeytoken{}, err
	} else if h != nil {
		return *h, nil
	}
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		user, secret, err := generate()
		if err != nil {
			return ported.Honeytoken{}, err
		}
		id, err := randomString("0123456789abcdef", 8)
		if err != nil {
			return ported.Honeytoken{}, err
		}
		h := ported.Honeytoken{ID: "ht_" + id, Username: user, Secret: secret, PlantedNodeID: nodeID,
			PlantedSensorID: sensorID, Status: StatusActive, CreatedAt: s.now()}
		if lastErr = s.Store.InsertHoneytoken(ctx, h); lastErr == nil {
			return h, nil
		}
	}
	return ported.Honeytoken{}, fmt.Errorf("creating honeytoken: %w", lastErr)
}

// Match finds honeytokens used in an event: by username (plaintext, any
// node) and by password (HMAC under the reporting node's capture key, or a
// plaintext capture). Hub-raised honeytoken events are never matched again.
func (s *Service) Match(ctx context.Context, ev *domain.Event) ([]ported.HoneytokenMatch, error) {
	if ev == nil || ev.Trigger == domain.TriggerHoneytokenUsed {
		return nil, nil
	}
	var details map[string]any
	if err := json.Unmarshal(ev.Details, &details); err != nil || details == nil {
		return nil, nil
	}
	users := candidateUsernames(details)
	hmacs, plain := candidatePasswords(details)
	if len(users) == 0 && len(hmacs) == 0 && len(plain) == 0 {
		return nil, nil
	}
	var key []byte
	if len(hmacs) > 0 && s.CaptureKey != nil {
		key = s.CaptureKey(ev.NodeID)
	}
	tokens, err := s.Store.ListHoneytokens(ctx)
	if err != nil {
		return nil, err
	}
	userSet := map[string]bool{}
	for _, u := range users {
		userSet[u] = true
	}
	protocol, _ := details["protocol"].(string)
	port := 0
	for _, k := range []string{"dst_port", "port"} {
		if f, ok := details[k].(float64); ok && f > 0 && f < 65536 {
			port = int(f)
			break
		}
	}
	var out []ported.HoneytokenMatch
	for _, t := range tokens {
		var on []string
		if userSet[strings.ToLower(t.Username)] {
			on = append(on, "username")
		}
		hit := false
		if len(key) > 0 {
			want := hmacHex(key, t.Secret)
			for _, h := range hmacs {
				hit = hmac.Equal([]byte(h), []byte(want)) || hit
			}
		}
		for _, p := range plain {
			hit = hmac.Equal([]byte(p), []byte(t.Secret)) || hit
		}
		if hit {
			on = append(on, "password")
		}
		if len(on) > 0 {
			out = append(out, ported.HoneytokenMatch{Token: t, MatchedOn: strings.Join(on, "+"), Protocol: protocol, DstPort: port})
		}
	}
	return out, nil
}

// RecordUse notes that a honeytoken was used.
func (s *Service) RecordUse(ctx context.Context, id string, at time.Time) error {
	return s.Store.IncrementHoneytokenUse(ctx, id, at)
}

// List returns every token.
func (s *Service) List(ctx context.Context) ([]ported.Honeytoken, error) {
	return s.Store.ListHoneytokens(ctx)
}

// Inventory returns one SIEM inventory record per token, never the secret,
// so a SIEM watchlist can look for the planted usernames on real systems.
func (s *Service) Inventory(ctx context.Context, now time.Time) ([]domain.HoneytokenInventory, error) {
	tokens, err := s.Store.ListHoneytokens(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.HoneytokenInventory, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, domain.HoneytokenInventory{Time: now.UTC(), HoneytokenID: t.ID, Username: t.Username,
			PlantedNodeID: t.PlantedNodeID, PlantedSensorID: t.PlantedSensorID, CreatedAt: t.CreatedAt, Status: t.Status})
	}
	return out, nil
}
