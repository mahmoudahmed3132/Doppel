// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package attack

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

// Mapper adapts this package to ported.AttackMapper. Technique tactics are
// ATT&CK tactic IDs (for example TA0007), which the SIEM output carries in
// mitre_tactic and threat.tactic.id.
type Mapper struct {
	Now func() time.Time // layer timestamp; nil means time.Now
}

var _ ported.AttackMapper = Mapper{}

func toDomain(t Technique) domain.Technique {
	ids := make([]string, len(t.Tactics))
	for i, tc := range t.Tactics {
		ids[i] = tc.ID
	}
	return domain.Technique{ID: t.ID, Name: t.Name, Tactics: ids}
}

// For returns the mapping of trigger, or nil when it is not mapped.
func (Mapper) For(trigger string) *domain.AttackMapping {
	m, ok := For(trigger)
	if !ok {
		return nil
	}
	out := &domain.AttackMapping{Primary: toDomain(m.Primary)}
	for _, s := range m.Secondary {
		out.Secondary = append(out.Secondary, toDomain(s))
	}
	return out
}

// NavigatorLayer renders the events (already limited to the requested
// window by the Hub) as an ATT&CK Navigator 4.5 layer.
func (m Mapper) NavigatorLayer(events []domain.EnrichedEvent) (json.RawMessage, error) {
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	return json.Marshal(Layer(Calculate(events, "window", time.Time{}), now()))
}

// MatrixProjection is the attack_matrix projection (QUESTIONS Q56).
type MatrixProjection struct{}

var _ ported.Projection = MatrixProjection{}

func (MatrixProjection) Name() string { return "attack_matrix" }

// Build aggregates the window's events by technique; params["days"] names
// the window in the result.
func (MatrixProjection) Build(_ context.Context, events []domain.EnrichedEvent, params map[string]string) (any, error) {
	tf := "all"
	if d, err := strconv.Atoi(params["days"]); err == nil && d > 0 {
		tf = strconv.Itoa(d) + "d"
	}
	return Calculate(events, tf, time.Time{}), nil
}
