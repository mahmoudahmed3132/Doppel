// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ids"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

// Store is the persistence the pipeline needs.
type Store interface {
	InsertEvent(ctx context.Context, e *domain.Event) (bool, error)
	TouchSensorActivity(ctx context.Context, nodeID, sensorID string, at time.Time) error
	Sensor(ctx context.Context, nodeID, id string) (*domain.Sensor, error)
}

// SourceLists provides the current whitelist and known-scanner matchers.
// Either may return nil (empty list).
type SourceLists interface {
	Whitelist() ported.SourceMatcher
	KnownScanners() ported.SourceMatcher
}

// Enricher computes output-only enrichment for an event.
type Enricher interface {
	Enrich(ctx context.Context, e *domain.Event) domain.EnrichedEvent
}

// SIEMSink accepts records for SIEM delivery. It must not block.
type SIEMSink interface {
	Enqueue(rec domain.Record)
}

// Notifier sends webhook notifications. It must not block; it applies the
// armed state and severity selection itself.
type Notifier interface {
	Notify(ev domain.EnrichedEvent)
}

// LiveFeed pushes events to connected UI clients. It must not block.
type LiveFeed interface {
	PublishEvent(ev domain.EnrichedEvent)
}

// Pipeline processes accepted events in the order defined by §6.5.
// Collaborators other than Store, Log and Now may be nil in tests.
type Pipeline struct {
	Store       Store
	Lists       SourceLists
	Beacons     ported.BeaconService
	Honeytokens ported.HoneytokenService
	Enricher    Enricher
	SIEM        SIEMSink
	Notifier    Notifier
	Live        LiveFeed
	Log         *slog.Logger
	Now         func() time.Time
}

// Result reports what happened to one event.
type Result struct {
	Stored     bool // false: duplicate
	Suppressed bool // whitelisted or known scanner
}

// RaiseHubEvent creates and processes a Hub-raised event (liveness,
// honeytoken use). Hub-raised events are never whitelisted.
func (p *Pipeline) RaiseHubEvent(ctx context.Context, nodeID, sensorID, trigger string, sev domain.Severity, source, target string, details map[string]any) (*domain.Event, error) {
	now := p.Now().UTC()
	raw, err := marshalDetails(details)
	if err != nil {
		return nil, err
	}
	clampedSource := Clamp(source)
	sourceIP, sourcePort, sourceKind := domain.ParseSource(clampedSource)
	ev := &domain.Event{
		EventID:    ids.UUIDv7(now),
		NodeID:     nodeID,
		SensorID:   sensorID,
		Trigger:    trigger,
		Severity:   sev,
		OccurredAt: now,
		ReceivedAt: now,
		Source:     clampedSource,
		SourceIP:   sourceIP,
		SourcePort: sourcePort,
		SourceKind: sourceKind,
		Labels:     domain.SourceLabels(sourceIP),
		Target:     Clamp(target),
		Details:    raw,
		HubRaised:  true,
	}
	_, err = p.Process(ctx, ev)
	return ev, err
}

// Process runs a normalised sensor event through the pipeline.
//
// Fire drills (ev.Drill, F-001) are stored, enriched and sent to the SIEM
// (labelled there), but skip beacon resolution (a drill must not count as a
// beacon use or change its severity), honeytoken matching (a drill must not
// raise honeytoken_used) and notifications. They are published to the live
// feed so the UI can show them in the Drills view.
func (p *Pipeline) Process(ctx context.Context, ev *domain.Event) (Result, error) {
	var res Result
	if ev.HubRaised {
		// Drills come only from authenticated sensors through ingest.
		ev.Drill = false
	}
	if ev.SourceKind == "" {
		ev.SourceIP, ev.SourcePort, ev.SourceKind = domain.ParseSource(ev.Source)
		if len(ev.Labels) == 0 {
			ev.Labels = domain.SourceLabels(ev.SourceIP)
		}
	}

	// Step 2: beacon resolution.
	knownBeacon := false
	var beaconID string
	if ev.Trigger == domain.TriggerBeaconTriggered && !ev.HubRaised && !ev.Drill {
		b, err := p.resolveBeacon(ctx, ev)
		if err != nil {
			return res, err
		}
		if b != nil {
			knownBeacon, beaconID = true, b.ID
		}
	}

	// Step 3: whitelist / known scanner.
	if !ev.HubRaised && !knownBeacon && p.Lists != nil {
		if m := p.Lists.Whitelist(); m != nil && m.Match(ev.Source) {
			ev.Whitelisted = true
		}
		if m := p.Lists.KnownScanners(); m != nil && m.Match(ev.Source) {
			ev.KnownScanner = true
		}
		if ev.Whitelisted || ev.KnownScanner {
			ev.Read, ev.Archived = true, true
			res.Suppressed = true
		}
	}

	// Step 4: store (idempotent).
	stored, err := p.Store.InsertEvent(ctx, ev)
	if err != nil {
		return res, fmt.Errorf("storing event: %w", err)
	}
	if !stored {
		return res, nil
	}
	res.Stored = true

	// Step 5: beacon use.
	if knownBeacon {
		if err := p.Beacons.RecordUse(ctx, beaconID, ev.ReceivedAt); err != nil {
			p.Log.Warn("recording beacon use failed", "beacon_id", beaconID, "error", err.Error())
		}
	}

	// Step 6: output-only enrichment.
	enriched := domain.EnrichedEvent{Event: *ev}
	if p.Enricher != nil {
		enriched = p.Enricher.Enrich(ctx, ev)
	}

	// Step 7: sensor activity (liveness input).
	if !ev.HubRaised {
		if err := p.Store.TouchSensorActivity(ctx, ev.NodeID, ev.SensorID, ev.ReceivedAt); err != nil {
			p.Log.Warn("updating sensor activity failed", "error", err.Error())
		}
	}

	// Step 8: SIEM (suppressed events too, flagged).
	if p.SIEM != nil {
		e := enriched
		p.SIEM.Enqueue(domain.Record{Kind: domain.RecordEvent, Event: &e})
	}

	// Step 9: honeytoken matching, even for suppressed events.
	if p.Honeytokens != nil && ev.Trigger != domain.TriggerHoneytokenUsed && !ev.Drill {
		p.matchHoneytokens(ctx, ev)
	}

	// Step 10.
	if res.Suppressed {
		return res, nil
	}

	// Step 11: webhook unless the sensor is silenced. Drills never notify:
	// no notification route opts in to drills until F-301 (include_drills).
	if p.Notifier != nil && !ev.Drill {
		silenced := false
		s, err := p.Store.Sensor(ctx, ev.NodeID, ev.SensorID)
		switch {
		case err == nil:
			silenced = s.Silenced && (s.SilencedUntil == nil || ev.ReceivedAt.Before(*s.SilencedUntil))
		case !errors.Is(err, domain.ErrNotFound):
			p.Log.Warn("sensor lookup failed", "error", err.Error())
		}
		if !silenced {
			p.Notifier.Notify(enriched)
		}
	}

	// Step 12: live feed.
	if p.Live != nil {
		p.Live.PublishEvent(enriched)
	}
	return res, nil
}

// resolveBeacon applies step 2 to ev in place and returns the known beacon.
func (p *Pipeline) resolveBeacon(ctx context.Context, ev *domain.Event) (*ported.Beacon, error) {
	details, err := DecodeDetails(ev.Details)
	if err != nil {
		details = map[string]any{}
	}
	var b *ported.Beacon
	if tok, ok := details["token"].(string); ok && tok != "" && p.Beacons != nil {
		b, err = p.Beacons.Resolve(ctx, tok)
		if err != nil {
			p.Log.Warn("beacon resolution failed, treating as unknown", "error", err.Error())
			b = nil
		}
	}
	if b != nil {
		ev.Severity = domain.SeverityCritical
		details["beacon"] = map[string]any{"id": b.ID, "name": b.Name, "type": b.Type, "domain": b.Domain}
		delete(details, "beacon_known")
	} else {
		ev.Severity = domain.SeverityMedium
		delete(details, "beacon")
		details["beacon_known"] = false
	}
	raw, err := marshalDetails(details)
	if err != nil {
		return nil, err
	}
	ev.Details = raw
	return b, nil
}

func (p *Pipeline) matchHoneytokens(ctx context.Context, ev *domain.Event) {
	matches, err := p.Honeytokens.Match(ctx, ev)
	if err != nil {
		p.Log.Warn("honeytoken matching failed", "error", err.Error())
		return
	}
	for _, m := range matches {
		if err := p.Honeytokens.RecordUse(ctx, m.Token.ID, ev.ReceivedAt); err != nil {
			p.Log.Warn("recording honeytoken use failed", "honeytoken_id", m.Token.ID, "error", err.Error())
		}
		details := map[string]any{
			"honeytoken_id":       m.Token.ID,
			"honeytoken_username": m.Token.Username,
			"matched_on":          m.MatchedOn,
			"planted_node_id":     m.Token.PlantedNodeID,
			"planted_sensor_id":   m.Token.PlantedSensorID,
			"triggering_event_id": ev.EventID,
			"triggering_trigger":  ev.Trigger,
			"protocol":            m.Protocol,
			"dst_port":            m.DstPort,
		}
		if _, err := p.RaiseHubEvent(ctx, ev.NodeID, ev.SensorID, domain.TriggerHoneytokenUsed, domain.SeverityCritical, ev.Source, ev.Target, details); err != nil {
			p.Log.Error("raising honeytoken_used failed", "error", err.Error())
		}
	}
}
