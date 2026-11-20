// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package projections

import (
	"context"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/geoip"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

const (
	defaultInsightsWindowDays = 30
	maxTopTriggers            = 10
)

// FleetReader provides read-only access to the Hub's managed nodes and
// deployed sensor instances. *store.DB satisfies this interface.
type FleetReader interface {
	Nodes(ctx context.Context) ([]domain.Node, error)
	Sensors(ctx context.Context, nodeID string) ([]domain.Sensor, error)
}

// HoneytokenLister provides read-only access to planted honeytokens.
// ported.HoneytokenService satisfies this interface.
type HoneytokenLister interface {
	List(ctx context.Context) ([]ported.Honeytoken, error)
}

// BeaconLister provides read-only access to active beacons.
// ported.BeaconService satisfies this interface.
type BeaconLister interface {
	List(ctx context.Context) ([]ported.Beacon, error)
}

// InsightsCoverage summarizes fleet decoy deployment, liveness, honeytoken,
// and beacon coverage.
type InsightsCoverage struct {
	DecoysDeployed     int `json:"decoys_deployed"`
	NodesWithDecoy     int `json:"nodes_with_decoy"`
	NodesWithoutDecoy  int `json:"nodes_without_decoy"`
	SensorsOnline      int `json:"sensors_online"`
	HoneytokensPlanted int `json:"honeytokens_planted"`
	BeaconsActive      int `json:"beacons_active"`
}

// InsightsByType summarizes deployment and attacker activity for one catalogue
// sensor type.
type InsightsByType struct {
	SensorType        string `json:"sensor_type"`
	InstancesDeployed int    `json:"instances_deployed"`
	InstancesOnline   int    `json:"instances_online"`
	Events            int    `json:"events"`
	DistinctSources   int    `json:"distinct_sources"`
	HighestSeverity   string `json:"highest_severity"`
	LastEventAt       string `json:"last_event_at"`
}

// InsightsTouched reports how many deployed decoy instances saw at least one
// attacker event in the window and the share of deployed instances that is.
type InsightsTouched struct {
	Instances int     `json:"instances"`
	Total     int     `json:"total"`
	Ratio     float64 `json:"ratio"`
}

// InsightsTriggerCount is one entry in top_triggers.
type InsightsTriggerCount struct {
	Trigger string `json:"trigger"`
	Count   int    `json:"count"`
}

// InsightsDTO is the insights projection read-model. It never includes event
// details, sensor configuration, or honeytoken/beacon secrets.
type InsightsDTO struct {
	Window        int                    `json:"window"`
	Coverage      InsightsCoverage       `json:"coverage"`
	ByType        []InsightsByType       `json:"by_type"`
	Touched       InsightsTouched        `json:"touched"`
	TopTriggers   []InsightsTriggerCount `json:"top_triggers"`
	AllowedEvents int                    `json:"allowed_events"`
}

// Insights is the insights projection: fleet coverage, per-decoy-type
// activity, touched decoy share, and top triggers. Safe for concurrent use.
type Insights struct {
	Fleet       FleetReader
	Honeytokens HoneytokenLister
	Beacons     BeaconLister
	GeoIP       *geoip.Service // optional; used for group_by=asn when events are not pre-enriched
}

// NewInsights constructs an Insights projection with read-only access to the
// fleet, honeytokens, and beacons. Any dependency may be nil.
func NewInsights(fleet FleetReader, honeytokens HoneytokenLister, beacons BeaconLister) *Insights {
	return &Insights{
		Fleet:       fleet,
		Honeytokens: honeytokens,
		Beacons:     beacons,
	}
}

var _ ported.Projection = (*Insights)(nil)

// Name returns the projection's registered name.
func (*Insights) Name() string { return "insights" }

type sensorKey struct {
	nodeID   string
	sensorID string
}

func fallbackSensorType(sensorID string) string {
	name := strings.TrimPrefix(sensorID, "ts-sensor-")
	if name == "" {
		return "unknown"
	}
	return name
}

func resolveWindowDays(ctx context.Context, params map[string]string) int {
	if days := ported.WindowDays(ctx); days > 0 {
		return days
	}
	if raw := strings.TrimSpace(params["days"]); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 && n <= 365 {
			return n
		}
	}
	return defaultInsightsWindowDays
}

// Build computes the insights projection over the Hub's enriched event window
// and current fleet state. Unknown query parameters are ignored.
func (in *Insights) Build(ctx context.Context, events []domain.EnrichedEvent, params map[string]string) (any, error) {
	groupBy, err := parseGroupBy(params)
	if err != nil {
		return nil, err
	}
	var (
		nodes   []domain.Node
		sensors []domain.Sensor
	)
	if in != nil && in.Fleet != nil {
		nodes, err = in.Fleet.Nodes(ctx)
		if err != nil {
			return nil, err
		}
		sensors, err = in.Fleet.Sensors(ctx, "")
		if err != nil {
			return nil, err
		}
	}

	honeytokensPlanted := 0
	if in != nil && in.Honeytokens != nil {
		tokens, err := in.Honeytokens.List(ctx)
		if err != nil {
			return nil, err
		}
		for _, t := range tokens {
			if t.Status == "" || t.Status == "active" {
				honeytokensPlanted++
			}
		}
	}

	beaconsActive := 0
	if in != nil && in.Beacons != nil {
		beacons, err := in.Beacons.List(ctx)
		if err != nil {
			return nil, err
		}
		beaconsActive = len(beacons)
	}

	type typeAgg struct {
		row     InsightsByType
		sources map[string]bool
		lastAt  time.Time
	}
	byType := map[string]*typeAgg{}
	getType := func(sensorType string) *typeAgg {
		a := byType[sensorType]
		if a == nil {
			a = &typeAgg{
				row:     InsightsByType{SensorType: sensorType},
				sources: map[string]bool{},
			}
			byType[sensorType] = a
		}
		return a
	}

	nodeSet := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		nodeSet[n.ID] = true
	}

	nodesWithDecoy := map[string]bool{}
	deployedType := make(map[sensorKey]string, len(sensors))
	sensorsOnline := 0
	for _, s := range sensors {
		if nodeSet[s.NodeID] {
			nodesWithDecoy[s.NodeID] = true
		}
		sensorType := s.CatalogueName
		if sensorType == "" {
			sensorType = fallbackSensorType(s.ID)
		}
		deployedType[sensorKey{nodeID: s.NodeID, sensorID: s.ID}] = sensorType
		a := getType(sensorType)
		a.row.InstancesDeployed++
		if s.Status == domain.StatusOnline {
			sensorsOnline++
			a.row.InstancesOnline++
		}
	}

	touchedInstances := map[sensorKey]bool{}
	triggerCounts := map[string]int{}
	allowedEvents := 0

	for _, e := range events {
		if !attacker(ctx, e.Event) {
			continue
		}
		if e.Whitelisted || e.KnownScanner {
			allowedEvents++
			continue
		}

		key := sensorKey{nodeID: e.NodeID, sensorID: e.SensorID}
		sensorType, deployed := deployedType[key]
		if deployed {
			touchedInstances[key] = true
		} else {
			sensorType = fallbackSensorType(e.SensorID)
		}

		var geo *geoip.Service
		if in != nil {
			geo = in.GeoIP
		}
		a := getType(sensorType)
		a.row.Events++
		if e.Source != "" {
			if key := sourceKey(e, groupBy, geo); key != "" {
				a.sources[key] = true
			}
		}
		if sev := string(e.Severity); sev != "" {
			if a.row.HighestSeverity == "" || sevRank[sev] > sevRank[a.row.HighestSeverity] {
				a.row.HighestSeverity = sev
			}
		}
		if !e.OccurredAt.IsZero() && (a.lastAt.IsZero() || e.OccurredAt.After(a.lastAt)) {
			a.lastAt = e.OccurredAt
		}
		if e.Trigger != "" {
			triggerCounts[e.Trigger]++
		}
	}

	byTypeOut := make([]InsightsByType, 0, len(byType))
	for _, a := range byType {
		a.row.DistinctSources = len(a.sources)
		if !a.lastAt.IsZero() {
			a.row.LastEventAt = ts(a.lastAt)
		}
		byTypeOut = append(byTypeOut, a.row)
	}
	sort.Slice(byTypeOut, func(i, j int) bool {
		if byTypeOut[i].Events != byTypeOut[j].Events {
			return byTypeOut[i].Events > byTypeOut[j].Events
		}
		if byTypeOut[i].InstancesDeployed != byTypeOut[j].InstancesDeployed {
			return byTypeOut[i].InstancesDeployed > byTypeOut[j].InstancesDeployed
		}
		return byTypeOut[i].SensorType < byTypeOut[j].SensorType
	})

	topTriggers := make([]InsightsTriggerCount, 0, len(triggerCounts))
	for trig, count := range triggerCounts {
		topTriggers = append(topTriggers, InsightsTriggerCount{Trigger: trig, Count: count})
	}
	sort.Slice(topTriggers, func(i, j int) bool {
		if topTriggers[i].Count != topTriggers[j].Count {
			return topTriggers[i].Count > topTriggers[j].Count
		}
		return topTriggers[i].Trigger < topTriggers[j].Trigger
	})
	if len(topTriggers) > maxTopTriggers {
		topTriggers = topTriggers[:maxTopTriggers]
	}

	totalDeployed := len(sensors)
	touchedCount := len(touchedInstances)
	ratio := 0.0
	if totalDeployed > 0 {
		ratio = math.Round(float64(touchedCount)/float64(totalDeployed)*10000) / 10000
	}

	return &InsightsDTO{
		Window: resolveWindowDays(ctx, params),
		Coverage: InsightsCoverage{
			DecoysDeployed:     totalDeployed,
			NodesWithDecoy:     len(nodesWithDecoy),
			NodesWithoutDecoy:  len(nodes) - len(nodesWithDecoy),
			SensorsOnline:      sensorsOnline,
			HoneytokensPlanted: honeytokensPlanted,
			BeaconsActive:      beaconsActive,
		},
		ByType: byTypeOut,
		Touched: InsightsTouched{
			Instances: touchedCount,
			Total:     totalDeployed,
			Ratio:     ratio,
		},
		TopTriggers:   topTriggers,
		AllowedEvents: allowedEvents,
	}, nil
}
