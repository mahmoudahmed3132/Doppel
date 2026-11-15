// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/attack"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

// MaxReportRange bounds one report.
const MaxReportRange = 366 * 24 * time.Hour

type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type Day struct {
	Date     string `json:"date"`
	Events   int    `json:"events"`
	Critical int    `json:"critical"`
}

type ReportSource struct {
	Source   string             `json:"source"`
	Events   int                `json:"events"`
	Critical int                `json:"critical"`
	Decoys   int                `json:"decoys"`
	First    string             `json:"firstSeen"`
	Last     string             `json:"lastSeen"`
	Asset    *domain.AssetMatch `json:"asset"`
}

// AssetActivity aggregates every in-range source that belongs to one
// inventory asset (a CIDR asset can cover several attacking addresses).
// Entries sharing a name and criticality are one asset spread over
// several ranges; a shared name with a different criticality stays a
// separate row.
type AssetActivity struct {
	Name        string `json:"name"`
	Criticality string `json:"criticality"`
	Sources     int    `json:"sources"`
	Events      int    `json:"events"`
}

type HoneytokenUse struct {
	Timestamp string `json:"timestamp"`
	Username  string `json:"username"`
	Source    string `json:"source"`
	NodeID    string `json:"nodeId"`
	SensorID  string `json:"sensorId"`
}

// ReportDTO is the report read-model (evidence report for PCI DSS / CBE
// reviews and management summaries).
type ReportDTO struct {
	From         string         `json:"from"`
	To           string         `json:"to"`
	GeneratedAt  string         `json:"generatedAt"`
	Events       int            `json:"events"`
	Severity     SeverityCounts `json:"severity"`
	Daily        []Day          `json:"daily"`
	TopSources   []ReportSource `json:"topSources"`
	SourcesTotal int            `json:"sourcesTotal"`
	// Assets covers all sources in range, not just TopSources.
	Assets         []AssetActivity        `json:"assets"`
	Techniques     []attack.TechniqueStat `json:"techniques"`
	HoneytokenUses []HoneytokenUse        `json:"honeytokenUses"`
	// ArchivedEvents counts in-range archived events (whitelisted, known
	// scanners, or archived by an analyst); they are excluded from the
	// figures above.
	ArchivedEvents int `json:"archivedEvents"`
}

// Report is the report projection. Parameters `from` and `to` (RFC 3339 or
// YYYY-MM-DD, to exclusive) narrow the Hub's window; by default the report
// covers the window from its first event to now.
type Report struct {
	Now func() time.Time
}

func (Report) Name() string { return "report" }

func parseWhen(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02", s)
}

func (r Report) Build(_ context.Context, events []domain.EnrichedEvent, params map[string]string) (any, error) {
	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}
	sorted := oldestFirst(events)
	from, to := now, now
	if len(sorted) > 0 {
		from = sorted[0].OccurredAt.UTC().Truncate(24 * time.Hour)
	}
	var err error
	if v := params["from"]; v != "" {
		if from, err = parseWhen(v); err != nil {
			return nil, errors.New("from must be RFC 3339 or YYYY-MM-DD")
		}
	}
	if v := params["to"]; v != "" {
		if to, err = parseWhen(v); err != nil {
			return nil, errors.New("to must be RFC 3339 or YYYY-MM-DD")
		}
	}
	if !from.Before(to) && !(len(sorted) == 0 && from.Equal(to)) {
		return nil, errors.New("from must be before to")
	}
	if to.Sub(from) > MaxReportRange {
		return nil, errors.New("a report covers at most 366 days")
	}
	return buildReport(sorted, from, to, now), nil
}

// buildReport covers events with from <= time < to. Active events are the
// figures; archived ones are only counted, since archiving is a triage
// decision.
func buildReport(sorted []domain.EnrichedEvent, from, to, now time.Time) *ReportDTO {
	in := func(e domain.EnrichedEvent) bool { return !e.OccurredAt.Before(from) && e.OccurredAt.Before(to) }
	var events []domain.EnrichedEvent
	d := &ReportDTO{
		From: ts(from), To: ts(to), GeneratedAt: ts(now),
		Daily: []Day{}, TopSources: []ReportSource{}, Assets: []AssetActivity{}, Techniques: []attack.TechniqueStat{}, HoneytokenUses: []HoneytokenUse{},
	}
	for _, e := range sorted {
		if !in(e) || !attacker(e.Event) {
			continue
		}
		if e.Archived {
			d.ArchivedEvents++
			continue
		}
		events = append(events, e)
	}
	d.Events = len(events)

	days := map[string]*Day{}
	for day := from.UTC().Truncate(24 * time.Hour); day.Before(to); day = day.Add(24 * time.Hour) {
		key := day.Format("2006-01-02")
		days[key] = &Day{Date: key}
	}
	srcs := map[string]*ReportSource{}
	srcDecoys := map[string]map[string]bool{}
	for _, e := range events {
		at := ts(e.OccurredAt)
		switch e.Severity {
		case "critical":
			d.Severity.Critical++
		case "high":
			d.Severity.High++
		case "medium":
			d.Severity.Medium++
		case "low":
			d.Severity.Low++
		default:
			d.Severity.Info++
		}
		if day := days[e.OccurredAt.UTC().Format("2006-01-02")]; day != nil {
			day.Events++
			if e.Severity == "critical" {
				day.Critical++
			}
		}
		s := srcs[e.Source]
		if s == nil {
			s = &ReportSource{Source: e.Source, First: at, Asset: e.Enrichment.Asset}
			srcs[e.Source] = s
			srcDecoys[e.Source] = map[string]bool{}
		}
		s.Events++
		if e.Severity == "critical" {
			s.Critical++
		}
		s.Last = at
		srcDecoys[e.Source][e.NodeID+"/"+e.SensorID] = true

		if e.Trigger == domain.TriggerHoneytokenUsed {
			var det struct {
				Username string `json:"honeytoken_username"`
			}
			_ = json.Unmarshal(e.Details, &det)
			d.HoneytokenUses = append(d.HoneytokenUses, HoneytokenUse{Timestamp: at, Username: det.Username, Source: e.Source, NodeID: e.NodeID, SensorID: e.SensorID})
		}
	}
	for _, day := range days {
		d.Daily = append(d.Daily, *day)
	}
	sort.Slice(d.Daily, func(i, j int) bool { return d.Daily[i].Date < d.Daily[j].Date })

	byAsset := map[domain.AssetMatch]*AssetActivity{}
	for k, s := range srcs {
		s.Decoys = len(srcDecoys[k])
		d.TopSources = append(d.TopSources, *s)
		if s.Asset != nil {
			a := byAsset[*s.Asset]
			if a == nil {
				a = &AssetActivity{Name: s.Asset.Name, Criticality: s.Asset.Criticality}
				byAsset[*s.Asset] = a
			}
			a.Sources++
			a.Events += s.Events
		}
	}
	for _, a := range byAsset {
		d.Assets = append(d.Assets, *a)
	}
	sort.Slice(d.Assets, func(i, j int) bool {
		if d.Assets[i].Events != d.Assets[j].Events {
			return d.Assets[i].Events > d.Assets[j].Events
		}
		if d.Assets[i].Name != d.Assets[j].Name {
			return d.Assets[i].Name < d.Assets[j].Name
		}
		return d.Assets[i].Criticality < d.Assets[j].Criticality
	})
	d.SourcesTotal = len(d.TopSources)
	sort.Slice(d.TopSources, func(i, j int) bool {
		a, b := d.TopSources[i], d.TopSources[j]
		if (a.Asset != nil) != (b.Asset != nil) {
			return a.Asset != nil
		}
		if a.Critical != b.Critical {
			return a.Critical > b.Critical
		}
		if a.Events != b.Events {
			return a.Events > b.Events
		}
		return a.Source < b.Source
	})
	if len(d.TopSources) > 25 {
		d.TopSources = d.TopSources[:25]
	}

	for _, t := range attack.Calculate(events, "custom", time.Time{}).Techniques {
		if t.PrimaryEvents+t.SecondaryEvents > 0 {
			d.Techniques = append(d.Techniques, t)
		}
	}
	sort.Slice(d.Techniques, func(i, j int) bool {
		if d.Techniques[i].PrimaryEvents != d.Techniques[j].PrimaryEvents {
			return d.Techniques[i].PrimaryEvents > d.Techniques[j].PrimaryEvents
		}
		return d.Techniques[i].ID < d.Techniques[j].ID
	})
	return d
}
