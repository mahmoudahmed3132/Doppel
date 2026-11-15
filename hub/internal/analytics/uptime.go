// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package analytics computes the Hub's own dashboard aggregates (§6.4
// Analytics); the richer projections are PORTED.
package analytics

import (
	"sort"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

// UptimeRow is one sensor's daily online percentage (UTC days, oldest
// first; -1 = sensor did not exist yet that day).
type UptimeRow struct {
	NodeID   string    `json:"node_id"`
	SensorID string    `json:"sensor_id"`
	Days     []string  `json:"days"`
	Percent  []float64 `json:"percent"`
}

// Uptime computes per-sensor, per-day online percentages over the last
// days UTC days (including today up to now) from status history. history
// must include, per sensor, the last change before the window start.
func Uptime(sensors []domain.Sensor, history []store.StatusChange, days int, now time.Time) []UptimeRow {
	now = now.UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	start := today.AddDate(0, 0, -(days - 1))
	type key struct{ n, s string }
	byKey := map[key][]store.StatusChange{}
	for _, c := range history {
		k := key{c.NodeID, c.SensorID}
		byKey[k] = append(byKey[k], c)
	}
	var out []UptimeRow
	for _, sn := range sensors {
		changes := byKey[key{sn.NodeID, sn.ID}]
		sort.Slice(changes, func(i, j int) bool { return changes[i].At.Before(changes[j].At) })
		row := UptimeRow{NodeID: sn.NodeID, SensorID: sn.ID}
		for d := 0; d < days; d++ {
			dayStart := start.AddDate(0, 0, d)
			dayEnd := dayStart.Add(24 * time.Hour)
			if dayEnd.After(now) {
				dayEnd = now
			}
			row.Days = append(row.Days, dayStart.Format("2006-01-02"))
			if !sn.CreatedAt.IsZero() && sn.CreatedAt.After(dayEnd) {
				row.Percent = append(row.Percent, -1)
				continue
			}
			from := dayStart
			if sn.CreatedAt.After(from) {
				from = sn.CreatedAt
			}
			row.Percent = append(row.Percent, onlineShare(changes, from, dayEnd))
		}
		out = append(out, row)
	}
	return out
}

// onlineShare returns the percentage of [from, to) spent online.
func onlineShare(changes []store.StatusChange, from, to time.Time) float64 {
	total := to.Sub(from)
	if total <= 0 {
		return 0
	}
	status := domain.StatusPending
	for _, c := range changes {
		if !c.At.After(from) {
			status = c.Status
		}
	}
	var online time.Duration
	cursor := from
	for _, c := range changes {
		if !c.At.After(from) {
			continue
		}
		if !c.At.Before(to) {
			break
		}
		if status == domain.StatusOnline {
			online += c.At.Sub(cursor)
		}
		cursor, status = c.At, c.Status
	}
	if status == domain.StatusOnline {
		online += to.Sub(cursor)
	}
	p := float64(online) / float64(total) * 100
	return float64(int(p*10+0.5)) / 10
}
