// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package projections

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/geoip"
)

// maxPointSources caps the sources listed per point (sourceCount is exact).
const maxPointSources = 20

// Point is the activity located at one place.
type Point struct {
	Lat          float64 `json:"lat"`
	Lon          float64 `json:"lon"`
	City         string  `json:"city"`
	Region       string  `json:"region"`
	Country      string  `json:"country"`
	CountryCode  string  `json:"countryCode"`
	Events       int     `json:"events"`
	BeaconEvents int     `json:"beaconEvents"`
	// Sources are event sources as stored (what Attack Path matches on);
	// for a DNS beacon that is the resolver. ClientSubnets are the beacon
	// client subnets (network addresses) that placed events here.
	SourceCount   int      `json:"sourceCount"`
	Sources       []string `json:"sources"`
	ClientSubnets []string `json:"clientSubnets"`
	Triggers      []string `json:"triggers"`
	MaxSeverity   string   `json:"maxSeverity"`
	LastSeen      string   `json:"lastSeen"`
}

// Country is the activity located in one country.
type Country struct {
	CountryCode string `json:"countryCode"`
	Country     string `json:"country"`
	Events      int    `json:"events"`
	Sources     int    `json:"sources"`
}

// GeoDTO is the geo_map read-model.
type GeoDTO struct {
	GeoIP geoip.Status `json:"geoip"`
	// Events in range (attacker activity only), split by how they placed:
	// located, internal (private/CGNAT/... source, never looked up) and
	// unlocated (public or a name, but not in the database).
	Events          int       `json:"events"`
	LocatedEvents   int       `json:"locatedEvents"`
	InternalEvents  int       `json:"internalEvents"`
	UnlocatedEvents int       `json:"unlocatedEvents"`
	Points          []Point   `json:"points"`
	Countries       []Country `json:"countries"`
}

// GeoMap is the geo_map projection; locations come from the Hub's GeoIP
// enrichment of each event.
type GeoMap struct {
	GeoIP *geoip.Service // status only; nil reports GeoIP as disabled
}

func (GeoMap) Name() string { return "geo_map" }

// internalSource reports an address the map never looks up (private,
// CGNAT, loopback, ...), as opposed to a name or an unlisted public address.
func internalSource(source string) bool {
	if host, _, err := net.SplitHostPort(source); err == nil {
		source = host
	}
	a, err := netip.ParseAddr(source)
	return err == nil && !geoip.Public(a)
}

func (g GeoMap) Build(_ context.Context, events []domain.EnrichedEvent, _ map[string]string) (any, error) {
	dto := &GeoDTO{GeoIP: g.GeoIP.Status(), Points: []Point{}, Countries: []Country{}}
	type pointAgg struct {
		p        *Point
		sources  map[string]bool
		subnets  map[string]bool
		triggers map[string]bool
	}
	points := map[string]*pointAgg{}
	countries := map[string]*Country{}
	countrySources := map[string]map[string]bool{}

	for _, e := range oldestFirst(events) {
		if !attacker(e.Event) {
			continue
		}
		dto.Events++
		l := e.Enrichment.Location
		if l == nil {
			if internalSource(e.Source) {
				dto.InternalEvents++
			} else {
				dto.UnlocatedEvents++
			}
			continue
		}
		dto.LocatedEvents++
		sev := string(e.Severity)

		if l.Lat != 0 || l.Lon != 0 {
			key := fmt.Sprintf("%.2f,%.2f", round2(l.Lat), round2(l.Lon))
			a := points[key]
			if a == nil {
				a = &pointAgg{
					p:        &Point{Lat: round2(l.Lat), Lon: round2(l.Lon), City: l.City, Region: l.Region, Country: l.Country, CountryCode: l.CountryCode, MaxSeverity: sev},
					sources:  map[string]bool{},
					subnets:  map[string]bool{},
					triggers: map[string]bool{},
				}
				points[key] = a
			}
			a.p.Events++
			if e.Trigger == domain.TriggerBeaconTriggered {
				a.p.BeaconEvents++
			}
			a.sources[e.Source] = true
			if l.Basis == "client_subnet" {
				a.subnets[l.Address] = true
			}
			a.triggers[e.Trigger] = true
			if sevRank[sev] > sevRank[a.p.MaxSeverity] {
				a.p.MaxSeverity = sev
			}
			a.p.LastSeen = ts(e.OccurredAt)
		}

		cc := l.CountryCode
		if cc == "" {
			cc = "??"
		}
		c := countries[cc]
		if c == nil {
			c = &Country{CountryCode: cc, Country: l.Country}
			countries[cc] = c
			countrySources[cc] = map[string]bool{}
		}
		c.Events++
		countrySources[cc][e.Source] = true
	}

	for _, a := range points {
		a.p.SourceCount = len(a.sources)
		a.p.Sources = sortedKeys(a.sources, maxPointSources)
		a.p.ClientSubnets = sortedKeys(a.subnets, maxPointSources)
		a.p.Triggers = sortedKeys(a.triggers, 0)
		dto.Points = append(dto.Points, *a.p)
	}
	sort.Slice(dto.Points, func(i, j int) bool {
		if dto.Points[i].Events != dto.Points[j].Events {
			return dto.Points[i].Events > dto.Points[j].Events
		}
		return dto.Points[i].City < dto.Points[j].City
	})
	for cc, c := range countries {
		c.Sources = len(countrySources[cc])
		dto.Countries = append(dto.Countries, *c)
	}
	sort.Slice(dto.Countries, func(i, j int) bool {
		if dto.Countries[i].Events != dto.Countries[j].Events {
			return dto.Countries[i].Events > dto.Countries[j].Events
		}
		return dto.Countries[i].CountryCode < dto.Countries[j].CountryCode
	})
	return dto, nil
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }
