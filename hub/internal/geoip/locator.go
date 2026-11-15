// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package geoip

import (
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

// Locator adapts a Service to ported.GeoLocator.
type Locator struct{ S *Service }

var _ ported.GeoLocator = Locator{}

// Enabled reports whether a database is loaded.
func (l Locator) Enabled() bool { return l.S.Enabled() }

// Locate places an event: a public EDNS client subnet from details first,
// else the source address. Internal addresses and names return nil.
func (l Locator) Locate(source string, details map[string]any) *domain.Location {
	loc := l.S.ForEvent(source, details)
	if loc == nil {
		return nil
	}
	return &domain.Location{CountryCode: loc.CountryCode, Country: loc.Country, Region: loc.Region, City: loc.City,
		Lat: loc.Lat, Lon: loc.Lon, Basis: loc.Basis, Address: loc.Address}
}
