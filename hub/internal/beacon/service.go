// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package beacon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

// ReceiverCatalogueName is the Token Receiver's catalogue name.
const ReceiverCatalogueName = "token-receiver"

// DomainConfigKey is the receiver setting that names its delegated zone.
const DomainConfigKey = "TS_BEACON_DOMAIN"

// ErrInvalid is returned for a create request that fails validation.
var ErrInvalid = errors.New("invalid beacon")

// Service implements ported.BeaconService.
type Service struct {
	Store ported.BeaconStore
	// ReceiverKey returns TS_BEACON_KEY as injected into receivers.
	ReceiverKey func(ctx context.Context) (string, error)
	// Domains lists the zones deployed Token Receivers serve.
	Domains func(ctx context.Context) ([]string, error)
	Now     func() time.Time
}

var _ ported.BeaconService = (*Service)(nil)

var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Create validates the request and stores a new beacon pointing at the zone
// of the deployed Token Receiver (exactly one zone must be configured).
func (s *Service) Create(ctx context.Context, typ, name, memo string) (ported.Beacon, error) {
	typ, name, memo = strings.TrimSpace(typ), strings.TrimSpace(name), strings.TrimSpace(memo)
	switch {
	case !types[typ]:
		return ported.Beacon{}, fmt.Errorf("%w: type must be dns, web-bug or kubeconfig", ErrInvalid)
	case name == "" || len(name) > 128:
		return ported.Beacon{}, fmt.Errorf("%w: name is required (up to 128 characters): say where it is planted", ErrInvalid)
	case len(memo) > 512:
		return ported.Beacon{}, fmt.Errorf("%w: memo is limited to 512 characters", ErrInvalid)
	}
	var domains []string
	if s.Domains != nil {
		var err error
		if domains, err = s.Domains(ctx); err != nil {
			return ported.Beacon{}, err
		}
	}
	if len(domains) != 1 {
		return ported.Beacon{}, fmt.Errorf("%w: deploy exactly one Token Receiver zone first (%s; deployed zones: %d)", ErrInvalid, DomainConfigKey, len(domains))
	}
	zone := domains[0]
	if len(zone) > 200 || !domainRe.MatchString(zone) {
		return ported.Beacon{}, fmt.Errorf("%w: zone %q is not a host name", ErrInvalid, zone)
	}
	key, err := s.ReceiverKey(ctx)
	if err != nil {
		return ported.Beacon{}, err
	}
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		random := make([]byte, tokenRandom)
		idb := make([]byte, 4)
		if _, err := rand.Read(random); err != nil {
			return ported.Beacon{}, err
		}
		if _, err := rand.Read(idb); err != nil {
			return ported.Beacon{}, err
		}
		b := ported.Beacon{ID: "bc_" + hex.EncodeToString(idb), Token: makeToken(key, random), Type: typ,
			Name: name, Memo: memo, Domain: zone, CreatedAt: s.now()}
		if lastErr = s.Store.InsertBeacon(ctx, b); lastErr == nil {
			return b, nil
		}
	}
	return ported.Beacon{}, fmt.Errorf("creating beacon: %w", lastErr)
}

// Artefact renders what the operator plants for beacon id.
func (s *Service) Artefact(ctx context.Context, id string) (ported.BeaconArtefact, error) {
	l, err := s.Store.ListBeacons(ctx)
	if err != nil {
		return ported.BeaconArtefact{}, err
	}
	for _, b := range l {
		if b.ID == id && b.Token != "" {
			return Render(b), nil
		}
	}
	return ported.BeaconArtefact{}, fmt.Errorf("%w: unknown beacon %s", ErrInvalid, id)
}

// Resolve returns the beacon a reported token belongs to, or nil for a
// token the Hub does not know (deleted beacon, or invented by the node).
func (s *Service) Resolve(ctx context.Context, token string) (*ported.Beacon, error) {
	token = strings.ToLower(strings.TrimSpace(token))
	if len(token) != TokenLen {
		return nil, nil
	}
	return s.Store.BeaconByToken(ctx, token)
}

func (s *Service) RecordUse(ctx context.Context, id string, at time.Time) error {
	return s.Store.IncrementBeaconUse(ctx, id, at)
}

func (s *Service) Delete(ctx context.Context, id string) error { return s.Store.DeleteBeacon(ctx, id) }

func (s *Service) List(ctx context.Context) ([]ported.Beacon, error) { return s.Store.ListBeacons(ctx) }

// Fleet is what ZonesFromFleet reads.
type Fleet interface {
	Nodes(ctx context.Context) ([]domain.Node, error)
	Sensors(ctx context.Context, nodeID string) ([]domain.Sensor, error)
}

// ZonesFromFleet returns the distinct zones (DomainConfigKey) of deployed
// Token Receivers, lower-cased, without trailing dots, sorted.
func ZonesFromFleet(f Fleet) func(ctx context.Context) ([]string, error) {
	return func(ctx context.Context) ([]string, error) {
		nodes, err := f.Nodes(ctx)
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		out := []string{}
		for _, n := range nodes {
			sensors, err := f.Sensors(ctx, n.ID)
			if err != nil {
				return nil, err
			}
			for _, sn := range sensors {
				if sn.CatalogueName != ReceiverCatalogueName {
					continue
				}
				z := strings.ToLower(strings.Trim(strings.TrimSpace(sn.Config[DomainConfigKey]), "."))
				if z != "" && !seen[z] {
					seen[z] = true
					out = append(out, z)
				}
			}
		}
		sort.Strings(out)
		return out, nil
	}
}
