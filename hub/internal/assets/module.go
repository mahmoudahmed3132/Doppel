// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package assets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

// Module adapts this package to ported.AssetInventory. The stored format is
// a JSON array of Asset ({"name", "address", "criticality", "owner",
// "tags"}); unknown fields are refused.
type Module struct{}

var _ ported.AssetInventory = Module{}

// Validate decodes strictly, normalises and re-encodes an inventory.
func (Module) Validate(raw json.RawMessage) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var list []Asset
	if err := dec.Decode(&list); err != nil {
		return nil, fmt.Errorf("asset inventory must be a JSON array of assets: %w", err)
	}
	if dec.More() {
		return nil, errors.New("asset inventory: trailing data")
	}
	if list == nil {
		list = []Asset{}
	}
	norm, err := Validate(list)
	if err != nil {
		return nil, err
	}
	return json.Marshal(norm)
}

// Index builds the lookup index for a normalised inventory.
func (Module) Index(normalised json.RawMessage) (ported.AssetIndex, error) {
	list, err := Decode(string(normalised))
	if err != nil {
		return nil, err
	}
	return index{NewIndex(list)}, nil
}

type index struct{ ix *Index }

// Lookup returns the most specific asset containing source, or nil.
func (i index) Lookup(source string) *domain.AssetMatch {
	r := i.ix.Lookup(source)
	if r == nil {
		return nil
	}
	return &domain.AssetMatch{Name: r.Name, Criticality: r.Criticality}
}
