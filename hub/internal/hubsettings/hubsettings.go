// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package hubsettings owns the Hub's typed, validated settings (§6.4
// Settings): public endpoint, registry, update checks, retention, source
// lists and the asset inventory. It provides the source-list matchers to
// the event pipeline and the asset index to enrichment.
package hubsettings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/auth"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/catalogue"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

// Settings keys.
const (
	KeyUpdateHours  = "update_check_hours"
	KeyArchiveDays  = "retention_archive_days"
	KeyPurgeDays    = "retention_purge_days"
	KeyHistoryDays  = "retention_history_days"
	KeyWhitelist    = "whitelist"
	KeyScanners     = "known_scanners"
	KeyAssets       = "assets"
	KeyCLINoticeAck = "cli_notice_ack"
)

// Limits.
const (
	MaxListEntries = 1000
	MaxEntryBytes  = 256
	MaxAssetsBytes = 512 << 10
)

// Errors.
var (
	ErrInvalid = errors.New("invalid settings")
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Store persists settings.
type Store interface {
	Setting(ctx context.Context, key string) (string, bool, error)
	PutSettings(ctx context.Context, kv map[string]*string) error
}

// View is the settings as shown to the admin (no secrets).
type View struct {
	PublicEndpoint        string    `json:"public_endpoint"`
	RegistryURL           string    `json:"registry_url"`
	CatalogueRefreshHours int       `json:"catalogue_refresh_hours"`
	UpdateCheckHours      int       `json:"update_check_hours"`
	Retention             Retention `json:"retention"`
	Whitelist             []string  `json:"whitelist"`
	KnownScanners         []string  `json:"known_scanners"`
	SourceListsActive     bool      `json:"source_lists_active"`
}

// Retention days; 0 disables a rule.
type Retention struct {
	ArchiveAfterDays       int `json:"archive_after_days"`
	PurgeArchivedAfterDays int `json:"purge_archived_after_days"`
	HistoryDays            int `json:"history_days"`
}

// Patch updates settings partially: nil fields are unchanged.
type Patch struct {
	PublicEndpoint        *string `json:"public_endpoint"`
	RegistryURL           *string `json:"registry_url"`
	CatalogueRefreshHours *int    `json:"catalogue_refresh_hours"`
	UpdateCheckHours      *int    `json:"update_check_hours"`
	Retention             *struct {
		ArchiveAfterDays       *int `json:"archive_after_days"`
		PurgeArchivedAfterDays *int `json:"purge_archived_after_days"`
		HistoryDays            *int `json:"history_days"`
	} `json:"retention"`
	Whitelist     *[]string `json:"whitelist"`
	KnownScanners *[]string `json:"known_scanners"`
}

// Service is the settings service.
type Service struct {
	Store           Store
	Parser          ported.SourceListParser
	Assets          ported.AssetInventory
	DefaultRegistry string
	AllowHTTP       bool
	Log             *slog.Logger

	mu         sync.RWMutex
	whitelist  ported.SourceMatcher
	scanners   ported.SourceMatcher
	assetIndex ported.AssetIndex
}

func (s *Service) intSetting(ctx context.Context, key string, def int) int {
	v, ok, err := s.Store.Setting(ctx, key)
	if err != nil || !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func (s *Service) listSetting(ctx context.Context, key string) []string {
	v, ok, err := s.Store.Setting(ctx, key)
	out := []string{}
	if err != nil || !ok {
		return out
	}
	if json.Unmarshal([]byte(v), &out) != nil {
		return []string{}
	}
	return out
}

// Load builds matchers and the asset index from stored settings.
func (s *Service) Load(ctx context.Context) error {
	wl, err := s.parseStored(s.listSetting(ctx, KeyWhitelist))
	if err != nil {
		s.Log.Error("stored whitelist is invalid; not applied", "error", err.Error())
	}
	sc, err := s.parseStored(s.listSetting(ctx, KeyScanners))
	if err != nil {
		s.Log.Error("stored known-scanner list is invalid; not applied", "error", err.Error())
	}
	var ix ported.AssetIndex
	if raw, ok, _ := s.Store.Setting(ctx, KeyAssets); ok {
		if ix, err = s.Assets.Index(json.RawMessage(raw)); err != nil {
			s.Log.Error("stored asset inventory cannot be indexed", "error", err.Error())
		}
	}
	s.mu.Lock()
	s.whitelist, s.scanners, s.assetIndex = wl, sc, ix
	s.mu.Unlock()
	return nil
}

// storedParser is implemented by matchers that can parse a stored list
// leniently: a list saved before a validation rule existed keeps working
// instead of being dropped.
type storedParser interface {
	ParseStored(entries []string) ported.SourceMatcher
}

func (s *Service) parseStored(entries []string) (ported.SourceMatcher, error) {
	if sp, ok := s.Parser.(storedParser); ok && len(entries) > 0 {
		return sp.ParseStored(entries), nil
	}
	return s.parse(entries)
}

func (s *Service) parse(entries []string) (ported.SourceMatcher, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	return s.Parser.Parse(entries)
}

// Whitelist implements ingest.SourceLists.
func (s *Service) Whitelist() ported.SourceMatcher {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.whitelist
}

// KnownScanners implements ingest.SourceLists.
func (s *Service) KnownScanners() ported.SourceMatcher {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.scanners
}

// AssetIndex implements enrich.AssetIndexProvider.
func (s *Service) AssetIndex(context.Context) ported.AssetIndex {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.assetIndex
}

// Get returns the settings view.
func (s *Service) Get(ctx context.Context) View {
	ep, _, _ := s.Store.Setting(ctx, auth.SettingEndpoint)
	reg, ok, _ := s.Store.Setting(ctx, catalogue.SettingRegistryURL)
	if !ok || reg == "" {
		reg = s.DefaultRegistry
	}
	return View{
		PublicEndpoint: ep, RegistryURL: reg,
		CatalogueRefreshHours: s.intSetting(ctx, catalogue.SettingRefreshHours, 24),
		UpdateCheckHours:      s.intSetting(ctx, KeyUpdateHours, 24),
		Retention: Retention{
			ArchiveAfterDays:       s.intSetting(ctx, KeyArchiveDays, 0),
			PurgeArchivedAfterDays: s.intSetting(ctx, KeyPurgeDays, 0),
			HistoryDays:            s.intSetting(ctx, KeyHistoryDays, 30),
		},
		Whitelist: s.listSetting(ctx, KeyWhitelist), KnownScanners: s.listSetting(ctx, KeyScanners),
		SourceListsActive: true,
	}
}

func cleanEntries(name string, in []string) ([]string, error) {
	if len(in) > MaxListEntries {
		return nil, invalid("%s: at most %d entries", name, MaxListEntries)
	}
	out := []string{}
	seen := map[string]bool{}
	for _, e := range in {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if len(e) > MaxEntryBytes || strings.IndexFunc(e, unicode.IsControl) >= 0 {
			return nil, invalid("%s: entries must be at most %d bytes without control characters", name, MaxEntryBytes)
		}
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return out, nil
}

func setInt(kv map[string]*string, key string, v *int, min, max int, what string) error {
	if v == nil {
		return nil
	}
	if *v < min || *v > max {
		return invalid("%s must be %d..%d", what, min, max)
	}
	s := strconv.Itoa(*v)
	kv[key] = &s
	return nil
}

// Update validates and applies a patch atomically.
func (s *Service) Update(ctx context.Context, p Patch) (View, error) {
	kv := map[string]*string{}
	if p.PublicEndpoint != nil {
		ep, err := auth.NormalizeEndpoint(*p.PublicEndpoint)
		if err != nil {
			return View{}, invalid("public_endpoint: %v", err)
		}
		kv[auth.SettingEndpoint] = &ep
	}
	if p.RegistryURL != nil {
		if *p.RegistryURL == "" {
			kv[catalogue.SettingRegistryURL] = nil // back to the default
		} else {
			u, err := catalogue.ParseBase(*p.RegistryURL, s.AllowHTTP)
			if err != nil {
				return View{}, invalid("registry_url: %v", err)
			}
			v := u.String()
			kv[catalogue.SettingRegistryURL] = &v
		}
	}
	if err := setInt(kv, catalogue.SettingRefreshHours, p.CatalogueRefreshHours, 1, 168, "catalogue_refresh_hours"); err != nil {
		return View{}, err
	}
	if err := setInt(kv, KeyUpdateHours, p.UpdateCheckHours, 0, 720, "update_check_hours"); err != nil {
		return View{}, err
	}
	if r := p.Retention; r != nil {
		if err := setInt(kv, KeyArchiveDays, r.ArchiveAfterDays, 0, 3650, "retention.archive_after_days"); err != nil {
			return View{}, err
		}
		if err := setInt(kv, KeyPurgeDays, r.PurgeArchivedAfterDays, 0, 3650, "retention.purge_archived_after_days"); err != nil {
			return View{}, err
		}
		if err := setInt(kv, KeyHistoryDays, r.HistoryDays, 1, 3650, "retention.history_days"); err != nil {
			return View{}, err
		}
	}
	var wl, sc ported.SourceMatcher
	wlSet, scSet := false, false
	for _, l := range []struct {
		name string
		in   *[]string
		key  string
		out  *ported.SourceMatcher
		set  *bool
	}{{"whitelist", p.Whitelist, KeyWhitelist, &wl, &wlSet}, {"known_scanners", p.KnownScanners, KeyScanners, &sc, &scSet}} {
		if l.in == nil {
			continue
		}
		entries, err := cleanEntries(l.name, *l.in)
		if err != nil {
			return View{}, err
		}
		m, err := s.parse(entries)
		if err != nil {
			return View{}, invalid("%s: %v", l.name, err)
		}
		b, _ := json.Marshal(entries)
		v := string(b)
		kv[l.key], *l.out, *l.set = &v, m, true
	}
	if err := s.Store.PutSettings(ctx, kv); err != nil {
		return View{}, err
	}
	s.mu.Lock()
	if wlSet {
		s.whitelist = wl
	}
	if scSet {
		s.scanners = sc
	}
	s.mu.Unlock()
	return s.Get(ctx), nil
}

// AssetsRaw returns the stored inventory ([] when none).
func (s *Service) AssetsRaw(ctx context.Context) json.RawMessage {
	if raw, ok, _ := s.Store.Setting(ctx, KeyAssets); ok {
		return json.RawMessage(raw)
	}
	return json.RawMessage("[]")
}

// ReplaceAssets validates and stores the inventory.
func (s *Service) ReplaceAssets(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) > MaxAssetsBytes {
		return nil, invalid("inventory exceeds %d bytes", MaxAssetsBytes)
	}
	norm, err := s.Assets.Validate(raw)
	if err != nil {
		return nil, invalid("%v", err)
	}
	ix, err := s.Assets.Index(norm)
	if err != nil {
		return nil, invalid("%v", err)
	}
	v := string(norm)
	if err := s.Store.PutSettings(ctx, map[string]*string{KeyAssets: &v}); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.assetIndex = ix
	s.mu.Unlock()
	return norm, nil
}

// CLINoticeAck returns the acknowledged CLI release version.
func (s *Service) CLINoticeAck(ctx context.Context) string {
	v, _, _ := s.Store.Setting(ctx, KeyCLINoticeAck)
	return v
}

// AckCLINotice stores the acknowledged CLI release version.
func (s *Service) AckCLINotice(ctx context.Context, version string) error {
	return s.Store.PutSettings(ctx, map[string]*string{KeyCLINoticeAck: &version})
}

// RetentionStore performs retention deletions.
type RetentionStore interface {
	ArchiveOlderThan(ctx context.Context, t time.Time) (int64, error)
	PurgeArchivedOlderThan(ctx context.Context, t time.Time) (int64, error)
	PurgeStatusHistory(ctx context.Context, before time.Time) (int64, error)
}

// RunRetention applies the retention rules once (§6.2).
func (s *Service) RunRetention(ctx context.Context, rs RetentionStore, now time.Time) error {
	r := s.Get(ctx).Retention
	day := 24 * time.Hour
	var errs []error
	if r.ArchiveAfterDays > 0 {
		if n, err := rs.ArchiveOlderThan(ctx, now.Add(-time.Duration(r.ArchiveAfterDays)*day)); err != nil {
			errs = append(errs, err)
		} else if n > 0 {
			s.Log.Info("retention: events archived", "count", n)
		}
	}
	if r.PurgeArchivedAfterDays > 0 {
		if n, err := rs.PurgeArchivedOlderThan(ctx, now.Add(-time.Duration(r.PurgeArchivedAfterDays)*day)); err != nil {
			errs = append(errs, err)
		} else if n > 0 {
			s.Log.Info("retention: archived events purged", "count", n)
		}
	}
	if r.HistoryDays > 0 {
		if _, err := rs.PurgeStatusHistory(ctx, now.Add(-time.Duration(r.HistoryDays)*day)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// RunRetentionLoop applies retention hourly until ctx ends.
func (s *Service) RunRetentionLoop(ctx context.Context, rs RetentionStore) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if err := s.RunRetention(ctx, rs, time.Now()); err != nil && ctx.Err() == nil {
			s.Log.Error("retention failed", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
