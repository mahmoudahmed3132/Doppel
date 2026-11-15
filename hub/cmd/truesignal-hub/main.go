// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Command truesignal-hub is the TrueSignal Hub.
//
//	truesignal-hub [serve]   run the Hub (default)
//	truesignal-hub mfa-reset remove MFA from the admin account (Hub stopped)
//	truesignal-hub version   print the version
package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/assets"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/attack"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/beacon"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ecs"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/honeytoken"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/siemhttp"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/audit"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/auth"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/catalogue"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/compose"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/config"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/enrich"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/fleet"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/geoip"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/httpapi"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/hubsettings"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ingest"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/livefeed"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/liveness"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/manifest"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/nodekey"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ratelimit"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/secrets"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/siem"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/signing"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/sourcelist"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/totp"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/updatecheck"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/webhook"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/webui"
)

// Version is the Hub version; overridden at build time with -ldflags -X.
var Version = "3.0.0-rc.1"

const contractVersion = 3

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(log)
	case "mfa-reset":
		err = mfaReset(log)
	case "version":
		fmt.Printf("truesignal-hub %s (contract %d, schema v%d)\n", Version, contractVersion, store.SchemaVersion())
	default:
		fmt.Fprintf(os.Stderr, "usage: truesignal-hub [serve|mfa-reset|version]\n")
		os.Exit(2)
	}
	if err != nil {
		log.Error("fatal", "error", err.Error())
		os.Exit(1)
	}
}

func mfaReset(log *slog.Logger) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	if _, err := os.Stat(cfg.DBPath); err != nil {
		return fmt.Errorf("database %s: %w", cfg.DBPath, err)
	}
	ctx := context.Background()
	db, err := store.Open(ctx, cfg.DBPath, store.Options{Logger: log})
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.ResetMFA(ctx); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return errors.New("no admin account exists; nothing to reset")
		}
		return err
	}
	log.Warn("MFA removed from the admin account; all sessions invalidated; an audit record (mfa.reset_cli) will be emitted on next Hub start")
	return nil
}

func serve(log *slog.Logger) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	for _, w := range cfg.DevWarnings() {
		log.Warn("DEVELOPMENT RELAXATION ACTIVE — DO NOT USE IN PRODUCTION", "detail", w)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	startedAt := time.Now().UTC()
	db, err := store.Open(ctx, cfg.DBPath, store.Options{Logger: log})
	if err != nil {
		return err
	}
	defer db.Close()

	// SIEM output first, so every later audit record reaches it.
	// ECS renderer and Elastic / LogScale transports: merged modules
	// (imports H9, H10).
	httpSIEM, err := siemhttp.New(cfg.SIEMCABundle)
	if err != nil {
		return err
	}
	siemSvc := &siem.Service{PEN: cfg.SyslogPEN, CABundle: cfg.SIEMCABundle, Log: log, Renderer: ecs.Renderer{}, HTTP: httpSIEM}
	siemCfg, err := siem.LoadConfig(ctx, db)
	if err == nil {
		siemCfg, err = siemCfg.Normalize(siemSvc.Capabilities())
	}
	if err != nil {
		log.Error("stored SIEM output is unusable; SIEM delivery is OFF until reconfigured", "error", err.Error())
		siemCfg = siem.Config{Protocol: siem.ProtoNone}
	}
	if err := siemSvc.Start(siemCfg); err != nil {
		log.Error("SIEM output could not start; SIEM delivery is OFF until reconfigured", "error", err.Error())
		if err := siemSvc.Start(siem.Config{Protocol: siem.ProtoNone}); err != nil {
			return err
		}
	}
	defer func() {
		fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		siemSvc.Shutdown(fctx)
	}()

	auditor := &audit.Recorder{Log: log, SIEM: siemSvc}
	if pending, err := db.TakeMFAResetMarker(ctx); err != nil {
		return err
	} else if pending {
		auditor.Record(ctx, domain.AuditRecord{Time: time.Now().UTC(), Action: "mfa.reset_cli", Method: "CLI",
			Route: "truesignal-hub mfa-reset", Path: "-", Status: 200, Outcome: "success", ActorIP: "local"})
	}

	authSvc, err := auth.New(auth.Options{
		Store:              db,
		Hasher:             auth.NewHasher(auth.DefaultArgon2, 4),
		TOTP:               totp.Module{}, // PORTED module, installed (merge import H5/H6)
		Log:                log,
		Now:                time.Now,
		SessionTTL:         cfg.SessionTTL,
		SessionIdle:        cfg.SessionIdle,
		RequireMFA:         cfg.RequireMFA,
		PasswordOverride:   cfg.DashboardPassword,
		SetupTokenOverride: cfg.SetupToken,
	})
	if err != nil {
		return err
	}
	if tok, err := authSvc.Init(ctx); err != nil {
		return err
	} else if tok != "" {
		// Printed exactly once by design (§6.3); required to complete setup.
		log.Warn("first start: complete setup in the web UI with this one-time setup token", "setup_token", tok)
	}
	go purgeSessions(ctx, authSvc, log)

	notifier := &webhook.Notifier{Store: db, AllowHTTP: cfg.Development, Log: log, Now: time.Now}
	if err := notifier.Load(ctx); err != nil {
		return err
	}
	notifier.Start(ctx)

	// Source lists use the PORTED matcher (step 1); the asset inventory is the
	// merged module (import H2).
	settingsSvc := &hubsettings.Service{Store: db, Parser: sourcelist.Parser{}, Assets: assets.Module{}, DefaultRegistry: cfg.RegistryURL, AllowHTTP: cfg.Development, Log: log}

	if err := settingsSvc.Load(ctx); err != nil {
		return err
	}
	go settingsSvc.RunRetentionLoop(ctx, db)
	// GeoIP (merge import H1): TS_GEOIP_DB, default geoip/dbip-city-lite.mmdb
	// next to the database. Without a file, events carry no location.
	geoPath := cfg.GeoIPDB
	if geoPath == "" {
		geoPath = filepath.Join(filepath.Dir(cfg.DBPath), "geoip", "dbip-city-lite.mmdb")
	}
	geoSvc := geoip.New(geoPath, cfg.GeoIPAutoUpdate, log)
	defer geoSvc.Close()
	go geoSvc.StartUpdater(ctx)
	enricher := &enrich.Enricher{Nodes: db, Assets: settingsSvc, Geo: geoip.Locator{S: geoSvc}, Attack: attack.Mapper{}}

	// Honeytokens (merge import H8): planted by the compose compiler (with
	// SIEM inventory records), matched by the ingest pipeline.
	hubKeys := &secrets.Keys{Store: db}
	honeytokens := &siem.InventoryHoneytokens{Sink: siemSvc, Log: log, Now: time.Now,
		HoneytokenService: &honeytoken.Service{Store: db, Now: time.Now,
			CaptureKey: func(nodeID string) []byte {
				mk, err := hubKeys.CaptureMasterKey(ctx)
				if err != nil {
					log.Warn("capture master key unavailable; honeytoken passwords not compared", "error", err.Error())
					return nil
				}
				return compose.CaptureKey(mk, nodeID)
			}}}

	// Beacons (merge import H7): tokens tagged under the receiver key the
	// compose compiler injects; zone from the deployed Token Receiver.
	beacons := &beacon.Service{Store: db, Now: time.Now, Domains: beacon.ZonesFromFleet(db),
		ReceiverKey: func(ctx context.Context) (string, error) {
			mk, err := hubKeys.BeaconMasterKey(ctx)
			if err != nil {
				return "", err
			}
			return compose.BeaconReceiverKey(mk), nil
		}}

	broker := livefeed.NewBroker()
	pipe := &ingest.Pipeline{Store: db, Log: log, Now: time.Now, Lists: settingsSvc,
		Enricher: enricher, SIEM: siemSvc, Notifier: notifier, Live: broker, Honeytokens: honeytokens, Beacons: beacons}
	go (&siem.Heartbeat{Sink: siemSvc, Fleet: db, Version: Version, StartedAt: startedAt, Log: log, Now: time.Now}).
		Run(ctx, siem.HeartbeatInterval)
	live := &liveness.Service{Store: db, Raiser: pipe, Publisher: broker, Log: log, Now: time.Now, StartedAt: startedAt}
	go live.Run(ctx, 5*time.Second)

	network := httpapi.Network{Trusted: cfg.TrustedProxies}
	admin := &httpapi.Admin{Auth: authSvc, Settings: db, Audit: auditor, Network: network,
		Development: cfg.Development, Log: log, Now: time.Now}

	keys := nodekey.NewAuthenticator(db) // shared: admin key rotation invalidates ingest auth
	// Manifests are verified (Sigstore keyless, PORTED step 1) against this
	// repository's publish-sensor.yml identity before parsing. A trusted root
	// that cannot be read stops the Hub: fail closed, never degrade (§13).
	trustedRoot, err := signing.TrustedRoot(cfg.SigstoreRoot)
	if err != nil {
		return fmt.Errorf("sigstore trusted root (%s): %w", config.EnvSigstoreTrustedRoot, err)
	}
	signerRepo := cfg.SignerRepo
	if signerRepo == "" {
		signerRepo = signing.DefaultSignerRepo
	}
	verifier, err := signing.New(trustedRoot, signerRepo)
	if err != nil {
		return fmt.Errorf("manifest verifier (%s): %w", config.EnvSignerRepo, err)
	}
	log.Info("sensor manifests must be signed by the publish workflow", "identity", verifier.Identity("<sensor>", "<version>"),
		"custom_trusted_root", cfg.SigstoreRoot != "")
	cat := &catalogue.Catalogue{
		Store:         db,
		Settings:      db,
		Verifier:      verifier,
		Fetcher:       catalogue.NewHTTPFetcher(),
		DefaultURL:    cfg.RegistryURL,
		AllowHTTP:     cfg.Development,
		AllowUnsigned: cfg.DevAllowUnsigned,
		Options:       manifest.Options{AllowUnpinned: cfg.DevAllowUnpinned},
		Log:           log,
		Now:           time.Now,
	}
	if err := cat.Load(ctx); err != nil {
		return fmt.Errorf("loading catalogue cache: %w", err)
	}
	go cat.Run(ctx)

	compiler := &compose.Compiler{
		Manifests:   cat,
		Settings:    db,
		Keys:        hubKeys,
		Honeytokens: honeytokens,
		Options:     manifest.Options{AllowUnpinned: cfg.DevAllowUnpinned},
		Log:         log,
	}
	fleetSvc := &fleet.Service{Store: db, Compiler: compiler, Catalogue: cat, Keys: keys, Log: log, Now: time.Now}
	(&httpapi.Fleet{
		Svc:      fleetSvc,
		Settings: db,
		Log:      log,
	}).Register(admin)

	(&httpapi.Catalogue{Cat: cat, Log: log}).Register(admin)
	(&httpapi.Outputs{SIEM: siemSvc, Store: db, Webhook: notifier, Network: network, Log: log, Now: time.Now}).Register(admin)
	(&httpapi.Events{Store: db, Enricher: enricher, Log: log}).Register(admin)
	updates := &updatecheck.Checker{URL: cfg.UpdateCheckURL, Log: log, Now: time.Now,
		Interval: func(ctx context.Context) time.Duration {
			return time.Duration(settingsSvc.Get(ctx).UpdateCheckHours) * time.Hour
		}}
	go updates.Run(ctx)
	(&httpapi.Insights{Store: db, Enricher: enricher, Updates: updates, Settings: settingsSvc, Auth: authSvc, Live: broker,
		Armed: notifier.Armed, SIEMStats: siemSvc.Stats, Version: Version, Schema: store.SchemaVersion(),
		StartedAt: startedAt, Development: cfg.Development, Log: log, Now: time.Now, Origin: admin.ExpectedOrigin,
		// Merged modules: ATT&CK mapper and projections (MERGE-INVENTORY.md).
		Attack:      attack.Mapper{},
		Projections: projections(),
	}).Register(admin)
	(&httpapi.System{Settings: settingsSvc, Auth: authSvc, BeaconDB: db, Beacons: beacons, SIEM: siemSvc, Network: network, Log: log, Now: time.Now,
		Reset: func(ctx context.Context, purge bool) error {
			if err := db.FactoryReset(ctx, purge); err != nil {
				return err
			}
			keys.Purge() // every node key is revoked immediately
			if err := siemSvc.Switch(ctx, siem.Config{Protocol: siem.ProtoNone}, nil); err != nil {
				log.Error("factory reset: SIEM output not cleared", "error", err.Error())
			}
			if err := notifier.Load(ctx); err != nil {
				log.Error("factory reset: webhook state not reloaded", "error", err.Error())
			}
			settingsSvc.Load(ctx)
			tok, err := authSvc.ResetSetupToken(ctx)
			if err != nil {
				return err
			}
			if tok != "" {
				log.Warn("factory reset complete: complete setup again with this one-time setup token", "setup_token", tok)
			}
			return nil
		}}).Register(admin)

	mux := http.NewServeMux()
	mux.Handle("/api/v3/", admin.Handler())
	ui := webui.Handler()
	if !ui.Built() {
		log.Warn("admin UI not embedded in this build; serving a placeholder page")
	}
	mux.Handle("/", ui)
	ingestAPI := &httpapi.Ingest{
		Auth:     keys,
		Limiter:  ratelimit.NewKeyed(50, 200),
		Store:    db,
		Pipeline: pipe,
		Liveness: live,
		Version:  httpapi.Version{Product: "truesignal-hub", Version: Version, Contract: contractVersion},
		Log:      log,
		Now:      time.Now,
	}
	ingestAPI.Register(mux)
	(&httpapi.NodeAPI{Ingest: ingestAPI, Fleet: fleetSvc, Store: db, Raiser: pipe, HubMajor: 3}).Register(mux)

	srv := &http.Server{
		Addr:              net.JoinHostPort("", strconv.Itoa(cfg.ListenPort)),
		Handler:           httpapi.SecurityHeaders(network, mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("hub listening", "port", cfg.ListenPort, "version", Version, "schema", store.SchemaVersion())
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutCtx)
}

func purgeSessions(ctx context.Context, a *auth.Service, log *slog.Logger) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := a.PurgeExpired(ctx); err != nil && ctx.Err() == nil {
				log.Warn("purging expired sessions failed", "error", err.Error())
			}
		}
	}
}

// projections lists the installed analytics projections by name (Q56).
func projections() map[string]ported.Projection {
	out := map[string]ported.Projection{}
	for _, p := range []ported.Projection{attack.MatrixProjection{}} {
		out[p.Name()] = p
	}
	return out
}
