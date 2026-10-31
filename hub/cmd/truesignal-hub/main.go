// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

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
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/config"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/httpapi"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ingest"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/liveness"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/nodekey"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ratelimit"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/store"
)

// Version is the Hub version; overridden at build time with -ldflags -X.
var Version = "3.0.0"

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

	if pending, err := db.TakeMFAResetMarker(ctx); err != nil {
		return err
	} else if pending {
		// Delivered to the SIEM once the audit pipeline is wired; always logged.
		log.Warn("audit", "action", "mfa.reset_cli", "outcome", "success", "actor_ip", "local")
	}

	log.Warn("PORTED modules are not installed: beacons, honeytokens, source lists, enrichment and SIEM rendering are inactive")

	pipe := &ingest.Pipeline{Store: db, Log: log, Now: time.Now}
	live := &liveness.Service{Store: db, Raiser: pipe, Log: log, Now: time.Now, StartedAt: startedAt}
	go live.Run(ctx, 5*time.Second)

	mux := http.NewServeMux()
	(&httpapi.Ingest{
		Auth:     nodekey.NewAuthenticator(db),
		Limiter:  ratelimit.NewKeyed(50, 200),
		Store:    db,
		Pipeline: pipe,
		Liveness: live,
		Version:  httpapi.Version{Product: "truesignal-hub", Version: Version, Contract: contractVersion},
		Log:      log,
		Now:      time.Now,
	}).Register(mux)

	srv := &http.Server{
		Addr:              net.JoinHostPort("", strconv.Itoa(cfg.ListenPort)),
		Handler:           mux,
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
