// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

// Command truesignal is the TrueSignal node agent CLI.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/cli/internal/app"
)

// Version is set at build time with -ldflags "-X main.Version=…".
var Version = "3.0.0"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := app.New(Version).Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
