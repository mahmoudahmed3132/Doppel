// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

//go:build unix

package sensor

import (
	"os"
	"os/signal"
	"syscall"
)

func notifySignals() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGUSR1)
	return ch, func() { signal.Stop(ch) }
}

func isDrillSignal(sig os.Signal) bool { return sig == syscall.SIGUSR1 }

func signalName(sig os.Signal) string {
	switch sig {
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGINT:
		return "SIGINT"
	}
	return sig.String()
}
