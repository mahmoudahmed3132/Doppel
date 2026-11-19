#!/bin/sh
# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
#
# Asserts that the Go toolchain installed on this machine satisfies go.work and
# every go.mod WITHOUT a silent toolchain download (F-004). Runs the check with
# GOTOOLCHAIN=local: if the local Go is older than what the modules require, Go
# refuses instead of fetching another toolchain, and this script fails with a
# clear message. In CI the installed version must also equal the pinned
# GO_VERSION (pass it as $1 or set GO_VERSION).
set -eu
cd "$(dirname "$0")/.."
want_pin="${1:-${GO_VERSION:-}}"
export GOTOOLCHAIN=local

have=$(go env GOVERSION 2>/dev/null) || { echo "go not found" >&2; exit 1; }
have=${have#go}

# Highest "toolchain" (else "go") directive across go.work and all go.mod files.
need=$(
	for f in go.work $(sed -n 's/^[[:space:]]*\.\/\(.*\)$/\1\/go.mod/p' go.work); do
		t=$(sed -n 's/^toolchain go\(.*\)$/\1/p' "$f")
		[ -n "$t" ] || t=$(sed -n 's/^go \(.*\)$/\1/p' "$f")
		[ -n "$t" ] || { echo "no go/toolchain directive in $f" >&2; exit 1; }
		echo "$t"
	done | sort -V | tail -n 1
)

# `go.mod` allows "1.27" or "1.27.0"; normalise to three components.
norm() { echo "$1" | awk -F. '{printf "%s.%s.%s", $1, $2, ($3==""?0:$3)}'; }
need=$(norm "$need"); have=$(norm "$have")
lowest=$(printf '%s\n%s\n' "$need" "$have" | sort -V | head -n 1)
if [ "$lowest" != "$need" ]; then
	echo "FAIL: local Go $have is older than go.mod/go.work require ($need); refusing to rely on a silent toolchain download (GOTOOLCHAIN=local)" >&2
	exit 1
fi
if [ -n "$want_pin" ] && [ "$(norm "$want_pin")" != "$have" ]; then
	echo "FAIL: installed Go $have differs from the pinned CI version $want_pin" >&2
	exit 1
fi
# Prove that the build tooling itself works without a download.
go list -m >/dev/null 2>&1 || { echo "FAIL: go list failed under GOTOOLCHAIN=local" >&2; exit 1; }
echo "ok: local Go $have satisfies $need${want_pin:+ and the pinned $want_pin} (GOTOOLCHAIN=local)"
