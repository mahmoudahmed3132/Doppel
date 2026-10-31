#!/bin/sh
# Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
#
# Prints the version declared in code for a component (§10: tags must match).
#   component-version.sh hub | cli | sensor <name>
set -eu
cd "$(dirname "$0")/../.."
case "${1:-}" in
hub) sed -n 's/^var Version = "\([^"]*\)"$/\1/p' hub/cmd/truesignal-hub/main.go ;;
cli) sed -n 's/^var Version = "\([^"]*\)"$/\1/p' cli/cmd/truesignal/main.go ;;
sensor)
	n="${2:?sensor name}"
	case "$n" in *[!a-z0-9-]* | -* | *- | "") echo "invalid sensor name" >&2; exit 2 ;; esac
	f="sensors/$n/manifest.json"
	[ -f "$f" ] || { echo "no manifest $f" >&2; exit 1; }
	jq -er '.version' "$f"
	;;
*) echo "usage: component-version.sh hub|cli|sensor <name>" >&2; exit 2 ;;
esac
