#!/bin/sh
# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
#
# Validates the Trivy waiver file used by the release gate (F-004). A waiver
# is accepted only with an id (CVE/GHSA), a written statement and a future
# expiry no more than 90 days away, so a waiver can never become permanent.
#   check-waivers.sh [file]   (default .github/trivy-waivers.json)
set -eu
cd "$(dirname "$0")/../.."
f="${1:-.github/trivy-waivers.json}"
[ -f "$f" ] || { echo "waiver file $f missing" >&2; exit 1; }
now=$(date -u +%Y-%m-%d)
max=$(date -u -d '+90 days' +%Y-%m-%d 2>/dev/null || date -u -v+90d +%Y-%m-%d)
jq -e 'type == "object" and ((.vulnerabilities // []) | type == "array")' "$f" >/dev/null || { echo "$f: malformed" >&2; exit 1; }
bad=$(jq -r --arg now "$now" --arg max "$max" '
	(.vulnerabilities // [])[] |
	select(
		((.id // "") | test("^(CVE-[0-9]{4}-[0-9]{4,}|GHSA-[0-9a-z-]+)$") | not) or
		((.statement // "") | length < 10) or
		((.expired_at // "") | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$") | not) or
		((.expired_at // "") <= $now) or
		((.expired_at // "") > $max)
	) | (.id // "<no id>")' "$f")
if [ -n "$bad" ]; then
	echo "invalid or expired waivers (need id, statement, expired_at in (today, +90d]):" >&2
	echo "$bad" >&2
	exit 1
fi
echo "waivers ok: $(jq '(.vulnerabilities // []) | length' "$f") active"
