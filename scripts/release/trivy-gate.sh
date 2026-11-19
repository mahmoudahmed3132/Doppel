#!/bin/sh
# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
#
# Release gate (F-004): fails on ANY critical vulnerability that is not
# covered by a valid, unexpired waiver, fixable or not. Waivers live in
# .github/trivy-waivers.json and are validated first.
#   trivy-gate.sh image <ref> | rootfs <dir>
set -eu
cd "$(dirname "$0")/../.."
mode="${1:?image|rootfs}"; target="${2:?target}"
case "$mode" in image | rootfs) ;; *) echo "usage: trivy-gate.sh image|rootfs <target>" >&2; exit 2 ;; esac
scripts/release/check-waivers.sh .github/trivy-waivers.json
exec trivy "$mode" --quiet --scanners vuln --severity CRITICAL --exit-code 1 \
	--ignorefile .github/trivy-waivers.json "$target"
