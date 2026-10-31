#!/bin/sh
# Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
#
# Runs inside a registry-branch worktree (via registry-commit.sh): adds one
# signed, pinned manifest and regenerates index.json. Refuses a version that
# is already present, so a published version is never replaced.
#   registry-add.sh <ts-registry> <name> <version> <dir with manifest.json + bundle>
set -eu
tool="${1:?}"; name="${2:?}"; version="${3:?}"; src="${4:?}"
if "$tool" published -dir . -name "$name" -version "$version"; then
	echo "registry-add: refusing to replace a published version" >&2
	exit 1
fi
dst="sensors/$name/$version"
mkdir -p "$dst"
cp "$src/manifest.json" "$src/manifest.json.sigstore.json" "$dst/"
"$tool" index -dir .
