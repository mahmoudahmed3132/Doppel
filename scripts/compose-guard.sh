#!/bin/sh
# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
#
# §10 compose guard: production compose files must never build images
# locally (no "build:" key); every image comes from the registry, pinned.
# Checks every compose file tracked in the repository outside test fixtures.
set -eu
status=0
files=$(git ls-files --cached --others --exclude-standard | grep -E '(^|/)(docker-)?compose[^/]*\.ya?ml$' | grep -vE '(^|/)(testdata|e2e)/' || true)
for f in $files; do
	if grep -nE '^[[:space:]]*build[[:space:]]*:' "$f"; then
		echo "compose-guard: $f contains build:" >&2
		status=1
	fi
	if grep -nE '^[[:space:]]*image[[:space:]]*:' "$f" | grep -vE '@sha256:' >/dev/null; then
		echo "compose-guard: $f has an image without @sha256 digest" >&2
		status=1
	fi
done
[ -n "$files" ] && echo "compose-guard: checked $(echo "$files" | wc -l) file(s)"
exit $status
