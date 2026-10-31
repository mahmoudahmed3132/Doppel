#!/bin/sh
# Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
#
# Points :latest at the highest published AND signature-verified Hub release
# (§10). The existing manifest is tagged unchanged (same digest), then
# :latest is re-resolved and must equal that digest. Pre-releases are never
# candidates. Needs crane, cosign and registry credentials.
#   hub-latest.sh <image> <owner/repo>
set -eu
image="${1:?image}"; repo="${2:?owner/repo}"
issuer=https://token.actions.githubusercontent.com
die() { echo "hub-latest: $*" >&2; exit 1; }

target="" digest=""
for v in $(git tag --list 'hub/v*' | sed 's|^hub/v||' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -t. -k1,1nr -k2,2nr -k3,3nr); do
	d=$(crane digest "$image:$v" 2>/dev/null) || { echo "hub-latest: $v not published, skipped"; continue; }
	if cosign verify "$image@$d" \
		--certificate-identity "https://github.com/$repo/.github/workflows/publish-hub.yml@refs/tags/hub/v$v" \
		--certificate-oidc-issuer "$issuer" >/dev/null 2>&1; then
		target=$v digest=$d
		break
	fi
	echo "hub-latest: $v ($d) signature does not verify, skipped" >&2
done
[ -n "$target" ] || die "no published, signature-verified Hub release found"

current=$(crane digest "$image:latest" 2>/dev/null || true)
if [ "$current" = "$digest" ]; then
	echo "hub-latest: :latest already at $target ($digest)"
else
	crane tag "$image@$digest" latest
fi
got=$(crane digest "$image:latest")
[ "$got" = "$digest" ] || die ":latest resolves to $got, expected $digest ($target)"
echo "hub-latest: :latest -> $target ($digest)"
