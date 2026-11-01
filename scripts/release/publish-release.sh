#!/bin/sh
# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
#
# Creates a GitHub release in the public releases repository (the source
# repository is private). The tag there points at the releases repository's
# main branch; with --install-sh, install.sh is first synchronised onto main,
# so raw.githubusercontent.com/<releases>/<tag>/install.sh is the installer
# that shipped with that release. Published releases are never replaced.
#   publish-release.sh [--install-sh FILE] <tag> <title> <notes-file> [asset...]
#   needs: RELEASES_REPO, RELEASES_TOKEN (also used as GH_TOKEN), gh, git
set -eu
die() { echo "publish-release: $*" >&2; exit 1; }
install_sh=""
if [ "${1:-}" = --install-sh ]; then install_sh="${2:?file}"; shift 2; fi
tag="${1:?tag}" title="${2:?title}" notes="${3:?notes file}"; shift 3
[ -f "$notes" ] || die "notes file $notes not found"
for a in "$@"; do [ -f "$a" ] || die "asset $a not found"; done
here=$(cd "$(dirname "$0")" && pwd)
. "$here/releases-auth.sh"
export GH_TOKEN="$RELEASES_TOKEN"

if out=$(gh release view "$tag" --repo "$RELEASES_REPO" --json tagName 2>&1); then
	die "$tag is already released in $RELEASES_REPO; published versions are never replaced"
fi
echo "$out" | grep -qi "release not found" || die "cannot determine whether $tag is released: $out"

wt=$(mktemp -d)
trap 'rm -rf "$wt"' EXIT INT TERM
git clone --quiet --depth 1 --branch main "$RELEASES_URL" "$wt/r" || die "cannot clone main of $RELEASES_REPO"
if [ -n "$install_sh" ]; then
	cp "$install_sh" "$wt/r/install.sh"
	git -C "$wt/r" add install.sh
	if ! git -C "$wt/r" diff --cached --quiet; then
		git -C "$wt/r" -c user.name="truesignal-release[bot]" -c user.email="noreply@users.noreply.github.com" \
			commit --quiet -m "install.sh from $tag"
		git -C "$wt/r" push --quiet origin HEAD:refs/heads/main || die "cannot push install.sh to $RELEASES_REPO main"
	fi
fi
target=$(git -C "$wt/r" rev-parse HEAD)

pre=""; case "$tag" in *-*) pre="--prerelease" ;; esac  # SemVer pre-release -> GitHub pre-release
gh release create "$tag" --repo "$RELEASES_REPO" --target "$target" $pre \
	--title "$title" --notes-file "$notes" "$@"
# Read it back: the release must list every asset.
n=$(gh release view "$tag" --repo "$RELEASES_REPO" --json assets --jq '.assets | length')
[ "$n" -eq $# ] || die "$tag lists $n assets, expected $#"
echo "publish-release: $tag released in $RELEASES_REPO at $target ($n assets)"
