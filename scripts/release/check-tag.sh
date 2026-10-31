#!/bin/sh
# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
#
# Publish guard (§10), part 1: parses a release tag, checks it is SemVer,
# that it equals the version in code/manifest, and that the tagged commit is
# on the default branch. Prints component=…, name=…, version=… lines (append
# to $GITHUB_OUTPUT). The "already published" check is component-specific
# and done by the workflow.
#   check-tag.sh <tag> [default-branch]
set -eu
tag="${1:?tag}"
default="${2:-}"
die() { echo "check-tag: $*" >&2; exit 1; }
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'
here="$(dirname "$0")"

case "$tag" in
hub/v*) component=hub name=hub version="${tag#hub/v}" ;;
cli/v*) component=cli name=cli version="${tag#cli/v}" ;;
sensor/*/v*)
	component=sensor
	rest="${tag#sensor/}"
	name="${rest%%/*}"
	version="${rest#*/v}"
	[ "sensor/$name/v$version" = "$tag" ] || die "malformed sensor tag $tag"
	echo "$name" | grep -Eq '^[a-z0-9]+(-[a-z0-9]+)*$' || die "invalid sensor name '$name'"
	;;
*) die "unrecognised tag $tag (want hub/vX.Y.Z, cli/vX.Y.Z or sensor/<name>/vX.Y.Z)" ;;
esac
echo "$version" | grep -Eq "$semver" || die "version '$version' is not SemVer"
# Hubs verify sensor manifests only for plain X.Y.Z versions (signing module,
# PORTED step 1): a pre-release sensor would publish a manifest no Hub accepts.
if [ "$component" = sensor ]; then
	echo "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || die "sensor versions must be plain X.Y.Z (Hubs refuse pre-release sensor manifests)"
fi

if [ "$component" = sensor ]; then
	code=$("$here/component-version.sh" sensor "$name") || die "sensor $name not found"
	m="sensors/$name/manifest.json"
	[ "$(jq -r .name "$m")" = "$name" ] || die "$m name is not $name"
	[ "$(jq -r .image.tag "$m")" = "$version" ] || die "$m image.tag must equal $version"
	[ -f "sensors/$name/Dockerfile" ] || die "sensors/$name/Dockerfile missing"
else
	code=$("$here/component-version.sh" "$component")
fi
[ "$code" = "$version" ] || die "tag $tag does not match the version in code ($code)"

if [ -n "$default" ]; then
	git fetch --quiet --no-tags origin "refs/heads/$default:refs/remotes/origin/$default" 2>/dev/null || true
	git merge-base --is-ancestor "$(git rev-parse "$tag^{commit}")" "refs/remotes/origin/$default" ||
		die "tag $tag points to a commit that is not on $default; release only reviewed code"
fi
printf 'component=%s\nname=%s\nversion=%s\n' "$component" "$name" "$version"
