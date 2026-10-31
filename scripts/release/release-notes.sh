#!/bin/sh
# Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
#
# Release notes against the previous tag of the SAME component (§10), limited
# to the paths that make up that component.
#   release-notes.sh <tag>
set -eu
tag="${1:?tag}"
case "$tag" in
hub/v*) prefix=hub/v paths="hub ui sdk/go" title="TrueSignal Hub" ;;
cli/v*) prefix=cli/v paths="cli install.sh" title="TrueSignal node CLI" ;;
sensor/*/v*) n="${tag#sensor/}"; n="${n%%/*}"; prefix="sensor/$n/v" paths="sensors/$n sdk/go" title="Sensor $n" ;;
*) echo "unrecognised tag $tag" >&2; exit 2 ;;
esac
version="${tag#"$prefix"}"
# Highest earlier SemVer tag of this component (release tags only).
prev=$(git tag --list "${prefix}*" | sed "s|^${prefix}||" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' |
	{ cat; echo "$version"; } | sort -t. -k1,1n -k2,2n -k3,3n -u | awk -v v="$version" '$0 == v {print p; exit} {p = $0}')
echo "## $title $version"
echo
if [ -n "$prev" ]; then
	echo "Changes since ${prefix}${prev}:"
	range="${prefix}${prev}..${tag}"
else
	echo "First release of this component."
	range="$tag"
fi
echo
# shellcheck disable=SC2086
git log --no-merges --pretty='- %s (%h)' "$range" -- $paths | head -n 300
