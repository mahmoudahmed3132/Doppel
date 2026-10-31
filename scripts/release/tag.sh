#!/bin/sh
# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
#
# Creates the release tag for a component from the version in code and pushes
# it ALONE (GitHub does not trigger workflows for pushes carrying more than
# three tags, §10). Refuses a dirty tree, a commit not on origin's default
# branch, or an existing tag (tags are immutable).
#   tag.sh hub | cli | sensor <name> [--skip-existing]
set -eu
here="$(dirname "$0")"
comp="${1:?hub|cli|sensor}"
name="" skip=""
case "$comp" in
sensor) name="${2:?sensor name}"; [ "${3:-}" = --skip-existing ] && skip=1 ;;
hub | cli) [ "${2:-}" = --skip-existing ] && skip=1 ;;
*) echo "usage: tag.sh hub|cli|sensor <name> [--skip-existing]" >&2; exit 2 ;;
esac
version=$("$here/component-version.sh" "$comp" $name)
case "$comp" in
sensor) tag="sensor/$name/v$version" ;;
*) tag="$comp/v$version" ;;
esac
die() { echo "tag: $*" >&2; exit 1; }

[ -z "$(git status --porcelain)" ] || die "working tree is not clean"
git fetch --quiet --tags origin
default=$(git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null | sed 's|^origin/||')
[ -n "$default" ] || die "cannot determine origin's default branch (git remote set-head origin --auto)"
git fetch --quiet origin "$default"
git merge-base --is-ancestor HEAD "refs/remotes/origin/$default" || die "HEAD is not on origin/$default"
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
	[ -n "$skip" ] && { echo "tag: $tag exists, skipped"; exit 0; }
	die "$tag already exists (tags are immutable; bump the version)"
fi
git tag -a "$tag" -m "$tag"
"$here/check-tag.sh" "$tag" >/dev/null || { git tag -d "$tag" >/dev/null; die "tag check failed"; }
git push origin "refs/tags/$tag"
echo "tag: pushed $tag"
