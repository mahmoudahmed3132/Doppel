#!/bin/sh
# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
#
# One-off migration of the public artefacts from the (now private) source
# repository to the public releases repository. Run by the owner from a clone
# of the source repository, logged in with `gh` (access to both repositories)
# and `gh auth setup-git` done. Idempotent: what is already there and
# identical is skipped; anything that differs stops the script.
#   1. registry branch copied unchanged (same commits, same signed files);
#   2. every existing release (cli/v*, hub/v*) recreated with the same tag
#      name, title, notes, pre-release flag and byte-identical assets;
#      install.sh is put on the releases repository's main first;
#   3. everything is read back anonymously and compared.
# Signatures are untouched: they keep naming the source repository's
# workflows, which is what the Hub, install.sh and cosign verify.
#   migrate-releases-repo.sh [releases-repo] [source-repo]
set -eu
dst="${1:-mahmoudahmed3132/truesignal-releases}"
src="${2:-mahmoudahmed3132/TrueSignal-Rewrite}"
here=$(cd "$(dirname "$0")" && pwd)
die() { echo "migrate: $*" >&2; exit 1; }
for t in gh git curl jq; do command -v "$t" >/dev/null || die "$t is required"; done
[ "$(gh repo view "$dst" --json visibility --jq .visibility)" = PUBLIC ] || die "$dst must exist and be public"
git ls-remote --exit-code --heads "https://github.com/$dst.git" refs/heads/main >/dev/null ||
	die "$dst has no main branch: create it with an initial commit (README) first"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT INT TERM

echo "== registry branch"
git fetch --quiet --no-tags origin +refs/heads/registry:refs/remotes/origin/registry
want=$(git rev-parse refs/remotes/origin/registry)
have=$(git ls-remote "https://github.com/$dst.git" refs/heads/registry | cut -f1)
if [ -z "$have" ]; then
	git push --quiet "https://github.com/$dst.git" "$want:refs/heads/registry"
	echo "registry pushed at $want"
elif [ "$have" = "$want" ]; then
	echo "registry already at $want"
else
	die "$dst registry is at $have, source at $want: reconcile by hand (never force-push the registry)"
fi

echo "== releases"
RELEASES_REPO="$dst" RELEASES_TOKEN=$(gh auth token); export RELEASES_REPO RELEASES_TOKEN
gh release list --repo "$src" --limit 100 --json tagName --jq '.[].tagName' | sort > "$T/tags"
while read -r tag; do
	case "$tag" in cli/v* | hub/v*) ;; *) echo "skip $tag (not a product release)"; continue ;; esac
	d="$T/$(echo "$tag" | tr / _)"; mkdir -p "$d/a"
	gh release download "$tag" --repo "$src" --dir "$d/a"
	(cd "$d/a" && find . -type f | sed 's|^\./||' | sort | xargs -r sha256sum) > "$d/sums"
	if gh release view "$tag" --repo "$dst" --json tagName >/dev/null 2>&1; then
		mkdir -p "$d/b"; gh release download "$tag" --repo "$dst" --dir "$d/b"
		(cd "$d/b" && find . -type f | sed 's|^\./||' | sort | xargs -r sha256sum) | cmp -s - "$d/sums" ||
			die "$tag exists in $dst with different assets"
		echo "$tag already released, assets identical"; continue
	fi
	gh release view "$tag" --repo "$src" --json name,body --jq .name > "$d/title"
	# Install snippets pointed at the private repository; point them here.
	gh release view "$tag" --repo "$src" --json body --jq .body |
		sed "s|raw.githubusercontent.com/$src/|raw.githubusercontent.com/$dst/|g" > "$d/notes.md"
	set --; for f in $(cut -d' ' -f3 "$d/sums"); do set -- "$@" "$d/a/$f"; done
	case "$tag" in
	cli/v*) "$here/publish-release.sh" --install-sh "$here/../../install.sh" "$tag" "$(cat "$d/title")" "$d/notes.md" "$@" ;;
	*) "$here/publish-release.sh" "$tag" "$(cat "$d/title")" "$d/notes.md" "$@" ;;
	esac
done < "$T/tags"

echo "== anonymous read-back"
git show refs/remotes/origin/registry:index.json > "$T/idx"
curl -fsS "https://raw.githubusercontent.com/$dst/registry/index.json" -o "$T/idx.pub" ||
	die "index.json is not readable anonymously (raw can lag a few minutes after the push: re-run)"
cmp -s "$T/idx" "$T/idx.pub" || die "index.json served anonymously differs from the source registry"
echo "index.json: identical"
while read -r tag; do
	d="$T/$(echo "$tag" | tr / _)"; [ -f "$d/sums" ] || continue
	while read -r sum f; do
		got=$(curl -fsSL "https://github.com/$dst/releases/download/$tag/$f" | sha256sum | cut -d' ' -f1)
		[ "$got" = "$sum" ] || die "$tag/$f served anonymously has sha256 $got, want $sum"
	done < "$d/sums"
	echo "$tag: all assets identical anonymously"
done < "$T/tags"
curl -fsS "https://api.github.com/repos/$dst/releases?per_page=100" | jq -r '.[].tag_name' | sort | sed 's/^/public release: /'
echo "migrate: done. Next: rulesets on $dst (docs/operations.md §9.1)."
