#!/bin/sh
# Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
#
# Self-test of the §10 publish guards and registry tooling, run in CI
# (acceptance §14.13). Uses a throwaway clone with a local bare "origin" and
# stub crane/cosign; nothing leaves the machine.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0
pass() { echo "ok   $*"; }
fail() { echo "FAIL $*"; fails=$((fails + 1)); }
expect_fail() { name=$1; shift; if "$@" >/dev/null 2>&1; then fail "$name accepted"; else pass "$name refused"; fi; }

(cd "$root/hub" && go build -o "$T/ts-registry" ./cmd/ts-registry)

# A clone whose HEAD is on origin's default branch.
git init -q --bare "$T/origin.git"
git clone -q "$root" "$T/w"
cd "$T/w"
rsync -a --exclude .git --exclude node_modules "$root/" ./ 2>/dev/null || cp -R "$root/scripts" "$root/Makefile" ./
git add -A && git -c user.name=t -c user.email=t@t commit -q --allow-empty -m test
git remote set-url origin "$T/origin.git"
git push -q origin HEAD:refs/heads/main 2>/dev/null
git remote set-head origin main
git tag -l | xargs -r git tag -d >/dev/null

hubv=$(scripts/release/component-version.sh hub)
cliv=$(scripts/release/component-version.sh cli)
tv=$(scripts/release/component-version.sh sensor tcp-tarpit)

# --- tag guard -------------------------------------------------------------
git tag "hub/v$hubv"; git tag "cli/v$cliv"; git tag "sensor/tcp-tarpit/v$tv"
scripts/release/check-tag.sh "hub/v$hubv" main >/dev/null && pass "hub tag matching code" || fail "hub tag matching code"
scripts/release/check-tag.sh "sensor/tcp-tarpit/v$tv" main >/dev/null && pass "sensor tag matching manifest" || fail "sensor tag"
git tag cli/v0.0.1; expect_fail "tag/version mismatch" scripts/release/check-tag.sh cli/v0.0.1 main
git tag hub/v1.0; expect_fail "non-SemVer tag" scripts/release/check-tag.sh hub/v1.0 main
expect_fail "unknown sensor" scripts/release/check-tag.sh sensor/nope/v1.0.0 main
expect_fail "malformed tag" scripts/release/check-tag.sh release-1 main
git switch -q -c side && git -c user.name=t -c user.email=t@t commit -q --allow-empty -m side
git tag -f "hub/v$hubv" >/dev/null
expect_fail "tag off the default branch" scripts/release/check-tag.sh "hub/v$hubv" main
git switch -q - && git tag -f "hub/v$hubv" >/dev/null

# --- registry: publish, race, immutability, rollback -------------------------
mk() { # name version -> pinned manifest + stub bundle in $T/out-<name>-<version>
	o="$T/out-$1-$2"; mkdir -p "$o"
	jq --arg v "$2" '.version=$v | .image.tag=$v' "sensors/$1/manifest.json" > "$o/src.json"
	"$T/ts-registry" fill -in "$o/src.json" -out "$o/manifest.json" -name "$1" -version "$2" \
		-repository "$(jq -r .image.repository "$o/src.json")" -tag "$2" -digest "sha256:$(printf '%064d' 1)"
	echo '{}' > "$o/manifest.json.sigstore.json"
}
add() { scripts/release/registry-commit.sh "registry: $1 $2" "$PWD/scripts/release/registry-add.sh" "$T/ts-registry" "$1" "$2" "$T/out-$1-$2"; }
mk tcp-tarpit 1.0.0; mk tcp-tarpit 1.1.0; mk icmp-canary 1.0.0
add tcp-tarpit 1.0.0 >/dev/null 2>&1 && pass "first publish creates the registry branch" || fail "first publish"
git clone -q "$T/origin.git" "$T/w2" 2>/dev/null; cp -R scripts "$T/w2/" 
( add tcp-tarpit 1.1.0 >/dev/null 2>&1 ) & a=$!
( cd "$T/w2" && add icmp-canary 1.0.0 >/dev/null 2>&1 ) & b=$!
wait $a && wait $b && pass "concurrent publishes both land" || fail "concurrent publishes"
latest=$(git --git-dir="$T/origin.git" show registry:index.json | jq -r '.sensors["tcp-tarpit"].latest + " " + .sensors["icmp-canary"].latest')
[ "$latest" = "1.1.0 1.0.0" ] && pass "index after race: $latest" || fail "index after race: $latest"
expect_fail "republishing a version" add tcp-tarpit 1.0.0
scripts/release/registry-commit.sh "rollback" "$T/ts-registry" deprecate -dir . -name tcp-tarpit >/dev/null 2>&1
l=$(git --git-dir="$T/origin.git" show registry:index.json | jq -r '.sensors["tcp-tarpit"] | .latest + " " + (.versions["1.1.0"].deprecated|tostring)')
[ "$l" = "1.0.0 true" ] && pass "rollback deprecates latest" || fail "rollback: $l"

# --- :latest selection --------------------------------------------------------
mkdir -p "$T/bin" "$T/reg"
cat > "$T/bin/crane" <<STUB
#!/bin/sh
case "\$1" in
digest) t=\${2##*:}; [ -f "$T/reg/\$t" ] && cat "$T/reg/\$t" || exit 1 ;;
tag) echo "\${2##*@}" > "$T/reg/\$3" ;;
esac
STUB
cat > "$T/bin/cosign" <<STUB
#!/bin/sh
grep -qx "\${2##*@}" "$T/reg/bad" 2>/dev/null && exit 1; exit 0
STUB
chmod +x "$T/bin/crane" "$T/bin/cosign"
git tag -l 'hub/v*' | xargs -r git tag -d >/dev/null
for v in 3.0.0 3.1.0 3.10.0 3.11.0 4.0.0-rc.1; do git tag "hub/v$v"; done
for v in 3.0.0 3.1.0 3.10.0 4.0.0-rc.1; do echo "sha256:$v" > "$T/reg/$v"; done
echo "sha256:3.10.0" > "$T/reg/bad"
PATH="$T/bin:$PATH" scripts/release/hub-latest.sh ghcr.io/x/ts-hub o/r >/dev/null 2>&1
[ "$(cat "$T/reg/latest")" = "sha256:3.1.0" ] && pass ":latest = highest published+verified, SemVer, no pre-release" || fail ":latest = $(cat "$T/reg/latest")"

# Stable tags exist but no image resolves (registry outage / failed publish): must fail.
rm -f "$T/reg/latest"
for v in 3.0.0 3.1.0 3.10.0; do rm -f "$T/reg/$v"; done
if PATH="$T/bin:$PATH" scripts/release/hub-latest.sh ghcr.io/x/ts-hub o/r >/dev/null 2>&1; then fail "unresolvable stable tags passed"; else pass "stable tags with no resolvable image fail the job"; fi
echo "sha256:3.0.0" > "$T/reg/3.0.0"; echo "sha256:3.0.0" > "$T/reg/bad"
if PATH="$T/bin:$PATH" scripts/release/hub-latest.sh ghcr.io/x/ts-hub o/r >/dev/null 2>&1; then fail "unverifiable stable release accepted"; else pass "stable release with a bad signature fails the job"; fi
# Only pre-release tags: :latest left unset, job succeeds.
git tag -l 'hub/v*' | grep -E '^hub/v[0-9]+\.[0-9]+\.[0-9]+$' | xargs -r git tag -d >/dev/null
PATH="$T/bin:$PATH" scripts/release/hub-latest.sh ghcr.io/x/ts-hub o/r >/dev/null 2>&1 && [ ! -f "$T/reg/latest" ] &&
	pass "only pre-release tags: :latest left unset, job succeeds" || fail "pre-release-only :latest handling"

echo
[ "$fails" -eq 0 ] && echo "release selftest: all passed" || { echo "release selftest: $fails failed"; exit 1; }
