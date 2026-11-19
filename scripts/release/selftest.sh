#!/bin/sh
# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
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
expect_fail "pre-release sensor tag" scripts/release/check-tag.sh sensor/tcp-tarpit/v1.0.0-rc.1 main
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

# Publishing to the separate public releases repository (REGISTRY_REMOTE, a URL).
git init -q --bare "$T/releases.git"
REGISTRY_REMOTE="$T/releases.git" add icmp-canary 1.0.0 >"$T/rr.log" 2>&1 && pass "publish to a REGISTRY_REMOTE URL" || { cat "$T/rr.log"; fail "publish to REGISTRY_REMOTE"; }
r=$(git --git-dir="$T/releases.git" show registry:index.json | jq -r '.sensors | keys | join(" ")')
[ "$r" = "icmp-canary" ] && pass "releases repository has only its own registry history" || fail "releases registry: $r"
expect_fail "unreachable registry remote (no new orphan history)" env REGISTRY_REMOTE="$T/missing.git" \
	scripts/release/registry-commit.sh "x" "$T/ts-registry" deprecate -dir . -name tcp-tarpit

# --- public release (publish-release.sh against a local "releases" repo) ----
git init -q --bare "$T/pub.git"
git clone -q "$T/pub.git" "$T/pubw" 2>/dev/null
git -C "$T/pubw" -c user.name=t -c user.email=t@t commit -q --allow-empty -m init
git -C "$T/pubw" push -q origin HEAD:refs/heads/main 2>/dev/null
mkdir -p "$T/ghbin"; : > "$T/gh.log"
cat > "$T/ghbin/gh" <<STUB
#!/bin/sh
echo "\$*" >> "$T/gh.log"
case "\$1 \$2" in
"release view") t=\$3; f="$T/rel-\$(echo "\$t" | tr / _)"
	[ -f "\$f" ] || { echo "release not found" >&2; exit 1; }
	case "\$*" in *assets*) cat "\$f" ;; *) echo "{}" ;; esac ;;
"release create") t=\$3; n=0; for a in "\$@"; do [ -f "\$a" ] && case "\$a" in *.md) ;; *) n=\$((n+1)) ;; esac; done
	echo "\$n" > "$T/rel-\$(echo "\$t" | tr / _)" ;;
esac
STUB
chmod +x "$T/ghbin/gh"
echo notes > "$T/notes.md"; echo bin > "$T/asset1"
pr() { PATH="$T/ghbin:$PATH" RELEASES_REPO=o/pub RELEASES_TOKEN=x TS_SELFTEST_RELEASES_GIT_URL="$T/pub.git" scripts/release/publish-release.sh "$@"; }
pr --install-sh install.sh cli/v9.0.0 "CLI v9.0.0" "$T/notes.md" "$T/asset1" >/dev/null 2>&1 && pass "CLI release published to the releases repository" || fail "CLI release"
git --git-dir="$T/pub.git" show main:install.sh | cmp -s - install.sh && pass "install.sh synchronised onto releases main" || fail "install.sh not on releases main"
grep "release create cli/v9.0.0" "$T/gh.log" | grep -q -- "--target $(git --git-dir="$T/pub.git" rev-parse main)" && pass "release tag targets the commit carrying install.sh" || fail "release target"
grep "release create cli/v9.0.0" "$T/gh.log" | grep -q -- --prerelease && fail "stable release marked pre-release" || pass "stable release not marked pre-release"
expect_fail "re-releasing a published version" pr cli/v9.0.0 "CLI v9.0.0" "$T/notes.md" "$T/asset1"
pr hub/v9.1.0-rc.1 "Hub v9.1.0-rc.1" "$T/notes.md" >/dev/null 2>&1 && grep "release create hub/v9.1.0-rc.1" "$T/gh.log" | grep -q -- --prerelease &&
	pass "SemVer pre-release published as a GitHub pre-release" || fail "pre-release flag"

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

# --- supply-chain gates (F-004) ---------------------------------------------
w="$T/waivers"; mkdir -p "$w"
today=$(date -u +%Y-%m-%d); soon=$(date -u -d '+30 days' +%Y-%m-%d 2>/dev/null || date -u -v+30d +%Y-%m-%d)
past=$(date -u -d '-1 day' +%Y-%m-%d 2>/dev/null || date -u -v-1d +%Y-%m-%d)
far=$(date -u -d '+400 days' +%Y-%m-%d 2>/dev/null || date -u -v+400d +%Y-%m-%d)
wv() { printf '{"vulnerabilities":[{"id":"%s","statement":"%s","expired_at":"%s"}]}' "$1" "$2" "$3" > "$w/$4"; }
scripts/release/check-waivers.sh .github/trivy-waivers.json >/dev/null && pass "shipped waiver file is valid" || fail "shipped waiver file"
wv CVE-2099-0001 "no fix upstream, compensating control documented" "$soon" good.json
scripts/release/check-waivers.sh "$w/good.json" >/dev/null && pass "unexpired waiver with statement accepted" || fail "valid waiver"
wv CVE-2099-0001 "no fix upstream, compensating control documented" "$past" expired.json; expect_fail "expired waiver" scripts/release/check-waivers.sh "$w/expired.json"
wv CVE-2099-0001 "no fix upstream, compensating control documented" "$far" long.json; expect_fail "waiver longer than 90 days" scripts/release/check-waivers.sh "$w/long.json"
wv CVE-2099-0001 "short" "$soon" nostmt.json; expect_fail "waiver without a real statement" scripts/release/check-waivers.sh "$w/nostmt.json"
wv "not-an-id" "no fix upstream, compensating control documented" "$soon" badid.json; expect_fail "waiver with a malformed id" scripts/release/check-waivers.sh "$w/badid.json"
echo '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"x"}]}' > "$w/ok.cdx.json"
scripts/release/sbom.sh verify "$w/ok.cdx.json" && pass "CycloneDX SBOM accepted" || fail "CycloneDX SBOM"
echo '{"bomFormat":"SPDX","components":[{"name":"x"}]}' > "$w/spdx.json"; expect_fail "non-CycloneDX SBOM" scripts/release/sbom.sh verify "$w/spdx.json"
echo '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}' > "$w/empty.cdx.json"; expect_fail "empty SBOM" scripts/release/sbom.sh verify "$w/empty.cdx.json"
GOTOOLCHAIN=local scripts/check-go-version.sh "99.0.0" >/dev/null 2>&1 && fail "Go version pin mismatch accepted" || pass "Go version pin mismatch refused"

echo
[ "$fails" -eq 0 ] && echo "release selftest: all passed" || { echo "release selftest: $fails failed"; exit 1; }
