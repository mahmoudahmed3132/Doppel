#!/bin/sh
# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
#
# Sourced (". scripts/release/releases-auth.sh") by publish steps that write
# to the public releases repository. Exposes RELEASES_TOKEN (a GitHub App
# installation token scoped to that one repository, contents:write) to git
# through environment-only configuration: the token never appears in a
# command line, a remote URL or .git/config, and is masked in the log.
#   needs: RELEASES_TOKEN, RELEASES_REPO (owner/name)
: "${RELEASES_TOKEN:?RELEASES_TOKEN is not set}"
: "${RELEASES_REPO:?RELEASES_REPO is not set}"
_ts_basic=$(printf 'x-access-token:%s' "$RELEASES_TOKEN" | base64 | tr -d '\n')
[ -z "${GITHUB_ACTIONS:-}" ] || echo "::add-mask::$_ts_basic"
GIT_CONFIG_COUNT=1
GIT_CONFIG_KEY_0="http.https://github.com/$RELEASES_REPO.git/.extraheader"
GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $_ts_basic"
RELEASES_URL="https://github.com/$RELEASES_REPO.git"
[ -z "${TS_SELFTEST_RELEASES_GIT_URL:-}" ] || RELEASES_URL="$TS_SELFTEST_RELEASES_GIT_URL"  # selftest.sh only
export GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0 RELEASES_URL
unset _ts_basic
