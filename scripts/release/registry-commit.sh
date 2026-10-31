#!/bin/sh
# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
#
# Applies a change to the registry branch and pushes it, retrying on
# conflict (§10: concurrent sensor publishes). Each attempt starts from the
# current remote branch in a fresh worktree, so a lost race is re-applied on
# top of the winner's commit, never merged blindly.
#   registry-commit.sh <message> <command> [args...]
# <command> runs inside the worktree (cwd) and must be idempotent per attempt.
# REGISTRY_REMOTE (default: origin) is the remote name or URL that holds the
# branch; publishing uses the public releases repository's URL.
set -eu
msg="${1:?message}"; shift
[ $# -gt 0 ] || { echo "registry-commit: no command" >&2; exit 2; }
root=$(git rev-parse --show-toplevel)
wt="$root/.registry-worktree"
branch=registry
remote="${REGISTRY_REMOTE:-origin}"
track="refs/remotes/registry-remote/$branch"
attempt=1
max=8
while :; do
	git -C "$root" worktree remove --force "$wt" 2>/dev/null || rm -rf "$wt"
	git -C "$root" worktree prune
	git -C "$root" branch -D registry-new >/dev/null 2>&1 || true  # left by an earlier branch creation
	# Create the branch only when the remote answers and lacks it (exit 2);
	# an unreachable or unauthorised remote must fail, not start a new history.
	set +e; git -C "$root" ls-remote --exit-code --heads "$remote" "refs/heads/$branch" >/dev/null; rc=$?; set -e
	if [ "$rc" -eq 0 ]; then
		git -C "$root" fetch --quiet --no-tags "$remote" "+refs/heads/$branch:$track"
		git -C "$root" worktree add --quiet --detach "$wt" "$track"
	elif [ "$rc" -ne 2 ]; then
		echo "registry-commit: cannot read $branch from the registry remote (git exit $rc)" >&2
		exit 1
	else
		echo "registry-commit: creating the $branch branch"
		git -C "$root" worktree add --quiet --detach "$wt" HEAD
		git -C "$wt" switch --quiet --orphan "registry-new"
		git -C "$wt" rm -rq --cached . 2>/dev/null || true
		find "$wt" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
	fi
	(cd "$wt" && "$@")
	git -C "$wt" add -A
	if git -C "$wt" diff --cached --quiet; then
		echo "registry-commit: nothing to commit"
		break
	fi
	git -C "$wt" -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
		commit --quiet -m "$msg"
	if git -C "$wt" push --quiet "$remote" "HEAD:refs/heads/$branch"; then
		echo "registry-commit: pushed ($msg) on attempt $attempt"
		break
	fi
	[ "$attempt" -lt "$max" ] || { echo "registry-commit: giving up after $max attempts" >&2; exit 1; }
	delay=$(( (attempt * 3) + $(od -An -N1 -tu1 /dev/urandom | tr -d ' ') % 5 ))
	echo "registry-commit: push rejected (concurrent publish?); retrying in ${delay}s" >&2
	sleep "$delay"
	attempt=$((attempt + 1))
done
git -C "$root" worktree remove --force "$wt" 2>/dev/null || true
