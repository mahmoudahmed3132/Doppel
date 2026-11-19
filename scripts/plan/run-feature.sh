#!/bin/sh
# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
#
# Start one feature from docs/plan/prompts in Claude Code.
#   run-feature.sh F-001            new git worktree ../Doppel-wt/F-001 on origin/main, then `claude "<prompt>"`
#   run-feature.sh F-001 --copy     copy the prompt to the clipboard (Claude Code web/desktop)
#   run-feature.sh F-001 --print    print the prompt
#   run-feature.sh --list           list prompts in run order
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DIR="$ROOT/docs/plan/prompts"

if [ "${1:-}" = "--list" ] || [ $# -eq 0 ]; then
	grep -E '^## Wave|^\| \[F-' "$DIR/00-INDEX.md" | sed -E 's/^\| \[([^]]+)\]\([^)]*\) \| ([^|]*)\|.*/  \1  \2/'
	exit 0
fi

ID=$(echo "$1" | tr '[:lower:]' '[:upper:]')
MODE=${2:-run}
PROMPT=$(ls "$DIR"/"$ID"-*.txt 2>/dev/null | head -n 1 || true)
[ -n "$PROMPT" ] || { echo "no prompt for $ID (try --list)" >&2; exit 1; }

case "$MODE" in
--print) cat "$PROMPT" ;;
--copy)
	if command -v pbcopy >/dev/null 2>&1; then pbcopy < "$PROMPT"
	elif command -v wl-copy >/dev/null 2>&1; then wl-copy < "$PROMPT"
	elif command -v xclip >/dev/null 2>&1; then xclip -selection clipboard < "$PROMPT"
	else echo "no clipboard tool; use --print" >&2; exit 1; fi
	echo "copied $(basename "$PROMPT") to the clipboard"
	;;
run)
	command -v claude >/dev/null 2>&1 || { echo "Claude Code CLI not found; use --copy" >&2; exit 1; }
	WT="$ROOT/../Doppel-wt/$ID"
	git -C "$ROOT" fetch -q origin
	if [ ! -d "$WT" ]; then
		# Detached at origin/main; the prompt itself creates the feature branch.
		git -C "$ROOT" worktree add -q --detach "$WT" origin/main
	fi
	echo "worktree: $WT"
	cd "$WT" && exec claude "$(cat "$PROMPT")"
	;;
*) echo "unknown option $MODE" >&2; exit 1 ;;
esac
