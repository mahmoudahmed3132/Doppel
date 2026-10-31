#!/bin/sh
# Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
#
# Fails if a source file lacks the licence header required by spec §0.8.
set -eu
HEADER='Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.'
status=0
for f in $(git ls-files --cached --others --exclude-standard \
	'*.go' '*.ts' '*.tsx' '*.js' '*.sh' '*.py' '*.css' 'Dockerfile' '**/Dockerfile' 'Makefile'); do
	[ -f "$f" ] || continue
	if ! head -n 3 "$f" | grep -qF "$HEADER"; then
		echo "missing licence header: $f"
		status=1
	fi
done
exit $status
