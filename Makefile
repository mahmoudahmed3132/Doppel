# Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

GO_MODULES := $(shell sed -n 's/^\t\.\/\(.*\)$$/\1/p' go.work)
export CGO_ENABLED := 0

.PHONY: all vet test check-headers ui hub-bin

all: check-headers vet test

vet:
	@for m in $(GO_MODULES); do echo "== vet $$m"; (cd $$m && go vet ./...) || exit 1; done

test:
	@for m in $(GO_MODULES); do echo "== test $$m"; (cd $$m && CGO_ENABLED=1 go test -race -count=1 ./...) || exit 1; done

check-headers:
	@./scripts/check-headers.sh

# Admin UI: install pinned deps (no install scripts), type-check, safety lint,
# build into hub/internal/webui/dist (embedded by the Hub).
ui:
	cd ui && npm ci --ignore-scripts --no-audit --no-fund && npm run check

hub-bin: ui
	cd hub && go build -trimpath -ldflags "-s -w" -o ../bin/truesignal-hub ./cmd/truesignal-hub
