# Copyright (c) 2026 TrueSignal Deception. All rights reserved.

GO_MODULES := $(shell sed -n 's/^[[:space:]]*\.\/\(.*\)$$/\1/p' go.work)
export CGO_ENABLED := 0

.PHONY: all fmt vet test check-headers ui hub-bin demo demo-docker tag-hub tag-cli tag-sensor tag-sensors

all: check-headers fmt vet test

fmt:
	@out=$$(gofmt -l $(GO_MODULES)); [ -z "$$out" ] || { echo "gofmt needed:"; echo "$$out"; exit 1; }

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
	cd hub && go build -trimpath -ldflags "-s -w" -o ../bin/doppel-hub ./cmd/doppel-hub
	ln -sf doppel-hub bin/truesignal-hub  # compatibility symlink, one major version

# Kill-chain demo natively (Linux or macOS) or fully inside Docker (any OS).
demo:
	./scripts/demo/run-demo.sh

demo-docker:
	docker build -f docker/demo/Dockerfile -t doppel-demo .
	docker run --rm -it -p 127.0.0.1:18080:18080 doppel-demo

# Release tags (§10): version read from code/manifest, one tag per push.
#   make tag-hub | make tag-cli | make tag-sensor NAME=tcp-tarpit | make tag-sensors
tag-hub:
	@./scripts/release/tag.sh hub

tag-cli:
	@./scripts/release/tag.sh cli

tag-sensor:
	@test -n "$(NAME)" || { echo "NAME=<sensor> required"; exit 2; }
	@./scripts/release/tag.sh sensor $(NAME)

# Tags every sensor whose current manifest version is not tagged yet, each in
# its own push.
tag-sensors:
	@for d in sensors/*/manifest.json; do n=$$(basename $$(dirname $$d)); [ "$$n" = template ] && continue; \
		./scripts/release/tag.sh sensor $$n --skip-existing || exit 1; done
