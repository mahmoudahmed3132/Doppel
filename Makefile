# Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

GO_MODULES := $(shell sed -n 's/^\t\.\/\(.*\)$$/\1/p' go.work)
export CGO_ENABLED := 0

.PHONY: all vet test check-headers

all: check-headers vet test

vet:
	@for m in $(GO_MODULES); do echo "== vet $$m"; (cd $$m && go vet ./...) || exit 1; done

test:
	@for m in $(GO_MODULES); do echo "== test $$m"; (cd $$m && CGO_ENABLED=1 go test -race -count=1 ./...) || exit 1; done

check-headers:
	@./scripts/check-headers.sh
