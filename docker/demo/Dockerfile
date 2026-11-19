# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
#
# Self-contained kill-chain demo: Hub + UI + 6 decoys + scripted attacker in
# one container, so the demo runs on any Docker host (macOS, Windows, Linux)
# with no local Go/Node/Python. Development image only; never deploy it.
#
#   docker build -f docker/demo/Dockerfile -t doppel-demo .
#   docker run --rm -it -p 127.0.0.1:18080:18080 doppel-demo           # UI on http://127.0.0.1:18080
#   docker run --rm doppel-demo --smoke                                 # assert and exit
#
# Base image pinned by digest; Node is pinned by version and SHA-256.

FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea
ARG TARGETARCH
ARG NODE_VERSION=22.23.5
ARG NODE_SHA256_AMD64=cdeb8670a0c81f51b4dc4ac61919f9b1ad917b304bf8221eb939570663d240f8
ARG NODE_SHA256_ARM64=2babb9eb5264860d540849f4b064a6fbdebcdc323657d9d382ce23d313fd5e09

RUN apt-get update -qq \
	&& apt-get install -y -qq --no-install-recommends python3 jq xz-utils \
	&& rm -rf /var/lib/apt/lists/*

RUN set -eu; \
	case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
		amd64) a=x64; sum="$NODE_SHA256_AMD64" ;; \
		arm64) a=arm64; sum="$NODE_SHA256_ARM64" ;; \
		*) echo "unsupported architecture" >&2; exit 1 ;; \
	esac; \
	curl -fsSL --proto '=https' -o /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${a}.tar.xz"; \
	echo "$sum  /tmp/node.tar.xz" | sha256sum -c -; \
	tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 --no-same-owner \
		--exclude='*/CHANGELOG.md' --exclude='*/README.md' --exclude='*/LICENSE'; \
	rm /tmp/node.tar.xz; \
	node --version

RUN useradd --create-home --uid 10001 demo && mkdir -p /src && chown -R demo /src /go
USER demo
ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src
COPY --chown=demo . .

# Build the UI once and warm the Go caches so container start is fast.
RUN cd ui && npm ci --ignore-scripts --no-audit --no-fund && npm run build
RUN for m in hub sensors/tcp-tarpit sensors/remote-access-decoy sensors/database-decoy \
		sensors/web-router-decoy sensors/file-canary sensors/token-receiver; do \
		(cd "$m" && go build -o /dev/null ./...) || exit 1; \
	done

ENV DEMO_LISTEN_HOST=0.0.0.0
EXPOSE 18080
ENTRYPOINT ["./scripts/demo/run-demo.sh"]
