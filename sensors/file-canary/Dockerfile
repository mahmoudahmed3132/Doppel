# Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
#
# Build from the repository root:
#   docker build -f sensors/file-canary/Dockerfile -t truesignal-sensor-file-canary .
# Base images are pinned by digest; bump them deliberately.

FROM golang:1.26.2-bookworm@sha256:47ce5636e9936b2c5cbf708925578ef386b4f8872aec74a67bd13a627d242b19 AS build
WORKDIR /src
COPY sdk/go/ sdk/go/
COPY sensors/file-canary/ sensors/file-canary/
WORKDIR /src/sensors/file-canary
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOWORK=off
RUN go build -ldflags='-s -w -buildid=' -o /out/sensor .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/sensor /sensor
USER 65532:65532
ENTRYPOINT ["/sensor"]
