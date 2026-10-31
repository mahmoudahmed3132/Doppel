# Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
#
# Build from the repository root:
#   docker build -f sensors/icmp-canary/Dockerfile -t ts-sensor-icmp-canary .
# Base images are pinned by digest; bump them deliberately.

FROM golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS build
WORKDIR /src
COPY sdk/go/ sdk/go/
COPY sensors/icmp-canary/ sensors/icmp-canary/
WORKDIR /src/sensors/icmp-canary
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOWORK=off
RUN go build -ldflags='-s -w -buildid=' -o /out/sensor .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/sensor /sensor
USER 65532:65532
ENTRYPOINT ["/sensor"]
