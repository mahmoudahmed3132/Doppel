# Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
#
# Build from the repository root:
#   docker build -f sensors/tcp-tarpit/Dockerfile -t ts-sensor-tcp-tarpit .
# Base images are pinned by digest; bump them deliberately.

FROM golang:1.27.3-bookworm@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9 AS build
WORKDIR /src
COPY sdk/go/ sdk/go/
COPY sensors/tcp-tarpit/ sensors/tcp-tarpit/
WORKDIR /src/sensors/tcp-tarpit
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOWORK=off
RUN go build -ldflags='-s -w -buildid=' -o /out/sensor .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/sensor /sensor
USER 65532:65532
ENTRYPOINT ["/sensor"]
