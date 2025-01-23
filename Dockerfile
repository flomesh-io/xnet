# syntax = docker/dockerfile:1.4
FROM --platform=$BUILDPLATFORM golang:1.23 AS gobuilder
ARG LDFLAGS
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

ADD go.mod .
ADD go.sum .

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    go mod download

ADD . .

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=1 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -v -o ./dist/xctr -ldflags "$LDFLAGS" ./cmd/xctr/*
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -v -o ./dist/xcni -ldflags "$LDFLAGS" ./cmd/xcni/*
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -v -o ./dist/xnat -ldflags "$LDFLAGS" ./cmd/xnat/*

FROM cybwan/ebpf:base22.04 AS ccbuilder

WORKDIR /app

COPY kern kern
COPY Makefile.cli.mk Makefile

RUN mkdir -p bin
RUN make bpf-build

FROM ubuntu:22.04

RUN apt-get update && \
  apt-get install -y iproute2 iputils-arping jq && \
  apt-get purge --auto-remove && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=gobuilder /app/dist/xctr /fsm-xnet-engine
COPY --from=gobuilder /app/dist/xnat /usr/local/bin/xnat
COPY --from=gobuilder /app/dist/xcni .fsm/.xcni
COPY --from=ccbuilder /app/bin/xnet.kern.o .fsm/.xnet.kern.o
COPY --from=ccbuilder /usr/local/sbin/bpftool /usr/local/bin/bpftool

STOPSIGNAL SIGQUIT
