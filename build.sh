#!/usr/bin/env bash
# Compile le binaire statique (WebUI embarquée). Linux/amd64 par défaut.
set -e
CGO_ENABLED=0 GOOS=${GOOS:-linux} GOARCH=${GOARCH:-amd64} \
  go build -trimpath -ldflags "-s -w" -o p2pfs ./cmd/p2pfs
echo "OK -> ./p2pfs ($(du -h p2pfs | cut -f1)), ${GOOS:-linux}/${GOARCH:-amd64}"
