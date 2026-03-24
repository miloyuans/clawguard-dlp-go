#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BASE_DIR"

mkdir -p build
CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags='-s -w' -o build/clawguard ./cmd/server

sha256sum build/clawguard > build/clawguard.sha256
ls -lh build/clawguard build/clawguard.sha256
