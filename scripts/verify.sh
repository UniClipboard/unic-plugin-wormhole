#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export GOWORK=off
export UNIC_WORMHOLE_RECEIPTS="${UNIC_WORMHOLE_RECEIPTS:-$PWD/.cache/acceptance}"
mkdir -p "$UNIC_WORMHOLE_RECEIPTS"
if [ "${UNIC_WORMHOLE_LIVE:-0}" = 1 ]; then
    npm ci --prefix e2e/process --ignore-scripts --no-audit
fi
go vet ./...
go test -race ./... -count=1 -v
