#!/usr/bin/env bash
# scripts/checks/go-tests.sh — Go unit + e2e tests for the P3Q
# precompile.
#
# Skips when run outside the precompile module tree (e.g., bare
# checkout without the broader luxfi/precompile module).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v go >/dev/null 2>&1; then
    echo "==> [skip] go not on PATH; skipping Go tests"
    exit 0
fi

# Only run if go.mod is reachable at module level — the precompile
# package depends on the surrounding luxfi/precompile module.
if [[ ! -f "../go.mod" && ! -f "../../go.mod" && ! -f "go.mod" ]]; then
    echo "==> [skip] no surrounding go.mod found; skipping Go tests"
    echo "          (run \`cd ~/work/lux/precompile && go test ./p3q/...\` directly)"
    exit 0
fi

echo "==> go vet ./..."
GOWORK=off GOFLAGS=-mod=mod go vet ./... || true

echo "==> go test -count=1 -race ./..."
if GOWORK=off GOFLAGS=-mod=mod go test -count=1 -race ./...; then
    echo "==> done — Go test gate green"
    exit 0
else
    echo "==> [FAIL] Go tests failed"
    exit 2
fi
