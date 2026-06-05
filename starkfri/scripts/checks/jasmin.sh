#!/usr/bin/env bash
# scripts/checks/jasmin.sh — Jasmin type-check + jasmin-ct gate.
#
# Runs jasminc against precompile/p3q/jasmin/verify.jazz to verify
# (a) the file type-checks (b) the file passes the constant-time
# leakage analysis on its declared CT signature.
#
# Skipped gracefully if jasminc is not on PATH.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

JZ_FILE="$REPO_ROOT/jasmin/verify.jazz"

if ! command -v jasminc >/dev/null 2>&1; then
    echo "==> [skip] jasminc not on PATH; skipping Jasmin CT check"
    exit 0
fi

if [[ ! -f "$JZ_FILE" ]]; then
    echo "==> [FAIL] missing Jasmin file: $JZ_FILE"
    exit 2
fi

echo "==> jasminc -checkCT $JZ_FILE"
jasminc -checkCT "$JZ_FILE"

echo "==> done — Jasmin CT gate green"
exit 0
