#!/usr/bin/env bash
# scripts/checks/ec-compile.sh — EasyCrypt compile-from-source gate.
#
# Compiles every EC file in the canonical set. Skipped gracefully if
# easycrypt is not on PATH (developer machine without EC installed —
# the static admit-budget check still trips on regressions).
#
# Adding a new EC file requires adding it to the EC_FILES list here.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

EC_ROOT="$REPO_ROOT/proofs/easycrypt"

EC_FILES=(
    "$EC_ROOT/P3Q_Verifier.ec"
    "$EC_ROOT/P3Q_Wire_Format.ec"
    "$EC_ROOT/P3Q_Gas_Model.ec"
    "$EC_ROOT/lemmas/P3Q_CT.ec"
)

if ! command -v easycrypt >/dev/null 2>&1; then
    echo "==> [skip] easycrypt not on PATH; skipping EC compile check"
    echo "          (static admit-budget check still runs)"
    exit 0
fi

OVERALL=0
for f in "${EC_FILES[@]}"; do
    if [[ ! -f "$f" ]]; then
        echo "==> [FAIL] missing EC file: $f"
        OVERALL=2
        continue
    fi
    echo "==> easycrypt $f"
    easycrypt -I "$EC_ROOT" "$f" || OVERALL=2
done

if [[ $OVERALL -eq 0 ]]; then
    echo "==> done — EC compile gate green"
fi
exit $OVERALL
