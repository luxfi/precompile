#!/usr/bin/env bash
# scripts/checks/ec-admits.sh — EasyCrypt admit-budget gate.
#
# Counts admit. occurrences across the canonical EC file set and
# fails if the count exceeds the hard-pinned ADMIT_BUDGET. The
# budget is checked statically (does NOT require easycrypt itself
# to be installed) so a regression on a CI-host without EC still
# trips.
#
# Adding a new admit requires bumping ADMIT_BUDGET here AND
# documenting it in the relevant file's accounting block.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

EC_ROOT="$REPO_ROOT/proofs/easycrypt"

ADMIT_BUDGET=0

EC_FILES=(
    "$EC_ROOT/P3Q_Verifier.ec"
    "$EC_ROOT/P3Q_Wire_Format.ec"
    "$EC_ROOT/P3Q_Gas_Model.ec"
    "$EC_ROOT/lemmas/P3Q_CT.ec"
)

ADMIT_COUNT=0
for f in "${EC_FILES[@]}"; do
    if [[ -f "$f" ]]; then
        n=$(grep -cE "^[[:space:]]*admit\.[[:space:]]*$" "$f" 2>/dev/null || true)
        [[ -z "$n" ]] && n=0
        ADMIT_COUNT=$((ADMIT_COUNT + n))
    fi
done

echo "==> EasyCrypt admit budget: $ADMIT_COUNT / $ADMIT_BUDGET"
if [[ $ADMIT_COUNT -gt $ADMIT_BUDGET ]]; then
    echo "    [FAIL] admit count exceeds budget — a new admit was added"
    echo "           without closing an existing one. Either close one"
    echo "           or update ADMIT_BUDGET in this script (and document"
    echo "           in the relevant file's accounting block)."
    exit 2
fi
exit 0
