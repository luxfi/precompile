#!/usr/bin/env bash
# P3Q high-assurance gate — orchestrator (per-push, REAL checks).
#
# Each check below lives in its own script under scripts/checks/. This
# file is intentionally THIN: it sequences the checks and propagates
# their exit codes. Each per-check script is independently runnable.
#
# The checks, in order:
#
#   1. jasmin.sh                  — jasminc type-check + jasmin-ct on
#                                   precompile/p3q/jasmin/verify.jazz
#                                   (blocking).
#   2. ec-admits.sh               — EasyCrypt admit-budget (0/0).
#   3. ec-compile.sh              — All EC files compile clean
#                                   (skipped gracefully if easycrypt
#                                   not on PATH).
#   4. go-tests.sh                — Go unit + e2e + fuzz tests for the
#                                   precompile.
#
# NOT in this gate (intentionally): dudect at smoke budget. A
# 10k-sample dudect run can't certify constant time; the budget
# isn't statistically meaningful. The REAL dudect gate is the
# submission-grade run from ct/dudect/run-submission.sh (10^9
# samples per target on a pinned CPU). It belongs in the nightly
# gate, not per-push.
#
# Any per-check failure (exit 2) fails the orchestrator with the
# same code. Per-check skips (exit 0 with a [skip] message) do not
# fail the gate.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CHECKS=(
    "scripts/checks/jasmin.sh"
    "scripts/checks/ec-admits.sh"
    "scripts/checks/ec-compile.sh"
    "scripts/checks/go-tests.sh"
)

echo "==> P3Q high-assurance track"
echo "    jasmin/   $REPO_ROOT/jasmin"
echo "    easycrypt $REPO_ROOT/proofs/easycrypt"
echo "    dudect    $REPO_ROOT/ct/dudect"
echo

OVERALL=0
for check in "${CHECKS[@]}"; do
    rc=0
    bash "$REPO_ROOT/$check" || rc=$?
    if [[ $rc -ne 0 ]]; then
        OVERALL=$rc
        echo
        echo "==> $check exited rc=$rc — aborting gate"
        break
    fi
    echo
done

if [[ $OVERALL -eq 0 ]]; then
    echo "==> done — high-assurance gate green"
fi
exit $OVERALL
