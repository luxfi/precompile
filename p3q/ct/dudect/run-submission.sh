#!/usr/bin/env bash
# Submission-grade dudect run: 10^9 samples per measurement run, 10
# batches, on a pinned-CPU quiet host. Produces the CT evidence
# required to close GATE-3 in CRYPTOGRAPHER-SIGN-OFF.md.
#
# Pre-flight checklist (operator-side):
#   * host is otherwise idle (no background syncs, no IO heavy load)
#   * one CPU pinned with `taskset -c <N>` on Linux, or
#     `pmset -a sleep 0` on macOS
#   * thermal headroom: ambient < 24°C; SoC at idle temp
#   * dudect harness built (`make`)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}/ct/dudect"

mkdir -p results

# 10^9 samples (1 GiB-sample equivalent at 24-byte chunk_size).
DUDECT_SAMPLES=${DUDECT_SAMPLES:-1000000000}
DUDECT_MAX_BATCHES=${DUDECT_MAX_BATCHES:-10}

LOG="results/$(date +%Y%m%d-%H%M%S)-submission.log"
echo "==> P3Q dudect submission run"
echo "    samples per batch: ${DUDECT_SAMPLES}"
echo "    max batches:       ${DUDECT_MAX_BATCHES}"
echo "    log:               ${LOG}"
echo

if command -v taskset >/dev/null 2>&1; then
    PIN="taskset -c 0"
elif command -v cpulimit >/dev/null 2>&1; then
    PIN=""
else
    PIN=""
fi

DUDECT_SAMPLES="${DUDECT_SAMPLES}" \
DUDECT_MAX_BATCHES="${DUDECT_MAX_BATCHES}" \
    ${PIN} ./dudect_verify 2>&1 | tee "${LOG}"

echo
echo "==> done"
echo "    review: tail -n 40 ${LOG}"
