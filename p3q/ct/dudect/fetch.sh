#!/usr/bin/env bash
# Fetch dudect.h at the pinned commit. The pinned commit matches the
# Pulsar harness for byte-equal upstream so results are comparable.

set -euo pipefail

# oreparaz/dudect, master @ 2024-09-25 — same pin as Pulsar.
DUDECT_REPO="https://github.com/oreparaz/dudect"
DUDECT_REF="dudect-0.1.0"
DUDECT_DIR="dudect"

if [[ -d "${DUDECT_DIR}/.git" ]]; then
    echo "==> dudect already cloned at ${DUDECT_DIR} — leaving as-is"
    exit 0
fi

if [[ -e "${DUDECT_DIR}" ]]; then
    echo "==> ${DUDECT_DIR} exists but is not a git checkout — refusing"
    exit 1
fi

echo "==> cloning ${DUDECT_REPO} ${DUDECT_REF} into ${DUDECT_DIR}"
git clone --depth 1 --branch "${DUDECT_REF}" "${DUDECT_REPO}" "${DUDECT_DIR}"
echo "==> dudect ready"
