// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// All quasar precompiles at 0x0300..0020-25 are deprecated stubs. The
// previous test suite pinned a trivially-forgeable Verkle "verify"
// (verifyVerkleLight accepted any (commitment, proof) whose first
// 17 bytes matched) — an oracle that shipped to C-Chain + Liquid EVM
// before being caught in PQC review. Deleted; callers should route
// to the LP-4200 0x012200 block.

package quasar

import (
	"testing"
)

// TestSentinel pins the deprecated-error symbol so a future rename
// can't quietly drop the refuse-everything contract.
func TestSentinel(t *testing.T) {
	if ErrQuasarPrecompileDeprecated == nil {
		t.Fatal("ErrQuasarPrecompileDeprecated must not be nil")
	}
}
