// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/hex"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// native_intentid_parity_test.go pins the ON-CHAIN DeriveIntentID against a shared golden the
// off-chain zap/dexsession side ALSO pins (its TestIntentID_OffChainEqualsOnChain). The
// sibling TestIntentID_OffChainEqualsOnChain (native_callindex_test.go) already proves the
// on-chain mint == this package's DeriveIntentID by running the REAL swap; this test extends
// that to a CROSS-REPO anchor: the same fixed inputs must hash to the same golden in BOTH
// repos, so the off-chain id derivation (a separate implementation that cannot import this
// package — it would drag the EVM+geth+cgo graph into the transport module) cannot silently
// drift from the chain's. The value-boundary contract: the off-chain pointer names the same
// object the chain mints.
const intentIDGolden = "5b0e8d3828def79d10b8ea811c422d702c58125508a6de78c5ae3a4b691ce016"

// TestIntentID_CrossRepoGolden pins the on-chain DeriveIntentID over FIXED inputs (IDENTICAL
// to the off-chain zap/dexsession twin) to the shared golden. Both repos green => off-chain id
// == on-chain id for the same inputs (the watch-correlation contract for non-fee-on-transfer
// inputs, where locked == amountIn).
func TestIntentID_CrossRepoGolden(t *testing.T) {
	var c, d ids.ID
	c[0], c[31] = 0xC0, 0x01
	d[0], d[31] = 0xD0, 0x02
	acct := common.HexToAddress("0x00000000000000000000000000000000000000AA")
	var assetIn [32]byte
	for i := range assetIn {
		assetIn[i] = byte(0x30 + i)
	}
	var market [32]byte
	for i := range market {
		market[i] = byte(0x70 + i)
	}
	got := DeriveIntentID(96369, c, d, acct, assetIn, 1_000_000, market, 7)
	if hex.EncodeToString(got[:]) != intentIDGolden {
		t.Fatalf("on-chain DeriveIntentID diverged from the shared golden:\n got %s\nwant %s\n"+
			"the off-chain keeper/SDK would derive a different id than the chain mints — the "+
			"watch could not correlate. Re-align with zap/dexsession DeriveIntentID.",
			hex.EncodeToString(got[:]), intentIDGolden)
	}
}
