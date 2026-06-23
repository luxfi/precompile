// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"testing"
	"unsafe"

	"github.com/luxfi/dex/pkg/lx"
)

// swap_sync_access_rowsize_test.go pins the predictor's order-row slot count to the ACTUAL
// dexcore order-row encoding width. PredictSyncSwapWriteSet declares dexOrderRowSlots EVM slots
// per resting order row, derived from the constant dexOrderRowBytes (== sizeof(lx.DEXOrder)).
// lx.EncodeRow is fixed-width (unsafe.Sizeof), so the constant must equal the live struct size:
// if a field is ever added to DEXOrder, the row grows, the predictor would under-declare the
// order-row data slots, and (absent this guard) the parity gate would only catch it when a maker
// row happens to span the extra slot. This guard makes the drift a LOUD, immediate failure at the
// SOURCE of truth — the by-construction floor under the parity gate.
func TestSyncAccessPredictor_OrderRowSizePinned(t *testing.T) {
	got := int(unsafe.Sizeof(lx.DEXOrder{}))
	if dexOrderRowBytes != got {
		t.Fatalf("dexOrderRowBytes (%d) != sizeof(lx.DEXOrder) (%d) — the predictor's order-row "+
			"slot count is STALE; update dexOrderRowBytes (and re-check the slot-count consts) so "+
			"PredictSyncSwapWriteSet declares the full order row, else a maker fill writes an "+
			"undeclared slot (silent fork risk caught only incidentally by the parity gate)", dexOrderRowBytes, got)
	}
	// And the derived slot count is exactly ceil(n/32)+1 (length word + data words).
	wantSlots := 1 + (got+31)/32
	if dexOrderRowSlots != wantSlots {
		t.Fatalf("dexOrderRowSlots (%d) != 1+ceil(%d/32) (%d)", dexOrderRowSlots, got, wantSlots)
	}
	t.Logf("order-row size pinned: sizeof(DEXOrder)=%d -> %d slots (declared correctly)", got, dexOrderRowSlots)
}
