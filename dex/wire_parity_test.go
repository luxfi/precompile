// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"testing"

	dexcore "github.com/luxfi/dex/pkg/dex"
	"github.com/luxfi/dex/pkg/zapwire"
)

// wire_parity_test.go pins the 0x9999 EVM surface's fixed-point price grid to the
// venue's frozen constants. The taker's CLOB price limit (priceLimitToCLOB) and the
// settlement MEV floor (enforceProceedsPriceFloor) quantize on priceScale; that grid
// MUST equal the matcher's PriceInt grid (dexcore.PriceMultiplier) and the dex
// v1.14.0 ZAP wire scale (zapwire.PriceScale) the chains/dexvm proxy carries, or the
// 0x9999 surface would price a limit the native venue reads at a different scale — an
// interop break. This is the guard that the local re-declaration never drifts.
func TestWireParity_PriceScaleMatchesVenue(t *testing.T) {
	if priceScale != dexcore.PriceMultiplier {
		t.Fatalf("priceScale %d != dexcore.PriceMultiplier %d (PriceInt grid drift)", priceScale, dexcore.PriceMultiplier)
	}
	if priceScale != zapwire.PriceScale {
		t.Fatalf("priceScale %d != zapwire.PriceScale %d (ZAP wire grid drift vs dex v1.14.0)", priceScale, zapwire.PriceScale)
	}
}
