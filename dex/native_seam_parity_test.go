// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/hex"
	"testing"

	"github.com/luxfi/geth/common"
)

// native_seam_parity_test.go pins the C<->D atomic object wire BYTE-FOR-BYTE against the
// dexvm side (chains/dexvm/atomic.go). The two repos encode/decode the SAME shared-memory
// UTXO value — rail(1) | owner(20) | asset(32) | amount(8) | spent(8) = 69 bytes — and a
// one-sided change to that layout is a SILENT CONSENSUS BREAK: D would export an object C
// could not decode (every swap settlement reverts ErrNativeSettleMalformed, no taker is ever
// credited) or, worse, a width both sides accept but interpret differently. This golden
// vector is the lockstep contract: it is reproduced by chains/dexvm encodeExportedOutput with
// the IDENTICAL inputs, so if either side drifts, this test (or its dexvm twin) fails BEFORE
// the bytes reach consensus.
//
// HOW THE GOLDEN WAS PRODUCED (reproducible). chains/dexvm encodeExportedOutput on:
//
//	rail   = 0 (railSwap)
//	owner  = 0x112233445566778899aabbccddeeff0102030405   (20 bytes)
//	asset  = 0xa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf (32 bytes)
//	amount = 0x0102030405060708
//	spent  = 0x1112131415161718
//
// yields the 69 bytes below. Any change to exportedOutputSize9999 or the field order/offsets
// breaks this — intentionally.
const parityGoldenHex = "00" + // rail
	"112233445566778899aabbccddeeff0102030405" + // owner (20)
	"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + // asset (32)
	"0102030405060708" + // amount (8, big-endian)
	"1112131415161718" //   spent  (8, big-endian)

func parityOwner() common.Address {
	return common.HexToAddress("0x112233445566778899aabbccddeeff0102030405")
}

func parityAsset() [32]byte {
	var a [32]byte
	for i := range a {
		a[i] = byte(0xA0 + i)
	}
	return a
}

// TestSeamWire_GoldenMatchesDexvm pins the precompile encoder against the cross-repo golden:
// encodeAtomicObjectSpent must produce the EXACT bytes chains/dexvm encodeExportedOutput does
// for the same inputs (lockstep), and the width must be the canonical 69.
func TestSeamWire_GoldenMatchesDexvm(t *testing.T) {
	want, err := hex.DecodeString(parityGoldenHex)
	if err != nil {
		t.Fatalf("bad golden hex: %v", err)
	}
	if len(want) != exportedOutputSize9999 {
		t.Fatalf("golden width %d != exportedOutputSize9999 %d — the wire changed on ONE side only "+
			"(consensus break: D exports a width C cannot decode). Update BOTH repos in lockstep.",
			len(want), exportedOutputSize9999)
	}
	got := encodeAtomicObjectSpent(railSwap, parityOwner(), parityAsset(), 0x0102030405060708, 0x1112131415161718)
	if hex.EncodeToString(got) != parityGoldenHex {
		t.Fatalf("precompile seam wire DIVERGED from the dexvm golden:\n got=%s\nwant=%s\n"+
			"the C<->D atomic object is no longer byte-identical — every swap settlement would "+
			"fail to decode. Re-align native_wire.go with chains/dexvm/atomic.go.",
			hex.EncodeToString(got), parityGoldenHex)
	}
}

// TestSeamWire_RoundTripCarriesSpent pins that decode is the exact inverse of encode AND that
// the trailing spent witness survives the round trip (the field the MEV floor reads). A decode
// that dropped spent (e.g. a stale 61-byte reader) would silently read 0 and disable the floor.
func TestSeamWire_RoundTripCarriesSpent(t *testing.T) {
	owner := parityOwner()
	asset := parityAsset()
	const amount uint64 = 9_000_000
	const spent uint64 = 4_500_000

	enc := encodeAtomicObjectSpent(railSwap, owner, asset, amount, spent)
	rail, gotOwner, gotAsset, gotAmount, gotSpent, ok := decodeAtomicObject(enc)
	if !ok {
		t.Fatal("decode of a canonical 69-byte object must succeed")
	}
	if rail != railSwap || gotOwner != owner || gotAsset != asset {
		t.Fatalf("round-trip mismatch on rail/owner/asset: rail=%d owner=%x asset=%x", rail, gotOwner, gotAsset)
	}
	if gotAmount != amount {
		t.Fatalf("round-trip amount = %d, want %d", gotAmount, amount)
	}
	if gotSpent != spent {
		t.Fatalf("round-trip SPENT = %d, want %d — the matched-input witness was lost (the MEV floor "+
			"would silently read 0 and never engage).", gotSpent, spent)
	}
}

// TestSeamWire_WrongWidthRejected pins that a non-canonical width never decodes into a credit
// (the corrupt-record defense; a 61-byte stale object or any other width is refused).
func TestSeamWire_WrongWidthRejected(t *testing.T) {
	for _, n := range []int{0, 60, 61, 68, 70, 100} {
		if _, _, _, _, _, ok := decodeAtomicObject(make([]byte, n)); ok {
			t.Fatalf("a %d-byte object must NOT decode (only the canonical %d is valid)", n, exportedOutputSize9999)
		}
	}
}
