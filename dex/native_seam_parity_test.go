// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
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

// --- the C->D SWAP INTENT object (value + operation) -----------------------------

// intentParityGoldenHex is the CROSS-REPO golden for the 118-byte C->D swap intent:
// the 69-byte value head (parityGoldenHex with spent=0, because a C->D leg has matched
// nothing yet) followed by the 49-byte operation tail
//
//	market     = b0b1..cf   (32, ascending from 0xB0)
//	side       = 01         (sell)
//	limitPrice = 0x0000000077359400  (2.0 on the PriceInt x1e8 grid)
//	size       = 0x00000000000003e8  (1000 base units)
//
// dex/pkg/dchain pins the IDENTICAL string. The two repos cannot import each other, so
// this vector is the only thing keeping the operation wire in lockstep — and an
// operation that decodes differently on the two sides is a taker's order executed at
// terms they never authorized.
const intentParityGoldenHex = "00" + // rail (swap)
	"112233445566778899aabbccddeeff0102030405" + // owner (20)
	"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + // asset (32)
	"0102030405060708" + // amount (8)
	"0000000000000000" + // spent  (8) — always 0 on a C->D leg
	"b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf" + // market (32)
	"01" + // side (sell)
	"000000000bebc200" + // limitPrice (8) = 2.0 * 1e8
	"00000000000003e8" //   size       (8) = 1000

func parityMarket() [32]byte {
	var m [32]byte
	for i := range m {
		m[i] = byte(0xB0 + i)
	}
	return m
}

func parityOp() SeamOp {
	return SeamOp{Market: parityMarket(), Side: seamSideSell, LimitPrice: 2 * priceScale, Size: 1000}
}

// TestIntentWire_GoldenMatchesDChain pins the intent encoder against the cross-repo
// golden, and pins that the VALUE HEAD is byte-identical to the 69-byte object every
// other consumer already reads. The head must not move: the settlement and LP rails
// still decode exactly those bytes.
func TestIntentWire_GoldenMatchesDChain(t *testing.T) {
	want, err := hex.DecodeString(intentParityGoldenHex)
	if err != nil {
		t.Fatalf("bad golden hex: %v", err)
	}
	if len(want) != intentObjectSize9999 {
		t.Fatalf("golden width %d != intentObjectSize9999 %d — the intent wire changed on ONE side "+
			"only. Update precompile/dex and dex/pkg/dchain in lockstep.", len(want), intentObjectSize9999)
	}
	got := encodeIntentObject(parityOwner(), parityAsset(), 0x0102030405060708, parityOp())
	if hex.EncodeToString(got) != intentParityGoldenHex {
		t.Fatalf("C->D intent wire DIVERGED from the D-Chain golden:\n got=%s\nwant=%s",
			hex.EncodeToString(got), intentParityGoldenHex)
	}
	// The value head is the SAME 69 bytes, spent=0.
	head := encodeAtomicObjectSpent(railSwap, parityOwner(), parityAsset(), 0x0102030405060708, 0)
	if !bytes.Equal(got[:exportedOutputSize9999], head) {
		t.Fatal("the intent's value head diverged from the canonical 69-byte object: the settlement " +
			"and LP rails decode exactly those bytes and would break")
	}
}

// TestIntentWire_WidthIsTheDiscriminator pins the fail-closed property that makes the
// two object generations safe to run past each other: a 69-byte VALUE object is NOT an
// intent (no operation => nothing to execute => refuse rather than invent one), and a
// 118-byte INTENT is not a settlement object.
func TestIntentWire_WidthIsTheDiscriminator(t *testing.T) {
	value := encodeAtomicObjectSpent(railSwap, parityOwner(), parityAsset(), 5, 0)
	if _, _, _, _, ok := decodeIntentObject(value); ok {
		t.Fatal("a 69-byte VALUE object decoded as an intent: D would have to invent the taker's " +
			"market/side/limit — an order they never authorized")
	}
	intent := encodeIntentObject(parityOwner(), parityAsset(), 5, parityOp())
	if _, _, _, _, _, ok := decodeAtomicObject(intent); ok {
		t.Fatal("a 118-byte INTENT decoded as a settlement value object: the settlement rails must " +
			"refuse it, not read 69 of its bytes")
	}
	if _, _, _, _, ok := decodeIntentObject(intent[:len(intent)-1]); ok {
		t.Fatal("a truncated intent decoded")
	}
	// Round trip.
	owner, asset, amount, op, ok := decodeIntentObject(intent)
	if !ok || owner != parityOwner() || asset != parityAsset() || amount != 5 || op != parityOp() {
		t.Fatalf("intent round trip lost a field: ok=%v owner=%s amount=%d op=%+v", ok, owner.Hex(), amount, op)
	}
}
