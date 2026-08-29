// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/hex"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// native_seam_parity_test.go pins the C<->D funding wire BYTE-FOR-BYTE against
// dex/pkg/dchain. The two repos cannot import each other, so this golden vector IS
// the cross-repo contract: a one-sided change to the layout is a SILENT CONSENSUS
// BREAK — D would write a claim C cannot decode (every import reverts, nobody is
// ever credited) or, worse, a width both sides accept and read differently.
// dex/pkg/dchain/atomic_wire_test.go pins the IDENTICAL strings, so if either side
// drifts one of the two tests fails before the bytes reach consensus.
//
// HOW THE GOLDEN WAS PRODUCED (reproducible). encodeClaim on:
//
//	beneficiary = 0x112233445566778899aabbccddeeff0102030405   (20 bytes)
//	asset       = 0xa0a1a2a3...bebf                            (32 bytes, ascending from 0xA0)
//	amount      = 0x0102030405060708
//
// yields the 60 bytes below. Any change to claimSize or the field order breaks it —
// intentionally.
const claimGoldenHex = "112233445566778899aabbccddeeff0102030405" + // beneficiary (20)
	"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + // asset (32)
	"0102030405060708" // amount (8, big-endian)

// claimIDGoldenHex pins DeriveClaimID over a fixed corridor and source transaction.
// dex/pkg/dchain derives the SAME id from the SAME inputs; if it did not, C would
// write a claim under one key and D would look for it under another, and every
// crossing would silently vanish.
//
//	source   = 0x0101..01 (32 × 0x01)
//	dest     = 0x0202..02 (32 × 0x02)
//	sourceTx = 0x0303..03 (32 × 0x03)
//	index    = 7
const claimIDGoldenHex = "0a5e96264cb3e4649c30aba257749a203119d0363677b1be3ead32ebf989f430"

func parityBeneficiary() common.Address {
	return common.HexToAddress("0x112233445566778899aabbccddeeff0102030405")
}

func parityAsset() [32]byte {
	var a [32]byte
	for i := range a {
		a[i] = byte(0xA0 + i)
	}
	return a
}

func repeatID(b byte) ids.ID {
	var id ids.ID
	for i := range id {
		id[i] = b
	}
	return id
}

// TestClaimWire_GoldenMatchesDChain pins the encoder against the cross-repo golden
// and pins the canonical width.
func TestClaimWire_GoldenMatchesDChain(t *testing.T) {
	want, err := hex.DecodeString(claimGoldenHex)
	if err != nil {
		t.Fatalf("bad golden hex: %v", err)
	}
	if len(want) != claimSize {
		t.Fatalf("golden width %d != claimSize %d — the wire changed on ONE side only "+
			"(consensus break: D writes a width C cannot decode). Update BOTH repos in lockstep.",
			len(want), claimSize)
	}
	got := encodeClaim(parityBeneficiary(), parityAsset(), 0x0102030405060708)
	if hex.EncodeToString(got) != claimGoldenHex {
		t.Fatalf("funding wire DIVERGED from the D-Chain golden:\n got=%s\nwant=%s\n"+
			"the C<->D claim is no longer byte-identical — every crossing would fail to "+
			"decode. Re-align native_wire.go with dex/pkg/dchain/atomic.go.",
			hex.EncodeToString(got), claimGoldenHex)
	}
}

// TestClaimID_GoldenMatchesDChain pins the id derivation across the repos. A drift
// here does not corrupt value, it LOSES it: C writes under one key, D reads another.
func TestClaimID_GoldenMatchesDChain(t *testing.T) {
	got := DeriveClaimID(repeatID(0x01), repeatID(0x02), repeatID(0x03), 7)
	if hex.EncodeToString(got[:]) != claimIDGoldenHex {
		t.Fatalf("claim id DIVERGED from the D-Chain golden:\n got=%s\nwant=%s",
			hex.EncodeToString(got[:]), claimIDGoldenHex)
	}
}

// TestClaimID_BindsItsCorridor pins that a claim id is scoped to one direction: the
// same source transaction and index on the reversed corridor derives a DIFFERENT id,
// so an object minted for C->D can never be presented as D->C.
func TestClaimID_BindsItsCorridor(t *testing.T) {
	src, dst, tx := repeatID(0x01), repeatID(0x02), repeatID(0x03)
	if DeriveClaimID(src, dst, tx, 0) == DeriveClaimID(dst, src, tx, 0) {
		t.Fatal("a claim id is identical in both directions: an object could be replayed " +
			"back across the corridor it just came from")
	}
	if DeriveClaimID(src, dst, tx, 0) == DeriveClaimID(src, dst, tx, 1) {
		t.Fatal("two claims from one transaction collide: a second crossing in the same tx " +
			"would overwrite the first")
	}
}

// TestClaimWire_RoundTrip pins that decode is the exact inverse of encode.
func TestClaimWire_RoundTrip(t *testing.T) {
	beneficiary, asset := parityBeneficiary(), parityAsset()
	const amount uint64 = 9_000_000

	gotB, gotA, gotAmt, ok := decodeClaim(encodeClaim(beneficiary, asset, amount))
	if !ok {
		t.Fatal("decode of a canonical claim must succeed")
	}
	if gotB != beneficiary || gotA != asset || gotAmt != amount {
		t.Fatalf("round-trip mismatch: beneficiary=%x asset=%x amount=%d", gotB, gotA, gotAmt)
	}
}

// TestClaimWire_WrongWidthRejected pins that a non-canonical width never decodes into
// a credit. In particular it pins the widths of the OLD braided object — 69 (value +
// lane byte + spent witness) and 118 (that, plus a market/side/limit/size tail) — so
// a stale object of either generation is refused rather than reinterpreted.
func TestClaimWire_WrongWidthRejected(t *testing.T) {
	for _, n := range []int{0, 59, 61, 69, 80, 118} {
		if _, _, _, ok := decodeClaim(make([]byte, n)); ok {
			t.Fatalf("a %d-byte object must NOT decode (only the canonical %d is valid)", n, claimSize)
		}
	}
}
