// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/luxfi/geth/common"
)

// zzpool_slot_test.go covers the int256 word codec (signedToSlot / slotToSigned)
// and safeFillBytes. These are the encoding under every BalanceDelta the swap and
// modify bindings persist: a NEGATIVE leg means "the pool owes the user", so an
// encoding that loses the sign turns a debt into a credit. The property demanded
// here is an exact round-trip over the whole signed range, not a spot check.

// zzpRoundTrip encodes v, decodes it back, and reports any drift.
func zzpRoundTrip(t *testing.T, v *big.Int) {
	t.Helper()
	in := new(big.Int).Set(v)
	slot := signedToSlot(in)
	if in.Cmp(v) != 0 {
		t.Errorf("signedToSlot mutated its argument: %s became %s", v, in)
	}
	out := slotToSigned(slot)
	if out.Cmp(v) != 0 {
		t.Errorf("round-trip drift: %s -> %x -> %s", v, slot, out)
	}
}

func TestZzpSignedSlotRoundTripsBoundaries(t *testing.T) {
	two255 := new(big.Int).Lsh(big.NewInt(1), 255)
	cases := []*big.Int{
		big.NewInt(0),
		big.NewInt(1), big.NewInt(-1),
		big.NewInt(2), big.NewInt(-2),
		big.NewInt(127), big.NewInt(-127), big.NewInt(-128),
		big.NewInt(255), big.NewInt(-255), big.NewInt(-256),
		big.NewInt(1 << 31), big.NewInt(-(1 << 31)),
		big.NewInt(int64(^uint32(0))), big.NewInt(-int64(^uint32(0))),
		big.NewInt(1<<62 - 1), big.NewInt(-(1<<62 - 1)),
		new(big.Int).SetInt64(9223372036854775807),  // int64 max
		new(big.Int).SetInt64(-9223372036854775808), // int64 min
		new(big.Int).Sub(two255, big.NewInt(1)),     // int256 max
		new(big.Int).Neg(two255),                    // int256 min
		new(big.Int).Add(new(big.Int).Neg(two255), big.NewInt(1)),
	}
	for _, v := range cases {
		zzpRoundTrip(t, v)
	}
	// nil encodes as the zero word and must not panic.
	if got := signedToSlot(nil); got != (common.Hash{}) {
		t.Errorf("signedToSlot(nil): got %x, want the zero word", got)
	}
}

// TestZzpSignedSlotRoundTripsRandom sweeps the signed range with a FIXED seed so
// the exact sequence is reproducible from this file alone. Seed 0x9010 is the
// precompile's own address digits — an arbitrary but documented constant.
func TestZzpSignedSlotRoundTripsRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(0x9010))
	for i := 0; i < 4_000; i++ {
		// Vary the WIDTH as well as the value so short and full-width words are
		// both exercised; a codec that only handles 32-byte magnitudes would pass
		// a fixed-width sweep and fail here.
		bits := uint(rng.Intn(255) + 1)
		mag := new(big.Int).Rand(rng, new(big.Int).Lsh(big.NewInt(1), bits))
		if rng.Intn(2) == 0 {
			mag.Neg(mag)
		}
		zzpRoundTrip(t, mag)
	}
}

func TestZzpSignedSlotSignIsTheHighBit(t *testing.T) {
	// The encoding is two's complement, so the sign lives in the top bit and
	// nowhere else. A decoder that looked anywhere else would mis-read exactly the
	// values around the boundary.
	pos := signedToSlot(big.NewInt(1))
	if pos[0]&0x80 != 0 {
		t.Error("a positive value set the sign bit")
	}
	neg := signedToSlot(big.NewInt(-1))
	if neg[0]&0x80 == 0 {
		t.Error("a negative value did not set the sign bit")
	}
	// The largest positive int256 must NOT read back negative (off-by-one at the
	// boundary is the classic two's-complement bug).
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1))
	if slotToSigned(signedToSlot(max)).Sign() <= 0 {
		t.Error("int256 max decoded as non-positive")
	}
	min := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 255))
	if slotToSigned(signedToSlot(min)).Sign() >= 0 {
		t.Error("int256 min decoded as non-negative")
	}
}

func TestZzpSlotToSignedIsInjective(t *testing.T) {
	// Two different words must not decode to the same value, or a stored delta is
	// ambiguous on read-back. Sweep every one-bit word plus its complement.
	seen := make(map[string]string)
	for i := 0; i < 256; i++ {
		var h common.Hash
		h[i/8] = 1 << (7 - uint(i%8))
		v := slotToSigned(h).String()
		if prior, dup := seen[v]; dup {
			t.Errorf("words %s and %x both decode to %s", prior, h, v)
		}
		seen[v] = h.Hex()
	}
}

// =========================================================================
// safeFillBytes — the UNSIGNED writer, which must zero rather than wrap
// =========================================================================

func TestZzpSafeFillBytesZeroesNilAndNegative(t *testing.T) {
	// safeFillBytes backs every unsigned pool/position word. A negative or nil
	// value must write ZERO, not a two's-complement wrap: a wrapped negative
	// liquidity would read back as an astronomically large balance.
	for _, tc := range []struct {
		name string
		v    *big.Int
	}{
		{"nil", nil},
		{"negative one", big.NewInt(-1)},
		{"large negative", new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 200))},
	} {
		buf := make([]byte, 32)
		for i := range buf {
			buf[i] = 0xFF // pre-dirty, so "did nothing" is distinguishable from "zeroed"
		}
		safeFillBytes(tc.v, buf)
		for i, b := range buf {
			if b != 0 {
				t.Fatalf("%s: byte %d = %#x, want 0 — a negative must never wrap into a huge unsigned word", tc.name, i, b)
			}
		}
	}
	// A positive value fills right-aligned, and the round-trip through SetBytes is
	// exact (this is how getPool reads back what setPool wrote).
	for _, v := range []int64{0, 1, 255, 1 << 40} {
		buf := make([]byte, 32)
		safeFillBytes(big.NewInt(v), buf)
		if got := new(big.Int).SetBytes(buf); got.Cmp(big.NewInt(v)) != 0 {
			t.Errorf("safeFillBytes(%d) round-trip: got %s", v, got)
		}
	}
}
