// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// tick_math.go — tick <-> sqrt price.
// ---------------------------------------------------------------------------

// TestGetSqrtRatioAtTickIsMonotonic asserts the property the whole swap loop rests
// on: price is strictly increasing in tick. A single inversion would let a swap cross
// a tick in the wrong direction and price against the wrong liquidity.
func TestGetSqrtRatioAtTickIsMonotonic(t *testing.T) {
	prev, err := GetSqrtRatioAtTick(MinTick)
	require.NoError(t, err)

	// Sweep the whole usable band at a stride that still visits both signs densely
	// near zero, where the negative-exponent branch flips.
	for tick := int32(MinTick) + 1; tick <= MaxTick; tick += 977 {
		cur, err := GetSqrtRatioAtTick(tick)
		require.NoErrorf(t, err, "tick %d is in range and must resolve", tick)
		require.Positivef(t, cur.Cmp(prev), "price must strictly increase at tick %d", tick)
		prev = cur
	}

	// Dense sweep across the sign boundary.
	prev, err = GetSqrtRatioAtTick(-500)
	require.NoError(t, err)
	for tick := int32(-499); tick <= 500; tick++ {
		cur, err := GetSqrtRatioAtTick(tick)
		require.NoError(t, err)
		require.Positivef(t, cur.Cmp(prev), "price must strictly increase at tick %d", tick)
		prev = cur
	}
}

// TestGetSqrtRatioAtTickRejectsOutOfRange: the bounds are exact. One tick outside the
// usable band must be refused, and both extremes must resolve.
func TestGetSqrtRatioAtTickRejectsOutOfRange(t *testing.T) {
	lo, err := GetSqrtRatioAtTick(MinTick)
	require.NoError(t, err, "MinTick is in range")
	hi, err := GetSqrtRatioAtTick(MaxTick)
	require.NoError(t, err, "MaxTick is in range")

	// The two bounds are DEFINED by these ticks: MinSqrtRatio == ratio(MinTick) and
	// MaxSqrtRatio == ratio(MaxTick). That equality at the top is exactly why
	// GetTickAtSqrtRatio's upper bound is EXCLUSIVE — the max price is the boundary of
	// a tick that no live pool can sit in, so a swap must stop below it.
	require.Equal(t, 0, lo.Cmp(MinSqrtRatio), "MinSqrtRatio must equal ratio(MinTick)")
	require.Equal(t, 0, hi.Cmp(MaxSqrtRatio), "MaxSqrtRatio must equal ratio(MaxTick)")

	_, err = GetTickAtSqrtRatio(hi)
	require.Error(t, err, "ratio(MaxTick) is the exclusive upper bound and must not invert")
	back, err := GetTickAtSqrtRatio(lo)
	require.NoError(t, err, "ratio(MinTick) is inclusive and must invert")
	require.Equal(t, int32(MinTick), back)

	for _, tick := range []int32{MinTick - 1, MaxTick + 1, -1 << 30, 1 << 30} {
		_, err := GetSqrtRatioAtTick(tick)
		require.Errorf(t, err, "tick %d is outside the usable band and must be refused", tick)
	}
}

// TestTickSqrtRoundTrip is the inverse property, which is what makes the two
// functions safe to compose in the swap loop: converting a tick to a price and back
// must land on the same tick. GetTickAtSqrtRatio floors, so the round trip is exact
// in this direction (price -> tick -> price is only exact at boundaries).
func TestTickSqrtRoundTrip(t *testing.T) {
	// Stop short of MaxTick: ratio(MaxTick) == MaxSqrtRatio, which GetTickAtSqrtRatio
	// excludes by design (asserted in TestGetSqrtRatioAtTickRejectsOutOfRange).
	for tick := int32(MinTick); tick < MaxTick; tick += 1013 {
		ratio, err := GetSqrtRatioAtTick(tick)
		require.NoError(t, err)
		back, err := GetTickAtSqrtRatio(ratio)
		require.NoErrorf(t, err, "tick %d round trip", tick)
		require.Equalf(t, tick, back, "tick %d must survive the round trip", tick)
	}

	// Dense across zero, where the sign branches meet.
	for tick := int32(-800); tick <= 800; tick++ {
		ratio, err := GetSqrtRatioAtTick(tick)
		require.NoError(t, err)
		back, err := GetTickAtSqrtRatio(ratio)
		require.NoError(t, err)
		require.Equalf(t, tick, back, "tick %d must survive the round trip", tick)
	}
}

// TestGetTickAtSqrtRatioFloors: the returned tick must satisfy
// ratio(tick) <= price < ratio(tick+1). Flooring is what keeps a price strictly
// inside the tick it is reported to be in.
func TestGetTickAtSqrtRatioFloors(t *testing.T) {
	const seed = 20260828
	r := rand.New(rand.NewSource(seed))
	span := new(big.Int).Sub(MaxSqrtRatio, MinSqrtRatio)

	for range 4000 {
		price := new(big.Int).Add(MinSqrtRatio, new(big.Int).Rand(r, span))
		tick, err := GetTickAtSqrtRatio(price)
		require.NoErrorf(t, err, "seed=%d price %v is in range", seed, price)

		at, err := GetSqrtRatioAtTick(tick)
		require.NoError(t, err)
		require.LessOrEqualf(t, at.Cmp(price), 0,
			"seed=%d ratio(tick) must not exceed the price", seed)

		if tick < MaxTick {
			next, err := GetSqrtRatioAtTick(tick + 1)
			require.NoError(t, err)
			require.Positivef(t, next.Cmp(price),
				"seed=%d ratio(tick+1) must exceed the price: the tick must be maximal", seed)
		}
	}
}

// TestGetTickAtSqrtRatioRejectsOutOfRange: the band is half-open [Min, Max). Both
// ends are asserted exactly, because an accepted out-of-band price would index
// liquidity that cannot exist.
func TestGetTickAtSqrtRatioRejectsOutOfRange(t *testing.T) {
	_, err := GetTickAtSqrtRatio(MinSqrtRatio)
	require.NoError(t, err, "MinSqrtRatio is inclusive")

	_, err = GetTickAtSqrtRatio(new(big.Int).Sub(MinSqrtRatio, big.NewInt(1)))
	require.Error(t, err, "one below MinSqrtRatio must be refused")

	_, err = GetTickAtSqrtRatio(MaxSqrtRatio)
	require.Error(t, err, "MaxSqrtRatio is EXCLUSIVE and must be refused")

	_, err = GetTickAtSqrtRatio(new(big.Int).Sub(MaxSqrtRatio, big.NewInt(1)))
	require.NoError(t, err, "one below MaxSqrtRatio is the largest legal price")

	_, err = GetTickAtSqrtRatio(big.NewInt(0))
	require.Error(t, err, "a zero price must be refused")
}

// TestMsb256 covers the bit-length helper the tick search normalizes with.
func TestMsb256(t *testing.T) {
	require.Equal(t, 0, msb256(big.NewInt(1)))
	require.Equal(t, 1, msb256(big.NewInt(2)))
	require.Equal(t, 1, msb256(big.NewInt(3)))
	require.Equal(t, 7, msb256(big.NewInt(255)))
	require.Equal(t, 8, msb256(big.NewInt(256)))
	for shift := uint(0); shift < 256; shift++ {
		require.Equalf(t, int(shift), msb256(new(big.Int).Lsh(big.NewInt(1), shift)), "msb(2^%d)", shift)
	}
}
