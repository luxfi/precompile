// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"math/big"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// swap_minout.go — the DM01 slippage floor.
// ---------------------------------------------------------------------------

// TestMinOutHookDataRoundTrip pins the DM01 codec. The floor is the taker's only
// protection on an exact-input market order, so a value that changes across the wire
// is a silently weakened floor.
func TestMinOutHookDataRoundTrip(t *testing.T) {
	for _, v := range []uint64{0, 1, 2, 1000, 1e9, 1<<32 - 1, 1 << 32, 1<<64 - 1} {
		enc := EncodeMinOutHookData(v)
		require.Len(t, enc, 4+minOutBodyLen, "DM01 is a fixed 36-byte encoding")
		require.Equal(t, minOutPhaseTag[:], enc[:4], "the DM01 tag must lead")

		got, present, err := decodeMinOut(enc)
		require.NoError(t, err)
		require.True(t, present, "a DM01 body must be reported as present")
		require.Equalf(t, v, got, "min-out %d must survive the round trip", v)
	}
}

// TestMinOutAbsentIsNotAnError: hookData that is not DM01 carries no declared floor.
// That must be reported as absent — never as a floor of zero, which would read as
// "the taker accepts any price" and is exactly the confusion the tag exists to avoid.
func TestMinOutAbsentIsNotAnError(t *testing.T) {
	for name, data := range map[string][]byte{
		"nil":                nil,
		"empty":              {},
		"shorter than a tag": {'D', 'M', '0'},
		"async intent tag":   append([]byte("DI01"), make([]byte, 32)...),
		"async settle tag":   append([]byte("DS01"), make([]byte, 32)...),
		"maker tag":          append([]byte("M999"), make([]byte, 32)...),
		"arbitrary bytes":    []byte("hello world, not a tag"),
	} {
		got, present, err := decodeMinOut(data)
		require.NoErrorf(t, err, "%s: a non-DM01 body is not malformed, just absent", name)
		require.Falsef(t, present, "%s must report NO declared floor", name)
		require.Zerof(t, got, "%s must not fabricate a floor", name)
	}
}

// TestMinOutMalformedIsRefused: a DM01 tag with a body that is the wrong width, or a
// value that does not fit uint64, must ERROR. Silently dropping the floor on a
// malformed body would turn a typo into an unbounded-slippage market order.
func TestMinOutMalformedIsRefused(t *testing.T) {
	// Every body width except the exact one is malformed.
	for n := 0; n <= 64; n++ {
		if n == minOutBodyLen {
			continue
		}
		body := append(minOutPhaseTag[:], make([]byte, n)...)
		_, present, err := decodeMinOut(body)
		require.ErrorIsf(t, err, ErrMinOutMalformed, "a %d-byte DM01 body must be refused", n)
		require.Falsef(t, present, "a malformed body must never report a usable floor")
	}

	// A 32-byte body whose value exceeds uint64 is malformed: the floor is a uint64
	// downstream, so accepting it would truncate the taker's number.
	tooBig := make([]byte, 32)
	tooBig[23] = 1 // bit 64 set => does not fit uint64
	_, _, err := decodeMinOut(append(minOutPhaseTag[:], tooBig...))
	require.ErrorIs(t, err, ErrMinOutMalformed, "a min-out above uint64 must be refused, not truncated")

	// The exact uint64 maximum is still accepted — the guard is a bound, not an
	// off-by-one that rejects the largest legal floor.
	maxU64 := make([]byte, 32)
	for i := 24; i < 32; i++ {
		maxU64[i] = 0xff
	}
	got, present, err := decodeMinOut(append(minOutPhaseTag[:], maxU64...))
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, uint64(1<<64-1), got)
}

// TestMinOutTagIsDistinctFromEveryOtherPhaseTag: the four hookData kinds must never
// collide, because the routing decision (sync vs async) is made from the tag. A
// collision would route a swap to the wrong handler.
func TestMinOutTagIsDistinctFromEveryOtherPhaseTag(t *testing.T) {
	others := map[string][4]byte{
		"async intent": {'D', 'I', '0', '1'},
		"async settle": {'D', 'S', '0', '1'},
		"maker":        {'M', '9', '9', '9'},
	}
	for name, tag := range others {
		require.NotEqualf(t, minOutPhaseTag, tag, "the DM01 tag must not collide with %s", name)
		// And a body carrying another tag must not be decoded as a floor.
		_, present, err := decodeMinOut(append(tag[:], make([]byte, 32)...))
		require.NoError(t, err)
		require.Falsef(t, present, "%s hookData must not be read as a min-out floor", name)
	}
}

// TestMinOutGuardIsNotWiredToAnyDispatchPath records a DEFECT, not a passing
// invariant, and pins it so the state of affairs cannot drift silently.
//
// swap_minout.go's header states that the symmetric SELL hazard "is closed HERE" and
// that on the value path a market SELL with neither a price limit nor a min-out "is
// refused (ErrSellRequiresProtection)". It is not: `decodeMinOut` has no caller
// anywhere in the repository, and ErrSellRequiresProtection / ErrExactOutputNotSupported
// are never returned by any code path. The codec is correct — the ENFORCEMENT is absent.
//
// The likely history is that the guard's subject was removed: the synchronous router's
// value selectors now revert PRECOMPILE_MOVED (see TestRouterValueSelectorsAreRetired),
// leaving this guard orphaned. That makes it dead rather than exploitable — but the
// header still reads as a live control, which is how a reviewer concludes market SELLs
// are protected when nothing checks.
//
// This test asserts the CODEC contract only. If the guard is ever wired, the assertions
// here keep holding and an enforcement test belongs beside them; if it is deleted, this
// test goes with it. Either resolution is fine — silently keeping a security control
// that does not run is not.
func TestMinOutGuardIsNotWiredToAnyDispatchPath(t *testing.T) {
	// The sentinels exist and are distinct, so a future wiring has them available.
	require.NotEqual(t, ErrSellRequiresProtection, ErrExactOutputNotSupported)
	require.NotNil(t, ErrMinOutMalformed)

	// The encoder and decoder are mutual inverses — the part that IS correct.
	for _, v := range []uint64{0, 42, 1 << 40} {
		got, present, err := decodeMinOut(EncodeMinOutHookData(v))
		require.NoError(t, err)
		require.True(t, present)
		require.Equal(t, v, got)
	}
}

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

// ---------------------------------------------------------------------------
// settle9999.go — the taker-authenticated price floor.
// ---------------------------------------------------------------------------

// TestPriceLimitToCLOBIsExactIntegerMath pins that the slippage floor crossing the
// C<->D seam is computed with EXACT integer arithmetic on the ×1e8 PriceInt grid.
// The header of settle9999.go is explicit that no float64 may touch this value: an
// out-of-range float->int conversion is architecture-dependent and would fork
// consensus. The assertions below reproduce the grid value independently.
func TestPriceLimitToCLOBIsExactIntegerMath(t *testing.T) {
	// price = (s / 2^96)^2, grid = round(price * 1e8).
	grid := func(s *big.Int) *big.Int {
		u := new(big.Int).Mul(s, s)
		u.Mul(u, big.NewInt(priceScale))
		u.Add(u, new(big.Int).Lsh(big.NewInt(1), 191))
		return u.Rsh(u, 192)
	}

	// A sell (zeroForOne) at a price of 1.0 => grid value 1e8.
	one := new(big.Int).Lsh(big.NewInt(1), 96)
	got, isUpper := priceLimitToCLOB(SwapParams{ZeroForOne: true, SqrtPriceLimitX96: one})
	require.False(t, isUpper, "a zeroForOne limit is a price FLOOR")
	require.Equal(t, grid(one).Uint64(), got)
	require.Equal(t, uint64(priceScale), got, "sqrt price 1.0 is exactly 1.00000000 on the grid")

	// A buy (!zeroForOne) bounds from above.
	_, isUpper = priceLimitToCLOB(SwapParams{ZeroForOne: false, SqrtPriceLimitX96: one})
	require.True(t, isUpper, "a oneForZero limit is a price CEILING")

	// Rounding is to NEAREST, not floor. The client's sqrtPriceLimitX96 is a FLOORED
	// sqrt, so its exact square sits an epsilon below the price the taker meant;
	// flooring the grid too would quantize a "50" limit to 49.99999999 and fail to
	// cross a maker resting exactly at 50 — the taker's own limit would lock them out.
	//
	// Sampling must stay where the grid value actually FITS a uint64 (prices near 1.0,
	// i.e. s near 2^96). A uniform draw across the whole sqrt-price band lands in the
	// overflow branch essentially every time and would never exercise rounding at all.
	const seed = 99887766
	r := rand.New(rand.NewSource(seed))
	lo := new(big.Int).Lsh(big.NewInt(1), 92)
	width := new(big.Int).Lsh(big.NewInt(1), 97)

	roundedUp := 0
	for range 5000 {
		s := new(big.Int).Add(lo, new(big.Int).Rand(r, width))
		want := grid(s)
		if !want.IsUint64() || want.Sign() <= 0 {
			continue
		}
		got, _ := priceLimitToCLOB(SwapParams{ZeroForOne: true, SqrtPriceLimitX96: s})
		require.Equalf(t, want.Uint64(), got, "seed=%d grid value must be exact for s=%v", seed, s)

		// Count the cases where nearest and floor DISAGREE, so the assertion above is
		// known to be discriminating rather than vacuously true.
		fl := new(big.Int).Mul(s, s)
		fl.Mul(fl, big.NewInt(priceScale))
		fl.Rsh(fl, 192)
		if fl.Cmp(want) != 0 {
			roundedUp++
		}
	}
	require.Greaterf(t, roundedUp, 100,
		"the sweep must actually hit cases where round-to-nearest differs from floor, "+
			"or it cannot detect the rounding direction (hit %d)", roundedUp)
}

// TestPriceLimitSentinelsMeanUnbounded: the V4 "no limit" sentinels must map to 0
// (no floor), on the correct side each. Treating a sentinel as a real limit would
// refuse every fill.
func TestPriceLimitSentinelsMeanUnbounded(t *testing.T) {
	for name, p := range map[string]SwapParams{
		"nil limit":            {ZeroForOne: true, SqrtPriceLimitX96: nil},
		"zero limit":           {ZeroForOne: true, SqrtPriceLimitX96: big.NewInt(0)},
		"negative limit":       {ZeroForOne: true, SqrtPriceLimitX96: big.NewInt(-1)},
		"sell at MinSqrtRatio": {ZeroForOne: true, SqrtPriceLimitX96: MinSqrtRatio},
		"sell below MinSqrtRatio": {ZeroForOne: true,
			SqrtPriceLimitX96: new(big.Int).Sub(MinSqrtRatio, big.NewInt(1))},
		"buy at MaxSqrtRatio": {ZeroForOne: false, SqrtPriceLimitX96: MaxSqrtRatio},
		"buy above MaxSqrtRatio": {ZeroForOne: false,
			SqrtPriceLimitX96: new(big.Int).Add(MaxSqrtRatio, big.NewInt(1))},
	} {
		got, _ := priceLimitToCLOB(p)
		require.Zerof(t, got, "%s must mean unbounded (0), not a real limit", name)
	}
}

// TestPriceLimitFailsOpenAboveTheUint64Grid records a DEFECT rather than asserting a
// desirable property.
//
// The grid value is a uint64. When a legitimate limit squares to more than
// 2^64-1 hundred-millionths — i.e. any price above ~1.8e11 quote-per-base, which a
// pair with mismatched decimals reaches easily — priceLimitToCLOB returns 0, and 0
// means "no limit". So the taker's slippage floor is SILENTLY DROPPED at exactly the
// prices where it is hardest to reason about, rather than the swap being refused.
//
// Fail-open on a slippage bound is the wrong direction: a taker who asked for
// protection gets none, and nothing tells them. The safe behaviour is to refuse the
// swap (or widen the grid), never to quietly proceed unprotected. This test pins the
// CURRENT behaviour so a fix is a deliberate, visible change.
func TestPriceLimitFailsOpenAboveTheUint64Grid(t *testing.T) {
	// Find a sqrt price whose grid value exceeds uint64 but which is still a legal
	// in-band V4 price, so this is a reachable input and not a contrived one.
	s := new(big.Int).Sub(MaxSqrtRatio, big.NewInt(1))
	u := new(big.Int).Mul(s, s)
	u.Mul(u, big.NewInt(priceScale))
	u.Rsh(u, 192)
	require.False(t, u.IsUint64(),
		"precondition: a near-max in-band price does overflow the uint64 grid")

	got, isUpper := priceLimitToCLOB(SwapParams{ZeroForOne: true, SqrtPriceLimitX96: s})
	require.False(t, isUpper, "still reported as a floor")
	require.Zerof(t, got,
		"DEFECT (pinned): an in-band limit above the uint64 grid returns 0 == NO LIMIT, "+
			"silently dropping the taker's slippage floor instead of refusing the swap")

	// Directly below the overflow the floor is still carried, which is what makes the
	// cliff above a silent behaviour change rather than a uniformly unsupported range.
	small := new(big.Int).Lsh(big.NewInt(1), 96)
	carried, _ := priceLimitToCLOB(SwapParams{ZeroForOne: true, SqrtPriceLimitX96: small})
	require.Positive(t, carried, "an ordinary price does carry its floor")
}

// TestMinOutEncodingIsBigEndian pins the wire byte order explicitly: the floor sits
// in the LOW 8 bytes of a 32-byte word, big-endian, so it matches an ABI uint256.
func TestMinOutEncodingIsBigEndian(t *testing.T) {
	enc := EncodeMinOutHookData(0x0102030405060708)
	require.Equal(t, minOutPhaseTag[:], enc[:4])
	require.Equal(t, make([]byte, 24), enc[4:28], "the high 24 bytes must be zero padding")
	require.Equal(t, uint64(0x0102030405060708), binary.BigEndian.Uint64(enc[28:36]))
}
