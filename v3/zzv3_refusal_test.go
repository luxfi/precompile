// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Refusals: everything the precompile must say no to. A concentrated-liquidity
// AMM holding custody has to be exactly as good at refusing as it is at
// executing, so each guard gets its own named case rather than a bulk sweep.
package v3

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/dex"
	"github.com/stretchr/testify/require"
)

const plentyGas = uint64(50_000_000)

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

// TestRun_TruncatedSelector proves an input shorter than the 4-byte selector is
// refused with the gas untouched — there is nothing to dispatch on, so nothing
// is charged.
func TestRun_TruncatedSelector(t *testing.T) {
	e := newEnv()
	for _, in := range [][]byte{nil, {}, {0x01}, {0x01, 0x02}, {0x01, 0x02, 0x03}} {
		_, rem, err := e.callRaw(trader, in, plentyGas, false)
		require.ErrorIs(t, err, ErrShortInput)
		require.Equal(t, plentyGas, rem, "an undispatched call must not be charged")
	}
	// Exactly four bytes dispatches (and then fails as an unknown selector).
	_, _, err := e.callRaw(trader, []byte{0x01, 0x02, 0x03, 0x04}, plentyGas, false)
	require.ErrorIs(t, err, ErrUnknownSelector)
}

// TestRun_UnknownSelectorNamesIt proves an unrecognised selector is refused and
// the error carries the selector, so a caller can tell a typo from a gas failure.
func TestRun_UnknownSelectorNamesIt(t *testing.T) {
	e := newEnv()
	_, rem, err := e.callRaw(trader, []byte{0xde, 0xad, 0xbe, 0xef}, plentyGas, false)
	require.ErrorIs(t, err, ErrUnknownSelector)
	require.Contains(t, err.Error(), "0xdeadbeef")
	require.Equal(t, plentyGas, rem)

	// A near-miss on a real selector is still unknown: no prefix matching.
	near := selBytes(selSwap)
	near[3] ^= 0x01
	_, _, err = e.callRaw(trader, near, plentyGas, false)
	require.ErrorIs(t, err, ErrUnknownSelector)
}

// TestReadOnly_EveryMutatorRefused proves ALL FIVE state transitions refuse a
// static call, and does so before any argument parsing — a malformed static call
// must still be reported as the read-only violation it is.
func TestReadOnly_EveryMutatorRefused(t *testing.T) {
	e := fundedEnv(e18x1000)
	maxU := new(big.Int).Set(maxUint128)
	limit := new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1))

	mutators := map[string][]byte{
		"initialize": inInitialize(stdPool, dex.Q96),
		"mint":       inMint(stdPool, -600, 600, oneE18),
		"burn":       inBurn(stdPool, -600, 600, oneE18),
		"collect":    inCollect(stdPool, -600, 600, maxU, maxU),
		"swap":       inSwap(stdPool, true, new(big.Int).Neg(oneE18), limit),
	}
	for name, in := range mutators {
		_, rem, err := e.callRaw(trader, in, plentyGas, true)
		require.ErrorIsf(t, err, ErrReadOnly, "%s must refuse a static call", name)
		require.Equal(t, plentyGas, rem, "%s: a refused static call must not be charged", name)

		// Truncated arguments do not change the answer: readOnly is checked first.
		_, _, err = e.callRaw(trader, short(in), plentyGas, true)
		require.ErrorIsf(t, err, ErrReadOnly, "%s must refuse a malformed static call as read-only", name)
	}

	// And the four views are permitted under exactly the same flag.
	views := map[string][]byte{
		"slot0":     inSlot0(stdPool),
		"liquidity": inLiquidity(stdPool),
		"ticks":     inTicks(stdPool, 0),
		"positions": inPositions(stdPool, trader, -600, 600),
	}
	for name, in := range views {
		_, _, err := e.callRaw(trader, in, plentyGas, true)
		require.NoErrorf(t, err, "%s must be callable in a static call", name)
	}
}

// TestReentrancy_EveryMutatorRefused proves the global guard blocks all five
// mutators — the state a malicious token's callback would find mid-custody — and
// that the views stay readable, since they take no guard and write nothing.
func TestReentrancy_EveryMutatorRefused(t *testing.T) {
	e := fundedEnv(e18x1000)
	_, _, err := e.mint(trader, stdPool, -600, 600, oneE18, false)
	require.NoError(t, err)

	require.True(t, enterGuard(e.db()), "guard must be free before the test sets it")
	defer exitGuard(e.db())

	maxU := new(big.Int).Set(maxUint128)
	limit := new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1))
	for name, in := range map[string][]byte{
		"initialize": inInitialize(poolCfg{c0: tokenA, c1: tokenC, fee: 3000, tickSpacing: 60}, dex.Q96),
		"mint":       inMint(stdPool, -600, 600, oneE18),
		"burn":       inBurn(stdPool, -600, 600, oneE18),
		"collect":    inCollect(stdPool, -600, 600, maxU, maxU),
		"swap":       inSwap(stdPool, true, new(big.Int).Neg(mustBig("1000000000000000")), limit),
	} {
		_, _, err := e.callRaw(trader, in, plentyGas, false)
		require.ErrorIsf(t, err, ErrReentrant, "%s must be refused while the guard is held", name)
	}

	// Reads are still served: they cannot corrupt a measurement in progress.
	_, _, err = e.callRaw(trader, inSlot0(stdPool), plentyGas, true)
	require.NoError(t, err)
}

// TestGuard_ReleasedAfterFailure proves the guard is released even when the call
// it wrapped failed — a mutator that errors must not wedge the precompile shut.
func TestGuard_ReleasedAfterFailure(t *testing.T) {
	e := fundedEnv(e18x1000)

	_, _, err := e.mint(trader, stdPool, -61, 60, big.NewInt(1000), false)
	require.ErrorIs(t, err, ErrTickMisaligned)

	// The guard slot is clear again, so the next call gets through.
	require.True(t, enterGuard(e.db()))
	exitGuard(e.db())
	_, _, err = e.mint(trader, stdPool, -60, 60, big.NewInt(100000), false)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Input length. Every selector must pin its argument blob to an exact size, or
// a caller can smuggle bytes past the decoder.
// ---------------------------------------------------------------------------

// TestInputLength_ShortAndLong walks every selector one byte short and one byte
// long.
//
// SEVEN of the nine pin an exact length. TWO — slot0 and liquidity — hand the
// whole blob to parsePoolKey, which only requires len >= 128, so a call carrying
// TRAILING BYTES is accepted and the extra bytes ignored (contract.go:842 and
// contract.go:859, neither preceded by a length check like the one at
// contract.go:873). Asserted here as it actually behaves, so the gap is visible
// and any future change to it shows up as a test change.
func TestInputLength_ShortAndLong(t *testing.T) {
	e := fundedEnv(e18x1000)
	maxU := new(big.Int).Set(maxUint128)
	limit := new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1))

	exact := map[string][]byte{
		"initialize": inInitialize(stdPool, dex.Q96),
		"mint":       inMint(stdPool, -600, 600, oneE18),
		"burn":       inBurn(stdPool, -600, 600, oneE18),
		"collect":    inCollect(stdPool, -600, 600, maxU, maxU),
		"swap":       inSwap(stdPool, true, new(big.Int).Neg(oneE18), limit),
		"ticks":      inTicks(stdPool, 0),
		"positions":  inPositions(stdPool, trader, -600, 600),
	}
	for name, in := range exact {
		_, _, err := e.callRaw(trader, short(in), plentyGas, false)
		require.ErrorIsf(t, err, ErrBadArgs, "%s must refuse one byte short", name)
		_, _, err = e.callRaw(trader, long(in), plentyGas, false)
		require.ErrorIsf(t, err, ErrBadArgs, "%s must refuse one byte long", name)
	}

	// slot0 / liquidity: short is refused (parsePoolKey needs its 128 bytes)...
	for name, in := range map[string][]byte{"slot0": inSlot0(stdPool), "liquidity": inLiquidity(stdPool)} {
		_, _, err := e.callRaw(trader, short(in), plentyGas, true)
		require.ErrorIsf(t, err, ErrBadArgs, "%s must refuse one byte short", name)

		// ...but one byte long is ACCEPTED and ignored. This is the gap: these two
		// selectors have no exact-length check. Harmless for custody (both are
		// read-only and their work is a fixed number of slot reads), but it is a
		// looser ABI surface than the other seven.
		_, _, err = e.callRaw(trader, long(in), plentyGas, true)
		require.NoErrorf(t, err, "%s currently accepts trailing bytes", name)
	}
}

// TestPoolKey_ShortBlobRefused proves the 128-byte pool key is checked before any
// field is read, so a truncated key cannot address state.
func TestPoolKey_ShortBlobRefused(t *testing.T) {
	_, _, err := parsePoolKey(make([]byte, 127))
	require.ErrorIs(t, err, ErrBadArgs)
	_, _, err = parsePoolKey(nil)
	require.ErrorIs(t, err, ErrBadArgs)

	// Exactly 128 is enough (an all-zero key fails later, on currency ordering).
	_, _, err = parsePoolKey(make([]byte, 128))
	require.ErrorIs(t, err, ErrCurrencyOrder)
}

// ---------------------------------------------------------------------------
// Pool-key well-formedness.
// ---------------------------------------------------------------------------

// TestPoolKey_CurrencyOrdering proves the strict ordering rule. Equal addresses
// must be refused as firmly as reversed ones: a pool of a token against itself
// would let a "swap" launder the reserve ledger between two views of one asset.
func TestPoolKey_CurrencyOrdering(t *testing.T) {
	e := newEnv()
	for name, p := range map[string]poolCfg{
		"reversed":     {c0: tokenB, c1: tokenA, fee: 3000, tickSpacing: 60},
		"identical":    {c0: tokenA, c1: tokenA, fee: 3000, tickSpacing: 60},
		"native twice": {c0: native, c1: native, fee: 3000, tickSpacing: 60},
		"native as c1": {c0: tokenA, c1: native, fee: 3000, tickSpacing: 60},
	} {
		_, err := e.initialize(p, dex.Q96, false)
		require.ErrorIsf(t, err, ErrCurrencyOrder, "%s must be refused", name)
	}

	// Native as currency0 is the ONE ordering that is legal for the zero address.
	_, err := e.initialize(nativePool, dex.Q96, false)
	require.NoError(t, err)
}

// TestPoolKey_FeeBounds proves the fee is a fraction of one: 999_999 pips is the
// last legal value and 1_000_000 (100%) is not, because a 100% fee would let a
// swap consume input and return nothing.
func TestPoolKey_FeeBounds(t *testing.T) {
	e := newEnv()
	ok := poolCfg{c0: tokenA, c1: tokenB, fee: 999_999, tickSpacing: 60}
	_, err := e.initialize(ok, dex.Q96, false)
	require.NoError(t, err, "999_999 pips is in range")

	for _, fee := range []uint32{1_000_000, 1_000_001, 16_777_215} { // up to uint24 max
		bad := poolCfg{c0: tokenA, c1: tokenB, fee: fee, tickSpacing: 60}
		_, err := e.initialize(bad, dex.Q96, false)
		require.ErrorIsf(t, err, ErrInvalidFee, "fee %d must be refused", fee)
	}

	// Zero fee is legal (a no-fee pool is a valid configuration).
	zero := poolCfg{c0: tokenA, c1: tokenB, fee: 0, tickSpacing: 60}
	_, err = e.initialize(zero, dex.Q96, false)
	require.NoError(t, err)
}

// TestPoolKey_TickSpacingBounds proves spacing must be in [1, 16384]. Spacing 0
// is the dangerous one: every `tick % tickSpacing` in the tick math would divide
// by zero, so it has to die at the boundary.
func TestPoolKey_TickSpacingBounds(t *testing.T) {
	e := newEnv()
	for _, ts := range []int32{0, -1, -60, 16385, 1 << 20} {
		bad := poolCfg{c0: tokenA, c1: tokenB, fee: 3000, tickSpacing: ts}
		_, err := e.initialize(bad, dex.Q96, false)
		require.ErrorIsf(t, err, ErrInvalidTickSpacing, "spacing %d must be refused", ts)
	}
	for _, ts := range []int32{1, 60, 16384} {
		ok := poolCfg{c0: tokenA, c1: tokenB, fee: uint32(1000 + ts), tickSpacing: ts}
		_, err := e.initialize(ok, dex.Q96, false)
		require.NoErrorf(t, err, "spacing %d is in range", ts)
	}
}

// TestPoolKey_SpacingIsSignedNotUnsigned proves the spacing word is read as a
// two's-complement int24, so a negative spacing arrives as negative and is
// refused — rather than being read as a huge positive and passing the upper
// bound check by wrapping.
func TestPoolKey_SpacingIsSignedNotUnsigned(t *testing.T) {
	words := pkWords(tokenA, tokenB, 3000, 0)
	copy(words[96:128], intWord(big.NewInt(-60)).Bytes())
	_, _, err := parsePoolKey(words)
	require.ErrorIs(t, err, ErrInvalidTickSpacing)
}

// ---------------------------------------------------------------------------
// Tick decoding and range validation.
// ---------------------------------------------------------------------------

// TestParseTick_RejectsBeforeTruncation is the tick-math boundary that matters
// most. parseTick returns an int32, so a 256-bit word must be range-checked
// while it is still a big.Int: 2^32 + 60 truncates to exactly 60, an aligned,
// perfectly in-range tick. If the check ran after the cast, that word would mint
// a position at tick 60 while the pool believed it had validated something else.
func TestParseTick_RejectsBeforeTruncation(t *testing.T) {
	twoPow32 := new(big.Int).Lsh(big.NewInt(1), 32)

	// Words whose low 32 bits are an in-range, spacing-aligned tick.
	for _, hi := range []*big.Int{
		twoPow32,                                   // 2^32 + 60 -> int32 60
		new(big.Int).Lsh(big.NewInt(1), 64),        // 2^64 + 60 -> int32 60
		new(big.Int).Lsh(big.NewInt(1), 200),       // 2^200 + 60 -> int32 60
		new(big.Int).Mul(twoPow32, big.NewInt(77)), // 77*2^32 + 60 -> int32 60
	} {
		word := new(big.Int).Add(hi, big.NewInt(60))
		require.EqualValues(t, 60, int32(word.Int64()), "fixture must truncate to 60")
		got, err := parseTick(rawWord(word))
		require.ErrorIsf(t, err, dex.ErrTickOutOfRange, "word %s must be refused, not truncated", word)
		require.Zero(t, got)
	}

	// The same attack one step outside each band edge.
	for _, v := range []*big.Int{
		big.NewInt(int64(dex.MaxTick) + 1),
		big.NewInt(int64(dex.MinTick) - 1),
		new(big.Int).Lsh(big.NewInt(1), 255), // most negative int256
	} {
		_, err := parseTick(intWord(v).Bytes())
		require.ErrorIsf(t, err, dex.ErrTickOutOfRange, "tick %s must be refused", v)
	}

	// Both band edges themselves are accepted.
	for _, v := range []int32{dex.MinTick, -1, 0, 1, dex.MaxTick} {
		got, err := parseTick(tickWord(v))
		require.NoErrorf(t, err, "tick %d is in band", v)
		require.Equal(t, v, got)
	}
}

// TestParseTick_TruncationRefusedThroughEveryEntryPoint proves the guard is on
// the decode path all four selectors share, not just in one of them.
func TestParseTick_TruncationRefusedThroughEveryEntryPoint(t *testing.T) {
	e := fundedEnv(e18x1000)
	evil := rawWord(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 32), big.NewInt(60)))

	mint := append(selBytes(selMint), stdPool.words()...)
	mint = append(mint, evil...)
	mint = append(mint, tickWord(600)...)
	mint = append(mint, uintArg(oneE18)...)
	_, _, err := e.callRaw(trader, mint, plentyGas, false)
	require.ErrorIs(t, err, dex.ErrTickOutOfRange)

	// The upper tick decodes through the same guard.
	mint2 := append(selBytes(selMint), stdPool.words()...)
	mint2 = append(mint2, tickWord(-600)...)
	mint2 = append(mint2, evil...)
	mint2 = append(mint2, uintArg(oneE18)...)
	_, _, err = e.callRaw(trader, mint2, plentyGas, false)
	require.ErrorIs(t, err, dex.ErrTickOutOfRange)

	burn := append(selBytes(selBurn), stdPool.words()...)
	burn = append(burn, evil...)
	burn = append(burn, tickWord(600)...)
	burn = append(burn, uintArg(oneE18)...)
	_, _, err = e.callRaw(trader, burn, plentyGas, false)
	require.ErrorIs(t, err, dex.ErrTickOutOfRange)

	coll := append(selBytes(selCollect), stdPool.words()...)
	coll = append(coll, evil...)
	coll = append(coll, tickWord(600)...)
	coll = append(coll, uintArg(big.NewInt(1))...)
	coll = append(coll, uintArg(big.NewInt(1))...)
	_, _, err = e.callRaw(trader, coll, plentyGas, false)
	require.ErrorIs(t, err, dex.ErrTickOutOfRange)

	ticks := append(selBytes(selTicks), stdPool.words()...)
	ticks = append(ticks, evil...)
	_, _, err = e.callRaw(trader, ticks, plentyGas, true)
	require.ErrorIs(t, err, dex.ErrTickOutOfRange)

	pos := append(selBytes(selPositions), stdPool.words()...)
	pos = append(pos, addressWord(trader)...)
	pos = append(pos, evil...)
	pos = append(pos, tickWord(600)...)
	_, _, err = e.callRaw(trader, pos, plentyGas, true)
	require.ErrorIs(t, err, dex.ErrTickOutOfRange)

	// positions' UPPER tick too.
	pos2 := append(selBytes(selPositions), stdPool.words()...)
	pos2 = append(pos2, addressWord(trader)...)
	pos2 = append(pos2, tickWord(-600)...)
	pos2 = append(pos2, evil...)
	_, _, err = e.callRaw(trader, pos2, plentyGas, true)
	require.ErrorIs(t, err, dex.ErrTickOutOfRange)
}

// TestValidateTickRange proves the three position-bound rules independently:
// strict ordering, band membership, and spacing alignment.
func TestValidateTickRange(t *testing.T) {
	// lower must be STRICTLY below upper — an empty range has no liquidity to own.
	require.ErrorIs(t, validateTickRange(60, 60, 60), dex.ErrInvalidTickRange)
	require.ErrorIs(t, validateTickRange(120, 60, 60), dex.ErrInvalidTickRange)
	require.ErrorIs(t, validateTickRange(0, -60, 60), dex.ErrInvalidTickRange)

	// Band membership. parseTick already refuses these upstream, so this is the
	// defence-in-depth layer and is only reachable by calling in directly.
	require.ErrorIs(t, validateTickRange(dex.MinTick-1, 0, 1), dex.ErrTickOutOfRange)
	require.ErrorIs(t, validateTickRange(0, dex.MaxTick+1, 1), dex.ErrTickOutOfRange)

	// Alignment, on each side independently.
	require.ErrorIs(t, validateTickRange(-61, 60, 60), ErrTickMisaligned)
	require.ErrorIs(t, validateTickRange(-60, 61, 60), ErrTickMisaligned)
	require.ErrorIs(t, validateTickRange(1, 2, 60), ErrTickMisaligned)

	// Aligned, ordered, in band.
	require.NoError(t, validateTickRange(-60, 60, 60))
	require.NoError(t, validateTickRange(0, 60, 60))
	require.NoError(t, validateTickRange(-887220, 887220, 60)) // widest 60-aligned range
	require.NoError(t, validateTickRange(dex.MinTick, dex.MaxTick, 1))
}

// TestMisalignedTicksRefusedOnBothSides proves alignment is enforced through the
// real entry points, on the lower and the upper tick separately.
func TestMisalignedTicksRefusedOnBothSides(t *testing.T) {
	e := fundedEnv(e18x1000)
	for _, r := range [][2]int32{{-61, 600}, {-600, 601}, {-1, 1}, {59, 121}} {
		_, _, err := e.mint(trader, stdPool, r[0], r[1], oneE18, false)
		require.ErrorIsf(t, err, ErrTickMisaligned, "range [%d,%d] must be refused", r[0], r[1])
		_, _, err = e.burn(trader, stdPool, r[0], r[1], oneE18)
		require.ErrorIsf(t, err, ErrTickMisaligned, "burn [%d,%d] must be refused", r[0], r[1])
	}
}

// ---------------------------------------------------------------------------
// Pool lifecycle refusals.
// ---------------------------------------------------------------------------

// TestUninitializedPoolRefused proves mint, burn and swap all require a pool to
// exist. Without the check they would read an all-zero price and divide by it.
func TestUninitializedPoolRefused(t *testing.T) {
	e := newEnv()
	e.db().fund(tokenA, trader, e18x1000)
	e.db().fund(tokenB, trader, e18x1000)
	limit := new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1))

	_, _, err := e.mint(trader, stdPool, -600, 600, oneE18, false)
	require.ErrorIs(t, err, dex.ErrPoolNotInitialized)
	_, _, err = e.burn(trader, stdPool, -600, 600, oneE18)
	require.ErrorIs(t, err, dex.ErrPoolNotInitialized)
	_, _, err = e.swap(trader, stdPool, true, new(big.Int).Neg(oneE18), limit)
	require.ErrorIs(t, err, dex.ErrPoolNotInitialized)
}

// TestInitialize_SqrtPriceBounds proves the initial price must lie in
// [MIN_SQRT_RATIO, MAX_SQRT_RATIO) — the half-open band the tick math is defined
// on. Zero is the one that matters: it is also the "pool does not exist"
// sentinel, so a pool initialized at zero would be permanently unusable.
func TestInitialize_SqrtPriceBounds(t *testing.T) {
	e := newEnv()
	for name, sp := range map[string]*big.Int{
		"zero":           big.NewInt(0),
		"one":            big.NewInt(1),
		"below min":      new(big.Int).Sub(dex.MinSqrtRatio, big.NewInt(1)),
		"at max":         new(big.Int).Set(dex.MaxSqrtRatio),
		"above max":      new(big.Int).Add(dex.MaxSqrtRatio, big.NewInt(1)),
		"absurdly above": new(big.Int).Lsh(big.NewInt(1), 200),
		"full uint256":   new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)),
	} {
		_, err := e.initialize(stdPool, sp, false)
		require.ErrorIsf(t, err, dex.ErrInvalidSqrtPrice, "%s must be refused", name)
	}

	// Both ends of the legal half-open band are accepted.
	require.False(t, isInitialized(e.db(), poolIdOf(stdPool)), "no failed attempt may have created the pool")
	tick, err := e.initialize(stdPool, dex.MinSqrtRatio, false)
	require.NoError(t, err)
	require.Equal(t, dex.MinTick, tick)

	e2 := newEnv()
	tick, err = e2.initialize(stdPool, new(big.Int).Sub(dex.MaxSqrtRatio, big.NewInt(1)), false)
	require.NoError(t, err)
	require.Equal(t, dex.MaxTick-1, tick)
}

// TestInitialize_TwiceRefused proves a second initialize cannot reprice a live
// pool — repricing under existing liquidity is a free-money bug.
func TestInitialize_TwiceRefused(t *testing.T) {
	e := fundedEnv(e18x1000)
	_, _, err := e.mint(trader, stdPool, -600, 600, oneE18, false)
	require.NoError(t, err)

	_, err = e.initialize(stdPool, new(big.Int).Mul(dex.Q96, big.NewInt(2)), false)
	require.ErrorIs(t, err, dex.ErrPoolAlreadyInitialized)

	sp, tick := e.slot0(stdPool)
	eqBig(t, dex.Q96, sp)
	require.Equal(t, int32(0), tick)
}

// ---------------------------------------------------------------------------
// Amount refusals.
// ---------------------------------------------------------------------------

// TestZeroAmountsRefused proves mint, burn and swap all refuse a zero amount.
// A zero-liquidity mint would flip tick-bitmap bits for a position that owns
// nothing; a zero-amount swap would persist pool state for a no-op.
func TestZeroAmountsRefused(t *testing.T) {
	e := fundedEnv(e18x1000)
	limit := new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1))

	_, _, err := e.mint(trader, stdPool, -600, 600, big.NewInt(0), false)
	require.ErrorIs(t, err, ErrZeroAmount)
	_, _, err = e.burn(trader, stdPool, -600, 600, big.NewInt(0))
	require.ErrorIs(t, err, ErrZeroAmount)
	_, _, err = e.swap(trader, stdPool, true, big.NewInt(0), limit)
	require.ErrorIs(t, err, ErrZeroAmount)

	// Nothing was recorded for the refused zero mint.
	info := loadTickInfo(e.db(), poolIdOf(stdPool), -600)
	eqBig(t, big.NewInt(0), info.LiquidityGross)
}

// TestMintAmountExceedsUint128 proves liquidity is capped at uint128, the width
// the tick and position slots are declared at. A wider value would be stored
// intact but would overflow every downstream consumer that reads it as uint128.
func TestMintAmountExceedsUint128(t *testing.T) {
	e := fundedEnv(e18x1000)
	over := new(big.Int).Add(maxUint128, big.NewInt(1))
	_, _, err := e.mint(trader, stdPool, -600, 600, over, false)
	require.ErrorIs(t, err, ErrAmountTooLarge)

	huge := new(big.Int).Lsh(big.NewInt(1), 250)
	_, _, err = e.mint(trader, stdPool, -600, 600, huge, false)
	require.ErrorIs(t, err, ErrAmountTooLarge)
}

// TestBurn_MoreThanOwnedRefused proves a burn is bounded by the CALLER's own
// position, not by the pool's liquidity — one LP must not be able to burn
// another's principal out from under them.
func TestBurn_MoreThanOwnedRefused(t *testing.T) {
	e := fundedEnv(e18x1000)
	other := common.HexToAddress("0x000000000000000000000000000000000000dddd")
	e.db().fund(tokenA, other, e18x1000)
	e.db().fund(tokenB, other, e18x1000)

	_, _, err := e.mint(trader, stdPool, -600, 600, oneE18, false)
	require.NoError(t, err)
	_, _, err = e.mint(other, stdPool, -600, 600, oneE18, false)
	require.NoError(t, err)

	// One wei more than owned is refused, even though the pool holds twice that.
	_, _, err = e.burn(trader, stdPool, -600, 600, new(big.Int).Add(oneE18, big.NewInt(1)))
	require.ErrorIs(t, err, ErrInsufficientLiq)

	// A stranger with no position at all can burn nothing.
	stranger := common.HexToAddress("0x000000000000000000000000000000000000eeee")
	_, _, err = e.burn(stranger, stdPool, -600, 600, big.NewInt(1))
	require.ErrorIs(t, err, ErrInsufficientLiq)

	// Exactly what is owned is allowed, and leaves the other LP's position intact.
	_, _, err = e.burn(trader, stdPool, -600, 600, oneE18)
	require.NoError(t, err)
	otherL, _, _ := e.positionOf(other, stdPool, -600, 600)
	eqBig(t, oneE18, otherL)
}

// ---------------------------------------------------------------------------
// State-corruption backstops. These guards are unreachable through a correct
// state machine, which is exactly why they need a test: they are what stands
// between a storage bug and an unbacked pay-out.
// ---------------------------------------------------------------------------

// TestPoolLiquidityUnderflowRefused proves modifyLiquidity refuses to drive the
// pool's active liquidity negative. Reached by corrupting the pool scalar so the
// position outlives the liquidity that backs it.
func TestPoolLiquidityUnderflowRefused(t *testing.T) {
	e := fundedEnv(e18x1000)
	poolId := poolIdOf(stdPool)
	_, _, err := e.mint(trader, stdPool, -600, 600, oneE18, false)
	require.NoError(t, err)

	storeLiquidity(e.db(), poolId, big.NewInt(0)) // corrupt: pool forgot the position

	_, _, err = e.burn(trader, stdPool, -600, 600, oneE18)
	require.ErrorIs(t, err, ErrLiquidityUnderflow)
	require.True(t, loadLiquidity(e.db(), poolId).Sign() >= 0, "liquidity must never be stored negative")
}

// TestPositionLiquidityUnderflowRefused pins updatePosition's own guard. runBurn
// checks the position first, so this is only reachable directly — but it is the
// backstop that keeps a position's liquidity a natural number.
func TestPositionLiquidityUnderflowRefused(t *testing.T) {
	m := newMockState()
	poolId := poolIdOf(stdPool)
	zero := big.NewInt(0)

	require.NoError(t, updatePosition(m, poolId, trader, -600, 600, big.NewInt(100), zero, zero))
	posKey := dex.PositionKey(trader, -600, 600, salt)
	eqBig(t, big.NewInt(100), loadPosition(m, poolId, posKey).Liquidity)

	err := updatePosition(m, poolId, trader, -600, 600, big.NewInt(-101), zero, zero)
	require.ErrorIs(t, err, ErrLiquidityUnderflow)
	eqBig(t, big.NewInt(100), loadPosition(m, poolId, posKey).Liquidity)
}

// TestSwapLiquidityUnderflowRefused proves the swap loop refuses to carry a
// negative active liquidity across a tick. Reached by corrupting one tick's
// liquidityNet so crossing it removes more than was ever added.
func TestSwapLiquidityUnderflowRefused(t *testing.T) {
	e := fundedEnv(e18x1000)
	poolId := poolIdOf(stdPool)
	_, _, err := e.mint(trader, stdPool, -600, 600, oneE18, false)
	require.NoError(t, err)

	// Corrupt tick -600 so crossing it downward subtracts far more than is active.
	info := loadTickInfo(e.db(), poolId, -600)
	info.LiquidityNet = new(big.Int).Mul(oneE18, big.NewInt(1000))
	storeTickInfo(e.db(), poolId, -600, info)

	limit := new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1))
	_, _, err = e.swap(trader, stdPool, true, new(big.Int).Neg(e18x1000), limit)
	require.ErrorIs(t, err, ErrLiquidityUnderflow)
}

// ---------------------------------------------------------------------------
// Gas floors. Every selector refuses before doing any work it cannot pay for.
// ---------------------------------------------------------------------------

// TestGasFloor_EverySelector proves each entry point checks its base cost first
// and, on refusal, returns ZERO remaining gas — the caller does not get a free
// probe of pool state.
func TestGasFloor_EverySelector(t *testing.T) {
	e := fundedEnv(e18x1000)
	maxU := new(big.Int).Set(maxUint128)
	limit := new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1))

	cases := []struct {
		name string
		in   []byte
		cost uint64
	}{
		{"initialize", inInitialize(poolCfg{c0: tokenA, c1: tokenC, fee: 3000, tickSpacing: 60}, dex.Q96), GasInitialize},
		{"mint", inMint(stdPool, -600, 600, oneE18), GasMint},
		{"burn", inBurn(stdPool, -600, 600, oneE18), GasBurn},
		{"collect", inCollect(stdPool, -600, 600, maxU, maxU), GasCollect},
		{"swap", inSwap(stdPool, true, new(big.Int).Neg(oneE18), limit), GasSwapBase},
		{"slot0", inSlot0(stdPool), GasView},
		{"liquidity", inLiquidity(stdPool), GasView},
		{"ticks", inTicks(stdPool, 0), GasView},
		{"positions", inPositions(stdPool, trader, -600, 600), GasView},
	}
	for _, c := range cases {
		readOnly := c.cost == GasView
		_, rem, err := e.callRaw(trader, c.in, c.cost-1, readOnly)
		require.ErrorIsf(t, err, ErrOutOfGas, "%s must refuse below its base cost", c.name)
		require.Zerof(t, rem, "%s must leave no gas on an out-of-gas refusal", c.name)

		// At exactly the base cost the call proceeds far enough to charge it.
		_, rem, _ = e.callRaw(trader, c.in, c.cost, readOnly)
		require.Zerof(t, rem, "%s must consume exactly its base cost", c.name)
	}
}

// TestViewsChargeBeforeReading proves a view charges its fee and then returns the
// remainder, so gas accounting is the same whether the pool exists or not.
func TestViewsChargeBeforeReading(t *testing.T) {
	e := fundedEnv(e18x1000)
	_, rem, err := e.callRaw(trader, inSlot0(stdPool), plentyGas, true)
	require.NoError(t, err)
	require.Equal(t, plentyGas-GasView, rem)

	// An empty pool costs the same to read as a live one.
	empty := poolCfg{c0: tokenA, c1: tokenC, fee: 3000, tickSpacing: 60}
	_, rem2, err := e.callRaw(trader, inSlot0(empty), plentyGas, true)
	require.NoError(t, err)
	require.Equal(t, rem, rem2)
}

// TestMalformedPoolKeyStillChargesBase proves a call refused on its arguments has
// already paid the base fee — otherwise a malformed call would be a free way to
// make the node do work.
func TestMalformedPoolKeyStillChargesBase(t *testing.T) {
	e := newEnv()
	bad := poolCfg{c0: tokenB, c1: tokenA, fee: 3000, tickSpacing: 60}
	_, rem, err := e.callRaw(trader, inInitialize(bad, dex.Q96), plentyGas, false)
	require.ErrorIs(t, err, ErrCurrencyOrder)
	require.Equal(t, plentyGas-GasInitialize, rem)
}

// TestSelectorsAreDerivedFromSignatures proves each selector is the keccak of its
// canonical signature. Combined with the pinned literals in math_vectors_test.go
// this closes the loop: the constant cannot drift from the signature string, and
// the signature string cannot drift without the literal changing.
func TestSelectorsAreDerivedFromSignatures(t *testing.T) {
	require.Equal(t, methodSelector("initialize"+poolKeyABI+",uint160)"), selInitialize)
	require.Equal(t, methodSelector("mint"+poolKeyABI+",int24,int24,uint128)"), selMint)
	require.Equal(t, methodSelector("burn"+poolKeyABI+",int24,int24,uint128)"), selBurn)
	require.Equal(t, methodSelector("collect"+poolKeyABI+",int24,int24,uint128,uint128)"), selCollect)
	require.Equal(t, methodSelector("swap"+poolKeyABI+",bool,int256,uint160)"), selSwap)
	require.Equal(t, methodSelector("slot0"+poolKeyABI+")"), selSlot0)
	require.Equal(t, methodSelector("liquidity"+poolKeyABI+")"), selLiquidity)
	require.Equal(t, methodSelector("ticks"+poolKeyABI+",int24)"), selTicks)
	require.Equal(t, methodSelector("positions"+poolKeyABI+",address,int24,int24)"), selPositions)

	// All nine are distinct — no two entry points share a dispatch value.
	seen := map[uint32]bool{}
	for _, s := range []uint32{
		selInitialize, selMint, selBurn, selCollect, selSwap,
		selSlot0, selLiquidity, selTicks, selPositions,
	} {
		require.Falsef(t, seen[s], "selector %#08x is not unique", s)
		seen[s] = true
	}
	require.Len(t, seen, 9)
	require.Equal(t, 4, contract.SelectorLen)
}
