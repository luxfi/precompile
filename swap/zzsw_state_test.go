// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package swap

import (
	"math"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// subReserve: the conservation guard. Under the invariant it never fires, so a
// false return means the trie is corrupt — and settlement must ABORT rather than
// wrap the reserve around 2^256.
// ---------------------------------------------------------------------------

func TestZZSubReserveRefusesUnderflow(t *testing.T) {
	m := newMockState()
	storeReserve(m, usdc, big.NewInt(100))

	require.False(t, subReserve(m, usdc, big.NewInt(101)), "debiting more than held must refuse")
	zzEqBig(t, big.NewInt(100), loadReserve(m, usdc), "a refused debit leaves the reserve intact")

	// The boundary: exactly the balance is debitable, one more is not.
	require.True(t, subReserve(m, usdc, big.NewInt(100)))
	zzEqBig(t, big.NewInt(0), loadReserve(m, usdc))
	require.False(t, subReserve(m, usdc, big.NewInt(1)))

	// An empty reserve for an untouched asset refuses any debit.
	require.False(t, subReserve(m, wbtc, big.NewInt(1)))
	require.True(t, subReserve(m, wbtc, big.NewInt(0)), "a zero debit is trivially satisfiable")

	// Partial debits compose exactly.
	storeReserve(m, wbtc, big.NewInt(10))
	require.True(t, subReserve(m, wbtc, big.NewInt(3)))
	require.True(t, subReserve(m, wbtc, big.NewInt(7)))
	require.False(t, subReserve(m, wbtc, big.NewInt(1)))
	zzEqBig(t, big.NewInt(0), loadReserve(m, wbtc))
}

// TestZZSettlementAbortsOnReserveUnderflow drives the guard through Run: a Locked
// swap whose amount exceeds the reserve backing it (only reachable via a corrupt
// trie) must refuse to settle rather than pay out value it never took in.
func TestZZSettlementAbortsOnReserveUnderflow(t *testing.T) {
	pre := preimageOf(0xF1)
	h := hashOf(pre)
	amt := big.NewInt(1000)

	t.Run("claim", func(t *testing.T) {
		e := newEnv(t0)
		id := common.Hash{0xF1}
		zzSeedLocked(e.db(), id, h, user, maker, usdc, amt, timeout)
		// No reserve credited, and the vault genuinely holds nothing.
		e.db().fund(usdc, swapAddr, amt) // even WITH tokens present, the ledger governs

		_, err := e.claim(watcher, id, pre, false)
		require.ErrorIs(t, err, ErrReserveUnderflow)
		zzEqBig(t, big.NewInt(0), e.db().bal(usdc, user), "an unbacked swap pays nobody")
		zzEqBig(t, amt, e.db().bal(usdc, swapAddr))
		require.Equal(t, StatusLocked, loadStatus(e.db(), id), "and stays unsettled")
	})

	t.Run("refund", func(t *testing.T) {
		e := newEnv(t0)
		id := common.Hash{0xF2}
		zzSeedLocked(e.db(), id, h, user, maker, usdc, amt, timeout)
		addReserve(e.db(), usdc, new(big.Int).Sub(amt, big.NewInt(1))) // one short
		e.setNow(timeout)

		_, err := e.refund(maker, id, false)
		require.ErrorIs(t, err, ErrReserveUnderflow)
		zzEqBig(t, big.NewInt(0), e.db().bal(usdc, maker))
		require.Equal(t, StatusLocked, loadStatus(e.db(), id))
	})

	t.Run("exactly_backed_settles", func(t *testing.T) {
		e := newEnv(t0)
		id := common.Hash{0xF3}
		zzSeedLocked(e.db(), id, h, user, maker, usdc, amt, timeout)
		addReserve(e.db(), usdc, amt) // exactly backed
		e.db().fund(usdc, swapAddr, amt)

		_, err := e.claim(watcher, id, pre, false)
		require.NoError(t, err, "the guard must not refuse an exactly-backed swap")
		zzEqBig(t, amt, e.db().bal(usdc, user))
		zzEqBig(t, big.NewInt(0), e.reserve(usdc))
	})
}

// ---------------------------------------------------------------------------
// wordUint64: a uint64 read out of a right-aligned 32-byte ABI word. Any value
// that does not fit is refused rather than truncated — a silently truncated
// timeout would move a swap's expiry.
// ---------------------------------------------------------------------------

func TestZZWordUint64RejectsOversizeWord(t *testing.T) {
	// Every one of the 24 high bytes is checked, not just the first.
	for i := 0; i < 24; i++ {
		w := make([]byte, 32)
		w[i] = 0x01
		_, ok := wordUint64(w)
		require.Falsef(t, ok, "a non-zero byte at index %d must be refused", i)
	}

	// The low 8 bytes are the value, and all of them count.
	for i := 24; i < 32; i++ {
		w := make([]byte, 32)
		w[i] = 0x01
		v, ok := wordUint64(w)
		require.Truef(t, ok, "byte %d is part of the uint64", i)
		require.Equal(t, uint64(1)<<(8*(31-i)), v)
	}

	// Boundaries.
	zero := make([]byte, 32)
	v, ok := wordUint64(zero)
	require.True(t, ok)
	require.Equal(t, uint64(0), v)

	maxWord := make([]byte, 32)
	for i := 24; i < 32; i++ {
		maxWord[i] = 0xFF
	}
	v, ok = wordUint64(maxWord)
	require.True(t, ok)
	require.Equal(t, uint64(math.MaxUint64), v)

	// One past uint64: the byte just above the value window.
	overflow := make([]byte, 32)
	overflow[23] = 0x01
	_, ok = wordUint64(overflow)
	require.False(t, ok, "2^64 must not truncate to 0")

	allOnes := make([]byte, 32)
	for i := range allOnes {
		allOnes[i] = 0xFF
	}
	_, ok = wordUint64(allOnes)
	require.False(t, ok)
}

// TestZZOversizeTimeoutRefusedAtLock drives the same guard through Run. Without
// it, a timeout word of 2^64 would truncate to 0 and be read as a past expiry.
func TestZZOversizeTimeoutRefusedAtLock(t *testing.T) {
	amt := big.NewInt(1000)
	h := hashOf(preimageOf(0xF4))

	for i := 0; i < 24; i++ {
		e := newEnv(t0)
		e.db().fund(usdc, maker, amt)

		in := zzLockInput(h, user, maker, usdc, amt, timeout)
		in[4+160+i] = 0x01 // poison one high byte of the timeout word

		zzUnchanged(t, e.db(), func() {
			_, _, err := e.c.Run(e.st, maker, swapAddr, in, e.gas, false)
			require.ErrorIsf(t, err, ErrBadArgs, "high byte %d of the timeout word", i)
			require.ErrorContains(t, err, "timeout exceeds uint64")
		})
	}
}

// ---------------------------------------------------------------------------
// Timeout bounds, including the uint64 overflow at swap.go:237. The check is
//
//	timeout < t0+MinTimeout || timeout > t0+MaxTimeout
//
// computed in wrapping uint64 arithmetic with NO overflow guard.
// ---------------------------------------------------------------------------

func TestZZTimeoutBoundsAreInclusive(t *testing.T) {
	amt := big.NewInt(1000)
	h := hashOf(preimageOf(0xF5))

	cases := []struct {
		name    string
		timeout uint64
		ok      bool
	}{
		{"one_below_min", t0 + MinTimeout - 1, false},
		{"exactly_min", t0 + MinTimeout, true},
		{"one_above_min", t0 + MinTimeout + 1, true},
		{"midrange", t0 + MinTimeout + (MaxTimeout-MinTimeout)/2, true},
		{"one_below_max", t0 + MaxTimeout - 1, true},
		{"exactly_max", t0 + MaxTimeout, true},
		{"one_above_max", t0 + MaxTimeout + 1, false},
		{"zero", 0, false},
		{"equal_to_now", t0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t0)
			e.db().fund(usdc, maker, amt)
			_, _, err := e.lock(maker, h, user, maker, usdc, amt, tc.timeout, false)
			if tc.ok {
				require.NoError(t, err)
				zzEqBig(t, amt, e.reserve(usdc))
				return
			}
			require.ErrorIs(t, err, ErrTimeoutBounds)
			zzEqBig(t, big.NewInt(0), e.reserve(usdc), "a refused lock takes no custody")
		})
	}
}

// TestZZTimeoutBoundsOverflowNearUint64Max documents the ACTUAL behaviour of the
// unguarded `t0+MinTimeout` / `t0+MaxTimeout` additions at swap.go:237.
//
// Two regimes exist above 2^64 − MaxTimeout:
//
//   - BOTH sums wrap (t0 > 2^64 − MinTimeout): the lower bound wraps to a small
//     number, so `timeout < t0+MinTimeout` stops rejecting past timeouts and a
//     lock is admitted whose expiry is ALREADY PAST. It is refundable on the
//     spot and never claimable — the ≥10-minute window the bound exists to
//     guarantee is gone.
//   - ONLY the upper sum wraps: the admissible interval inverts to the empty set
//     and EVERY timeout is refused, so no native or token lock is possible at all.
//
// Both need a block timestamp within ~30 days of 2^64 seconds (~584 billion
// years), so neither is reachable on a real chain. Pinned so the boundary
// behaviour is a decision rather than an accident.
func TestZZTimeoutBoundsOverflowNearUint64Max(t *testing.T) {
	amt := big.NewInt(1000)
	pre := preimageOf(0xF6)
	h := hashOf(pre)

	t.Run("both_sums_wrap_admits_a_past_timeout", func(t *testing.T) {
		// t0 chosen so t0+MinTimeout wraps to exactly 0.
		now := uint64(math.MaxUint64) - MinTimeout + 1
		require.Equal(t, uint64(0), now+MinTimeout, "lower bound wraps to zero")
		upper := now + MaxTimeout
		require.Less(t, upper, now, "upper bound wraps too")

		past := uint64(1000) // astronomically BEFORE `now`
		require.Less(t, past, now)
		require.LessOrEqual(t, past, upper, "and lands inside the wrapped window")

		e := newEnv(now)
		e.db().fund(usdc, maker, amt)
		id, _, err := e.lock(maker, h, user, maker, usdc, amt, past, false)
		require.NoError(t, err, "the unguarded addition ADMITS a timeout in the past")

		// The consequence: born expired. Never claimable, refundable immediately.
		_, err = e.claim(user, id, pre, false)
		require.ErrorIs(t, err, ErrExpired, "a swap admitted this way can never be claimed")

		_, err = e.refund(maker, id, false)
		require.NoError(t, err, "and is refundable in the very block it was created")
		zzEqBig(t, amt, e.db().bal(usdc, maker))
		zzConserved(t, e, usdc)
	})

	t.Run("only_upper_sum_wraps_refuses_everything", func(t *testing.T) {
		now := uint64(math.MaxUint64) - MaxTimeout + 1
		require.Greater(t, now+MinTimeout, now, "lower bound does NOT wrap here")
		require.Less(t, now+MaxTimeout, now, "upper bound does")

		e := newEnv(now)
		e.db().fund(usdc, maker, amt)
		for _, to := range []uint64{0, 1000, now, now + MinTimeout, now + MinTimeout + 1, math.MaxUint64} {
			_, _, err := e.lock(maker, h, user, maker, usdc, amt, to, false)
			require.ErrorIsf(t, err, ErrTimeoutBounds, "timeout %d must be refused in the inverted window", to)
		}
		zzEqBig(t, big.NewInt(0), e.reserve(usdc))
	})

	t.Run("just_below_the_wrap_still_sane", func(t *testing.T) {
		// One second below the wrap point, arithmetic is exact and the bounds behave.
		now := uint64(math.MaxUint64) - MaxTimeout
		require.Greater(t, now+MaxTimeout, now)

		e := newEnv(now)
		e.db().fund(usdc, maker, new(big.Int).Mul(amt, big.NewInt(2)))
		_, _, err := e.lock(maker, h, user, maker, usdc, amt, now+MinTimeout-1, false)
		require.ErrorIs(t, err, ErrTimeoutBounds)
		_, _, err = e.lock(maker, h, user, maker, usdc, amt, now+MinTimeout, false)
		require.NoError(t, err)
	})
}

// TestZZDustGuardBoundary pins the floor exactly: MinSwapAmount is admissible,
// one below it is not, and a zero amount never takes custody.
func TestZZDustGuardBoundary(t *testing.T) {
	h := hashOf(preimageOf(0xF7))
	require.Equal(t, 0, MinSwapAmount.Cmp(big.NewInt(1)), "the global floor is 1")

	below := new(big.Int).Sub(MinSwapAmount, big.NewInt(1))
	e := newEnv(t0)
	e.db().fund(usdc, maker, big.NewInt(1_000))
	_, _, err := e.lock(maker, h, user, maker, usdc, below, timeout, false)
	require.ErrorIs(t, err, ErrDustAmount)
	zzEqBig(t, big.NewInt(0), e.reserve(usdc))

	_, _, err = e.lock(maker, h, user, maker, usdc, MinSwapAmount, timeout, false)
	require.NoError(t, err, "exactly MinSwapAmount is lockable")
	zzEqBig(t, MinSwapAmount, e.reserve(usdc))

	// Native honours the same floor.
	e2 := newEnv(t0)
	_, _, err = e2.lock(maker, h, user, maker, native, big.NewInt(0), timeout, false)
	require.ErrorIs(t, err, ErrDustAmount, "the dust floor precedes the delta measurement")
	zzEqBig(t, big.NewInt(0), e2.reserve(native))
}

// TestZZZeroAddressGuards covers the three non-zero requirements independently,
// including the case where the SAME address fills both roles (legal) and where
// the asset is zero (legal — that is native, not a missing asset).
func TestZZZeroAddressGuards(t *testing.T) {
	amt := big.NewInt(1000)
	h := hashOf(preimageOf(0xF8))

	t.Run("zero_hashlock", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fund(usdc, maker, amt)
		_, _, err := e.lock(maker, common.Hash{}, user, maker, usdc, amt, timeout, false)
		require.ErrorIs(t, err, ErrZeroHashlock)
	})

	t.Run("zero_recipient", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fund(usdc, maker, amt)
		_, _, err := e.lock(maker, h, common.Address{}, maker, usdc, amt, timeout, false)
		require.ErrorIs(t, err, ErrZeroRecipient, "a swap must never be claimable into the burn address")
	})

	t.Run("zero_refund", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fund(usdc, maker, amt)
		_, _, err := e.lock(maker, h, user, common.Address{}, usdc, amt, timeout, false)
		require.ErrorIs(t, err, ErrZeroRefund, "an expired swap must never burn its refund")
	})

	t.Run("zero_asset_is_native_not_a_refusal", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fundNative(swapAddr, amt)
		_, _, err := e.lock(maker, h, user, maker, common.Address{}, amt, timeout, false)
		require.NoError(t, err, "asset == address(0) selects native LUX")
		zzEqBig(t, amt, e.reserve(native))
	})

	t.Run("recipient_equal_to_refund_is_legal", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fund(usdc, maker, amt)
		_, _, err := e.lock(maker, h, maker, maker, usdc, amt, timeout, false)
		require.NoError(t, err, "a self-swap is degenerate but not malformed")
	})

	// The guards are checked in a fixed order, so the FIRST offending field is the
	// one reported even when several are zero.
	e := newEnv(t0)
	_, _, err := e.lock(maker, common.Hash{}, common.Address{}, common.Address{}, usdc, big.NewInt(0), 0, false)
	require.ErrorIs(t, err, ErrZeroHashlock)
}

// ---------------------------------------------------------------------------
// getSwap: the full tuple, word by word, before and after settlement.
// ---------------------------------------------------------------------------

func TestZZGetSwapTupleLayout(t *testing.T) {
	e := newEnv(t0)
	amt := big.NewInt(0xDEADBEEF)
	pre := preimageOf(0xF9)
	h := hashOf(pre)
	// Two locks happen below (amt, then MinSwapAmount); fund for both.
	e.db().fund(usdc, maker, new(big.Int).Add(amt, MinSwapAmount))

	// An unknown swap is an all-zero tuple — status None and nothing else.
	unknown, err := e.getSwap(common.Hash{0xAB}, true)
	require.NoError(t, err)
	require.Len(t, unknown, 8*32)
	require.Equal(t, make([]byte, 8*32), unknown, "a nonexistent swap reads as all zeroes")
	require.Equal(t, StatusNone, unknown[31])

	id, _, err := e.lock(maker, h, user, watcher, usdc, amt, timeout, false)
	require.NoError(t, err)

	out, err := e.getSwap(id, true)
	require.NoError(t, err)
	require.Len(t, out, 8*32)
	require.Equal(t, StatusLocked, out[31])
	require.Equal(t, h, common.BytesToHash(out[1*32:2*32]))
	require.Equal(t, user, common.BytesToAddress(out[2*32:3*32]))
	require.Equal(t, watcher, common.BytesToAddress(out[3*32:4*32]))
	require.Equal(t, usdc, common.BytesToAddress(out[4*32:5*32]))
	zzEqBig(t, amt, new(big.Int).SetBytes(out[5*32:6*32]))
	require.Equal(t, timeout, new(big.Int).SetBytes(out[6*32:7*32]).Uint64())
	require.Equal(t, make([]byte, 32), out[7*32:8*32], "no preimage before the claim")

	// After the claim only status and preimage change; the terms are immutable.
	_, err = e.claim(watcher, id, pre, false)
	require.NoError(t, err)
	after, err := e.getSwap(id, true)
	require.NoError(t, err)
	require.Equal(t, StatusClaimed, after[31])
	require.Equal(t, pre[:], after[7*32:8*32])
	require.Equal(t, out[1*32:7*32], after[1*32:7*32], "settlement must not rewrite the terms")

	// A refunded swap records no preimage.
	id2, _, err := e.lock(maker, hashOf(preimageOf(0xFA)), user, watcher, usdc, MinSwapAmount, timeout, false)
	require.NoError(t, err)
	e.setNow(timeout)
	_, err = e.refund(maker, id2, false)
	require.NoError(t, err)
	ref, err := e.getSwap(id2, true)
	require.NoError(t, err)
	require.Equal(t, StatusRefunded, ref[31])
	require.Equal(t, make([]byte, 32), ref[7*32:8*32], "a refund reveals no secret")
}

// ---------------------------------------------------------------------------
// Storage layout: distinct keys never collide, and the singleton slots are
// distinct from every per-swap field slot.
// ---------------------------------------------------------------------------

func TestZZStorageSlotsAreDistinct(t *testing.T) {
	idA, idB := common.Hash{0x01}, common.Hash{0x02}
	seen := map[common.Hash]string{}
	add := func(name string, slot common.Hash) {
		prev, dup := seen[slot]
		require.Falsef(t, dup, "%s collides with %s", name, prev)
		seen[slot] = name
	}

	for f := byte(fStatus); f <= fPreimage; f++ {
		add("A/field", swapFieldSlot(idA, f))
		add("B/field", swapFieldSlot(idB, f))
	}
	add("nonce", nonceSlot())
	add("guard", guardSlot())
	add("preimageIdx/A", preimageIdxSlot(idA))
	add("preimageIdx/B", preimageIdxSlot(idB))
	add("reserve/usdc", reserveSlot(usdc))
	add("reserve/wbtc", reserveSlot(wbtc))
	add("reserve/native", reserveSlot(native))

	require.Len(t, seen, 8*2+2+2+3)

	// Deterministic: the same key always yields the same slot.
	require.Equal(t, swapFieldSlot(idA, fAmount), swapFieldSlot(idA, fAmount))
	require.Equal(t, reserveSlot(usdc), reserveSlot(usdc))
}

// TestZZFieldRoundTrips pins each accessor pair against the values that actually
// occur, including the extremes a 32-byte word can hold.
func TestZZFieldRoundTrips(t *testing.T) {
	m := newMockState()
	id := common.Hash{0x77}

	for _, s := range []uint8{StatusNone, StatusLocked, StatusClaimed, StatusRefunded, 255} {
		storeStatus(m, id, s)
		require.Equal(t, s, loadStatus(m, id))
	}

	maxU256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	for _, v := range []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(1 << 62), maxU256} {
		storeAmount(m, id, fAmount, v)
		zzEqBig(t, v, loadAmount(m, id, fAmount))
	}

	for _, v := range []uint64{0, 1, t0, timeout, math.MaxUint64} {
		storeTimeout(m, id, v)
		require.Equal(t, v, loadTimeout(m, id))
	}

	for _, a := range []common.Address{{}, maker, user, usdc, swapAddr} {
		storeAddress(m, id, fRecipient, a)
		require.Equal(t, a, loadAddress(m, id, fRecipient))
	}

	for _, n := range []uint64{0, 1, math.MaxUint64} {
		storeNonce(m, n)
		require.Equal(t, n, loadNonce(m))
	}

	for _, p := range [][preimageLen]byte{{}, preimageOf(0xFF), preimageOf(0x01)} {
		storePreimageIdx(m, common.Hash{0x99}, p)
		require.Equal(t, p, loadPreimageIdx(m, common.Hash{0x99}))
	}

	// Reserve arithmetic composes over the accessors.
	storeReserve(m, usdc, big.NewInt(0))
	addReserve(m, usdc, big.NewInt(70))
	addReserve(m, usdc, big.NewInt(30))
	zzEqBig(t, big.NewInt(100), loadReserve(m, usdc))
}

// TestZZWordHelpers covers the ABI encoders the views return.
func TestZZWordHelpers(t *testing.T) {
	require.Equal(t, append(make([]byte, 31), 1), boolWord(true))
	require.Equal(t, make([]byte, 32), boolWord(false))
	require.Equal(t, append(make([]byte, 31), 42), uint8Word(42))
	require.Equal(t, make([]byte, 32), uint8Word(0))

	w := uint64Word(math.MaxUint64)
	require.Len(t, w, 32)
	require.Equal(t, make([]byte, 24), w[:24], "a uint64 is right-aligned in the word")
	require.Equal(t, uint64(math.MaxUint64), new(big.Int).SetBytes(w).Uint64())

	require.Equal(t, common.BytesToHash(usdc.Bytes()).Bytes(), addressWord(usdc))
	require.Equal(t, make([]byte, 32), addressWord(common.Address{}))

	// wordAddress reads the low 20 bytes and ignores the padding.
	padded := make([]byte, 32)
	copy(padded[12:], usdc.Bytes())
	require.Equal(t, usdc, wordAddress(padded))
	dirty := make([]byte, 32)
	copy(dirty[12:], usdc.Bytes())
	for i := 0; i < 12; i++ {
		dirty[i] = 0xFF
	}
	require.Equal(t, usdc, wordAddress(dirty), "high padding is not part of the address")
}

// TestZZPreimageMatches pins the hashlock predicate directly.
func TestZZPreimageMatches(t *testing.T) {
	p := preimageOf(0x5E)
	require.True(t, preimageMatches(p, hashOf(p)))
	require.False(t, preimageMatches(p, common.Hash{}))
	require.False(t, preimageMatches(p, hashOf(preimageOf(0x5F))))
	require.False(t, preimageMatches([preimageLen]byte{}, hashOf(p)))
	require.True(t, preimageMatches([preimageLen]byte{}, hashOf([preimageLen]byte{})))

	// A single flipped bit anywhere in the secret breaks the match.
	for i := 0; i < preimageLen; i++ {
		var q [preimageLen]byte
		copy(q[:], p[:])
		q[i] ^= 0x01
		require.Falsef(t, preimageMatches(q, hashOf(p)), "bit flip at byte %d must not match", i)
	}
}

// TestZZGuardPrimitives pins enterGuard/exitGuard as a pair.
func TestZZGuardPrimitives(t *testing.T) {
	m := newMockState()
	require.True(t, enterGuard(m), "a fresh guard is takeable")
	require.False(t, enterGuard(m), "a held guard refuses")
	require.False(t, enterGuard(m), "and keeps refusing")

	exitGuard(m)
	require.True(t, enterGuard(m), "a released guard is takeable again")
	exitGuard(m)

	// Only the low byte carries the flag; a dirty high word still reads as held.
	var dirty common.Hash
	dirty[0] = 0xFF
	dirty[31] = 1
	m.SetState(swapAddr, guardSlot(), dirty)
	require.False(t, enterGuard(m))
	exitGuard(m)
	require.Equal(t, common.Hash{}, m.GetState(swapAddr, guardSlot()), "exit clears the whole word")
}
