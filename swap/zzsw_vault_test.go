// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package swap

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// CONSERVATION. reserve[asset] is the precompile's own ledger of what it owes.
// It must equal what the vault actually holds at every observable instant, for
// both asset kinds, and it must never be credited by anything but an OBSERVED
// inbound delta.
// ---------------------------------------------------------------------------

// TestZZConservationAcrossMixedSequence drives a long deterministic sequence
// mixing both asset kinds and all three transitions, asserting the invariant
// after EVERY step rather than only at the end.
func TestZZConservationAcrossMixedSequence(t *testing.T) {
	e := newEnv(t0)
	e.db().fund(usdc, maker, big.NewInt(1_000_000))
	e.db().fund(wbtc, user, big.NewInt(1_000_000))

	check := func(step string) {
		zzEqBig(t, e.reserve(usdc), e.db().bal(usdc, swapAddr), "usdc reserve vs vault after %s", step)
		zzEqBig(t, e.reserve(wbtc), e.db().bal(wbtc, swapAddr), "wbtc reserve vs vault after %s", step)
		zzEqBig(t, e.reserve(native), e.db().nativeBal(swapAddr), "native reserve vs vault after %s", step)
	}
	check("genesis")

	type live struct {
		id    common.Hash
		asset common.Address
		amt   *big.Int
		pre   [preimageLen]byte
	}
	var open []live

	lock := func(from common.Address, asset common.Address, amt *big.Int, secret byte) {
		if asset == native {
			e.db().fundNative(swapAddr, amt) // the EVM moved msg.value in before Run
		}
		p := preimageOf(secret)
		id, _, err := e.lock(from, hashOf(p), user, from, asset, amt, timeout, false)
		require.NoError(t, err)
		open = append(open, live{id, asset, amt, p})
		check("lock " + asset.Hex())
	}

	lock(maker, usdc, big.NewInt(100), 0x01)
	lock(user, wbtc, big.NewInt(70), 0x02)
	lock(maker, native, big.NewInt(5_000), 0x03)
	lock(maker, usdc, big.NewInt(250), 0x04)
	lock(maker, native, big.NewInt(9), 0x05)
	lock(user, wbtc, big.NewInt(1), 0x06)

	// The reserve is the exact sum of the live locks, per asset.
	sum := map[common.Address]*big.Int{}
	for _, l := range open {
		if sum[l.asset] == nil {
			sum[l.asset] = big.NewInt(0)
		}
		sum[l.asset].Add(sum[l.asset], l.amt)
	}
	for asset, want := range sum {
		zzEqBig(t, want, e.reserve(asset), "reserve is the sum of live locks for %s", asset.Hex())
	}

	// Claim the even-indexed swaps, then expire and refund the rest.
	for i, l := range open {
		if i%2 != 0 {
			continue
		}
		_, err := e.claim(watcher, l.id, l.pre, false)
		require.NoError(t, err)
		check("claim")
		sum[l.asset].Sub(sum[l.asset], l.amt)
		zzEqBig(t, sum[l.asset], e.reserve(l.asset), "reserve falls by exactly the claimed amount")
	}

	e.setNow(timeout)
	for i, l := range open {
		if i%2 == 0 {
			continue
		}
		_, err := e.refund(watcher, l.id, false)
		require.NoError(t, err)
		check("refund")
		sum[l.asset].Sub(sum[l.asset], l.amt)
		zzEqBig(t, sum[l.asset], e.reserve(l.asset), "reserve falls by exactly the refunded amount")
	}

	// Everything settled: all three reserves and all three vault balances are zero.
	for _, asset := range []common.Address{usdc, wbtc, native} {
		zzEqBig(t, big.NewInt(0), e.reserve(asset), "reserve drained for %s", asset.Hex())
	}
	zzEqBig(t, big.NewInt(0), e.db().bal(usdc, swapAddr))
	zzEqBig(t, big.NewInt(0), e.db().bal(wbtc, swapAddr))
	zzEqBig(t, big.NewInt(0), e.db().nativeBal(swapAddr))
	check("final")
}

// TestZZReservesAreIsolatedPerAsset proves one asset's ledger cannot fund
// another's payout — the reserve is keyed by asset, so a native lock can never
// underwrite an ERC-20 claim.
func TestZZReservesAreIsolatedPerAsset(t *testing.T) {
	e := newEnv(t0)
	amt := big.NewInt(1000)
	e.db().fund(usdc, maker, amt)
	e.db().fundNative(swapAddr, amt)

	pre := preimageOf(0x91)
	h := hashOf(pre)
	idTok, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
	require.NoError(t, err)
	idNat, _, err := e.lock(maker, hashOf(preimageOf(0x92)), user, maker, native, amt, timeout, false)
	require.NoError(t, err)

	zzEqBig(t, amt, e.reserve(usdc))
	zzEqBig(t, amt, e.reserve(native))
	zzEqBig(t, big.NewInt(0), e.reserve(wbtc), "an untouched asset has no reserve")

	// Settling the token leg leaves the native ledger exactly where it was.
	_, err = e.claim(watcher, idTok, pre, false)
	require.NoError(t, err)
	zzEqBig(t, big.NewInt(0), e.reserve(usdc))
	zzEqBig(t, amt, e.reserve(native), "settling one asset must not move another's reserve")
	zzEqBig(t, amt, e.db().nativeBal(swapAddr))
	require.Equal(t, StatusLocked, zzStatus(t, e, idNat))
}

// ---------------------------------------------------------------------------
// NATIVE custody. delivered = balanceOf(swapAddr) − reserve[native] is the value
// THIS call carried. Exact-delta, so short, zero and over-delivery all refuse.
// ---------------------------------------------------------------------------

func TestZZNativeExactDeltaRequired(t *testing.T) {
	amt := big.NewInt(1_000)
	h := hashOf(preimageOf(0xA1))

	deliveries := map[string]*big.Int{
		"zero_value":     big.NewInt(0),
		"one_short":      new(big.Int).Sub(amt, big.NewInt(1)),
		"one_over":       new(big.Int).Add(amt, big.NewInt(1)),
		"half":           new(big.Int).Div(amt, big.NewInt(2)),
		"double":         new(big.Int).Mul(amt, big.NewInt(2)),
		"wildly_overpay": big.NewInt(1_000_000),
	}
	for name, delivered := range deliveries {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t0)
			e.db().fundNative(swapAddr, delivered)

			_, _, err := e.lock(maker, h, user, maker, native, amt, timeout, false)
			require.ErrorIs(t, err, ErrDeltaMismatch)
			zzEqBig(t, big.NewInt(0), e.reserve(native), "a refused lock credits nothing")
			zzEqBig(t, delivered, e.db().nativeBal(swapAddr), "and moves nothing")
		})
	}

	// Exactly right is accepted.
	e := newEnv(t0)
	e.db().fundNative(swapAddr, amt)
	_, _, err := e.lock(maker, h, user, maker, native, amt, timeout, false)
	require.NoError(t, err)
	zzEqBig(t, amt, e.reserve(native))
}

// TestZZNativeSequentialLocksMeasureOnlyTheirOwnValue pins the "surplus over the
// accounted reserve" idiom: after a lock, the reserve absorbs the balance, so the
// NEXT lock sees only the value its own call delivered.
func TestZZNativeSequentialLocksMeasureOnlyTheirOwnValue(t *testing.T) {
	e := newEnv(t0)
	a, b, c := big.NewInt(100), big.NewInt(250), big.NewInt(7)

	e.db().fundNative(swapAddr, a)
	id1, _, err := e.lock(maker, hashOf(preimageOf(0xA2)), user, maker, native, a, timeout, false)
	require.NoError(t, err)

	// A second lock that delivers `b` must lock `b`, not a+b.
	e.db().fundNative(swapAddr, b)
	_, _, err = e.lock(maker, hashOf(preimageOf(0xA3)), user, maker, native, new(big.Int).Add(a, b), timeout, false)
	require.ErrorIs(t, err, ErrDeltaMismatch, "the earlier lock's value is already accounted, not re-lockable")

	id2, _, err := e.lock(maker, hashOf(preimageOf(0xA3)), user, maker, native, b, timeout, false)
	require.NoError(t, err)
	zzEqBig(t, new(big.Int).Add(a, b), e.reserve(native))
	zzConservedNative(t, e)

	// Settle one, then a third lock still measures only its own value.
	_, err = e.claim(watcher, id1, preimageOf(0xA2), false)
	require.NoError(t, err)
	zzEqBig(t, b, e.reserve(native))
	zzConservedNative(t, e)

	e.db().fundNative(swapAddr, c)
	id3, _, err := e.lock(maker, hashOf(preimageOf(0xA4)), user, maker, native, c, timeout, false)
	require.NoError(t, err)
	zzEqBig(t, new(big.Int).Add(b, c), e.reserve(native))
	zzConservedNative(t, e)
	require.Equal(t, StatusLocked, zzStatus(t, e, id2))
	require.Equal(t, StatusLocked, zzStatus(t, e, id3))
}

// TestZZNativeDonationBreaksTheNextLock documents a real consequence of measuring
// delivery as (balance − reserve): native LUX force-sent to swapAddr by anyone
// (selfdestruct, a coinbase payout, a plain transfer) is indistinguishable from
// msg.value. It makes the NEXT native lock over-deliver and be refused, and it is
// then absorbed by whichever lock finally reconciles. See the report.
func TestZZNativeDonationBreaksTheNextLock(t *testing.T) {
	e := newEnv(t0)
	amt := big.NewInt(1_000)
	h := hashOf(preimageOf(0xA5))

	// A griefer force-sends 1 wei; the honest locker then delivers exactly `amt`.
	e.db().fundNative(swapAddr, big.NewInt(1))
	e.db().fundNative(swapAddr, amt)

	_, _, err := e.lock(maker, h, user, maker, native, amt, timeout, false)
	require.ErrorIs(t, err, ErrDeltaMismatch,
		"an unsolicited native donation makes a correctly-built lock fail")
	zzEqBig(t, big.NewInt(0), e.reserve(native))

	// The donation is not lost to the contract: a lock sized to the full observed
	// surplus succeeds and absorbs it into that swap.
	absorb := new(big.Int).Add(amt, big.NewInt(1))
	id, _, err := e.lock(maker, h, user, maker, native, absorb, timeout, false)
	require.NoError(t, err)
	zzEqBig(t, absorb, e.reserve(native), "the donation is absorbed into the reconciling swap")
	zzConservedNative(t, e)

	// And it settles normally to the recipient, donation included.
	_, err = e.claim(watcher, id, preimageOf(0xA5), false)
	require.NoError(t, err)
	zzEqBig(t, absorb, e.db().nativeBal(user))
	zzEqBig(t, big.NewInt(0), e.reserve(native))
	zzConservedNative(t, e)
}

// TestZZNativeSettlementIsValueConserving asserts the Sub/Add pair moves value
// rather than minting it: the total native supply across all accounts is
// unchanged by a lock and by a settlement.
func TestZZNativeSettlementIsValueConserving(t *testing.T) {
	e := newEnv(t0)
	amt := big.NewInt(12_345)
	e.db().setNative(maker, big.NewInt(50_000))

	supply := func() *big.Int {
		total := big.NewInt(0)
		for _, v := range e.db().native {
			total.Add(total, v)
		}
		return total
	}

	// The EVM debits the maker and credits swapAddr before Run; supply is constant.
	e.db().setNative(maker, new(big.Int).Sub(e.db().nativeBal(maker), amt))
	e.db().fundNative(swapAddr, amt)
	before := supply()

	id, _, err := e.lock(maker, hashOf(preimageOf(0xA6)), user, maker, native, amt, timeout, false)
	require.NoError(t, err)
	zzEqBig(t, before, supply(), "locking mints nothing")

	_, err = e.claim(watcher, id, preimageOf(0xA6), false)
	require.NoError(t, err)
	zzEqBig(t, before, supply(), "settling mints nothing")
	zzEqBig(t, amt, e.db().nativeBal(user))
	zzEqBig(t, big.NewInt(0), e.db().nativeBal(swapAddr))
}

// ---------------------------------------------------------------------------
// ERC-20 custody: the transferFrom-delta idiom.
// ---------------------------------------------------------------------------

// TestZZFeeOnTransferRejectedAtEveryRate proves a short-delivering token is
// REFUSED rather than silently under-locked, whatever the fee rate.
func TestZZFeeOnTransferRejectedAtEveryRate(t *testing.T) {
	amt := big.NewInt(1_000_000)
	h := hashOf(preimageOf(0xB5))

	for _, bps := range []int{1, 30, 100, 5000, 9999, 10000} {
		e := newEnv(t0)
		e.db().fund(usdc, maker, amt)
		e.db().feeBps[usdc] = bps

		_, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
		require.ErrorIsf(t, err, ErrDeltaMismatch, "fee of %d bps must be refused", bps)
		zzEqBig(t, big.NewInt(0), e.reserve(usdc), "nothing credited at %d bps", bps)
	}

	// A token that delivers exactly what was asked is accepted.
	e := newEnv(t0)
	e.db().fund(usdc, maker, amt)
	_, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
	require.NoError(t, err)
	zzEqBig(t, amt, e.reserve(usdc))
	zzConserved(t, e, usdc)
}

// TestZZPayoutTransferFailureAborts covers the pay-out half of the vault seam:
// a token whose transfer reverts on the way OUT must surface ErrTransferFailed
// from both claim and refund, so the EVM reverts the frame rather than marking a
// swap settled that never paid.
func TestZZPayoutTransferFailureAborts(t *testing.T) {
	amt := big.NewInt(1000)
	pre := preimageOf(0xB6)
	h := hashOf(pre)

	t.Run("claim", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fund(usdc, maker, amt)
		id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
		require.NoError(t, err)

		e.db().failTransfer[usdc] = true // the token starts reverting after the lock
		_, err = e.claim(watcher, id, pre, false)
		require.ErrorIs(t, err, ErrTransferFailed)

		// No value moved. (The mock does not roll back storage the way the EVM
		// reverts the frame, so the status write above it is expected to persist
		// here; the invariant under test is that NOTHING WAS PAID.)
		zzEqBig(t, big.NewInt(0), e.db().bal(usdc, user), "a failed transfer pays nobody")
		zzEqBig(t, amt, e.db().bal(usdc, swapAddr), "the value stays in the vault")
	})

	t.Run("refund", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fund(usdc, maker, amt)
		id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
		require.NoError(t, err)
		e.setNow(timeout)

		e.db().failTransfer[usdc] = true
		_, err = e.refund(maker, id, false)
		require.ErrorIs(t, err, ErrTransferFailed)
		zzEqBig(t, big.NewInt(0), e.db().bal(usdc, maker))
		zzEqBig(t, amt, e.db().bal(usdc, swapAddr))
	})
}

// TestZZPushOutSurfacesTokenError unit-tests the pay-out helper directly, since
// the wrapped cause is what an operator reads in the revert.
func TestZZPushOutSurfacesTokenError(t *testing.T) {
	m := newMockState()
	m.fund(usdc, swapAddr, big.NewInt(1000))

	require.NoError(t, pushOut(m, usdc, user, big.NewInt(400)))
	zzEqBig(t, big.NewInt(400), m.bal(usdc, user))

	// Over-drawing the vault reverts in the token and surfaces as ErrTransferFailed.
	err := pushOut(m, usdc, user, big.NewInt(10_000))
	require.ErrorIs(t, err, ErrTransferFailed)
	require.ErrorContains(t, err, errTokenReverted.Error(), "the token's own cause is preserved")

	m.failTransfer[usdc] = true
	require.ErrorIs(t, pushOut(m, usdc, user, big.NewInt(1)), ErrTransferFailed)
}

// ---------------------------------------------------------------------------
// A StateDB without the erc20Vault capability refuses ERC-20 custody cleanly on
// BOTH sides — it never fakes a credit and never fakes a payout.
// ---------------------------------------------------------------------------

func TestZZVaultUnavailableRefusesTokenCustody(t *testing.T) {
	db := zzNewNoVault()
	_, hasVault := interface{}(db).(erc20Vault)
	require.False(t, hasVault, "this fixture must NOT carry the capability")

	st := &zzState{db: db, blk: &mockBlock{ts: t0}}
	c := &SwapContract{}
	amt := big.NewInt(1000)
	pre := preimageOf(0xC5)
	h := hashOf(pre)

	// lock: refused before any state is written.
	_, _, err := c.Run(st, maker, swapAddr, zzLockInput(h, user, maker, usdc, amt, timeout), 10_000_000, false)
	require.ErrorIs(t, err, ErrVaultUnavailable)
	require.Equal(t, uint8(StatusNone), loadStatus(db, computeSwapID(h, user, maker, usdc, amt, timeout, maker, 0)))
	zzEqBig(t, big.NewInt(0), loadReserve(db, usdc))

	// claim/refund: seed a Locked ERC-20 swap (a state this StateDB could have
	// inherited from a host that once had the capability) and prove settlement
	// refuses rather than marking it paid. Each transition gets its OWN swap:
	// effects precede the interaction, so the failed claim leaves this mock's
	// status flipped where a real EVM would revert the whole frame.
	claimID, refundID := common.Hash{0xC5}, common.Hash{0xC6}
	zzSeedLocked(db, claimID, h, user, maker, usdc, amt, timeout)
	zzSeedLocked(db, refundID, h, user, maker, usdc, amt, timeout)
	addReserve(db, usdc, new(big.Int).Mul(amt, big.NewInt(2)))

	_, _, err = c.Run(st, watcher, swapAddr, zzClaimInput(claimID, pre), 10_000_000, false)
	require.ErrorIs(t, err, ErrVaultUnavailable)

	st.blk = &mockBlock{ts: timeout}
	_, _, err = c.Run(st, watcher, swapAddr, zzRefundInput(refundID), 10_000_000, false)
	require.ErrorIs(t, err, ErrVaultUnavailable)

	// Neither settlement paid anyone: the capability is missing, so no ERC-20
	// value can have moved at all.
	require.Empty(t, db.m.tokens, "a vault-less StateDB has no token ledger to move")

	// Native custody still works on the very same StateDB: the missing capability
	// is scoped to ERC-20, not to the precompile.
	st.blk = &mockBlock{ts: t0}
	db.m.fundNative(swapAddr, amt)
	ret, _, err := c.Run(st, maker, swapAddr, zzLockInput(hashOf(preimageOf(0xC8)), user, maker, native, amt, timeout), 10_000_000, false)
	require.NoError(t, err, "native needs no vault capability")
	var nativeID common.Hash
	copy(nativeID[:], ret)
	_, _, err = c.Run(st, watcher, swapAddr, zzClaimInput(nativeID, preimageOf(0xC8)), 10_000_000, false)
	require.NoError(t, err)
	zzEqBig(t, amt, db.m.nativeBal(user))
}

func TestZZPayOutDispatchesOnAssetKind(t *testing.T) {
	// Native routes to the balance ledger.
	m := newMockState()
	m.fundNative(swapAddr, big.NewInt(500))
	require.NoError(t, payOut(m, native, user, big.NewInt(500)))
	zzEqBig(t, big.NewInt(500), m.nativeBal(user))

	// An ERC-20 routes to the vault capability.
	m2 := newMockState()
	m2.fund(usdc, swapAddr, big.NewInt(500))
	require.NoError(t, payOut(m2, usdc, user, big.NewInt(500)))
	zzEqBig(t, big.NewInt(500), m2.bal(usdc, user))

	// Without the capability, only the ERC-20 side refuses.
	nv := zzNewNoVault()
	nv.m.fundNative(swapAddr, big.NewInt(500))
	require.NoError(t, payOut(nv, native, user, big.NewInt(500)))
	require.ErrorIs(t, payOut(nv, usdc, user, big.NewInt(500)), ErrVaultUnavailable)
}

// ---------------------------------------------------------------------------
// pushOutNative's own guards. SubBalance is uint256-modular and does NOT revert
// from a precompile, so an unguarded underflow would WRAP swapAddr's balance to
// ~2^256 — minting the chain's entire supply. The guard must fail loud instead.
// ---------------------------------------------------------------------------

func TestZZNativePayoutRefusesUnderflow(t *testing.T) {
	m := newMockState()
	m.fundNative(swapAddr, big.NewInt(100))

	require.ErrorIs(t, pushOutNative(m, user, big.NewInt(101)), ErrReserveUnderflow)
	zzEqBig(t, big.NewInt(100), m.nativeBal(swapAddr), "a refused payout moves nothing")
	zzEqBig(t, big.NewInt(0), m.nativeBal(user))

	// The boundary: exactly the balance is payable.
	require.NoError(t, pushOutNative(m, user, big.NewInt(100)))
	zzEqBig(t, big.NewInt(0), m.nativeBal(swapAddr))
	zzEqBig(t, big.NewInt(100), m.nativeBal(user))

	// And an empty vault pays nothing at all.
	require.ErrorIs(t, pushOutNative(m, user, big.NewInt(1)), ErrReserveUnderflow)
}

// TestZZNativePayoutRefusesOversizeAmount covers the uint256 conversion guard.
// Through Run the amount is read from a 32-byte word and can never exceed
// 2^256−1, so this branch is reachable only by calling the helper directly — it
// is defence in depth for a future caller that is not the ABI decoder.
func TestZZNativePayoutRefusesOversizeAmount(t *testing.T) {
	m := newMockState()
	m.fundNative(swapAddr, big.NewInt(1000))

	tooBig := new(big.Int).Lsh(big.NewInt(1), 256) // 2^256 — one past uint256
	require.ErrorIs(t, pushOutNative(m, user, tooBig), ErrTransferFailed)
	zzEqBig(t, big.NewInt(1000), m.nativeBal(swapAddr))
	zzEqBig(t, big.NewInt(0), m.nativeBal(user))

	// The largest representable uint256 is not itself rejected by the conversion;
	// it is refused by the balance guard instead.
	maxU256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	require.ErrorIs(t, pushOutNative(m, user, maxU256), ErrReserveUnderflow)
}

// TestZZNativeClaimRefusesWhenVaultDrained drives the underflow guard through
// Run: the reserve still says the swap is funded, but the vault's real native
// balance is gone. Settlement must abort, not wrap.
func TestZZNativeClaimRefusesWhenVaultDrained(t *testing.T) {
	pre := preimageOf(0xC7)
	h := hashOf(pre)
	amt := big.NewInt(1000)

	t.Run("claim", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fundNative(swapAddr, amt)
		id, _, err := e.lock(maker, h, user, maker, native, amt, timeout, false)
		require.NoError(t, err)

		e.db().setNative(swapAddr, big.NewInt(0)) // the vault's real balance vanishes
		_, err = e.claim(watcher, id, pre, false)
		require.ErrorIs(t, err, ErrReserveUnderflow)
		zzEqBig(t, big.NewInt(0), e.db().nativeBal(user), "no value conjured for the recipient")
		zzEqBig(t, big.NewInt(0), e.db().nativeBal(swapAddr), "and none wrapped into the vault")
	})

	t.Run("refund", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fundNative(swapAddr, amt)
		id, _, err := e.lock(maker, h, user, maker, native, amt, timeout, false)
		require.NoError(t, err)

		e.db().setNative(swapAddr, new(big.Int).Sub(amt, big.NewInt(1))) // one short
		e.setNow(timeout)
		_, err = e.refund(maker, id, false)
		require.ErrorIs(t, err, ErrReserveUnderflow)
		zzEqBig(t, big.NewInt(0), e.db().nativeBal(maker))
	})
}
