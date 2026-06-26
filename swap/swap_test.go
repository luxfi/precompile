// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package swap

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

var errTokenReverted = errors.New("mock token: transfer reverted")

// Test fixtures.
var (
	maker   = common.HexToAddress("0x1111111111111111111111111111111111111111")
	user    = common.HexToAddress("0x2222222222222222222222222222222222222222")
	watcher = common.HexToAddress("0x3333333333333333333333333333333333333333")
	usdc    = common.HexToAddress("0xA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48")
	wbtc    = common.HexToAddress("0x2260FAC5E5542A773AA44FBCFEDF7C193BC2C599")
)

const (
	t0      = uint64(1_700_000_000)
	timeout = t0 + 3600 // 1h, within [MinTimeout, MaxTimeout]
)

func preimageOf(b byte) [32]byte {
	var p [32]byte
	for i := range p {
		p[i] = b
	}
	return p
}

func hashOf(p [32]byte) common.Hash {
	s := sha256.Sum256(p[:])
	return common.BytesToHash(s[:])
}

// ---------------------------------------------------------------------------
// Selector authority: derived selectors must equal the canonical values.
// ---------------------------------------------------------------------------

func TestSelectorsAreAuthoritative(t *testing.T) {
	require.Equal(t, uint32(0x4da2c728), selLock)
	require.Equal(t, uint32(0x84cc9dfb), selClaim)
	require.Equal(t, uint32(0x7249fbb6), selRefund)
	require.Equal(t, uint32(0x3da0e66e), selGetSwap)
	require.Equal(t, uint32(0x0f622b04), selGetPreimage)
}

// ---------------------------------------------------------------------------
// Happy path: lock -> claim. Recipient is paid the stored amount, the secret is
// relayed, reserve and vault balance both fall by exactly the amount.
// ---------------------------------------------------------------------------

func TestLockThenClaim(t *testing.T) {
	e := newEnv(t0)
	amt := big.NewInt(1_000_000)
	e.db().fund(usdc, maker, amt)

	pre := preimageOf(0xAB)
	h := hashOf(pre)

	id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
	require.NoError(t, err)
	require.NotEqual(t, common.Hash{}, id)

	// Funds left the maker, sit in the vault, reserve credited.
	eqBig(t, big.NewInt(0), e.db().bal(usdc, maker))
	eqBig(t, amt, e.db().bal(usdc, swapAddr))
	eqBig(t, amt, e.reserve(usdc))
	require.Equal(t, StatusLocked, loadStatus(e.db(), id))

	// A watchtower (not the recipient) submits the claim — caller-agnostic.
	ret, err := e.claim(watcher, id, pre, false)
	require.NoError(t, err)
	require.Equal(t, boolWord(true), ret)

	// Recipient paid exactly amount; vault drained; reserve zeroed.
	eqBig(t, amt, e.db().bal(usdc, user))
	eqBig(t, big.NewInt(0), e.db().bal(usdc, swapAddr))
	eqBig(t, big.NewInt(0), e.reserve(usdc))
	require.Equal(t, StatusClaimed, loadStatus(e.db(), id))

	// Secret relayed on-chain for the counterparty leg.
	got, err := e.getPreimage(h, true)
	require.NoError(t, err)
	require.Equal(t, pre, got)
}

// ---------------------------------------------------------------------------
// Refund path: lock -> (timeout passes) -> refund to the stored refund address.
// ---------------------------------------------------------------------------

func TestLockThenRefundAfterTimeout(t *testing.T) {
	e := newEnv(t0)
	amt := big.NewInt(500)
	e.db().fund(usdc, maker, amt)
	h := hashOf(preimageOf(0x01))

	id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
	require.NoError(t, err)

	// Cannot refund before the timeout.
	_, err = e.refund(maker, id, false)
	require.ErrorIs(t, err, ErrNotExpired)

	// At/after timeout, refund pays the stored refund address (maker).
	e.setNow(timeout)
	ret, err := e.refund(watcher, id, false)
	require.NoError(t, err)
	require.Equal(t, boolWord(true), ret)
	eqBig(t, amt, e.db().bal(usdc, maker))
	eqBig(t, big.NewInt(0), e.db().bal(usdc, swapAddr))
	eqBig(t, big.NewInt(0), e.reserve(usdc))
	require.Equal(t, StatusRefunded, loadStatus(e.db(), id))
}

// ---------------------------------------------------------------------------
// Wrong preimage is rejected with NO state change and NO payout.
// ---------------------------------------------------------------------------

func TestClaimWrongPreimageRejected(t *testing.T) {
	e := newEnv(t0)
	amt := big.NewInt(777)
	e.db().fund(usdc, maker, amt)
	h := hashOf(preimageOf(0x42))

	id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
	require.NoError(t, err)

	_, err = e.claim(user, id, preimageOf(0x43), false) // wrong secret
	require.ErrorIs(t, err, ErrBadPreimage)

	// Nothing moved; swap still claimable by the right secret.
	require.Equal(t, StatusLocked, loadStatus(e.db(), id))
	eqBig(t, amt, e.db().bal(usdc, swapAddr))
	eqBig(t, amt, e.reserve(usdc))
	eqBig(t, big.NewInt(0), e.db().bal(usdc, user))

	got, err := e.getPreimage(h, true)
	require.NoError(t, err)
	require.Equal(t, [32]byte{}, got) // no secret leaked
}

// ---------------------------------------------------------------------------
// Disjoint boundary: claim requires T0 < timeout, refund requires T0 >= timeout.
// A swap is never simultaneously claimable and refundable.
// ---------------------------------------------------------------------------

func TestClaimRefundBoundaryDisjoint(t *testing.T) {
	pre := preimageOf(0x55)
	h := hashOf(pre)
	amt := big.NewInt(100)

	t.Run("just_before_timeout: claim ok, refund rejected", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fund(usdc, maker, amt)
		id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
		require.NoError(t, err)
		e.setNow(timeout - 1)
		_, err = e.refund(maker, id, false)
		require.ErrorIs(t, err, ErrNotExpired)
		_, err = e.claim(user, id, pre, false)
		require.NoError(t, err)
	})

	t.Run("at_timeout: claim rejected, refund ok", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fund(usdc, maker, amt)
		id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
		require.NoError(t, err)
		e.setNow(timeout) // exactly at timeout
		_, err = e.claim(user, id, pre, false)
		require.ErrorIs(t, err, ErrExpired)
		_, err = e.refund(maker, id, false)
		require.NoError(t, err)
	})
}

// ---------------------------------------------------------------------------
// Double-claim and double-refund are rejected (status flips once).
// ---------------------------------------------------------------------------

func TestDoubleSpendRejected(t *testing.T) {
	pre := preimageOf(0x09)
	h := hashOf(pre)
	amt := big.NewInt(2024)

	t.Run("double_claim", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fund(usdc, maker, amt)
		id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
		require.NoError(t, err)
		_, err = e.claim(user, id, pre, false)
		require.NoError(t, err)
		_, err = e.claim(user, id, pre, false)
		require.ErrorIs(t, err, ErrNotLocked)
		// Recipient paid once, not twice.
		eqBig(t, amt, e.db().bal(usdc, user))
		eqBig(t, big.NewInt(0), e.db().bal(usdc, swapAddr))
	})

	t.Run("double_refund", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fund(usdc, maker, amt)
		id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
		require.NoError(t, err)
		e.setNow(timeout)
		_, err = e.refund(maker, id, false)
		require.NoError(t, err)
		_, err = e.refund(maker, id, false)
		require.ErrorIs(t, err, ErrNotLocked)
		eqBig(t, amt, e.db().bal(usdc, maker))
	})

	t.Run("claim_then_refund_blocked", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fund(usdc, maker, amt)
		id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
		require.NoError(t, err)
		_, err = e.claim(user, id, pre, false)
		require.NoError(t, err)
		e.setNow(timeout) // even after expiry, a claimed swap cannot refund
		_, err = e.refund(maker, id, false)
		require.ErrorIs(t, err, ErrNotLocked)
	})
}

// ---------------------------------------------------------------------------
// claim/refund on a nonexistent swap, and various lock validations.
// ---------------------------------------------------------------------------

func TestLockValidation(t *testing.T) {
	amt := big.NewInt(1000)
	h := hashOf(preimageOf(0x11))

	cases := []struct {
		name     string
		hashlock common.Hash
		recip    common.Address
		ref      common.Address
		asset    common.Address
		amount   *big.Int
		timeout  uint64
		wantErr  error
	}{
		{"zero_hashlock", common.Hash{}, user, maker, usdc, amt, timeout, ErrZeroHashlock},
		{"zero_recipient", h, common.Address{}, maker, usdc, amt, timeout, ErrZeroRecipient},
		{"zero_refund", h, user, common.Address{}, usdc, amt, timeout, ErrZeroRefund},
		{"dust", h, user, maker, usdc, big.NewInt(0), timeout, ErrDustAmount},
		{"timeout_too_soon", h, user, maker, usdc, amt, t0 + MinTimeout - 1, ErrTimeoutBounds},
		{"timeout_too_late", h, user, maker, usdc, amt, t0 + MaxTimeout + 1, ErrTimeoutBounds},
		{"native_gated", h, user, maker, common.Address{}, amt, timeout, ErrNativeUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t0)
			e.db().fund(usdc, maker, amt)
			_, _, err := e.lock(maker, tc.hashlock, tc.recip, tc.ref, tc.asset, tc.amount, tc.timeout, false)
			require.ErrorIs(t, err, tc.wantErr)
			// No swap created on any rejection; no funds taken.
			eqBig(t, amt, e.db().bal(usdc, maker))
			eqBig(t, big.NewInt(0), e.db().bal(usdc, swapAddr))
			eqBig(t, big.NewInt(0), e.reserve(usdc))
		})
	}
}

func TestClaimRefundNonexistent(t *testing.T) {
	e := newEnv(t0)
	var id common.Hash
	id[0] = 0xDE
	_, err := e.claim(user, id, preimageOf(1), false)
	require.ErrorIs(t, err, ErrNotLocked)
	_, err = e.refund(user, id, false)
	require.ErrorIs(t, err, ErrNotLocked)
}

// ---------------------------------------------------------------------------
// Native (asset == 0) is gated, NOT minted: no reserve, no vault balance.
// ---------------------------------------------------------------------------

func TestNativeLockNotMinted(t *testing.T) {
	e := newEnv(t0)
	h := hashOf(preimageOf(0x77))
	_, _, err := e.lock(maker, h, user, maker, common.Address{}, big.NewInt(1e9), timeout, false)
	require.ErrorIs(t, err, ErrNativeUnsupported)
	eqBig(t, big.NewInt(0), e.reserve(common.Address{}))
	eqBig(t, big.NewInt(0), e.db().bal(common.Address{}, swapAddr))
}

// ---------------------------------------------------------------------------
// Fee-on-transfer / short-delivery is rejected at lock (delta != amount), and a
// reverting token aborts the lock with no swap created.
// ---------------------------------------------------------------------------

func TestLockFundsInSafety(t *testing.T) {
	amt := big.NewInt(1_000_000)
	h := hashOf(preimageOf(0x88))

	t.Run("fee_on_transfer_rejected", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fund(usdc, maker, amt)
		e.db().feeBps[usdc] = 30 // delivers 0.3% less than requested
		_, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
		require.ErrorIs(t, err, ErrDeltaMismatch)
		eqBig(t, big.NewInt(0), e.reserve(usdc))
	})

	t.Run("reverting_token_aborts", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fund(usdc, maker, amt)
		e.db().failTransfer[usdc] = true
		_, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
		require.ErrorIs(t, err, ErrTransferFailed)
		eqBig(t, big.NewInt(0), e.reserve(usdc))
		eqBig(t, amt, e.db().bal(usdc, maker))
	})
}

// ---------------------------------------------------------------------------
// read-only (static) calls: state transitions rejected, views allowed.
// ---------------------------------------------------------------------------

func TestReadOnlyGating(t *testing.T) {
	e := newEnv(t0)
	amt := big.NewInt(1000)
	e.db().fund(usdc, maker, amt)
	pre := preimageOf(0x21)
	h := hashOf(pre)

	_, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, true)
	require.ErrorIs(t, err, ErrReadOnly)

	// Lock for real, then prove claim/refund are read-only gated and views are not.
	id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
	require.NoError(t, err)
	_, err = e.claim(user, id, pre, true)
	require.ErrorIs(t, err, ErrReadOnly)
	_, err = e.refund(maker, id, true)
	require.ErrorIs(t, err, ErrReadOnly)

	_, err = e.getSwap(id, true)
	require.NoError(t, err)
	_, err = e.getPreimage(h, true)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Reentrancy: a token that reenters lock during transferFrom is rejected by the
// global guard; the outer lock still completes correctly.
// ---------------------------------------------------------------------------

func TestReentrancyGuard(t *testing.T) {
	e := newEnv(t0)
	amt := big.NewInt(1000)
	e.db().fund(usdc, maker, new(big.Int).Mul(amt, big.NewInt(2)))
	h := hashOf(preimageOf(0x31))

	var reentryErr error
	e.db().reenter = func() {
		// Attempt a nested lock during the outer lock's transferFrom.
		_, _, reentryErr = e.lock(maker, hashOf(preimageOf(0x32)), user, maker, usdc, amt, timeout, false)
	}

	id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
	require.NoError(t, err)
	require.ErrorIs(t, reentryErr, ErrReentrant)
	// Exactly one swap funded; the reentrant attempt moved nothing extra.
	eqBig(t, amt, e.db().bal(usdc, swapAddr))
	eqBig(t, amt, e.reserve(usdc))
	require.Equal(t, StatusLocked, loadStatus(e.db(), id))
}

// ---------------------------------------------------------------------------
// Conservation invariant across a mixed sequence: at every step
// balanceOf(swapAddr) == reserve[asset], and the global pay-out never exceeds the
// global lock-in (no extraction).
// ---------------------------------------------------------------------------

func TestConservationAcrossSequence(t *testing.T) {
	e := newEnv(t0)
	totalIn := big.NewInt(0)
	// Generous funding for many makers.
	e.db().fund(usdc, maker, big.NewInt(1_000_000))
	e.db().fund(wbtc, maker, big.NewInt(1_000_000))

	check := func() {
		// Per-asset: real vault balance equals the precompile's own reserve ledger.
		eqBig(t, e.reserve(usdc), e.db().bal(usdc, swapAddr))
		eqBig(t, e.reserve(wbtc), e.db().bal(wbtc, swapAddr))
	}

	lockOne := func(asset common.Address, amt *big.Int, secret byte, to uint64) common.Hash {
		h := hashOf(preimageOf(secret))
		id, _, err := e.lock(maker, h, user, maker, asset, amt, to, false)
		require.NoError(t, err)
		totalIn.Add(totalIn, amt)
		check()
		return id
	}

	a := lockOne(usdc, big.NewInt(100), 0xA1, timeout)
	b := lockOne(usdc, big.NewInt(250), 0xA2, timeout)
	c := lockOne(wbtc, big.NewInt(70), 0xA3, timeout)

	// Claim a, refund c (after timeout), leave b live.
	_, err := e.claim(user, a, preimageOf(0xA1), false)
	require.NoError(t, err)
	check()

	e.setNow(timeout)
	_, err = e.refund(maker, c, false)
	require.NoError(t, err)
	check()

	// b is still locked: its asset's vault balance equals its amount.
	require.Equal(t, StatusLocked, loadStatus(e.db(), b))
	eqBig(t, big.NewInt(250), e.reserve(usdc))
	eqBig(t, big.NewInt(250), e.db().bal(usdc, swapAddr))

	// No extraction: total paid out (to user + back to maker) never exceeds
	// total locked in. Sum across both assets of (out) = in - stillLocked.
	stillLocked := new(big.Int).Add(e.reserve(usdc), e.reserve(wbtc))
	paidOut := new(big.Int).Sub(totalIn, stillLocked)
	// user received 100 (claim a); maker received 70 back (refund c) = 170.
	eqBig(t, big.NewInt(170), paidOut)
	require.True(t, paidOut.Cmp(totalIn) <= 0)
}

// ---------------------------------------------------------------------------
// Two-leg atomic scenario: claiming leg A publishes the secret s; the maker's
// watchtower reads s via getPreimage and uses it to claim leg B (same hashlock).
// This is the cross-leg secret relay that makes the swap atomic.
// ---------------------------------------------------------------------------

func TestTwoLegAtomicScenario(t *testing.T) {
	e := newEnv(t0)
	pre := preimageOf(0xCC)
	h := hashOf(pre)

	// Leg A: maker locks USDC, recipient = user (the secret holder).
	amtA := big.NewInt(10_000)
	e.db().fund(usdc, maker, amtA)
	legA, _, err := e.lock(maker, h, user, maker, usdc, amtA, timeout-10, false) // earlier timeout
	require.NoError(t, err)

	// Leg B: user locks WBTC, recipient = maker, SAME hashlock, LATER timeout.
	amtB := big.NewInt(40)
	e.db().fund(wbtc, user, amtB)
	legB, _, err := e.lock(user, h, maker, user, wbtc, amtB, timeout, false)
	require.NoError(t, err)

	// User claims leg A with the secret -> receives USDC, publishes s.
	_, err = e.claim(user, legA, pre, false)
	require.NoError(t, err)
	eqBig(t, amtA, e.db().bal(usdc, user))

	// Maker's watchtower reads the published secret from the chain by hashlock...
	relayed, err := e.getPreimage(h, true)
	require.NoError(t, err)
	require.Equal(t, pre, relayed)

	// ...and uses it to claim leg B WITHOUT ever having been told s out-of-band.
	_, err = e.claim(maker, legB, relayed, false)
	require.NoError(t, err)
	eqBig(t, amtB, e.db().bal(wbtc, maker))

	// Both legs settled to the agreed recipients; both vaults empty; conserved.
	require.Equal(t, StatusClaimed, loadStatus(e.db(), legA))
	require.Equal(t, StatusClaimed, loadStatus(e.db(), legB))
	eqBig(t, big.NewInt(0), e.db().bal(usdc, swapAddr))
	eqBig(t, big.NewInt(0), e.db().bal(wbtc, swapAddr))
	eqBig(t, big.NewInt(0), e.reserve(usdc))
	eqBig(t, big.NewInt(0), e.reserve(wbtc))
}

// ---------------------------------------------------------------------------
// Distinct callers / identical terms produce distinct swapIds (nonce binding),
// and getSwap reflects stored fields.
// ---------------------------------------------------------------------------

func TestSwapIDUniquenessAndView(t *testing.T) {
	e := newEnv(t0)
	amt := big.NewInt(1000)
	e.db().fund(usdc, maker, new(big.Int).Mul(amt, big.NewInt(2)))
	h := hashOf(preimageOf(0x44))

	id1, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
	require.NoError(t, err)
	id2, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
	require.NoError(t, err)
	require.NotEqual(t, id1, id2, "identical terms must yield distinct ids via the nonce")

	out, err := e.getSwap(id1, true)
	require.NoError(t, err)
	require.Len(t, out, 8*32)
	require.Equal(t, byte(StatusLocked), out[31])             // status word
	require.Equal(t, h, common.BytesToHash(out[32:64]))       // hashlock word
	require.Equal(t, user, common.BytesToAddress(out[64:96])) // recipient word
}

// ---------------------------------------------------------------------------
// Out-of-gas and malformed input.
// ---------------------------------------------------------------------------

func TestGasAndMalformedInput(t *testing.T) {
	e := newEnv(t0)
	h := hashOf(preimageOf(0x66))

	// Out of gas on lock.
	in := selBytes(selLock)
	in = append(in, h[:]...)
	in = append(in, addrArg(user)...)
	in = append(in, addrArg(maker)...)
	in = append(in, addrArg(usdc)...)
	in = append(in, amountArg(big.NewInt(1000))...)
	in = append(in, u64Arg(timeout)...)
	_, _, err := e.c.Run(e.st, maker, swapAddr, in, GasLock-1, false)
	require.ErrorIs(t, err, ErrOutOfGas)

	// Short input (< selector).
	_, _, err = e.c.Run(e.st, maker, swapAddr, []byte{0x01, 0x02}, e.gas, false)
	require.ErrorIs(t, err, ErrShortInput)

	// Unknown selector.
	_, _, err = e.c.Run(e.st, maker, swapAddr, []byte{0xff, 0xff, 0xff, 0xff}, e.gas, false)
	require.ErrorIs(t, err, ErrUnknownSelector)

	// Malformed lock args (wrong length).
	bad := append(selBytes(selLock), 0x00)
	_, _, err = e.c.Run(e.st, maker, swapAddr, bad, e.gas, false)
	require.ErrorIs(t, err, ErrBadArgs)
}

// ---------------------------------------------------------------------------
// Module registration sanity: the precompile is wired at LP-90A0.
// ---------------------------------------------------------------------------

func TestModuleRegistered(t *testing.T) {
	require.Equal(t, swapAddr, Module.Address)
	require.Equal(t, ConfigKey, Module.ConfigKey)
	require.Equal(t, common.HexToAddress("0x00000000000000000000000000000000000090A0"), swapAddr)
}
