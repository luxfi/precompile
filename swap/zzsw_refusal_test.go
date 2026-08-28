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
// Dispatch: input shorter than a selector, and every selector that is not ours.
// Both are refused BEFORE any state is read and charge nothing.
// ---------------------------------------------------------------------------

func TestZZShortInputRefused(t *testing.T) {
	e := newEnv(t0)
	for n := 0; n < contract4(); n++ {
		in := make([]byte, n)
		for i := range in {
			in[i] = 0xAA
		}
		ret, gas, err := e.c.Run(e.st, maker, swapAddr, in, e.gas, false)
		require.ErrorIsf(t, err, ErrShortInput, "input of %d bytes", n)
		require.Nil(t, ret)
		require.Equal(t, e.gas, gas, "a call rejected before dispatch consumes nothing")
	}
	// nil input is the degenerate short input.
	_, _, err := e.c.Run(e.st, maker, swapAddr, nil, e.gas, false)
	require.ErrorIs(t, err, ErrShortInput)
	require.Empty(t, e.db().storage, "no refused call may touch state")
}

// contract4 keeps the selector width a single derived value rather than a
// transcribed 4.
func contract4() int { return 4 }

func TestZZUnknownSelectorRefused(t *testing.T) {
	e := newEnv(t0)
	known := map[uint32]bool{selLock: true, selClaim: true, selRefund: true, selGetSwap: true, selGetPreimage: true}

	for _, sel := range []uint32{
		0x00000000, 0xffffffff, 0x12345678,
		selLock ^ 1, selClaim ^ 1, selRefund ^ 1, selGetSwap ^ 1, selGetPreimage ^ 1,
		// The keccak (not SHA-256) commit-reveal selectors from the same-chain
		// primitive must NOT be answered here.
		methodSelector("reveal(bytes32,bytes32)"),
		methodSelector("settle(bytes32)"),
		// An owner/pause/upgrade surface does not exist by design.
		methodSelector("pause()"),
		methodSelector("setOwner(address)"),
		methodSelector("setBalance(address,address,uint256)"),
	} {
		require.False(t, known[sel], "fixture selector %#08x collides with a real one", sel)
		in := append(selBytes(sel), make([]byte, 192)...)
		ret, gas, err := e.c.Run(e.st, maker, swapAddr, in, e.gas, false)
		require.ErrorIsf(t, err, ErrUnknownSelector, "selector %#08x", sel)
		require.Nil(t, ret)
		require.Equal(t, e.gas, gas)
	}
	require.Empty(t, e.db().storage)
}

// ---------------------------------------------------------------------------
// A nil BlockContext is refused for EVERY selector, including the views: the
// clock is what makes the claim and refund windows disjoint, so a call that
// cannot read it must not proceed at all.
// ---------------------------------------------------------------------------

func TestZZNilBlockContextRefused(t *testing.T) {
	st := &zzState{db: newMockState(), blk: nil}
	c := &SwapContract{}
	h := hashOf(preimageOf(0x01))

	for name, in := range map[string][]byte{
		"lock":        zzWellFormedLock(),
		"claim":       zzClaimInput(common.Hash{1}, preimageOf(0x01)),
		"refund":      zzRefundInput(common.Hash{1}),
		"getSwap":     zzGetSwapInput(common.Hash{1}),
		"getPreimage": zzGetPreimageInput(h),
	} {
		for _, ro := range []bool{false, true} {
			ret, gas, err := c.Run(st, maker, swapAddr, in, 10_000_000, ro)
			require.ErrorIsf(t, err, ErrNoBlockContext, "%s readOnly=%v", name, ro)
			require.Nil(t, ret)
			require.Equal(t, uint64(10_000_000), gas)
		}
	}
}

// ---------------------------------------------------------------------------
// Exact argument length. Every selector fixes its payload size, so there is no
// input a caller can grow to buy unbounded work at the flat fee. One byte short
// and one byte long are both refused, and the flat fee is still charged.
// ---------------------------------------------------------------------------

func TestZZArgLengthIsExactForEverySelector(t *testing.T) {
	cases := []struct {
		name string
		sel  uint32
		want int
		gas  uint64
	}{
		{"lock", selLock, 6 * 32, GasLock},
		{"claim", selClaim, 2 * 32, GasClaim},
		{"refund", selRefund, 32, GasRefund},
		{"getSwap", selGetSwap, 32, GasGetSwap},
		{"getPreimage", selGetPreimage, 32, GasGetPreimage},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t0)
			zzUnchanged(t, e.db(), func() {
				for _, n := range []int{0, 1, tc.want - 1, tc.want + 1, tc.want + 32, 4096} {
					in := append(selBytes(tc.sel), make([]byte, n)...)
					ret, gas, err := e.c.Run(e.st, maker, swapAddr, in, e.gas, false)
					require.ErrorIsf(t, err, ErrBadArgs, "%s with %d arg bytes (want exactly %d)", tc.name, n, tc.want)
					require.Nil(t, ret)
					require.Equalf(t, e.gas-tc.gas, gas,
						"%s must still charge its flat fee on a malformed call", tc.name)
				}
			})
		})
	}
}

// ---------------------------------------------------------------------------
// Gas. Each selector charges a flat fee up front; suppliedGas == fee is enough
// (the boundary is `<`, not `<=`) and one wei of gas less is refused with the
// whole budget consumed.
// ---------------------------------------------------------------------------

func TestZZGasBoundaryPerSelector(t *testing.T) {
	amt := big.NewInt(1000)
	pre := preimageOf(0xB1)
	h := hashOf(pre)

	// Build a live swap the claim/refund/view budgets can act on.
	build := func() (*env, common.Hash) {
		e := newEnv(t0)
		e.db().fund(usdc, maker, new(big.Int).Mul(amt, big.NewInt(4)))
		id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
		require.NoError(t, err)
		return e, id
	}

	t.Run("lock", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fund(usdc, maker, amt)
		in := zzLockInput(h, user, maker, usdc, amt, timeout)

		zzUnchanged(t, e.db(), func() {
			_, gas, err := e.c.Run(e.st, maker, swapAddr, in, GasLock-1, false)
			require.ErrorIs(t, err, ErrOutOfGas)
			require.Zero(t, gas, "an out-of-gas precompile consumes the whole budget")
		})

		ret, gas, err := e.c.Run(e.st, maker, swapAddr, in, GasLock, false)
		require.NoError(t, err, "suppliedGas == GasLock must be sufficient")
		require.Len(t, ret, 32)
		require.Zero(t, gas)
	})

	t.Run("claim", func(t *testing.T) {
		e, id := build()
		in := zzClaimInput(id, pre)

		_, gas, err := e.c.Run(e.st, watcher, swapAddr, in, GasClaim-1, false)
		require.ErrorIs(t, err, ErrOutOfGas)
		require.Zero(t, gas)
		require.Equal(t, StatusLocked, loadStatus(e.db(), id), "an out-of-gas claim settles nothing")
		zzEqBig(t, big.NewInt(0), e.db().bal(usdc, user))

		_, gas, err = e.c.Run(e.st, watcher, swapAddr, in, GasClaim, false)
		require.NoError(t, err)
		require.Zero(t, gas)
		zzEqBig(t, amt, e.db().bal(usdc, user))
	})

	t.Run("refund", func(t *testing.T) {
		e, id := build()
		e.setNow(timeout)
		in := zzRefundInput(id)

		_, gas, err := e.c.Run(e.st, watcher, swapAddr, in, GasRefund-1, false)
		require.ErrorIs(t, err, ErrOutOfGas)
		require.Zero(t, gas)
		require.Equal(t, StatusLocked, loadStatus(e.db(), id))

		_, gas, err = e.c.Run(e.st, watcher, swapAddr, in, GasRefund, false)
		require.NoError(t, err)
		require.Zero(t, gas)
		require.Equal(t, StatusRefunded, loadStatus(e.db(), id))
	})

	t.Run("getSwap", func(t *testing.T) {
		e, id := build()
		in := zzGetSwapInput(id)

		_, gas, err := e.c.Run(e.st, user, swapAddr, in, GasGetSwap-1, true)
		require.ErrorIs(t, err, ErrOutOfGas)
		require.Zero(t, gas)

		ret, gas, err := e.c.Run(e.st, user, swapAddr, in, GasGetSwap, true)
		require.NoError(t, err)
		require.Len(t, ret, 8*32)
		require.Zero(t, gas)
	})

	t.Run("getPreimage", func(t *testing.T) {
		e, _ := build()
		in := zzGetPreimageInput(h)

		_, gas, err := e.c.Run(e.st, user, swapAddr, in, GasGetPreimage-1, true)
		require.ErrorIs(t, err, ErrOutOfGas)
		require.Zero(t, gas)

		ret, gas, err := e.c.Run(e.st, user, swapAddr, in, GasGetPreimage, true)
		require.NoError(t, err)
		require.Len(t, ret, 32)
		require.Zero(t, gas)
	})
}

// TestZZGasChargedOnSuccessIsTheFlatFee pins the exact fee each selector deducts
// from a large budget, so a change to the constants shows up as a test failure
// rather than as a silent repricing.
func TestZZGasChargedOnSuccessIsTheFlatFee(t *testing.T) {
	amt := big.NewInt(1000)
	pre := preimageOf(0xB2)
	h := hashOf(pre)

	e := newEnv(t0)
	// Three locks of `amt` happen below; fund for all of them. The mock reverts a
	// transferFrom the owner cannot cover, which would surface as ErrTransferFailed
	// and look like a product failure rather than a short fixture.
	e.db().fund(usdc, maker, new(big.Int).Mul(amt, big.NewInt(3)))

	_, gas, err := e.c.Run(e.st, maker, swapAddr, zzLockInput(h, user, maker, usdc, amt, timeout), e.gas, false)
	require.NoError(t, err)
	require.Equal(t, e.gas-GasLock, gas)

	id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
	require.NoError(t, err)

	_, gas, err = e.c.Run(e.st, user, swapAddr, zzGetSwapInput(id), e.gas, true)
	require.NoError(t, err)
	require.Equal(t, e.gas-GasGetSwap, gas)

	_, gas, err = e.c.Run(e.st, user, swapAddr, zzGetPreimageInput(h), e.gas, true)
	require.NoError(t, err)
	require.Equal(t, e.gas-GasGetPreimage, gas)

	_, gas, err = e.c.Run(e.st, watcher, swapAddr, zzClaimInput(id, pre), e.gas, false)
	require.NoError(t, err)
	require.Equal(t, e.gas-GasClaim, gas)

	// The remaining swap expires and is refunded.
	id2, _, err := e.lock(maker, hashOf(preimageOf(0xB3)), user, maker, usdc, amt, timeout, false)
	require.NoError(t, err)
	e.setNow(timeout)
	_, gas, err = e.c.Run(e.st, watcher, swapAddr, zzRefundInput(id2), e.gas, false)
	require.NoError(t, err)
	require.Equal(t, e.gas-GasRefund, gas)

	// The fees are ordered by the work each does: lock (transferFrom + 7 cold
	// SSTOREs) > claim (transfer + 3 SSTOREs) > refund (transfer + 2 SSTOREs) >
	// the two read-only views.
	require.Greater(t, GasLock, GasClaim)
	require.Greater(t, GasClaim, GasRefund)
	require.Greater(t, GasRefund, GasGetSwap)
	require.Greater(t, GasGetSwap, GasGetPreimage)
}

// ---------------------------------------------------------------------------
// read-only (static) gating: the three transitions are refused, the two views
// answer identically whether or not the frame is static.
// ---------------------------------------------------------------------------

func TestZZReadOnlyGatesTransitionsNotViews(t *testing.T) {
	amt := big.NewInt(1000)
	pre := preimageOf(0xC1)
	h := hashOf(pre)

	e := newEnv(t0)
	e.db().fund(usdc, maker, amt)
	id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
	require.NoError(t, err)
	_, err = e.claim(user, id, pre, false)
	require.NoError(t, err)

	// Every transition, refused in a static frame with the full budget returned —
	// the refusal precedes the fee.
	for name, in := range map[string][]byte{
		"lock":   zzWellFormedLock(),
		"claim":  zzClaimInput(id, pre),
		"refund": zzRefundInput(id),
	} {
		ret, gas, err := e.c.Run(e.st, maker, swapAddr, in, e.gas, true)
		require.ErrorIsf(t, err, ErrReadOnly, "%s in a static frame", name)
		require.Nil(t, ret)
		require.Equal(t, e.gas, gas)
	}

	// Views are answer-identical across the static flag.
	swapRO, err := e.getSwap(id, true)
	require.NoError(t, err)
	swapRW, err := e.getSwap(id, false)
	require.NoError(t, err)
	require.Equal(t, swapRO, swapRW)

	preRO, err := e.getPreimage(h, true)
	require.NoError(t, err)
	preRW, err := e.getPreimage(h, false)
	require.NoError(t, err)
	require.Equal(t, preRO, preRW)
	require.Equal(t, pre, preRO)
}

// ---------------------------------------------------------------------------
// Reentrancy guard: one global flag, taken by every transition and released on
// EVERY exit path. A guard that leaked on an error would brick the precompile.
// ---------------------------------------------------------------------------

func TestZZGuardBlocksTransitionsAndAdmitsViews(t *testing.T) {
	e := newEnv(t0)
	amt := big.NewInt(1000)
	e.db().fund(usdc, maker, amt)
	pre := preimageOf(0xD1)
	h := hashOf(pre)

	id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
	require.NoError(t, err)

	// Hold the guard as an outer frame would.
	require.True(t, enterGuard(e.db()))
	require.False(t, enterGuard(e.db()), "the guard is not re-entrant with itself")

	for name, call := range map[string]func() error{
		"lock": func() error {
			_, _, err := e.lock(maker, hashOf(preimageOf(0xD2)), user, maker, usdc, amt, timeout, false)
			return err
		},
		"claim":  func() error { _, err := e.claim(user, id, pre, false); return err },
		"refund": func() error { _, err := e.refund(maker, id, false); return err },
	} {
		require.ErrorIsf(t, call(), ErrReentrant, "%s must be refused while the guard is held", name)
	}

	// Views stay callable under the guard — a watchtower reading the chain must
	// never be blocked by an unrelated in-flight settlement.
	require.Equal(t, StatusLocked, zzStatus(t, e, id))
	got, err := e.getPreimage(h, true)
	require.NoError(t, err)
	require.Equal(t, [preimageLen]byte{}, got)

	// Released, the same calls succeed.
	exitGuard(e.db())
	require.True(t, enterGuard(e.db()))
	exitGuard(e.db())
	_, err = e.claim(user, id, pre, false)
	require.NoError(t, err)
}

func TestZZGuardReleasedAfterEveryFailedTransition(t *testing.T) {
	amt := big.NewInt(1000)
	pre := preimageOf(0xD3)
	h := hashOf(pre)

	// Each entry drives a transition that fails somewhere inside the guarded
	// region; afterwards the guard must be clear and an honest lock must work.
	fail := map[string]func(e *env){
		"lock_reverting_token": func(e *env) {
			e.db().failTransfer[wbtc] = true
			e.db().fund(wbtc, maker, amt)
			_, _, err := e.lock(maker, h, user, maker, wbtc, amt, timeout, false)
			require.ErrorIs(t, err, ErrTransferFailed)
		},
		"lock_bad_args": func(e *env) {
			_, _, err := e.c.Run(e.st, maker, swapAddr, append(selBytes(selLock), 1, 2, 3), e.gas, false)
			require.ErrorIs(t, err, ErrBadArgs)
		},
		"lock_dust": func(e *env) {
			_, _, err := e.lock(maker, h, user, maker, usdc, big.NewInt(0), timeout, false)
			require.ErrorIs(t, err, ErrDustAmount)
		},
		"claim_unknown_swap": func(e *env) {
			_, err := e.claim(user, common.Hash{0xEE}, pre, false)
			require.ErrorIs(t, err, ErrNotLocked)
		},
		"refund_unknown_swap": func(e *env) {
			_, err := e.refund(user, common.Hash{0xEE}, false)
			require.ErrorIs(t, err, ErrNotLocked)
		},
		"claim_out_of_gas": func(e *env) {
			_, _, err := e.c.Run(e.st, user, swapAddr, zzClaimInput(common.Hash{0xEE}, pre), GasClaim-1, false)
			require.ErrorIs(t, err, ErrOutOfGas)
		},
	}

	for name, drive := range fail {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t0)
			e.db().fund(usdc, maker, amt)
			drive(e)

			require.Zero(t, e.db().GetState(swapAddr, guardSlot())[31], "guard leaked after a failed transition")
			id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
			require.NoError(t, err, "a leaked guard would brick every later settlement")
			require.Equal(t, StatusLocked, loadStatus(e.db(), id))
		})
	}
}

// TestZZReentrantClaimDuringLockRefused drives the real attack shape: a malicious
// token calls back into the precompile from inside transferFrom, while the outer
// lock has measured its inbound delta but not yet written the swap.
func TestZZReentrantClaimDuringLockRefused(t *testing.T) {
	e := newEnv(t0)
	amt := big.NewInt(1000)
	e.db().fund(usdc, maker, new(big.Int).Mul(amt, big.NewInt(3)))
	pre := preimageOf(0xD4)
	h := hashOf(pre)

	victim, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
	require.NoError(t, err)

	var claimErr, refundErr, lockErr error
	e.db().reenter = func() {
		_, claimErr = e.claim(user, victim, pre, false)
		_, refundErr = e.refund(maker, victim, false)
		_, _, lockErr = e.lock(maker, hashOf(preimageOf(0xD5)), user, maker, usdc, amt, timeout, false)
	}

	outer, _, err := e.lock(maker, hashOf(preimageOf(0xD6)), user, maker, usdc, amt, timeout, false)
	require.NoError(t, err)
	require.ErrorIs(t, claimErr, ErrReentrant)
	require.ErrorIs(t, refundErr, ErrReentrant)
	require.ErrorIs(t, lockErr, ErrReentrant)

	// The victim is untouched and the outer lock landed exactly once.
	require.Equal(t, StatusLocked, loadStatus(e.db(), victim))
	require.Equal(t, StatusLocked, loadStatus(e.db(), outer))
	zzEqBig(t, big.NewInt(0), e.db().bal(usdc, user))
	zzEqBig(t, new(big.Int).Mul(amt, big.NewInt(2)), e.reserve(usdc))
	zzConserved(t, e, usdc)
}
