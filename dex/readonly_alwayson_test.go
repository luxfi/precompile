// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// This file covers two load-bearing structural claims:
//
//  1. 0x9998 (Quoter) and 0x9997 (StateView) are WRITE-INCAPABLE by design. The code
//     asserts this by construction (readOnlyView has no usable write method) and backs
//     it with a panicking tripwire. A comment is not a guarantee, so the tests below
//     drive every selector through the real StateDB and assert its full contents are
//     byte-identical afterwards.
//
//  2. 0x9999 (Settle) is the only AlwaysOn module in the repo — active from genesis on
//     every chain with no config entry. Its input validation is therefore load-bearing
//     for every Lux network, and is tested hardest.

// ---------------------------------------------------------------------------
// Observing the absence of a state change.
// ---------------------------------------------------------------------------

// stateFingerprint is a copy of every OBSERVABLE slot and balance in the harness
// StateDB. Comparing two fingerprints proves the absence of a state CHANGE, which is
// strictly stronger than counting SetState calls: it also catches a balance move, and
// it cannot be fooled by a write that stores back the value it read.
//
// Zero-valued slots are omitted deliberately. GetState returns the zero hash for an
// absent key, so a slot explicitly written to zero and a slot never written are
// indistinguishable to every reader and to the state trie. Keeping them would make
// this assert something stricter than the property that matters — a transient guard
// that sets a flag and clears it again is not a state change, and 0x9999 takes exactly
// such a guard on its custody paths.
type stateFingerprint struct {
	slots    map[common.Address]map[common.Hash]common.Hash
	balances map[common.Address]string
}

func fingerprint(db *MockStateDB) stateFingerprint {
	fp := stateFingerprint{
		slots:    make(map[common.Address]map[common.Hash]common.Hash, len(db.states)),
		balances: make(map[common.Address]string, len(db.balances)),
	}
	for addr, kv := range db.states {
		cp := make(map[common.Hash]common.Hash, len(kv))
		for k, v := range kv {
			if v == (common.Hash{}) {
				continue // indistinguishable from absent
			}
			cp[k] = v
		}
		if len(cp) > 0 {
			fp.slots[addr] = cp
		}
	}
	for addr, bal := range db.balances {
		if bal.IsZero() {
			continue
		}
		fp.balances[addr] = bal.String()
	}
	return fp
}

// ---------------------------------------------------------------------------
// READ-ONLY ENFORCEMENT — 0x9998 and 0x9997.
// ---------------------------------------------------------------------------

// TestReadOnlyViewTripwireFires pins the structural guard itself. readOnlyView
// exists so a read handler holds no write surface; SetState is present only to
// satisfy the stateKV interface and must PANIC rather than silently mutate
// consensus state if a future refactor ever wires a writing helper to a view.
func TestReadOnlyViewTripwireFires(t *testing.T) {
	rv := readOnlyView{state: nil}
	require.PanicsWithValue(t,
		"dex: read-only view attempted a state write (0x9998/0x9997 are write-incapable by design)",
		func() { rv.SetState(common.Address{}, common.Hash{}, common.Hash{}) },
		"the read-only tripwire must fire loudly, not corrupt state silently")
}

// TestQuoterNeverWritesState is the real read-only guarantee for 0x9998: drive
// EVERY quoter selector — valid and malformed, readOnly and not — and assert the
// StateDB is byte-identical afterwards. This is what makes 0x9998 safe to expose as
// a view; a single write here would be consensus state mutated by a `staticcall`.
func TestQuoterNeverWritesState(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)                    // a LIVE market, so the SUCCESS paths are covered too — a view
	before := fingerprint(h.state.stateDB) // that only ever errored would prove nothing
	q := &QuoterContract{}

	selectors := []uint32{
		SelQExactInput, SelQExactInputSingle,
		SelQExactOutput, SelQExactOutputSingle,
		SelQAgainstBook, SelQWithDepth, SelQWithFees, SelQWithSlippage,
	}

	// Well-formed input for the real market the harness registered, plus a spread of
	// malformed shapes — a write is just as unacceptable on an error path.
	bodies := [][]byte{
		quoteBody(h.key, big.NewInt(1000), true),
		quoteBody(h.key, big.NewInt(1000), false),
		quoteBody(h.key, big.NewInt(1), true),
		quoteBody(h.key, big.NewInt(0), true), // zero amount: refused
		make([]byte, 0),
		make([]byte, 32),
		make([]byte, 223),
		make([]byte, 224),
	}

	for _, sel := range selectors {
		for _, body := range bodies {
			in := append(selectorBytes(sel), body...)
			require.NotPanics(t, func() {
				_, _, _ = q.Run(h.state, h.caller, common.HexToAddress(DEXQuoterAddress), in, 10_000_000, true)
			})
			require.NotPanics(t, func() {
				// Also with readOnly=false: 0x9998 must be write-incapable regardless of
				// how the EVM invoked it, not merely when asked nicely.
				_, _, _ = q.Run(h.state, h.caller, common.HexToAddress(DEXQuoterAddress), in, 10_000_000, false)
			})
		}
	}
	// An unknown selector must also be inert.
	_, _, err := q.Run(h.state, h.caller, common.HexToAddress(DEXQuoterAddress),
		append(selectorBytes(0xdeadbeef), make([]byte, 224)...), 10_000_000, true)
	require.Error(t, err)

	require.Equal(t, before, fingerprint(h.state.stateDB),
		"0x9998 mutated state; the Quoter must be write-incapable")
}

// TestStateViewNeverWritesState is the same proof for 0x9997.
func TestStateViewNeverWritesState(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	before := fingerprint(h.state.stateDB)
	v := &StateViewContract{}

	poolID := h.key.ID()
	id32 := make([]byte, 32)
	copy(id32, poolID[:])

	selectors := []uint32{
		SelectorGetPool, SelectorGetPoolId, SelectorGetSlot0, SelectorGetLiquidity,
		SelectorGetPosition, SelectorGetMarket, SelectorGetBestBidAsk, SelectorGetDepth,
		SelectorGetOpenOrders, SelectorGetReceiptStatus, SelectorGetHaltStatus,
	}
	bodies := [][]byte{
		EncodePoolKeyABI(h.key),
		id32,
		append(append([]byte{}, id32...), make([]byte, 32)...),
		make([]byte, 32),
		make([]byte, 0),
		make([]byte, 31),
		make([]byte, 160),
	}

	for _, sel := range selectors {
		for _, body := range bodies {
			in := append(selectorBytes(sel), body...)
			for _, ro := range []bool{true, false} {
				require.NotPanics(t, func() {
					_, _, _ = v.Run(h.state, h.caller, common.HexToAddress(DEXStateViewAddress), in, 10_000_000, ro)
				})
			}
		}
	}
	_, _, err := v.Run(h.state, h.caller, common.HexToAddress(DEXStateViewAddress),
		append(selectorBytes(0xfeedface), make([]byte, 32)...), 10_000_000, true)
	require.Error(t, err)

	require.Equal(t, before, fingerprint(h.state.stateDB),
		"0x9997 mutated state; the StateView must be write-incapable")
}

// TestViewsAreIndifferentToReadOnlyFlag: because both addresses are write-incapable
// by construction, the readOnly flag must make NO difference to the result. A
// divergence would mean there IS a write path being gated by the flag — i.e. the
// structural claim is false and the guarantee rests on the caller instead.
func TestViewsAreIndifferentToReadOnlyFlag(t *testing.T) {
	h := newSettleHarness(t)
	q := &QuoterContract{}
	v := &StateViewContract{}
	poolID := h.key.ID()
	id32 := make([]byte, 32)
	copy(id32, poolID[:])

	type call struct {
		name string
		run  func(ro bool) ([]byte, uint64, error)
	}
	calls := []call{
		{"quoteExactInput", func(ro bool) ([]byte, uint64, error) {
			in := append(selectorBytes(SelQExactInput), quoteBody(h.key, big.NewInt(1000), true)...)
			return q.Run(h.state, h.caller, common.HexToAddress(DEXQuoterAddress), in, 10_000_000, ro)
		}},
		{"getPoolId", func(ro bool) ([]byte, uint64, error) {
			in := append(selectorBytes(SelectorGetPoolId), EncodePoolKeyABI(h.key)...)
			return v.Run(h.state, h.caller, common.HexToAddress(DEXStateViewAddress), in, 10_000_000, ro)
		}},
		{"getMarket", func(ro bool) ([]byte, uint64, error) {
			in := append(selectorBytes(SelectorGetMarket), id32...)
			return v.Run(h.state, h.caller, common.HexToAddress(DEXStateViewAddress), in, 10_000_000, ro)
		}},
	}
	for _, c := range calls {
		outRO, gasRO, errRO := c.run(true)
		outRW, gasRW, errRW := c.run(false)
		require.Equalf(t, errRO == nil, errRW == nil, "%s: readOnly changed the outcome", c.name)
		require.Equalf(t, outRO, outRW, "%s: readOnly changed the result", c.name)
		require.Equalf(t, gasRO, gasRW, "%s: readOnly changed the gas", c.name)
	}
}

// TestViewsChargeGasBeforeWork proves neither view is a free oracle: both deduct
// their fee up front and refuse below it with nothing left over. An unpriced view is
// a free read amplification for any caller.
func TestViewsChargeGasBeforeWork(t *testing.T) {
	h := newSettleHarness(t)
	q := &QuoterContract{}
	v := &StateViewContract{}

	qin := append(selectorBytes(SelQExactInput), quoteBody(h.key, big.NewInt(1000), true)...)
	_, remaining, err := q.Run(h.state, h.caller, common.HexToAddress(DEXQuoterAddress), qin, GasQuoteView-1, true)
	require.Error(t, err, "below GasQuoteView the quoter must refuse")
	require.Zero(t, remaining)

	vin := append(selectorBytes(SelectorGetPoolId), EncodePoolKeyABI(h.key)...)
	_, remaining, err = v.Run(h.state, h.caller, common.HexToAddress(DEXStateViewAddress), vin, GasStateView-1, true)
	require.Error(t, err, "below GasStateView the view must refuse")
	require.Zero(t, remaining)

	// At exactly the fee the call proceeds and the fee is deducted.
	_, remaining, err = v.Run(h.state, h.caller, common.HexToAddress(DEXStateViewAddress), vin, GasStateView, true)
	require.NoError(t, err)
	require.Zero(t, remaining, "the view fee must be fully consumed")
}

// ---------------------------------------------------------------------------
// 0x9999 — the ONLY AlwaysOn module.
// ---------------------------------------------------------------------------

// TestSettleIsTheOnlyAlwaysOnModule pins the fact the rest of this section rests
// on. AlwaysOn means "active from genesis on every chain, with no config entry", so
// its input validation is load-bearing for every Lux network — while every other
// module only becomes reachable once a chain opts in at an upgrade timestamp.
//
// If a second module ever becomes AlwaysOn, that is a new unconditional attack
// surface and it must be a deliberate, reviewed decision — this test forces it.
func TestSettleIsTheOnlyAlwaysOnModule(t *testing.T) {
	require.True(t, SettleModule.AlwaysOn, "0x9999 is the money path and must be always-on")
	require.Equal(t, DEXPoolManagerAddress, SettleModule.Address.Hex())

	for name, m := range map[string]struct{ on bool }{
		"quoter":    {QuoterModule.AlwaysOn},
		"stateview": {StateViewModule.AlwaysOn},
		"position":  {PositionManagerModule.AlwaysOn},
		"router":    {RouterModule.AlwaysOn},
	} {
		require.Falsef(t, m.on,
			"%s must NOT be always-on: only 0x9999 is unconditionally active", name)
	}
}

// TestSettleRefusesMalformedInput is the hardest-tested refusal surface in the
// repo, because 0x9999 answers on every chain from genesis. Every truncation of
// every selector must be refused without panicking and without writing state —
// a panic here halts the block on ALL networks at once.
func TestSettleRefusesMalformedInput(t *testing.T) {
	h := newSettleHarness(t)
	before := fingerprint(h.state.stateDB)
	addr := common.HexToAddress(DEXPoolManagerAddress)

	selectors := []uint32{
		SelectorSetHaltGlobal, SelectorSetHaltMarket, SelectorSetHaltAsset,
		SelectorCollectPosition, SelectorReclaimIntent, SelectorSeedSeamReserve,
		SelectorCreditPositionFee,
	}

	t.Run("input shorter than a selector", func(t *testing.T) {
		for n := range 4 {
			require.NotPanicsf(t, func() {
				_, _, err := h.c.Run(h.state, h.caller, addr, make([]byte, n), 10_000_000, false)
				require.Errorf(t, err, "a %d-byte input carries no selector and must be refused", n)
			}, "%d-byte input must not panic", n)
		}
	})

	t.Run("unknown selector", func(t *testing.T) {
		for _, sel := range []uint32{0x00000000, 0xffffffff, 0xdeadbeef} {
			require.NotPanics(t, func() {
				_, _, err := h.c.Run(h.state, h.caller, addr,
					append(selectorBytes(sel), make([]byte, 128)...), 10_000_000, false)
				require.Error(t, err, "selector %#x must be refused", sel)
			})
		}
	})

	t.Run("every truncation of every selector", func(t *testing.T) {
		body := make([]byte, 160)
		for i := range body {
			body[i] = 0xab
		}
		for _, sel := range selectors {
			in := append(selectorBytes(sel), body...)
			for cut := 4; cut < len(in); cut++ {
				require.NotPanicsf(t, func() {
					_, _, _ = h.c.Run(h.state, h.caller, addr, in[:cut], 10_000_000, false)
				}, "selector %#x truncated to %d bytes must not panic — 0x9999 is on every chain", sel, cut)
			}
		}
	})

	t.Run("all-zero and all-ones payloads", func(t *testing.T) {
		for _, fill := range []byte{0x00, 0xff} {
			body := make([]byte, 256)
			for i := range body {
				body[i] = fill
			}
			for _, sel := range selectors {
				require.NotPanicsf(t, func() {
					_, _, _ = h.c.Run(h.state, h.caller, addr,
						append(selectorBytes(sel), body...), 10_000_000, false)
				}, "selector %#x with an all-%#x payload must not panic", sel, fill)
			}
		}
	})

	t.Run("zero gas", func(t *testing.T) {
		for _, sel := range selectors {
			require.NotPanicsf(t, func() {
				_, _, err := h.c.Run(h.state, h.caller, addr,
					append(selectorBytes(sel), make([]byte, 160)...), 0, false)
				require.Errorf(t, err, "selector %#x with zero gas must be refused", sel)
			}, "selector %#x with zero gas must not panic", sel)
		}
	})

	// None of the refusals above may have written state: a rejected call must leave
	// no trace, or a malformed input becomes a state-mutation primitive.
	require.Equal(t, before, fingerprint(h.state.stateDB),
		"0x9999 mutated state while REFUSING malformed input; a rejected call must leave no trace")
}

// TestSettleGovernanceSelectorsRefuseUnauthorizedCaller: the halt switches are the
// chain's emergency brake. They must gate on the runtime governance controller, and
// an arbitrary caller must never move them — on any network, since 0x9999 is
// unconditionally active.
func TestSettleGovernanceSelectorsRefuseUnauthorizedCaller(t *testing.T) {
	h := newSettleHarness(t)
	addr := common.HexToAddress(DEXPoolManagerAddress)
	stranger := common.HexToAddress("0xBADBADBADBADBADBADBADBADBADBADBADBADBAD0")
	require.NotEqual(t, testGovernance, stranger, "the test must use a non-governance caller")

	arg := make([]byte, 64)
	arg[31] = 1 // bool true / a non-zero id

	for name, sel := range map[string]uint32{
		"setHaltGlobal": SelectorSetHaltGlobal,
		"setHaltMarket": SelectorSetHaltMarket,
		"setHaltAsset":  SelectorSetHaltAsset,
	} {
		_, _, err := h.c.Run(h.state, stranger, addr, append(selectorBytes(sel), arg...), 10_000_000, false)
		require.Errorf(t, err, "%s must refuse a non-governance caller", name)
	}
}

// TestSettleRefusesStateWritesInReadOnly: 0x9999 IS a write path, so unlike the
// views it must honour the readOnly flag. A static call that mutated the money path
// would be a consensus break.
func TestSettleRefusesStateWritesInReadOnly(t *testing.T) {
	h := newSettleHarness(t)
	before := fingerprint(h.state.stateDB)
	addr := common.HexToAddress(DEXPoolManagerAddress)
	arg := make([]byte, 64)
	arg[31] = 1

	for name, sel := range map[string]uint32{
		"setHaltGlobal":     SelectorSetHaltGlobal,
		"setHaltMarket":     SelectorSetHaltMarket,
		"setHaltAsset":      SelectorSetHaltAsset,
		"seedSeamReserve":   SelectorSeedSeamReserve,
		"creditPositionFee": SelectorCreditPositionFee,
		"collectPosition":   SelectorCollectPosition,
		"reclaimIntent":     SelectorReclaimIntent,
	} {
		require.NotPanicsf(t, func() {
			_, _, err := h.c.Run(h.state, testGovernance, addr,
				append(selectorBytes(sel), arg...), 10_000_000, true /*readOnly*/)
			require.Errorf(t, err, "%s must be refused in a read-only call", name)
		}, "%s must not panic under readOnly", name)
	}
	require.Equal(t, before, fingerprint(h.state.stateDB),
		"0x9999 mutated state during a read-only call")
}

// ---------------------------------------------------------------------------
// Encoding helpers (test-local).
// ---------------------------------------------------------------------------

// selectorBytes renders a 4-byte big-endian selector.
func selectorBytes(sel uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, sel)
	return b
}

// quoteBody builds the quoter's argument tail: PoolKey(160) | amount(32) | zeroForOne(32).
func quoteBody(key PoolKey, amount *big.Int, zeroForOne bool) []byte {
	out := make([]byte, 0, 224)
	out = append(out, EncodePoolKeyABI(key)...)
	amt := make([]byte, 32)
	amount.FillBytes(amt)
	out = append(out, amt...)
	flag := make([]byte, 32)
	if zeroForOne {
		flag[31] = 1
	}
	return append(out, flag...)
}

// TestQuoterRefusesDegenerateQuotes covers the quoter's own refusal surface. A view
// that answers a nonsense question is worse than one that refuses: a zero-amount or
// unregistered-market quote returning a zero is indistinguishable from a real quote
// of zero, and a caller sizing a trade off it has no way to tell.
func TestQuoterRefusesDegenerateQuotes(t *testing.T) {
	h := newSettleHarness(t)
	q := &QuoterContract{}
	addr := common.HexToAddress(DEXQuoterAddress)

	t.Run("zero amount", func(t *testing.T) {
		for _, sel := range []uint32{SelQExactInput, SelQExactInputSingle, SelQExactOutput,
			SelQAgainstBook, SelQWithDepth, SelQWithFees, SelQWithSlippage} {
			in := append(selectorBytes(sel), quoteBody(h.key, big.NewInt(0), true)...)
			_, _, err := q.Run(h.state, h.caller, addr, in, 10_000_000, true)
			require.ErrorIsf(t, err, ErrQuoteZeroAmount,
				"selector %#x must refuse a zero-amount quote, not answer zero", sel)
		}
	})

	t.Run("unregistered market", func(t *testing.T) {
		unknown := h.key
		unknown.Fee = 777 // a fee tier no market was opened at
		in := append(selectorBytes(SelQExactInput), quoteBody(unknown, big.NewInt(1000), true)...)
		_, _, err := q.Run(h.state, h.caller, addr, in, 10_000_000, true)
		require.Error(t, err, "a quote for an unregistered market must be refused")
	})

	t.Run("input shorter than the argument tuple", func(t *testing.T) {
		full := append(selectorBytes(SelQExactInput), quoteBody(h.key, big.NewInt(1000), true)...)
		for cut := 4; cut < len(full); cut++ {
			require.NotPanicsf(t, func() {
				_, _, err := q.Run(h.state, h.caller, addr, full[:cut], 10_000_000, true)
				require.Errorf(t, err, "a quote truncated to %d bytes must be refused", cut)
			}, "truncation to %d bytes must not panic", cut)
		}
	})

	t.Run("shorter than a selector", func(t *testing.T) {
		for n := range 4 {
			_, _, err := q.Run(h.state, h.caller, addr, make([]byte, n), 10_000_000, true)
			require.Errorf(t, err, "a %d-byte input carries no selector", n)
		}
	})
}
