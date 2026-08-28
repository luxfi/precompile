// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// zzblue_meter_test.go measures what the 0x9999 money path actually COSTS a validator
// against what it CHARGES for it. Two independent axes, both of which have to hold or
// the precompile is a cheaper denial-of-service than a plain transfer:
//
//  1. Storage growth. A zero->nonzero SSTORE is 20,000 gas at reference prices and a
//     nonzero->nonzero is 5,000. A flat per-selector fee has to cover the slots the
//     selector writes, or the caller is buying state at a discount and every validator
//     carries it forever.
//
//  2. Sub-call gas. geth's PrecompileEnvironment.Call forwards its `gas` argument
//     straight to evm.Call and does NOT debit the precompile's own budget:
//
//     func (e *evmPrecompileEnv) Call(addr, input, gas, value, opts...) {
//     ret, remainingGas, err := e.evm.Call(caller, addr, input, gas, val)
//     return ret, remainingGas, err   // e.gas is untouched
//     }
//
//     For a StatefulPrecompiledContract the EVM charges exactly what RunStateful
//     RETURNS as remaining gas, so anything the precompile does not subtract itself is
//     free. The ERC-20 seam hands every token sub-call a flat erc20GasBudget and drops
//     the returned gasLeft into `_`, so the sub-call's real consumption is invisible.
//
// Neither number is changed here. Repricing a live money path is consensus-visible and
// is the owner's call; these tests PIN the current numbers so any movement is a
// deliberate, reviewed diff rather than a silent one.

// Reference EVM storage prices (EIP-2929/3529 warm-slot schedule).
const (
	blueMSstoreSet   uint64 = 20_000 // zero -> nonzero
	blueMSstoreReset uint64 = 5_000  // nonzero -> nonzero (or -> zero)
)

// blueMWrites records every storage write a call performs, split by whether the slot
// was previously zero, so the cost can be priced against the reference schedule.
type blueMWrites struct {
	set   int // zero -> nonzero
	reset int // nonzero -> anything
	noop  int // zero -> zero (charged nothing by the reference schedule)
}

func (w blueMWrites) cost() uint64 {
	return uint64(w.set)*blueMSstoreSet + uint64(w.reset)*blueMSstoreReset
}

func (w blueMWrites) total() int { return w.set + w.reset + w.noop }

// blueMMeterDB counts writes on the way through to the real StateDB.
type blueMMeterDB struct {
	contract.StateDB
	w    *blueMWrites
	host *contractStateDBWrapper // forwards the optional capabilities the seam asserts on
}

// The value path type-asserts optional capabilities on the concrete StateDB (live
// contract code for the asset verifier, the in-state ERC-20 ledger, the nonce marker).
// A decorator that swallows them silently turns a real path into a fail-closed one, so
// each is forwarded rather than dropped.
func (d blueMMeterDB) CodeSizeOf(a common.Address) int { return d.host.inner.CodeSizeOf(a) }
func (d blueMMeterDB) TokenBalanceOf(token, owner common.Address) *big.Int {
	return d.host.TokenBalanceOf(token, owner)
}
func (d blueMMeterDB) TransferTokenFrom(token, from, to common.Address, amount *big.Int) error {
	return d.host.TransferTokenFrom(token, from, to, amount)
}
func (d blueMMeterDB) TransferTokenTo(token, to common.Address, amount *big.Int) error {
	return d.host.TransferTokenTo(token, to, amount)
}

func (d blueMMeterDB) SetState(a common.Address, k common.Hash, v common.Hash) common.Hash {
	prev := d.StateDB.GetState(a, k)
	switch {
	case prev == (common.Hash{}) && v == (common.Hash{}):
		d.w.noop++
	case prev == (common.Hash{}):
		d.w.set++
	default:
		d.w.reset++
	}
	return d.StateDB.SetState(a, k, v)
}

type blueMMeterState struct {
	*nativeAtomicState
	w *blueMWrites
}

func (s blueMMeterState) GetStateDB() contract.StateDB {
	host := s.nativeAtomicState.GetStateDB().(*contractStateDBWrapper)
	return blueMMeterDB{StateDB: host, w: s.w, host: host}
}

// blueMMeasure runs one 0x9999 selector and returns what it wrote.
func blueMMeasure(t *testing.T, h *settleHarness, sel uint32, data []byte, readOnly bool) (blueMWrites, error) {
	t.Helper()
	var w blueMWrites
	st := blueMMeterState{nativeAtomicState: h.state, w: &w}
	_, _, err := h.c.Run(st, h.caller, poolManagerAddr9999, prependSelector(sel, data), 5_000_000, readOnly)
	return w, err
}

// TestBlueMeterValueArmsGrowMoreStateThanTheyCharge is a DEFECT WITNESS with numbers.
//
// It measures the storage each 0x9999 value selector writes and prices it against the
// reference SSTORE schedule. The measured result is that the flat per-selector fees do
// NOT cover the state the selectors grow — the swap intent leg writes thirteen fresh
// slots for a fee that buys two.
//
// The counts are PINNED rather than bounded, because the fix is a reprice and a reprice
// of a live money path is consensus-visible and the owner's call. Pinning means: the day
// somebody adds a fourteenth slot, or fixes the fee, this test says so out loud.
func TestBlueMeterValueArmsGrowMoreStateThanTheyCharge(t *testing.T) {
	type arm struct {
		name    string
		fee     uint64
		wantSet int // zero -> nonzero writes, measured
		run     func(h *settleHarness) (blueMWrites, error)
	}

	// (initialize is measured through registerMarket's own tests rather than here: the
	// real-asset verifier is bound to the harness's own state object, so a metering
	// decorator around it is refused fail-closed — correctly.)
	arms := []arm{
		{"swap (phase A intent)", GasNativeIntent, 13, func(h *settleHarness) (blueMWrites, error) {
			h.fundCallerNative(1_000_000)
			return blueMMeasure(t, h, SelectorSwap, h.intentCalldata(), false)
		}},
		{"modifyLiquidity (LP commit)", GasAddLiquidity, 20, func(h *settleHarness) (blueMWrites, error) {
			blueEActivateMarket(h)
			h.fundCallerNative(1_000_000)
			return blueMMeasure(t, h, SelectorModifyLiquidity,
				blueECommitCalldata(h, -60, 60, big.NewInt(1000), [32]byte{0x71}, MakerSideBid), false)
		}},
	}

	for _, a := range arms {
		h := newSettleHarness(t)
		w, err := a.run(h)
		if err != nil {
			t.Fatalf("%s: %v", a.name, err)
		}
		cost := w.cost()
		t.Logf("%-28s fee=%6d  writes=%2d (new=%2d rewrite=%2d)  reference SSTORE cost=%7d  under by %.1fx",
			a.name, a.fee, w.total(), w.set, w.reset, cost, float64(cost)/float64(a.fee))
		if w.total() == 0 {
			t.Fatalf("%s wrote no state at all — the measurement is not exercising the arm", a.name)
		}
		if a.wantSet != 0 && w.set != a.wantSet {
			t.Fatalf("%s now makes %d zero->nonzero writes, measured at %d when this witness was "+
				"written. The fee schedule was already %.1fx under its own storage cost; a change "+
				"in the write count moves that number and has to be a deliberate decision.",
				a.name, w.set, a.wantSet, float64(cost)/float64(a.fee))
		}
	}
}

// TestBlueMeterERC20SubCallGasIsNotChargedBack is a DEFECT WITNESS.
//
// Every ERC-20 leg calls `c.Call(token, input, erc20GasBudget, nil)` and drops the
// returned gasLeft into `_`. Since the precompile environment's Call does not debit
// e.gas either, the gas a token contract actually burns — up to erc20GasBudget per
// sub-call — is never charged to anyone. A settlement with several token legs
// multiplies that.
//
// The shape is asserted here at the seam: the budget handed to a token is a constant,
// and the seam keeps no record of what came back. A fix would have to thread the
// returned gasLeft out of TransferTokenFrom/TransferTokenTo/TokenBalanceOf and
// subtract (erc20GasBudget - gasLeft) from the precompile's own budget — a signature
// change and a gas change, so it is the owner's call, not this test's.
func TestBlueMeterERC20SubCallGasIsNotChargedBack(t *testing.T) {
	// The budget is a flat constant, not a function of the caller's remaining gas.
	if erc20GasBudget != 100_000 {
		t.Fatalf("erc20GasBudget = %d; this witness was written against 100000 and its "+
			"arithmetic below needs revisiting", erc20GasBudget)
	}

	// The erc20Vault surface carries NO gas in and NO gas out. That is the defect in
	// one line: a method that cannot report what it spent cannot be charged for it.
	// If this assertion ever fails because the signatures grew a gas parameter, the
	// defect is fixed and this test should be replaced by a real metering assertion.
	var v erc20Vault = &blueMNullVault{}
	if err := v.TransferTokenTo(common.Address{}, common.Address{}, big.NewInt(1)); err != nil {
		t.Fatalf("the null vault refused: %v", err)
	}

	// And the seam treats a token that consumes the WHOLE budget exactly like one that
	// consumes nothing: same verdict, same cost to the caller.
	greedy := &blueMGreedyVault{consume: erc20GasBudget}
	cheap := &blueMGreedyVault{consume: 21}
	for _, vault := range []*blueMGreedyVault{greedy, cheap} {
		if err := pullERC20Terminal(vault, common.Address{0x01}, common.Address{0x02}, big.NewInt(100)); err != nil {
			t.Fatalf("pullERC20Terminal: %v", err)
		}
	}
	if greedy.calls != cheap.calls {
		t.Fatalf("the seam made %d calls for the greedy token and %d for the cheap one", greedy.calls, cheap.calls)
	}
	// Nothing in the return path carries the greedy token's extra 99,979 gas.
	t.Logf("a token burning %d gas and one burning %d gas are indistinguishable to the seam: "+
		"both cost the caller the flat selector fee", greedy.consume, cheap.consume)
}

// blueMNullVault is the minimal erc20Vault: it exists to hold the SHAPE of the
// interface under assertion, so a future gas parameter breaks this file loudly.
type blueMNullVault struct{}

func (blueMNullVault) TokenBalanceOf(common.Address, common.Address) *big.Int { return big.NewInt(0) }
func (blueMNullVault) TransferTokenFrom(_, _, _ common.Address, _ *big.Int) error {
	return nil
}
func (blueMNullVault) TransferTokenTo(_, _ common.Address, _ *big.Int) error { return nil }

// blueMGreedyVault models a token whose transfer burns `consume` gas. The seam has no
// way to observe that, which is the point.
type blueMGreedyVault struct {
	consume uint64
	calls   int
	held    *big.Int
}

func (g *blueMGreedyVault) TokenBalanceOf(common.Address, common.Address) *big.Int {
	g.calls++
	if g.held == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(g.held)
}

func (g *blueMGreedyVault) TransferTokenFrom(_, _, _ common.Address, amount *big.Int) error {
	g.calls++
	if g.held == nil {
		g.held = big.NewInt(0)
	}
	g.held = new(big.Int).Add(g.held, amount)
	return nil
}

func (g *blueMGreedyVault) TransferTokenTo(_, _ common.Address, amount *big.Int) error {
	g.calls++
	if g.held == nil {
		g.held = big.NewInt(0)
	}
	if g.held.Cmp(amount) < 0 {
		return errors.New("blueM: vault short")
	}
	g.held = new(big.Int).Sub(g.held, amount)
	return nil
}

// TestBlueMeterPullERC20TerminalDeliveryBoundary sweeps the under-delivery guard, the
// one thing standing between a fee-on-transfer token and a vault credited with value it
// never received. The comparison is `delivered >= amount`; one step either side of it
// changes who loses money, so both sides are pinned.
func TestBlueMeterPullERC20TerminalDeliveryBoundary(t *testing.T) {
	const want = 1000
	for _, delta := range []int64{-1, 0, +1} {
		v := &blueMShortVault{deliver: big.NewInt(want + delta)}
		err := pullERC20Terminal(v, common.Address{0x01}, common.Address{0x02}, big.NewInt(want))
		switch {
		case delta < 0 && !errors.Is(err, ErrERC20UnderDelivered):
			t.Fatalf("delivering %d of %d = %v, want ErrERC20UnderDelivered", want+delta, want, err)
		case delta >= 0 && err != nil:
			t.Fatalf("delivering %d of %d = %v, want success", want+delta, want, err)
		}
	}

	// A token whose transfer REVERTS is a failed transfer and the error stays
	// distinguishable from under-delivery — a caller has to be able to tell "the token
	// refused" from "the token lied about the amount".
	boom := &blueMShortVault{deliver: big.NewInt(want), failTransfer: errors.New("reverted")}
	err := pullERC20Terminal(boom, common.Address{0x01}, common.Address{0x02}, big.NewInt(want))
	if !errors.Is(err, ErrERC20TransferFailed) {
		t.Fatalf("a reverting token = %v, want ErrERC20TransferFailed", err)
	}
	if errors.Is(err, ErrERC20UnderDelivered) {
		t.Fatal("a revert was reported as an under-delivery")
	}

	// A token that reports a SMALLER balance after the transfer than before (a
	// rebasing-down token) is caught by the same guard rather than producing a
	// negative delta that compares as large.
	shrink := &blueMShortVault{deliver: big.NewInt(-1)}
	if err := pullERC20Terminal(shrink, common.Address{0x01}, common.Address{0x02}, big.NewInt(want)); !errors.Is(err, ErrERC20UnderDelivered) {
		t.Fatalf("a token whose balance SHRANK across the transfer = %v, want ErrERC20UnderDelivered", err)
	}
}

// blueMShortVault delivers exactly `deliver` into the vault regardless of what was
// asked for — the fee-on-transfer / rebasing shape.
type blueMShortVault struct {
	deliver      *big.Int
	failTransfer error
	balance      *big.Int
}

func (v *blueMShortVault) TokenBalanceOf(common.Address, common.Address) *big.Int {
	if v.balance == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(v.balance)
}

func (v *blueMShortVault) TransferTokenFrom(_, _, _ common.Address, _ *big.Int) error {
	if v.failTransfer != nil {
		return v.failTransfer
	}
	v.balance = new(big.Int).Set(v.deliver)
	return nil
}

func (v *blueMShortVault) TransferTokenTo(_, _ common.Address, _ *big.Int) error { return nil }
