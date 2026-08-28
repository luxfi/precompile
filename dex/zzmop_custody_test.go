// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
)

// zzmop_custody_test.go covers the 0x9999 vault's funds-in / funds-out / balance
// surface (settle_custody.go). 0x9999 is the ONLY always-on precompile, so every
// refusal here is load-bearing on every Lux network from genesis.
//
// The invariant under test throughout is CUSTODY CONSERVATION: value in equals
// value out. A depositor's claim and the per-asset vault total move in lock-step
// with the vault's REAL balance, an over-withdraw is clamped rather than minted,
// and an underflow ABORTS rather than wrapping 0x9999's balance.

// zzmpAssetAmountData builds the 2-word (address asset, uint256 amount) calldata body
// the deposit / withdraw / seed selectors share.
func zzmpAssetAmountData(asset common.Address, amount *big.Int) []byte {
	data := make([]byte, 64)
	copy(data[12:32], asset.Bytes())
	if amount != nil && amount.Sign() > 0 {
		amount.FillBytes(data[32:64])
	}
	return data
}

// zzmpBalanceOfData builds balanceOf(address account, address asset) calldata.
func zzmpBalanceOfData(account, asset common.Address) []byte {
	data := make([]byte, 64)
	copy(data[12:32], account.Bytes())
	copy(data[44:64], asset.Bytes())
	return data
}

// zzmpNoPanic runs fn and turns a panic into a test failure naming ctx. A panic that
// escapes a precompile entry point is a CHAIN HALT, not a safe refusal, so it must be
// reported as a failure rather than allowed to abort the whole binary.
func zzmpNoPanic(t *testing.T, ctx string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("PANIC escaped a precompile entry point (chain halt) at %s: %v", ctx, r)
		}
	}()
	fn()
}

// zzmpRun drives a 0x9999 selector through the real Run dispatcher.
func zzmpRun(h *settleHarness, caller common.Address, sel uint32, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	return h.c.Run(h.state, caller, poolManagerAddr9999, prependSelector(sel, data), gas, readOnly)
}

// zzmpDB is the harness's state as the dex StateDB adapter (the same adapter the
// handlers build), so a test can read the very slots the handlers wrote.
func zzmpDB(h *settleHarness) *poolStateAdapter { return newPoolStateAdapter(h.state) }

// zzmpSetHaltAsset drives the REAL governance-gated setHaltAsset selector.
func zzmpSetHaltAsset(t *testing.T, h *settleHarness, aid [32]byte, on bool) {
	t.Helper()
	data := make([]byte, 64)
	copy(data[0:32], aid[:])
	if on {
		data[63] = 1
	}
	if _, _, err := zzmpRun(h, h.operator(), SelectorSetHaltAsset, data, 5_000_000, false); err != nil {
		t.Fatalf("setHaltAsset: %v", err)
	}
}

// zzmpSetHaltGlobal drives the REAL governance-gated setHaltGlobal selector.
func zzmpSetHaltGlobal(t *testing.T, h *settleHarness, on bool) {
	t.Helper()
	data := make([]byte, 32)
	if on {
		data[31] = 1
	}
	if _, _, err := zzmpRun(h, h.operator(), SelectorSetHaltGlobal, data, 5_000_000, false); err != nil {
		t.Fatalf("setHaltGlobal: %v", err)
	}
}

// ---------------------------------------------------------------------------
// deposit — refusals
// ---------------------------------------------------------------------------

func TestZzmpDepositRefusesReadOnlyOutOfGasAndShortInput(t *testing.T) {
	h := newSettleHarness(t)
	good := zzmpAssetAmountData(common.Address{}, big.NewInt(10))

	if _, gasLeft, err := zzmpRun(h, h.caller, SelectorDeposit, good, 5_000_000, true); err == nil {
		t.Fatal("read-only deposit must be refused")
	} else if gasLeft != 5_000_000 {
		t.Fatalf("a read-only refusal must charge no gas, got gasLeft=%d", gasLeft)
	}

	if _, gasLeft, err := zzmpRun(h, h.caller, SelectorDeposit, good, GasSettlement-1, false); err == nil {
		t.Fatal("deposit under GasSettlement must be refused")
	} else if gasLeft != 0 {
		t.Fatalf("an out-of-gas refusal must consume the supply, got gasLeft=%d", gasLeft)
	}

	// EVERY truncation of a well-formed body must be refused (never credited, never panic).
	for n := 0; n < 64; n++ {
		n := n
		zzmpNoPanic(t, "deposit truncated body", func() {
			if _, _, err := zzmpRun(h, h.caller, SelectorDeposit, good[:n], 5_000_000, false); err == nil {
				t.Errorf("deposit accepted a %d-byte body (needs 64)", n)
			}
		})
	}
	// A calldata too short to even carry a selector must be refused at the dispatcher.
	for n := 0; n < 4; n++ {
		n := n
		zzmpNoPanic(t, "sub-selector calldata", func() {
			if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, make([]byte, n), 5_000_000, false); err == nil {
				t.Errorf("0x9999 accepted %d-byte calldata (needs a 4-byte selector)", n)
			}
		})
	}
}

func TestZzmpDepositRefusesZeroAmountAndHaltedAsset(t *testing.T) {
	h := newSettleHarness(t)

	// A zero-amount deposit must not mint a claim.
	if _, _, err := zzmpRun(h, h.caller, SelectorDeposit, zzmpAssetAmountData(common.Address{}, big.NewInt(0)), 5_000_000, false); !errors.Is(err, ErrInvalidAmount) {
		t.Fatalf("zero-amount deposit: want ErrInvalidAmount, got %v", err)
	}

	// A halted ASSET refuses funding of that asset...
	aid := h.inAssetID() // native
	zzmpSetHaltAsset(t, h, aid, true)
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(50)) // host frame delivered value
	if _, _, err := zzmpRun(h, h.caller, SelectorDeposit, zzmpAssetAmountData(common.Address{}, big.NewInt(50)), 5_000_000, false); !errors.Is(err, ErrAssetHalted) {
		t.Fatalf("halted-asset deposit: want ErrAssetHalted, got %v", err)
	}
	if got := loadSettleVault(zzmpDB(h), aid); got.Sign() != 0 {
		t.Fatalf("a refused deposit credited the vault: %s", got)
	}
	if got := loadDepositorClaim(zzmpDB(h), h.caller, aid); got.Sign() != 0 {
		t.Fatalf("a refused deposit credited a claim: %s", got)
	}

	// ...and un-halting restores it (a halt is a switch, not a one-way door).
	zzmpSetHaltAsset(t, h, aid, false)
	if _, _, err := zzmpRun(h, h.caller, SelectorDeposit, zzmpAssetAmountData(common.Address{}, big.NewInt(50)), 5_000_000, false); err != nil {
		t.Fatalf("deposit after un-halt: %v", err)
	}
}

func TestZzmpDepositRefusesReentrantEntry(t *testing.T) {
	h := newSettleHarness(t)
	db := zzmpDB(h)
	// Arm the SHARED 0x9999 custody guard exactly as an in-flight custody op leaves it.
	db.SetState(poolManagerAddr9999, custodyGuardKey9999, common.Hash{31: 1})

	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(100))
	if _, _, err := zzmpRun(h, h.caller, SelectorDeposit, zzmpAssetAmountData(common.Address{}, big.NewInt(100)), 5_000_000, false); !errors.Is(err, ErrCustodyReentrant) {
		t.Fatalf("re-entered deposit: want ErrCustodyReentrant, got %v", err)
	}
	if _, _, err := zzmpRun(h, h.caller, SelectorWithdraw, zzmpAssetAmountData(common.Address{}, big.NewInt(1)), 5_000_000, false); !errors.Is(err, ErrCustodyReentrant) {
		t.Fatalf("re-entered withdraw: want ErrCustodyReentrant, got %v", err)
	}
	if got := loadDepositorClaim(db, h.caller, h.inAssetID()); got.Sign() != 0 {
		t.Fatalf("a reentrancy-refused deposit still credited a claim: %s", got)
	}
}

// TestZzmpDepositNativeRequiresDeliveredValue pins the OBSERVED-DELTA rule: the claim
// is minted only for native the CALL actually carried. An absolute-balance test would
// let a msg.value==0 deposit mint a claim against OTHER depositors' funds in the shared
// vault, so a deposit with no delivered value must refuse.
func TestZzmpDepositNativeRequiresDeliveredValue(t *testing.T) {
	h := newSettleHarness(t)
	aid := h.inAssetID()

	// No delivered value at all.
	if _, _, err := zzmpRun(h, h.caller, SelectorDeposit, zzmpAssetAmountData(common.Address{}, big.NewInt(100)), 5_000_000, false); !errors.Is(err, ErrSettleDepositShort) {
		t.Fatalf("undelivered native deposit: want ErrSettleDepositShort, got %v", err)
	}

	// A genuine first deposit of 100.
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(100))
	if _, _, err := zzmpRun(h, h.caller, SelectorDeposit, zzmpAssetAmountData(common.Address{}, big.NewInt(100)), 5_000_000, false); err != nil {
		t.Fatalf("funded deposit: %v", err)
	}
	db := zzmpDB(h)
	if got := loadSettleVault(db, aid); got.Int64() != 100 {
		t.Fatalf("vault total after deposit: want 100, got %s", got)
	}

	// THE ATTACK: a SECOND depositor calls deposit(100) delivering NOTHING. The vault's
	// real balance is 100 (the first depositor's), but it is already tracked, so the
	// observed delta is 0 and the claim must be refused.
	attacker := common.HexToAddress("0xBAD0000000000000000000000000000000000BAD")
	if _, _, err := zzmpRun(h, attacker, SelectorDeposit, zzmpAssetAmountData(common.Address{}, big.NewInt(100)), 5_000_000, false); !errors.Is(err, ErrSettleDepositShort) {
		t.Fatalf("value-free deposit against another depositor's funds: want ErrSettleDepositShort, got %v", err)
	}
	if got := loadDepositorClaim(db, attacker, aid); got.Sign() != 0 {
		t.Fatalf("a value-free deposit minted a claim of %s against the shared vault", got)
	}
	// Conservation: Σ claims == vault total == real 0x9999 balance.
	if got := loadDepositorClaim(db, h.caller, aid); got.Int64() != 100 {
		t.Fatalf("honest depositor's claim: want 100, got %s", got)
	}
	if got := h.state.stateDB.GetBalance(poolManagerAddr9999).Uint64(); got != 100 {
		t.Fatalf("real 0x9999 native balance: want 100, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// deposit -> withdraw — conservation
// ---------------------------------------------------------------------------

func TestZzmpNativeDepositWithdrawConservesValue(t *testing.T) {
	h := newSettleHarness(t)
	aid := h.inAssetID()
	db := zzmpDB(h)

	const amount = 1_000
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(amount))
	out, _, err := zzmpRun(h, h.caller, SelectorDeposit, zzmpAssetAmountData(common.Address{}, big.NewInt(amount)), 5_000_000, false)
	if err != nil {
		t.Fatalf("deposit: %v", err)
	}
	if got := new(big.Int).SetBytes(out).Int64(); got != amount {
		t.Fatalf("deposit returned %d, want %d", got, amount)
	}

	callerBefore := h.state.stateDB.GetBalance(h.caller).Uint64()
	vaultBefore := h.state.stateDB.GetBalance(poolManagerAddr9999).Uint64()

	// Withdraw in two halves; every intermediate state must balance exactly.
	for i, want := range []int64{400, 600} {
		out, _, err := zzmpRun(h, h.caller, SelectorWithdraw, zzmpAssetAmountData(common.Address{}, big.NewInt(want)), 5_000_000, false)
		if err != nil {
			t.Fatalf("withdraw %d: %v", i, err)
		}
		if got := new(big.Int).SetBytes(out).Int64(); got != want {
			t.Fatalf("withdraw %d realized %d, want %d", i, got, want)
		}
	}

	if got := loadDepositorClaim(db, h.caller, aid); got.Sign() != 0 {
		t.Fatalf("claim after full withdraw: want 0, got %s", got)
	}
	if got := loadSettleVault(db, aid); got.Sign() != 0 {
		t.Fatalf("vault total after full withdraw: want 0, got %s", got)
	}
	if got := h.state.stateDB.GetBalance(h.caller).Uint64(); got != callerBefore+amount {
		t.Fatalf("caller balance: want %d, got %d", callerBefore+amount, got)
	}
	if got := h.state.stateDB.GetBalance(poolManagerAddr9999).Uint64(); got != vaultBefore-amount {
		t.Fatalf("vault balance: want %d, got %d", vaultBefore-amount, got)
	}
}

// TestZzmpWithdrawClampsToClaimAndToVault pins BOTH clamps. Over-asking must yield the
// depositor's OWN claim, never another depositor's funds; and if the tracked vault total
// is somehow below the claim, the vault total wins (defense in depth).
func TestZzmpWithdrawClampsToClaimAndToVault(t *testing.T) {
	h := newSettleHarness(t)
	aid := h.inAssetID()
	db := zzmpDB(h)

	// Two depositors fund the SHARED vault.
	other := common.HexToAddress("0x0000000000000000000000000000000000005151")
	for _, dep := range []struct {
		who    common.Address
		amount int64
	}{{h.caller, 300}, {other, 700}} {
		h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(uint64(dep.amount)))
		if _, _, err := zzmpRun(h, dep.who, SelectorDeposit, zzmpAssetAmountData(common.Address{}, big.NewInt(dep.amount)), 5_000_000, false); err != nil {
			t.Fatalf("deposit for %s: %v", dep.who.Hex(), err)
		}
	}

	// The caller asks for the WHOLE vault; it must be clamped to its own 300.
	out, _, err := zzmpRun(h, h.caller, SelectorWithdraw, zzmpAssetAmountData(common.Address{}, big.NewInt(1_000)), 5_000_000, false)
	if err != nil {
		t.Fatalf("over-ask withdraw: %v", err)
	}
	if got := new(big.Int).SetBytes(out).Int64(); got != 300 {
		t.Fatalf("over-ask withdraw realized %d — it must clamp to the caller's own claim of 300", got)
	}
	if got := loadDepositorClaim(db, other, aid); got.Int64() != 700 {
		t.Fatalf("another depositor's claim was drawn on: want 700, got %s", got)
	}
	if got := loadSettleVault(db, aid); got.Int64() != 700 {
		t.Fatalf("vault total after clamped withdraw: want 700, got %s", got)
	}

	// Defense in depth: a claim that exceeds the tracked vault total clamps to the total.
	storeDepositorClaim(db, h.caller, aid, big.NewInt(5_000))
	out, _, err = zzmpRun(h, h.caller, SelectorWithdraw, zzmpAssetAmountData(common.Address{}, big.NewInt(5_000)), 5_000_000, false)
	if err != nil {
		t.Fatalf("vault-clamped withdraw: %v", err)
	}
	if got := new(big.Int).SetBytes(out).Int64(); got != 700 {
		t.Fatalf("a claim above the vault total realized %d — it must clamp to the vault's 700", got)
	}
	if got := loadSettleVault(db, aid); got.Sign() != 0 {
		t.Fatalf("vault total after the clamp: want 0, got %s", got)
	}
}

func TestZzmpWithdrawOfNothingIsANoOp(t *testing.T) {
	h := newSettleHarness(t)
	before := h.state.stateDB.GetBalance(h.caller).Uint64()

	out, _, err := zzmpRun(h, h.caller, SelectorWithdraw, zzmpAssetAmountData(common.Address{}, big.NewInt(0)), 5_000_000, false)
	if err != nil {
		t.Fatalf("zero withdraw must be a no-op, got %v", err)
	}
	if len(out) != 32 || new(big.Int).SetBytes(out).Sign() != 0 {
		t.Fatalf("zero withdraw must return a zero word, got %x", out)
	}
	// No claim either -> still a no-op, not a mint.
	if _, _, err := zzmpRun(h, h.caller, SelectorWithdraw, zzmpAssetAmountData(common.Address{}, big.NewInt(50)), 5_000_000, false); err != nil {
		t.Fatalf("claimless withdraw must be a no-op, got %v", err)
	}
	if got := h.state.stateDB.GetBalance(h.caller).Uint64(); got != before {
		t.Fatalf("a no-op withdraw moved value: %d -> %d", before, got)
	}
}

// TestZzmpWithdrawUnderflowAbortsRatherThanWrapping is the load-bearing one:
// SubBalance is uint256-MODULAR from a precompile. If the ledger ever claims more
// native than 0x9999 really holds, the withdraw must ABORT — wrapping would hand the
// caller ~2^256 and leave the vault with a colossal phantom balance.
func TestZzmpWithdrawUnderflowAbortsRatherThanWrapping(t *testing.T) {
	h := newSettleHarness(t)
	aid := h.inAssetID()
	db := zzmpDB(h)

	// A ledger that says 100 while the vault really holds 0 (a regression / corruption).
	storeDepositorClaim(db, h.caller, aid, big.NewInt(100))
	storeSettleVault(db, aid, big.NewInt(100))
	if got := h.state.stateDB.GetBalance(poolManagerAddr9999).Uint64(); got != 0 {
		t.Fatalf("precondition: vault must really hold 0, got %d", got)
	}

	callerBefore := h.state.stateDB.GetBalance(h.caller).Uint64()
	if _, _, err := zzmpRun(h, h.caller, SelectorWithdraw, zzmpAssetAmountData(common.Address{}, big.NewInt(100)), 5_000_000, false); !errors.Is(err, ErrSettleClaimShort) {
		t.Fatalf("unbacked native withdraw: want ErrSettleClaimShort, got %v", err)
	}
	if got := h.state.stateDB.GetBalance(poolManagerAddr9999); got.Sign() != 0 {
		t.Fatalf("the vault's native balance WRAPPED to %s instead of aborting", got)
	}
	if got := h.state.stateDB.GetBalance(h.caller).Uint64(); got != callerBefore {
		t.Fatalf("an aborted withdraw still credited the caller: %d -> %d", callerBefore, got)
	}
}

// TestZzmpWithdrawIsNotHaltGated pins the safe default: a halt stops NEW swaps but must
// never strand funds. Deposit is asset-halt-gated; withdraw and balanceOf are not gated
// at all, so escrowed value can always exit.
func TestZzmpWithdrawIsNotHaltGated(t *testing.T) {
	h := newSettleHarness(t)
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(250))
	if _, _, err := zzmpRun(h, h.caller, SelectorDeposit, zzmpAssetAmountData(common.Address{}, big.NewInt(250)), 5_000_000, false); err != nil {
		t.Fatalf("deposit: %v", err)
	}

	zzmpSetHaltGlobal(t, h, true)
	zzmpSetHaltAsset(t, h, h.inAssetID(), true)

	out, _, err := zzmpRun(h, h.caller, SelectorWithdraw, zzmpAssetAmountData(common.Address{}, big.NewInt(250)), 5_000_000, false)
	if err != nil {
		t.Fatalf("withdraw under a global+asset halt must still work (funds always exit), got %v", err)
	}
	if got := new(big.Int).SetBytes(out).Int64(); got != 250 {
		t.Fatalf("halted withdraw realized %d, want 250", got)
	}
	out, _, err = zzmpRun(h, h.caller, SelectorBalanceOf, zzmpBalanceOfData(h.caller, common.Address{}), 5_000_000, true)
	if err != nil {
		t.Fatalf("balanceOf under halt: %v", err)
	}
	if new(big.Int).SetBytes(out).Sign() != 0 {
		t.Fatalf("balanceOf after full withdraw: want 0, got %x", out)
	}
}

func TestZzmpWithdrawRefusesReadOnlyOutOfGasAndShortInput(t *testing.T) {
	h := newSettleHarness(t)
	good := zzmpAssetAmountData(common.Address{}, big.NewInt(1))

	if _, gasLeft, err := zzmpRun(h, h.caller, SelectorWithdraw, good, 5_000_000, true); err == nil {
		t.Fatal("read-only withdraw must be refused")
	} else if gasLeft != 5_000_000 {
		t.Fatalf("read-only refusal must charge no gas, got %d", gasLeft)
	}
	if _, gasLeft, err := zzmpRun(h, h.caller, SelectorWithdraw, good, GasSettlement-1, false); err == nil {
		t.Fatal("withdraw under GasSettlement must be refused")
	} else if gasLeft != 0 {
		t.Fatalf("out-of-gas refusal must consume the supply, got %d", gasLeft)
	}
	for n := 0; n < 64; n++ {
		n := n
		zzmpNoPanic(t, "withdraw truncated body", func() {
			if _, _, err := zzmpRun(h, h.caller, SelectorWithdraw, good[:n], 5_000_000, false); err == nil {
				t.Errorf("withdraw accepted a %d-byte body (needs 64)", n)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// balanceOf
// ---------------------------------------------------------------------------

func TestZzmpBalanceOfReadsTheNamedAccountsClaim(t *testing.T) {
	h := newSettleHarness(t)
	other := common.HexToAddress("0x00000000000000000000000000000000000000B0")

	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(77))
	if _, _, err := zzmpRun(h, h.caller, SelectorDeposit, zzmpAssetAmountData(common.Address{}, big.NewInt(77)), 5_000_000, false); err != nil {
		t.Fatalf("deposit: %v", err)
	}

	out, gasLeft, err := zzmpRun(h, other, SelectorBalanceOf, zzmpBalanceOfData(h.caller, common.Address{}), 5_000_000, true)
	if err != nil {
		t.Fatalf("balanceOf: %v", err)
	}
	if got := new(big.Int).SetBytes(out).Int64(); got != 77 {
		t.Fatalf("balanceOf(depositor): want 77, got %d", got)
	}
	if gasLeft != 5_000_000-GasPoolLookup {
		t.Fatalf("balanceOf gas: want %d, got %d", 5_000_000-GasPoolLookup, gasLeft)
	}
	// balanceOf is keyed by (account, asset): a different account, and a different
	// asset for the same account, both read zero.
	out, _, err = zzmpRun(h, other, SelectorBalanceOf, zzmpBalanceOfData(other, common.Address{}), 5_000_000, true)
	if err != nil || new(big.Int).SetBytes(out).Sign() != 0 {
		t.Fatalf("balanceOf(non-depositor): want 0/nil, got %x/%v", out, err)
	}
	out, _, err = zzmpRun(h, other, SelectorBalanceOf, zzmpBalanceOfData(h.caller, h.outToken()), 5_000_000, true)
	if err != nil || new(big.Int).SetBytes(out).Sign() != 0 {
		t.Fatalf("balanceOf(depositor, other asset): want 0/nil, got %x/%v", out, err)
	}

	// Refusals.
	if _, gasLeft, err := zzmpRun(h, other, SelectorBalanceOf, zzmpBalanceOfData(h.caller, common.Address{}), GasPoolLookup-1, true); err == nil {
		t.Fatal("balanceOf under GasPoolLookup must be refused")
	} else if gasLeft != 0 {
		t.Fatalf("out-of-gas refusal must consume the supply, got %d", gasLeft)
	}
	for n := 0; n < 64; n++ {
		n := n
		zzmpNoPanic(t, "balanceOf truncated body", func() {
			if _, _, err := zzmpRun(h, other, SelectorBalanceOf, make([]byte, n), 5_000_000, true); err == nil {
				t.Errorf("balanceOf accepted a %d-byte body (needs 64)", n)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ERC-20 legs
// ---------------------------------------------------------------------------

func TestZzmpERC20DepositWithdrawConservesTokenValue(t *testing.T) {
	h := newSettleHarness(t)
	token := h.outToken()
	aid := h.outAssetID()
	db := zzmpDB(h)

	h.wrapper().mintTestToken(token, h.caller, big.NewInt(1_000))
	callerTokBefore := h.wrapper().TokenBalanceOf(token, h.caller)

	if _, _, err := zzmpRun(h, h.caller, SelectorDeposit, zzmpAssetAmountData(token, big.NewInt(600)), 5_000_000, false); err != nil {
		t.Fatalf("erc20 deposit: %v", err)
	}
	if got := loadDepositorClaim(db, h.caller, aid); got.Int64() != 600 {
		t.Fatalf("erc20 claim: want 600, got %s", got)
	}
	if got := loadSettleVault(db, aid); got.Int64() != 600 {
		t.Fatalf("erc20 vault total: want 600, got %s", got)
	}
	if got := h.wrapper().TokenBalanceOf(token, poolManagerAddr9999); got.Int64() != 600 {
		t.Fatalf("vault token holding: want 600, got %s", got)
	}
	if got := h.wrapper().TokenBalanceOf(token, h.caller); got.Cmp(new(big.Int).Sub(callerTokBefore, big.NewInt(600))) != 0 {
		t.Fatalf("caller token balance: want %s, got %s", new(big.Int).Sub(callerTokBefore, big.NewInt(600)), got)
	}

	out, _, err := zzmpRun(h, h.caller, SelectorWithdraw, zzmpAssetAmountData(token, big.NewInt(600)), 5_000_000, false)
	if err != nil {
		t.Fatalf("erc20 withdraw: %v", err)
	}
	if got := new(big.Int).SetBytes(out).Int64(); got != 600 {
		t.Fatalf("erc20 withdraw realized %d, want 600", got)
	}
	if got := h.wrapper().TokenBalanceOf(token, h.caller); got.Cmp(callerTokBefore) != 0 {
		t.Fatalf("token value not conserved across deposit+withdraw: want %s, got %s", callerTokBefore, got)
	}
	if got := h.wrapper().TokenBalanceOf(token, poolManagerAddr9999); got.Sign() != 0 {
		t.Fatalf("vault still holds %s of the token after a full withdraw", got)
	}
	if got := loadSettleVault(db, aid); got.Sign() != 0 {
		t.Fatalf("erc20 vault total after full withdraw: want 0, got %s", got)
	}
}

// TestZzmpERC20DepositRefusesUnderDelivery pins the fail-secure conservation guard:
// a fee-on-transfer / rebasing-down token delivers less than requested, so the frame
// must REFUSE rather than record a claim the vault cannot back. (Rolling the Phase-A
// record back is the EVM frame's revert, which the mock does not model — the assertion
// here is that the call REFUSES.)
func TestZzmpERC20DepositRefusesUnderDelivery(t *testing.T) {
	h := newSettleHarness(t)
	token := h.outToken()
	h.wrapper().mintTestToken(token, h.caller, big.NewInt(1_000))
	h.state.stateDB.feeOnTransferBps = 100 // 1% skimmed in transit

	if _, _, err := zzmpRun(h, h.caller, SelectorDeposit, zzmpAssetAmountData(token, big.NewInt(500)), 5_000_000, false); !errors.Is(err, ErrERC20UnderDelivered) {
		t.Fatalf("under-delivering token deposit: want ErrERC20UnderDelivered, got %v", err)
	}

	// A token whose transferFrom outright fails (insufficient balance) is refused too.
	h.state.stateDB.feeOnTransferBps = 0
	poor := common.HexToAddress("0x00000000000000000000000000000000000F0000")
	if _, _, err := zzmpRun(h, poor, SelectorDeposit, zzmpAssetAmountData(token, big.NewInt(5)), 5_000_000, false); !errors.Is(err, ErrERC20TransferFailed) {
		t.Fatalf("unfunded erc20 deposit: want ErrERC20TransferFailed, got %v", err)
	}
}

// TestZzmpERC20WithdrawRefusesWhenTheVaultCannotPay pins that the terminal transfer's
// failure surfaces as a refusal rather than being swallowed into a silent partial.
func TestZzmpERC20WithdrawRefusesWhenTheVaultCannotPay(t *testing.T) {
	h := newSettleHarness(t)
	token := h.outToken()
	aid := h.outAssetID()
	db := zzmpDB(h)

	// A ledger that claims 400 of the token while the vault holds none.
	storeDepositorClaim(db, h.caller, aid, big.NewInt(400))
	storeSettleVault(db, aid, big.NewInt(400))

	if _, _, err := zzmpRun(h, h.caller, SelectorWithdraw, zzmpAssetAmountData(token, big.NewInt(400)), 5_000_000, false); !errors.Is(err, ErrERC20TransferFailed) {
		t.Fatalf("unbacked erc20 withdraw: want ErrERC20TransferFailed, got %v", err)
	}
	if got := h.wrapper().TokenBalanceOf(token, h.caller); got.Sign() != 0 {
		t.Fatalf("an aborted erc20 withdraw still delivered %s", got)
	}
}
