// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// native_conservation_test.go is the FIX-3 regression suite: the conservation
// blast-radius between the SEAM (Phase-A lock / Phase-B credit) and CUSTODY
// (deposit / withdraw), which share the 0x9999 vault ACCOUNT but must keep DISJOINT
// claims on it.
//
// THE BUG (Red-found): both subsystems wrote ONE pot (settleVault[a]), and a Phase-B
// settlement credit checked only the TOTAL settleVault[a] >= amount. So a settlement
// could pay a taker out of a custody DEPOSITOR's withdrawable claim, and a depositor's
// withdraw could drain the pot and strand a legitimately-backed settlement.
//
// THE FIX: the seam owns a separate seamReserve[a] pot; settleVault[a] is now PURELY
// the depositor pot (== Σ depositorClaim). The vault-account invariant per asset a is
//
//	realHolding(0x9999, a) == settleVault[a] + makerLockedVault[a] + seamReserve[a]
//
// and a settlement credit draws ONLY seamReserve[a], a withdraw ONLY settleVault[a].
// These tests exercise BOTH subsystems against the SAME asset and assert the pots
// never raid each other and the invariant holds end-to-end.

// vaultInvariantNative asserts the FULL vault-account invariant for the native asset:
//
//	realHolding == settleVault + makerLockedVault + seamReserve + committedPositions
//
// the four orthogonal pots that partition the 0x9999 vault by CLAIM (depositor pot,
// legacy maker pot, swap-rail seam reserve, LP-rail committed positions). Each pot
// backs only its own credits; none can raid another.
func (h *settleHarness) vaultInvariantNative(t testing.TB, where string) {
	t.Helper()
	db := newPoolStateAdapter(h.state)
	native := [32]byte{}
	real := h.state.stateDB.GetBalance(poolManagerAddr9999).ToBig()
	sum := new(big.Int).Add(loadSettleVault(db, native), loadMakerLockedVault(db, native))
	sum.Add(sum, loadSeamReserve(db, native))
	sum.Add(sum, loadCommittedPositions(db, native))
	if real.Cmp(sum) != 0 {
		t.Fatalf("%s: vault-account invariant violated: realHolding=%s != settleVault+makerLocked+seamReserve+committedPositions=%s", where, real, sum)
	}
}

// depositNative funds a depositor's claim through the custody deposit selector using
// the native observed-delta path: the EVM moves msg.value into 0x9999 before Run, so
// we add the balance first (the host frame), then call deposit(asset=0, amount).
func (h *settleHarness) depositNative(t testing.TB, depositor common.Address, amount int64) {
	t.Helper()
	h.state.stateDB.AddBalance(depositor, uint256.NewInt(uint64(amount)))
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(uint64(amount))) // host frame moved msg.value
	data := make([]byte, 64)                                                         // asset = address(0) (native), amount
	new(big.Int).SetInt64(amount).FillBytes(data[32:64])
	_, _, err := h.c.Run(h.state, depositor, poolManagerAddr9999,
		prependSelector(SelectorDeposit, data), 5_000_000, false)
	if err != nil {
		t.Fatalf("depositNative(%d): %v", amount, err)
	}
}

// withdrawNative pulls a depositor's claim back through the custody withdraw selector.
func (h *settleHarness) withdrawNative(t testing.TB, depositor common.Address, amount int64) {
	t.Helper()
	data := make([]byte, 64) // asset = address(0), want
	new(big.Int).SetInt64(amount).FillBytes(data[32:64])
	_, _, err := h.c.Run(h.state, depositor, poolManagerAddr9999,
		prependSelector(SelectorWithdraw, data), 5_000_000, false)
	if err != nil {
		t.Fatalf("withdrawNative(%d): %v", amount, err)
	}
}

// TestFIX3_SettlementCannotRaidDepositorClaim — a Phase-B settlement credit draws ONLY
// on the seam reserve. With a fat depositor claim in settleVault but ZERO seam reserve,
// a settlement that consumes a real D->C object REVERTS (unbacked) — it can NOT pay the
// taker out of the depositor's funds. The OLD code (one pot, total check) would have
// let it through and silently un-backed the depositor's claim.
func TestFIX3_SettlementCannotRaidDepositorClaim(t *testing.T) {
	h := newSettleHarness(t)
	depositor := common.HexToAddress("0xD0905170000000000000000000000000000000A1")
	native := [32]byte{}

	// A depositor funds the vault — this is the DEPOSITOR pot (settleVault), NOT seam.
	h.depositNative(t, depositor, 1000)
	if loadDepositorClaim(newPoolStateAdapter(h.state), depositor, native).Int64() != 1000 {
		t.Fatal("depositor claim must be 1000")
	}
	if loadSeamReserve(newPoolStateAdapter(h.state), native).Sign() != 0 {
		t.Fatal("seam reserve must be ZERO (no operator seed, no intent locks)")
	}
	h.vaultInvariantNative(t, "after deposit")

	// D exported a D->C native settlement object for the taker. The vault HAS 1000
	// native (the depositor's), but the seam reserve is 0.
	outputID := ids.ID{0x5E, 0x77}
	h.putDtoCObject(t, h.caller, outputID, native, 500)

	credited, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: outputID, Asset: native, AssetAddr: common.Address{}, Amount: 500, Recipient: h.caller,
	})
	if err != ErrNativeSettleUnbacked {
		t.Fatalf("BLAST RADIUS: a settlement with empty seam reserve must REVERT (ErrNativeSettleUnbacked), not raid the depositor pot; got credited=%d err=%v", credited, err)
	}
	// The depositor's claim is untouched — they can still withdraw all 1000.
	if loadDepositorClaim(newPoolStateAdapter(h.state), depositor, native).Int64() != 1000 {
		t.Fatal("depositor claim must remain 1000 after the refused settlement")
	}
	h.vaultInvariantNative(t, "after refused settlement")
}

// TestFIX3_WithdrawCannotStrandSettlement — a depositor withdrawing their FULL claim
// touches only settleVault; the seam reserve (operator-seeded) is untouched, so a
// backed settlement still succeeds afterward. The OLD code's shared pot let a withdraw
// drain the funds a settlement relied on.
func TestFIX3_WithdrawCannotStrandSettlement(t *testing.T) {
	h := newSettleHarness(t)
	depositor := common.HexToAddress("0xD0905170000000000000000000000000000000A2")
	native := [32]byte{}

	// Operator seeds the SEAM reserve (counterparty backing for settlements).
	h.fundVaultNativeOut(500) // -> seamReserve[native] = 500, real += 500
	// A depositor independently funds their claim (depositor pot).
	h.depositNative(t, depositor, 1000) // -> settleVault[native] = 1000, real += 1000
	h.vaultInvariantNative(t, "after seed + deposit")

	// The depositor withdraws their ENTIRE claim. This must NOT reach the seam reserve.
	h.withdrawNative(t, depositor, 1000)
	db := newPoolStateAdapter(h.state)
	if loadDepositorClaim(db, depositor, native).Sign() != 0 {
		t.Fatal("depositor claim must be 0 after full withdraw")
	}
	if loadSeamReserve(db, native).Int64() != 500 {
		t.Fatalf("seam reserve must remain 500 after the depositor's withdraw, got %s", loadSeamReserve(db, native))
	}
	h.vaultInvariantNative(t, "after full withdraw")

	// A backed settlement (consuming a real D->C object) still succeeds — the seam
	// reserve was never raided by the withdraw.
	outputID := ids.ID{0x5E, 0x78}
	h.putDtoCObject(t, h.caller, outputID, native, 500)
	credited, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: outputID, Asset: native, AssetAddr: common.Address{}, Amount: 500, Recipient: h.caller,
	})
	if err != nil || credited != 500 {
		t.Fatalf("a seam-backed settlement must succeed after a depositor withdraw: credited=%d err=%v", credited, err)
	}
	if loadSeamReserve(db, native).Sign() != 0 {
		t.Fatal("seam reserve must be 0 after the settlement consumed it")
	}
	h.vaultInvariantNative(t, "after backed settlement")
}

// TestFIX3_VaultInvariantAcrossBothSubsystems — the FIX-3 vault-account invariant holds
// across a full interleaving of BOTH subsystems on the SAME native asset: operator
// seed, depositor deposit, Phase-A intent lock, Phase-B settlement credit, depositor
// withdraw. After every step realHolding == settleVault + makerLockedVault + seamReserve.
func TestFIX3_VaultInvariantAcrossBothSubsystems(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	depositor := common.HexToAddress("0xD0905170000000000000000000000000000000A3")
	native := [32]byte{}

	h.vaultInvariantNative(t, "genesis")

	// 1) Operator seeds the seam reserve (so a settlement of the SWAP'S INPUT asset —
	// native here — can be refunded/settled back).
	h.fundVaultNativeOut(2000)
	h.vaultInvariantNative(t, "after seed")

	// 2) A custody depositor funds their claim of the SAME native asset.
	h.depositNative(t, depositor, 3000)
	h.vaultInvariantNative(t, "after deposit")

	// 3) A taker submits a Phase-A intent that LOCKS native tokenIn into the seam
	// reserve (the caller funds it). seamReserve grows; settleVault (depositor) is
	// untouched.
	h.fundCallerNative(1000)
	seamBeforeLock := loadSeamReserve(newPoolStateAdapter(h.state), native)
	if _, err := h.runSwap(t, h.intentCalldata(), false); err != nil {
		t.Fatalf("phase-A intent: %v", err)
	}
	seamAfterLock := loadSeamReserve(newPoolStateAdapter(h.state), native)
	if new(big.Int).Sub(seamAfterLock, seamBeforeLock).Int64() != 100 { // AmountSpecified = -100
		t.Fatalf("intent must add 100 to the seam reserve, delta=%s", new(big.Int).Sub(seamAfterLock, seamBeforeLock))
	}
	if loadDepositorClaim(newPoolStateAdapter(h.state), depositor, native).Int64() != 3000 {
		t.Fatal("a Phase-A intent lock must NOT touch the depositor pot")
	}
	h.vaultInvariantNative(t, "after intent lock")

	// 4) A backed Phase-B settlement credits the taker out of the seam reserve only.
	outputID := ids.ID{0x5E, 0x79}
	h.putDtoCObject(t, h.caller, outputID, native, 1500)
	seamBeforeCredit := loadSeamReserve(newPoolStateAdapter(h.state), native)
	credited, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: outputID, Asset: native, AssetAddr: common.Address{}, Amount: 1500, Recipient: h.caller,
	})
	if err != nil || credited != 1500 {
		t.Fatalf("backed settlement: credited=%d err=%v", credited, err)
	}
	seamAfterCredit := loadSeamReserve(newPoolStateAdapter(h.state), native)
	if new(big.Int).Sub(seamBeforeCredit, seamAfterCredit).Int64() != 1500 {
		t.Fatalf("settlement must debit 1500 from the seam reserve, delta=%s", new(big.Int).Sub(seamBeforeCredit, seamAfterCredit))
	}
	if loadDepositorClaim(newPoolStateAdapter(h.state), depositor, native).Int64() != 3000 {
		t.Fatal("a settlement credit must NOT touch the depositor pot")
	}
	h.vaultInvariantNative(t, "after settlement credit")

	// 5) The depositor withdraws part of their claim — settleVault only.
	h.withdrawNative(t, depositor, 1000)
	if loadDepositorClaim(newPoolStateAdapter(h.state), depositor, native).Int64() != 2000 {
		t.Fatal("depositor claim must be 2000 after withdrawing 1000")
	}
	h.vaultInvariantNative(t, "after partial withdraw")
}

var _ = ids.Empty
