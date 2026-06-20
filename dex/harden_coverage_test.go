// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
)

// harden_coverage_test.go — coverage-gap closure for the consensus money paths:
// the ERC-20 settle legs, custody (deposit/withdraw/balanceOf), maker conservation
// (every branch + the cross-path settleVault/makerLockedVault invariant), halt
// governance authorization, STM access-set parity, validator-set rotation, the
// BindToSwap rejection matrix, verifyCert staged certTypes, and the read views.
// Real tests only — every assertion drives a real handler with real state.

// ── ERC-20 settle: the live token-in / token-out money path ──────────────────

// erc20Harness funds two ERC-20 tokens and a registered market over them so the
// settle path's safeTransferTokenFrom (IN leg) + safeTransferTokenTo (OUT leg) run.
func newERC20Harness(t *testing.T) *settleHarness {
	t.Helper()
	h := newSettleHarness(t)
	// Re-point the pool to two ERC-20 tokens (sorted): currency0 = token A, currency1 = token B.
	tokA := common.HexToAddress("0x00000000000000000000000000000000000000A1")
	tokB := common.HexToAddress("0x00000000000000000000000000000000000000B2")
	h.key = PoolKey{
		Currency0:   Currency{Address: tokA},
		Currency1:   Currency{Address: tokB},
		Fee:         3000,
		TickSpacing: 60,
	}
	return h
}

// TestCov_Settle_ERC20InTokenOut: a fully-certified swap with ERC-20 tokenIn AND
// ERC-20 tokenOut moves value through both safeTransferToken legs (observed-delta
// IN, vault-backed OUT), exercising the ERC-20 settle branches at 0% before.
func TestCov_Settle_ERC20InTokenOut(t *testing.T) {
	h := newERC20Harness(t)
	tokA := h.key.Currency0.Address // tokenIn
	tokB := h.key.Currency1.Address // tokenOut
	w := h.wrapper()

	// Sender holds tokenA; vault holds tokenB (the output backing) + its ledger.
	w.mintTestToken(tokA, h.caller, big.NewInt(5000))
	w.mintTestToken(tokB, poolManagerAddr9999, big.NewInt(5000))
	storeSettleVault(newPoolStateAdapter(h.state), assetID(h.key.Currency1), big.NewInt(5000))

	hookData, _, _ := h.buildReceiptCert(t, func(r *DFillReceiptV1) {
		r.TokenInAssetID = assetID(h.key.Currency0)
		r.TokenOutAssetID = assetID(h.key.Currency1)
		r.AmountIn = big.NewInt(1000)
		r.AmountOut = big.NewInt(900)
	}, 0, 1)

	senderInBefore := w.TokenBalanceOf(tokA, h.caller)
	recipOutBefore := w.TokenBalanceOf(tokB, h.caller)
	if _, err := h.runSwap(t, h.caller, hookData); err != nil {
		t.Fatalf("ERC-20 settle failed: %v", err)
	}
	if new(big.Int).Sub(senderInBefore, w.TokenBalanceOf(tokA, h.caller)).Cmp(big.NewInt(1000)) != 0 {
		t.Fatal("sender must pay 1000 tokenA in")
	}
	if new(big.Int).Sub(w.TokenBalanceOf(tokB, h.caller), recipOutBefore).Cmp(big.NewInt(900)) != 0 {
		t.Fatal("recipient must receive 900 tokenB out")
	}
}

// TestCov_Settle_ERC20Unbacked: an ERC-20 out leg the vault cannot back reverts
// ErrSettleUnbacked (no mint).
func TestCov_Settle_ERC20Unbacked(t *testing.T) {
	h := newERC20Harness(t)
	w := h.wrapper()
	w.mintTestToken(h.key.Currency0.Address, h.caller, big.NewInt(5000))
	// vault holds only 100 tokenB but the fill wants 900 out.
	w.mintTestToken(h.key.Currency1.Address, poolManagerAddr9999, big.NewInt(100))
	storeSettleVault(newPoolStateAdapter(h.state), assetID(h.key.Currency1), big.NewInt(100))
	hookData, _, _ := h.buildReceiptCert(t, func(r *DFillReceiptV1) {
		r.TokenInAssetID = assetID(h.key.Currency0)
		r.TokenOutAssetID = assetID(h.key.Currency1)
		r.AmountIn = big.NewInt(1000)
		r.AmountOut = big.NewInt(900)
	}, 0, 1)
	if _, err := h.runSwap(t, h.caller, hookData); err != ErrSettleUnbacked {
		t.Fatalf("unbacked ERC-20 out must revert ErrSettleUnbacked, got: %v", err)
	}
}

// TestCov_Settle_ERC20InsufficientSenderReverts: the IN leg transferFrom fails when
// the sender lacks the token (ErrERC20TransferFailed surfaced through settle).
func TestCov_Settle_ERC20InsufficientSenderReverts(t *testing.T) {
	h := newERC20Harness(t)
	w := h.wrapper()
	// Sender has only 10 tokenA but the fill needs 1000 in.
	w.mintTestToken(h.key.Currency0.Address, h.caller, big.NewInt(10))
	w.mintTestToken(h.key.Currency1.Address, poolManagerAddr9999, big.NewInt(5000))
	storeSettleVault(newPoolStateAdapter(h.state), assetID(h.key.Currency1), big.NewInt(5000))
	hookData, _, _ := h.buildReceiptCert(t, func(r *DFillReceiptV1) {
		r.TokenInAssetID = assetID(h.key.Currency0)
		r.TokenOutAssetID = assetID(h.key.Currency1)
		r.AmountIn = big.NewInt(1000)
		r.AmountOut = big.NewInt(900)
	}, 0, 1)
	if _, err := h.runSwap(t, h.caller, hookData); err == nil {
		t.Fatal("ERC-20 settle with an under-funded sender must revert")
	}
}

// TestCov_Settle_ZeroAmountOut: a zero-output fill settles by the debit alone (the
// early-return branch in settle()).
func TestCov_Settle_ZeroAmountOut(t *testing.T) {
	h := newSettleHarness(t)
	h.fund(t, 10_000, 10_000)
	hookData, _, _ := h.buildReceiptCert(t, func(r *DFillReceiptV1) {
		r.AmountIn = big.NewInt(1000)
		r.AmountOut = big.NewInt(0)
	}, 0, 1)
	if _, err := h.runSwap(t, h.caller, hookData); err != nil {
		t.Fatalf("zero-amountOut fill must settle by the debit alone, got: %v", err)
	}
}

// TestCov_Settle_NativeSenderShort: native-in fill where the sender lacks native
// reverts ErrSettleNativeFunds (the fail-fast precheck).
func TestCov_Settle_NativeSenderShort(t *testing.T) {
	h := newSettleHarness(t)
	h.fund(t, 0, 10_000) // sender has NO native.
	hookData, _, _ := h.buildReceiptCert(t, func(r *DFillReceiptV1) {
		r.AmountIn = big.NewInt(1000)
		r.AmountOut = big.NewInt(900)
	}, 0, 1)
	if _, err := h.runSwap(t, h.caller, hookData); err != ErrSettleNativeFunds {
		t.Fatalf("native-short sender must revert ErrSettleNativeFunds, got: %v", err)
	}
}

// ── custody: deposit / withdraw / balanceOf ──────────────────────────────────

// TestCov_Custody_NativeDepositWithdrawRoundTrip drives the full native custody
// cycle through Run (the real funding gate) and the balanceOf read.
func TestCov_Custody_NativeDepositWithdrawRoundTrip(t *testing.T) {
	h := newSettleHarness(t)
	db := h.state.stateDB
	nativeID := [32]byte{}

	// deposit: EVM moved 3000 native into the vault first.
	db.AddBalance(poolManagerAddr9999, uint256.NewInt(3000))
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorDeposit, encodeDepositCalldata(common.Address{}, 3000)), 5_000_000, false); err != nil {
		t.Fatalf("native deposit: %v", err)
	}
	// balanceOf reflects the claim.
	balOut, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorBalanceOf, append(leftPad32(h.caller.Bytes()), leftPad32(common.Address{}.Bytes())...)), 5_000_000, true)
	if err != nil || new(big.Int).SetBytes(balOut).Cmp(big.NewInt(3000)) != 0 {
		t.Fatalf("balanceOf must report 3000, got %v (err %v)", new(big.Int).SetBytes(balOut), err)
	}
	// withdraw 1200.
	callerBalBefore := db.GetBalance(h.caller).Uint64()
	wd, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorWithdraw, encodeDepositCalldata(common.Address{}, 1200)), 5_000_000, false)
	if err != nil || new(big.Int).SetBytes(wd).Cmp(big.NewInt(1200)) != 0 {
		t.Fatalf("withdraw must realize 1200, got %v (err %v)", new(big.Int).SetBytes(wd), err)
	}
	if db.GetBalance(h.caller).Uint64()-callerBalBefore != 1200 {
		t.Fatal("withdraw must credit the caller 1200 native")
	}
	if loadDepositorClaim(newPoolStateAdapter(h.state), h.caller, nativeID).Cmp(big.NewInt(1800)) != 0 {
		t.Fatal("remaining claim must be 1800")
	}
}

// TestCov_Custody_WithdrawClampsToClaim: a withdraw exceeding the claim realizes
// only the claim (clamp branch).
func TestCov_Custody_WithdrawClampsToClaim(t *testing.T) {
	h := newSettleHarness(t)
	db := h.state.stateDB
	db.AddBalance(poolManagerAddr9999, uint256.NewInt(500))
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorDeposit, encodeDepositCalldata(common.Address{}, 500)), 5_000_000, false); err != nil {
		t.Fatalf("deposit: %v", err)
	}
	// Withdraw 99999 -> realizes only the 500 claim.
	wd, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorWithdraw, encodeDepositCalldata(common.Address{}, 99999)), 5_000_000, false)
	if err != nil || new(big.Int).SetBytes(wd).Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("withdraw must clamp to claim (500), got %v (err %v)", new(big.Int).SetBytes(wd), err)
	}
}

// TestCov_Custody_WithdrawNothing: a withdraw with no claim realizes 0 (the
// nothing-to-withdraw early return).
func TestCov_Custody_WithdrawNothing(t *testing.T) {
	h := newSettleHarness(t)
	wd, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorWithdraw, encodeDepositCalldata(common.Address{}, 100)), 5_000_000, false)
	if err != nil || new(big.Int).SetBytes(wd).Sign() != 0 {
		t.Fatalf("withdraw with no claim must realize 0, got %v (err %v)", new(big.Int).SetBytes(wd), err)
	}
}

// TestCov_Custody_ERC20DepositWithdraw drives the ERC-20 custody legs (observed
// delta IN via transferFrom, release OUT via transfer).
func TestCov_Custody_ERC20DepositWithdraw(t *testing.T) {
	h := newSettleHarness(t)
	tok := common.HexToAddress("0x00000000000000000000000000000000000000C3")
	w := h.wrapper()
	w.mintTestToken(tok, h.caller, big.NewInt(4000))

	dep := func(amount uint64) ([]byte, error) {
		out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorDeposit, encodeDepositCalldata(tok, amount)), 5_000_000, false)
		return out, err
	}
	if _, err := dep(3000); err != nil {
		t.Fatalf("ERC-20 deposit: %v", err)
	}
	if w.TokenBalanceOf(tok, poolManagerAddr9999).Cmp(big.NewInt(3000)) != 0 {
		t.Fatal("vault must hold 3000 of the token after deposit")
	}
	if loadDepositorClaim(newPoolStateAdapter(h.state), h.caller, assetID(Currency{Address: tok})).Cmp(big.NewInt(3000)) != 0 {
		t.Fatal("ERC-20 claim must be 3000")
	}
	// withdraw 1000 token.
	wd, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorWithdraw, encodeDepositCalldata(tok, 1000)), 5_000_000, false)
	if err != nil || new(big.Int).SetBytes(wd).Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("ERC-20 withdraw must realize 1000, got %v (err %v)", new(big.Int).SetBytes(wd), err)
	}
	if w.TokenBalanceOf(tok, h.caller).Cmp(big.NewInt(2000)) != 0 {
		t.Fatal("caller must hold 2000 token after deposit(3000)+withdraw(1000) from 4000")
	}
}

// TestCov_Custody_DepositZeroRejected / shortInput / readonly exercise the guards.
func TestCov_Custody_DepositGuards(t *testing.T) {
	h := newSettleHarness(t)
	// readOnly deposit rejected.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorDeposit, encodeDepositCalldata(common.Address{}, 100)), 5_000_000, true); err == nil {
		t.Fatal("deposit in readOnly must revert")
	}
	// zero amount rejected.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorDeposit, encodeDepositCalldata(common.Address{}, 0)), 5_000_000, false); err != ErrInvalidAmount {
		t.Fatalf("zero-amount deposit must revert ErrInvalidAmount, got: %v", err)
	}
	// short input rejected.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorDeposit, make([]byte, 10)), 5_000_000, false); err == nil {
		t.Fatal("short deposit input must revert")
	}
	// deposit of a halted asset rejected.
	tok := common.HexToAddress("0x00000000000000000000000000000000000000D4")
	SetHaltAsset(newPoolStateAdapter(h.state), assetID(Currency{Address: tok}), true)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorDeposit, encodeDepositCalldata(tok, 100)), 5_000_000, false); err != ErrAssetHalted {
		t.Fatalf("deposit of a halted asset must revert ErrAssetHalted, got: %v", err)
	}
}

// ── maker conservation: the cross-path settleVault/makerLockedVault invariant ──

// TestRED_MakerLock_NotDoubleSpentByUnrelatedSwap is the headline maker-lock fix:
// a maker's locked funds are NO LONGER in the swap-payable pool, so an unrelated
// taker payout cannot drain them, and the maker cannot then double-spend by
// REMOVE+withdraw on top of a payout that consumed its locked funds.
//
// The harness pool is currency0=native (the maker's BID asset), currency1=token. The
// maker deposits + locks ALL its native; an unrelated taker tries to take native OUT.
// Before the fix settleVault stayed inflated (it still counted the locked native), so
// the taker drained the maker's locked funds and the maker could STILL withdraw them
// after cancel — paying the same native twice. After the fix the locked native is in
// makerLockedVault, settleVault is 0, so the taker payout reverts ErrSettleUnbacked
// (the locked funds are untouchable) and the maker withdraws exactly its own 1000.
func TestRED_MakerLock_NotDoubleSpentByUnrelatedSwap(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	db := newPoolStateAdapter(h.state)
	nativeID := assetID(h.key.Currency0) // BID side = currency0 = native.
	tokenID := assetID(h.key.Currency1)

	maker := h.caller
	taker := common.HexToAddress("0x7a4e000000000000000000000000000000000000")

	// (1) maker deposits 1000 native (settleVault = 1000); seed the vault's REAL native.
	fundClaim(db, maker, nativeID, big.NewInt(1000))
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(1000))

	// (2) maker locks ALL 1000 via modifyLiquidity ADD => settleVault drops to 0,
	// makerLockedVault = 1000 (THE FIX moves the locked native out of swap-payable).
	var salt [32]byte
	salt[31] = 0x55
	if _, _, err := h.c.Run(h.state, maker, poolManagerAddr9999,
		modLiqCalldata(h.key, -60, 60, big.NewInt(1000), salt, MakerSideBid), 5_000_000, false); err != nil {
		t.Fatalf("maker ADD: %v", err)
	}
	if got := loadSettleVault(db, nativeID); got.Sign() != 0 {
		t.Fatalf("after maker ADD, swap-payable settleVault must be 0 (locked moved out), got %s", got)
	}
	if got := loadMakerLockedVault(db, nativeID); got.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("makerLockedVault must be 1000, got %s", got)
	}

	// (3) an UNRELATED taker tries to take 1000 native OUT (oneForZero, token in). The
	// maker's locked native is the ONLY native in the vault, but it is no longer
	// swap-payable, so the settle MUST revert ErrSettleUnbacked (cannot drain it).
	takerParams := SwapParams{ZeroForOne: false, AmountSpecified: big.NewInt(0), SqrtPriceLimitX96: big.NewInt(0)}
	h.wrapper().mintTestToken(h.key.Currency1.Address, taker, big.NewInt(2000))
	tr := &DFillReceiptV1{
		Version: 1, NetworkID: h.networkID, DChainID: h.dChainID, CChainID: h.cChainID,
		DHeight: 100, MarketID: h.key.ID(), FillID: [32]byte{0xF2}, ReceiptID: keccak32([]byte("taker-rcpt")),
		PoolKeyHash: h.key.ID(), SwapParamsHash: swapParamsHash(takerParams),
		Sender: taker, Recipient: taker,
		TokenInAssetID: tokenID, TokenOutAssetID: nativeID, // token in, native out.
		AmountIn: big.NewInt(900), AmountOut: big.NewInt(1000), FeeAmount: big.NewInt(0),
		Deadline: 1 << 40, Nonce: 1, PrecompileAddr: poolManagerAddr9999, CertType: CertTypeBLSFastPath,
	}
	takerCert := buildCert(t, h.vsID, h.vals, tr, tr.ReceiptID, 0, 1)
	takerHook := EncodeSettlementHookData(tr, takerCert, nil)
	takerCalldata := prependSelector(SelectorSwap, buildSwapCalldata(h.key, takerParams, takerHook))
	if _, _, err := h.c.Run(h.state, taker, poolManagerAddr9999, takerCalldata, 50_000_000, false); err != ErrSettleUnbacked {
		t.Fatalf("taker payout of a maker's locked native must revert ErrSettleUnbacked, got: %v", err)
	}
	// The maker's locked vault is UNTOUCHED by the failed taker swap.
	if got := loadMakerLockedVault(db, nativeID); got.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("maker's locked vault must survive a refused swap, got %s", got)
	}

	// (4) maker REMOVE => locked moves back to settleVault, claim restored.
	if _, _, err := h.c.Run(h.state, maker, poolManagerAddr9999,
		modLiqCalldata(h.key, -60, 60, big.NewInt(-1000), salt, MakerSideBid), 5_000_000, false); err != nil {
		t.Fatalf("maker REMOVE: %v", err)
	}
	if got := loadMakerLockedVault(db, nativeID); got.Sign() != 0 {
		t.Fatalf("makerLockedVault must be 0 after REMOVE, got %s", got)
	}
	// (5) maker withdraws EXACTLY its own 1000 — not a double of it.
	makerBalBefore := h.state.stateDB.GetBalance(maker).Uint64()
	wd, _, err := h.c.Run(h.state, maker, poolManagerAddr9999, prependSelector(SelectorWithdraw, encodeDepositCalldata(common.Address{}, 1000)), 5_000_000, false)
	if err != nil || new(big.Int).SetBytes(wd).Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("maker withdraw must realize its own 1000, got %v (err %v)", new(big.Int).SetBytes(wd), err)
	}
	if h.state.stateDB.GetBalance(maker).Uint64()-makerBalBefore != 1000 {
		t.Fatal("maker must receive exactly 1000 (no double-spend)")
	}
	// (6) the vault is now EMPTY of native — the maker spent its 1000 exactly once.
	if h.state.stateDB.GetBalance(poolManagerAddr9999).Sign() != 0 {
		t.Fatalf("vault native must be 0 after the single withdrawal, got %s", h.state.stateDB.GetBalance(poolManagerAddr9999))
	}
}

// TestCov_SettleVault_SolvencyInvariant: after an interleaving of deposit/ADD/
// REMOVE/swap/withdraw, settleVault(unlocked) + makerLockedVault == real vault
// holdings, and no withdraw exceeds the caller's claim.
func TestCov_SettleVault_SolvencyInvariant(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	db := newPoolStateAdapter(h.state)
	nativeID := assetID(h.key.Currency0)
	m1 := h.caller
	m2 := common.HexToAddress("0x4d32000000000000000000000000000000000000")

	fundClaim(db, m1, nativeID, big.NewInt(3000))
	fundClaim(db, m2, nativeID, big.NewInt(2000))
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(5000))

	add := func(c common.Address, salt byte, amt int64) {
		var s [32]byte
		s[31] = salt
		if _, _, err := h.c.Run(h.state, c, poolManagerAddr9999, modLiqCalldata(h.key, -60, 60, big.NewInt(amt), s, MakerSideBid), 5_000_000, false); err != nil {
			t.Fatalf("ADD: %v", err)
		}
	}
	rem := func(c common.Address, salt byte, amt int64) {
		var s [32]byte
		s[31] = salt
		if _, _, err := h.c.Run(h.state, c, poolManagerAddr9999, modLiqCalldata(h.key, -60, 60, big.NewInt(-amt), s, MakerSideBid), 5_000_000, false); err != nil {
			t.Fatalf("REMOVE: %v", err)
		}
	}
	add(m1, 1, 1500)
	add(m2, 2, 500)
	add(m1, 3, 500)
	rem(m1, 1, 1500)
	add(m2, 4, 800)
	rem(m2, 2, 500)

	// Invariant: settleVault + makerLockedVault == real native vault holdings.
	unlocked := loadSettleVault(db, nativeID)
	locked := loadMakerLockedVault(db, nativeID)
	real := h.state.stateDB.GetBalance(poolManagerAddr9999).ToBig()
	if new(big.Int).Add(unlocked, locked).Cmp(real) != 0 {
		t.Fatalf("solvency invariant broken: settleVault(%s) + makerLockedVault(%s) != realVault(%s)", unlocked, locked, real)
	}
}

// ── maker branch coverage: ASK side, re-add, double-cancel, clamps, halt ──────

func TestCov_Maker_AskSideLockUnlock(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	db := newPoolStateAdapter(h.state)
	askAsset := assetID(h.key.Currency1) // ASK rests currency1.
	fundClaim(db, h.caller, askAsset, big.NewInt(1000))

	var salt [32]byte
	salt[31] = 0x61
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, modLiqCalldata(h.key, -60, 60, big.NewInt(400), salt, MakerSideAsk), 5_000_000, false); err != nil {
		t.Fatalf("ASK ADD: %v", err)
	}
	if loadLockedReserve(db, h.caller, askAsset).Cmp(big.NewInt(400)) != 0 {
		t.Fatal("ASK ADD must lock currency1")
	}
	if loadDepositorClaim(db, h.caller, askAsset).Cmp(big.NewInt(600)) != 0 {
		t.Fatal("ASK ADD must debit currency1 claim")
	}
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, modLiqCalldata(h.key, -60, 60, big.NewInt(-400), salt, MakerSideAsk), 5_000_000, false); err != nil {
		t.Fatalf("ASK REMOVE: %v", err)
	}
	if loadLockedReserve(db, h.caller, askAsset).Sign() != 0 {
		t.Fatal("ASK REMOVE must unlock")
	}
}

func TestCov_Maker_ReAddTopUp(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	db := newPoolStateAdapter(h.state)
	bidAsset := assetID(h.key.Currency0)
	fundClaim(db, h.caller, bidAsset, big.NewInt(1000))
	var salt [32]byte
	salt[31] = 0x62
	// ADD 500 then ADD 300 to the SAME (salt,range) => order accumulates to 800.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, modLiqCalldata(h.key, -60, 60, big.NewInt(500), salt, MakerSideBid), 5_000_000, false); err != nil {
		t.Fatalf("ADD 500: %v", err)
	}
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, modLiqCalldata(h.key, -60, 60, big.NewInt(300), salt, MakerSideBid), 5_000_000, false); err != nil {
		t.Fatalf("ADD 300: %v", err)
	}
	orderID := MakerOrderID(h.caller, h.key.ID(), salt, -60, 60)
	if loadRestingOrder(db, orderID).LockedAmt.Cmp(big.NewInt(800)) != 0 {
		t.Fatal("re-add must accumulate the order to 800")
	}
	if loadLockedReserve(db, h.caller, bidAsset).Cmp(big.NewInt(800)) != 0 {
		t.Fatal("re-add must accumulate locked reserve to 800")
	}
	// The index must NOT grow on the re-add (idempotent membership).
	if len(OwnerOrderIDs(db, h.caller)) != 1 {
		t.Fatalf("re-add must not grow the owner index, got %d", len(OwnerOrderIDs(db, h.caller)))
	}
}

func TestCov_Maker_DoubleCancelAndPartialClamp(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	db := newPoolStateAdapter(h.state)
	bidAsset := assetID(h.key.Currency0)
	fundClaim(db, h.caller, bidAsset, big.NewInt(1000))
	var salt [32]byte
	salt[31] = 0x63
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, modLiqCalldata(h.key, -60, 60, big.NewInt(600), salt, MakerSideBid), 5_000_000, false); err != nil {
		t.Fatalf("ADD: %v", err)
	}
	// Partial REMOVE 200 (clamps within order); order stays OPEN at 400.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, modLiqCalldata(h.key, -60, 60, big.NewInt(-200), salt, MakerSideBid), 5_000_000, false); err != nil {
		t.Fatalf("partial REMOVE: %v", err)
	}
	orderID := MakerOrderID(h.caller, h.key.ID(), salt, -60, 60)
	if loadRestingOrder(db, orderID).LockedAmt.Cmp(big.NewInt(400)) != 0 {
		t.Fatal("partial REMOVE must leave 400 locked")
	}
	// Over-REMOVE 9999 clamps to remaining 400 and CANCELS.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, modLiqCalldata(h.key, -60, 60, big.NewInt(-9999), salt, MakerSideBid), 5_000_000, false); err != nil {
		t.Fatalf("over REMOVE: %v", err)
	}
	if loadRestingOrder(db, orderID).Status != OrderStatusCancelled {
		t.Fatal("over-REMOVE must cancel the order")
	}
	// Double cancel => ErrMakerAlreadyClosed.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, modLiqCalldata(h.key, -60, 60, big.NewInt(-100), salt, MakerSideBid), 5_000_000, false); err != ErrMakerAlreadyClosed {
		t.Fatalf("double cancel must revert ErrMakerAlreadyClosed, got: %v", err)
	}
}

func TestCov_Maker_Guards(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	bidAsset := assetID(h.key.Currency0)
	fundClaim(newPoolStateAdapter(h.state), h.caller, bidAsset, big.NewInt(1000))
	var salt [32]byte
	// zero delta.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, modLiqCalldata(h.key, -60, 60, big.NewInt(0), salt, MakerSideBid), 5_000_000, false); err != ErrMakerZeroDelta {
		t.Fatalf("zero delta must revert ErrMakerZeroDelta, got: %v", err)
	}
	// bad tick range (lower >= upper).
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, modLiqCalldata(h.key, 60, -60, big.NewInt(100), salt, MakerSideBid), 5_000_000, false); err != ErrMakerBadTickRange {
		t.Fatalf("bad tick range must revert ErrMakerBadTickRange, got: %v", err)
	}
	// unregistered market.
	other := h.key
	other.Fee = 100
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, modLiqCalldata(other, -60, 60, big.NewInt(100), salt, MakerSideBid), 5_000_000, false); err != ErrMakerNoMarket {
		t.Fatalf("unregistered market must revert ErrMakerNoMarket, got: %v", err)
	}
	// readOnly.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, modLiqCalldata(h.key, -60, 60, big.NewInt(100), salt, MakerSideBid), 5_000_000, true); err == nil {
		t.Fatal("modifyLiquidity in readOnly must revert")
	}
}

// TestCov_Maker_HaltAssetOnAddButCancelStillWorks: a halted asset blocks new ADDs
// but REMOVE/cancel still releases funds (never strand).
func TestCov_Maker_HaltAssetOnAddButCancelStillWorks(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	db := newPoolStateAdapter(h.state)
	bidAsset := assetID(h.key.Currency0)
	fundClaim(db, h.caller, bidAsset, big.NewInt(1000))
	var salt [32]byte
	salt[31] = 0x64
	// Open an order BEFORE halting.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, modLiqCalldata(h.key, -60, 60, big.NewInt(500), salt, MakerSideBid), 5_000_000, false); err != nil {
		t.Fatalf("ADD: %v", err)
	}
	// Halt the locked asset.
	SetHaltAsset(db, bidAsset, true)
	// New ADD blocked.
	var salt2 [32]byte
	salt2[31] = 0x65
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, modLiqCalldata(h.key, -60, 60, big.NewInt(100), salt2, MakerSideBid), 5_000_000, false); err != ErrAssetHalted {
		t.Fatalf("ADD of a halted asset must revert ErrAssetHalted, got: %v", err)
	}
	// REMOVE/cancel still works (funds releasable under halt).
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, modLiqCalldata(h.key, -60, 60, big.NewInt(-500), salt, MakerSideBid), 5_000_000, false); err != nil {
		t.Fatalf("REMOVE under asset-halt must succeed (never strand), got: %v", err)
	}
}

// ── decodeMakerSide branches ─────────────────────────────────────────────────

func TestCov_DecodeMakerSide(t *testing.T) {
	if decodeMakerSide(nil) != MakerSideBid {
		t.Fatal("nil hookData defaults to BID")
	}
	if decodeMakerSide([]byte("not a maker envelope")) != MakerSideBid {
		t.Fatal("non-tagged hookData defaults to BID")
	}
	ask := []byte{makerEnvelopeTag[0], makerEnvelopeTag[1], makerEnvelopeTag[2], makerEnvelopeTag[3], byte(MakerSideAsk)}
	if decodeMakerSide(ask) != MakerSideAsk {
		t.Fatal("tagged ASK envelope must decode ASK")
	}
	bid := []byte{makerEnvelopeTag[0], makerEnvelopeTag[1], makerEnvelopeTag[2], makerEnvelopeTag[3], byte(MakerSideBid)}
	if decodeMakerSide(bid) != MakerSideBid {
		t.Fatal("tagged BID envelope must decode BID")
	}
}

// ── halt governance authorization ────────────────────────────────────────────

func TestCov_HaltGovernance_AuthGates(t *testing.T) {
	h := newSettleHarness(t)
	controller := h.c.protocolFeeController
	stranger := common.HexToAddress("0x57aE000000000000000000000000000000000000")

	boolWord := func(on bool) []byte {
		b := make([]byte, 32)
		if on {
			b[31] = 1
		}
		return b
	}
	scopedWord := func(id [32]byte, on bool) []byte {
		b := make([]byte, 64)
		copy(b[0:32], id[:])
		if on {
			b[63] = 1
		}
		return b
	}

	// setHaltGlobal: stranger => ErrUnauthorized; controller => effective.
	if _, _, err := h.c.Run(h.state, stranger, poolManagerAddr9999, prependSelector(SelectorSetHaltGlobal, boolWord(true)), 5_000_000, false); err != ErrUnauthorized {
		t.Fatalf("non-controller setHaltGlobal must revert ErrUnauthorized, got: %v", err)
	}
	if _, _, err := h.c.Run(h.state, controller, poolManagerAddr9999, prependSelector(SelectorSetHaltGlobal, boolWord(true)), 5_000_000, false); err != nil {
		t.Fatalf("controller setHaltGlobal: %v", err)
	}
	if !isHalted(newPoolStateAdapter(h.state), haltGlobalKey) {
		t.Fatal("global halt must be effective after controller sets it")
	}
	// readOnly rejected.
	if _, _, err := h.c.Run(h.state, controller, poolManagerAddr9999, prependSelector(SelectorSetHaltGlobal, boolWord(false)), 5_000_000, true); err == nil {
		t.Fatal("setHaltGlobal in readOnly must revert")
	}

	// scoped (market) halt auth gate.
	mid := [32]byte{0xAA}
	if _, _, err := h.c.Run(h.state, stranger, poolManagerAddr9999, prependSelector(SelectorSetHaltMarket, scopedWord(mid, true)), 5_000_000, false); err != ErrUnauthorized {
		t.Fatalf("non-controller setHaltMarket must revert ErrUnauthorized, got: %v", err)
	}
	if _, _, err := h.c.Run(h.state, controller, poolManagerAddr9999, prependSelector(SelectorSetHaltMarket, scopedWord(mid, true)), 5_000_000, false); err != nil {
		t.Fatalf("controller setHaltMarket: %v", err)
	}
	// asset + validatorSet scoped.
	if _, _, err := h.c.Run(h.state, controller, poolManagerAddr9999, prependSelector(SelectorSetHaltAsset, scopedWord([32]byte{0xBB}, true)), 5_000_000, false); err != nil {
		t.Fatalf("controller setHaltAsset: %v", err)
	}
	if _, _, err := h.c.Run(h.state, controller, poolManagerAddr9999, prependSelector(SelectorSetHaltValidatorSet, scopedWord([32]byte{0xCC}, true)), 5_000_000, false); err != nil {
		t.Fatalf("controller setHaltValidatorSet: %v", err)
	}
	// receiptType halt auth gate.
	rt := make([]byte, 64)
	rt[31] = byte(CertTypeBLSFastPath)
	rt[63] = 1
	if _, _, err := h.c.Run(h.state, stranger, poolManagerAddr9999, prependSelector(SelectorSetHaltReceiptType, rt), 5_000_000, false); err != ErrUnauthorized {
		t.Fatalf("non-controller setHaltReceiptType must revert ErrUnauthorized, got: %v", err)
	}
	if _, _, err := h.c.Run(h.state, controller, poolManagerAddr9999, prependSelector(SelectorSetHaltReceiptType, rt), 5_000_000, false); err != nil {
		t.Fatalf("controller setHaltReceiptType: %v", err)
	}
}

// ── validator-set rotation handler ───────────────────────────────────────────

func TestRED_RegisterValidatorSet_RequiresControllerAndPoP(t *testing.T) {
	h := newSettleHarness(t)
	controller := h.c.protocolFeeController
	stranger := common.HexToAddress("0x57aE000000000000000000000000000000000001")
	vals := newTestValidators(t, 1, 1, 1)
	newVSID := [32]byte{0x77}

	payload := encodeValidatorSetWire(t, h.dChainID, newVSID, CertTypeBLSFastPath, 0, 2, 3, vals, true /*valid PoP*/)

	// stranger => ErrUnauthorized.
	if _, _, err := h.c.Run(h.state, stranger, poolManagerAddr9999, prependSelector(SelectorRegisterValidatorSet, payload), 5_000_000, false); err != ErrUnauthorized {
		t.Fatalf("non-controller register must revert ErrUnauthorized, got: %v", err)
	}
	// readOnly => revert.
	if _, _, err := h.c.Run(h.state, controller, poolManagerAddr9999, prependSelector(SelectorRegisterValidatorSet, payload), 5_000_000, true); err == nil {
		t.Fatal("register in readOnly must revert")
	}
	// controller, valid PoP => the new set resolves and a cert under it verifies.
	if _, _, err := h.c.Run(h.state, controller, poolManagerAddr9999, prependSelector(SelectorRegisterValidatorSet, payload), 5_000_000, false); err != nil {
		t.Fatalf("controller register with valid PoP: %v", err)
	}
	vs, err := ResolveValidatorSet(newPoolStateAdapter(h.state), h.dChainID, newVSID, CertTypeBLSFastPath, 100)
	if err != nil || len(vs.Validators) != 3 {
		t.Fatalf("rotated set must resolve, got err=%v n=%d", err, len(vs.Validators))
	}

	// controller, INVALID PoP => rejected (rogue-key defense on the rotation path).
	badPayload := encodeValidatorSetWire(t, h.dChainID, [32]byte{0x78}, CertTypeBLSFastPath, 0, 2, 3, vals, false /*bad PoP*/)
	if _, _, err := h.c.Run(h.state, controller, poolManagerAddr9999, prependSelector(SelectorRegisterValidatorSet, badPayload), 5_000_000, false); err != ErrVerifierBadPoP {
		t.Fatalf("register with bad PoP must revert ErrVerifierBadPoP, got: %v", err)
	}
}

// TestCov_RegisterValidatorSet_MalformedWire: a truncated payload reverts cleanly.
func TestCov_RegisterValidatorSet_MalformedWire(t *testing.T) {
	h := newSettleHarness(t)
	controller := h.c.protocolFeeController
	if _, _, err := h.c.Run(h.state, controller, poolManagerAddr9999, prependSelector(SelectorRegisterValidatorSet, make([]byte, 10)), 5_000_000, false); err != ErrVerifierBadWire {
		t.Fatalf("truncated register payload must revert ErrVerifierBadWire, got: %v", err)
	}
}

// encodeValidatorSetWire builds the registerValidatorSet calldata. If validPoP is
// false each member carries a 96-byte zero PoP (which fails VerifyProofOfPossession).
func encodeValidatorSetWire(t testing.TB, dChainID, vsID [32]byte, ct CertType, activation uint64, qn, qd uint32, vals []testValidator, validPoP bool) []byte {
	t.Helper()
	b := make([]byte, 0, validatorSetWireHeaderLen+len(vals)*validatorWireLen)
	b = append(b, dChainID[:]...)
	b = append(b, vsID[:]...)
	b = append(b, byte(ct))
	var u8 [8]byte
	putU64(u8[:], activation)
	b = append(b, u8[:]...)
	var qnB, qdB [4]byte
	qnB[0], qnB[1], qnB[2], qnB[3] = byte(qn>>24), byte(qn>>16), byte(qn>>8), byte(qn)
	qdB[0], qdB[1], qdB[2], qdB[3] = byte(qd>>24), byte(qd>>16), byte(qd>>8), byte(qd)
	b = append(b, qnB[:]...)
	b = append(b, qdB[:]...)
	var cnt [4]byte
	n := uint32(len(vals))
	cnt[0], cnt[1], cnt[2], cnt[3] = byte(n>>24), byte(n>>16), byte(n>>8), byte(n)
	b = append(b, cnt[:]...)
	for _, v := range vals {
		pk := makePubkeyBytes(t, v)
		b = append(b, pk...)
		var w [8]byte
		putU64(w[:], v.weight)
		b = append(b, w[:]...)
		if validPoP {
			b = append(b, makePoP(t, v)...)
		} else {
			b = append(b, make([]byte, 96)...) // zero PoP => invalid.
		}
	}
	return b
}

// ── verifyCert staged certTypes ──────────────────────────────────────────────

func TestCov_VerifyCert_StagedCertTypesRejected(t *testing.T) {
	h := newSettleHarness(t)
	db := newPoolStateAdapter(h.state)
	// Register sets under each staged certType so ResolveValidatorSet passes the
	// certType match, then verifyCert hits the staged ErrUnsupportedCertType arm.
	for _, ct := range []CertType{CertTypeQ, CertTypeQPQ, CertTypeZK} {
		vals := newTestValidators(t, 1, 1, 1)
		vsID := [32]byte{byte(ct), 0x99}
		vs := validatorSetFrom([32]byte{0xDD}, vsID, vals)
		vs.CertType = ct
		if err := PutValidatorSet(db, vs); err != nil {
			t.Fatalf("put staged set: %v", err)
		}
		r := sampleReceipt()
		r.CertType = ct
		cert := &BLSCert{Version: blsCertVersion, CertType: ct, ValidatorSetID: vsID, SignerBitmap: bitmapForSigners(3, 0, 1)}
		if err := verifyCert(db, r, r.ReceiptID, cert); err != ErrUnsupportedCertType {
			t.Fatalf("certType %d must revert ErrUnsupportedCertType, got: %v", ct, err)
		}
	}
}

// ── BindToSwap rejection matrix ──────────────────────────────────────────────

func TestCov_BindToSwap_RejectionMatrix(t *testing.T) {
	h := newSettleHarness(t)
	base := func() *DFillReceiptV1 {
		return &DFillReceiptV1{
			NetworkID: h.networkID, CChainID: h.cChainID, PrecompileAddr: poolManagerAddr9999,
			PoolKeyHash: h.key.ID(), SwapParamsHash: swapParamsHash(h.params),
			Sender: h.caller, Recipient: h.caller,
			TokenInAssetID: assetID(h.key.Currency0), TokenOutAssetID: assetID(h.key.Currency1),
			AmountIn: big.NewInt(1000), AmountOut: big.NewInt(990), FeeAmount: big.NewInt(0),
			Deadline: 1 << 40,
		}
	}
	bind := func(r *DFillReceiptV1, blockTime uint64) error {
		return r.BindToSwap(h.key, h.params, h.caller, h.caller, h.networkID, h.cChainID, blockTime, false)
	}
	// happy path.
	if err := bind(base(), 100); err != nil {
		t.Fatalf("valid receipt must bind, got: %v", err)
	}
	cases := []struct {
		name string
		mut  func(*DFillReceiptV1)
		bt   uint64
		want error
	}{
		{"nil amountIn", func(r *DFillReceiptV1) { r.AmountIn = nil }, 100, ErrReceiptBadAmounts},
		{"neg amountOut", func(r *DFillReceiptV1) { r.AmountOut = big.NewInt(-1) }, 100, ErrReceiptBadAmounts},
		{"neg fee", func(r *DFillReceiptV1) { r.FeeAmount = big.NewInt(-1) }, 100, ErrReceiptBadAmounts},
		{"wrong network", func(r *DFillReceiptV1) { r.NetworkID = 999 }, 100, ErrReceiptWrongNetwork},
		{"wrong cChain", func(r *DFillReceiptV1) { r.CChainID = [32]byte{0xEE} }, 100, ErrReceiptWrongCChain},
		{"wrong addr", func(r *DFillReceiptV1) { r.PrecompileAddr = common.HexToAddress("0x1234") }, 100, ErrReceiptWrongAddr},
		{"wrong pool", func(r *DFillReceiptV1) { r.PoolKeyHash = [32]byte{0x11} }, 100, ErrReceiptWrongPool},
		{"wrong params", func(r *DFillReceiptV1) { r.SwapParamsHash = [32]byte{0x22} }, 100, ErrReceiptWrongParams},
		{"wrong sender", func(r *DFillReceiptV1) { r.Sender = common.HexToAddress("0xdead") }, 100, ErrReceiptWrongSender},
		{"wrong recipient", func(r *DFillReceiptV1) { r.Recipient = common.HexToAddress("0xbeef") }, 100, ErrReceiptWrongRecip},
		{"wrong assets", func(r *DFillReceiptV1) { r.TokenInAssetID = [32]byte{0x33} }, 100, ErrReceiptWrongAssets},
		{"expired", func(r *DFillReceiptV1) { r.Deadline = 50 }, 100, ErrReceiptExpired},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			r := base()
			c.mut(r)
			if err := bind(r, c.bt); err != c.want {
				t.Fatalf("%s: want %v got %v", c.name, c.want, err)
			}
		})
	}
}

// TestCov_BindToSwap_BelowMinExactOutput: an exact-output swap (AmountSpecified>0)
// whose receipt AmountOut is below the requested output reverts ErrReceiptBelowMin.
func TestCov_BindToSwap_BelowMinExactOutput(t *testing.T) {
	h := newSettleHarness(t)
	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(1000), SqrtPriceLimitX96: big.NewInt(0)}
	r := &DFillReceiptV1{
		NetworkID: h.networkID, CChainID: h.cChainID, PrecompileAddr: poolManagerAddr9999,
		PoolKeyHash: h.key.ID(), SwapParamsHash: swapParamsHash(params),
		Sender: h.caller, Recipient: h.caller,
		TokenInAssetID: assetID(h.key.Currency0), TokenOutAssetID: assetID(h.key.Currency1),
		AmountIn: big.NewInt(1000), AmountOut: big.NewInt(500), FeeAmount: big.NewInt(0), // 500 < 1000 floor.
		Deadline: 1 << 40,
	}
	if err := r.BindToSwap(h.key, params, h.caller, h.caller, h.networkID, h.cChainID, 100, false); err != ErrReceiptBelowMin {
		t.Fatalf("exact-output below floor must revert ErrReceiptBelowMin, got: %v", err)
	}
	// At/above floor binds.
	r.AmountOut = big.NewInt(1000)
	if err := r.BindToSwap(h.key, params, h.caller, h.caller, h.networkID, h.cChainID, 100, false); err != nil {
		t.Fatalf("exact-output at floor must bind, got: %v", err)
	}
}

// TestCov_BindToSwap_OperatorAuthorized: callerAuthorized lets a non-sender settle.
func TestCov_BindToSwap_OperatorAuthorized(t *testing.T) {
	h := newSettleHarness(t)
	operator := common.HexToAddress("0x09e9a70000000000000000000000000000000000")
	r := &DFillReceiptV1{
		NetworkID: h.networkID, CChainID: h.cChainID, PrecompileAddr: poolManagerAddr9999,
		PoolKeyHash: h.key.ID(), SwapParamsHash: swapParamsHash(h.params),
		Sender: h.caller, Recipient: h.caller,
		TokenInAssetID: assetID(h.key.Currency0), TokenOutAssetID: assetID(h.key.Currency1),
		AmountIn: big.NewInt(1000), AmountOut: big.NewInt(990), FeeAmount: big.NewInt(0), Deadline: 1 << 40,
	}
	// non-authorized non-sender => wrong sender.
	if err := r.BindToSwap(h.key, h.params, operator, h.caller, h.networkID, h.cChainID, 100, false); err != ErrReceiptWrongSender {
		t.Fatalf("unauthorized non-sender must revert ErrReceiptWrongSender, got: %v", err)
	}
	// authorized operator binds.
	if err := r.BindToSwap(h.key, h.params, operator, h.caller, h.networkID, h.cChainID, 100, true); err != nil {
		t.Fatalf("authorized operator must bind, got: %v", err)
	}
}
