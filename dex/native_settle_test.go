// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// native_settle_test.go — the native C<->D atomic 0x9999 money-path tests. These
// are the PRIMARY 0x9999 tests (the BLS synthetic-receipt tests are quarantined).
// Every test asserts a leg of the SHIP RULE:
//
//	C is credited ONLY by consuming a D->C atomic object;
//	D is funded ONLY by consuming a C->D atomic object.

// runSwap calls the 0x9999 swap selector with the given hookData phase body.
func (h *settleHarness) runSwap(t testing.TB, calldata []byte, readOnly bool) ([]byte, error) {
	t.Helper()
	out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, readOnly)
	return out, err
}

// Test9999Swap_CreatesCToDAtomicIntent — PHASE A: a plain swap (empty hookData)
// LOCKS the taker's input into the 0x9999 escrow and writes a C->D atomic object
// into shared memory, returning the intent id (NOT a fill). It must NOT credit any
// output to the caller.
func Test9999Swap_CreatesCToDAtomicIntent(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(1000) // taker funds the native input leg.

	callerBefore := h.state.stateDB.GetBalance(h.caller).ToBig()
	vaultBefore := h.state.stateDB.GetBalance(poolManagerAddr9999).ToBig()

	out, err := h.runSwap(t, h.intentCalldata(), false)
	if err != nil {
		t.Fatalf("intent swap: %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("intent must return a 32-byte intent id, got %d bytes", len(out))
	}
	var intentID ids.ID
	copy(intentID[:], out)
	if intentID == ids.Empty {
		t.Fatal("intent id must be non-zero")
	}

	// The input (|AmountSpecified| = 100) was DEBITED from the caller into the vault.
	callerAfter := h.state.stateDB.GetBalance(h.caller).ToBig()
	vaultAfter := h.state.stateDB.GetBalance(poolManagerAddr9999).ToBig()
	if new(big.Int).Sub(callerBefore, callerAfter).Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("caller must be debited exactly 100, debited %s", new(big.Int).Sub(callerBefore, callerAfter))
	}
	if new(big.Int).Sub(vaultAfter, vaultBefore).Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("vault must be credited exactly 100, credited %s", new(big.Int).Sub(vaultAfter, vaultBefore))
	}

	// The intent STAGED the C->D object (revert-aware); the host flushes it to shared
	// memory at block accept. Simulate that flush, then assert the object is readable.
	h.flushStaged(t)

	// A C->D atomic object MUST now be readable by D via Get(cChainID, intentID),
	// recording owner=caller, asset=native(0), amount=100. This is the funding D
	// will consume — D is funded ONLY by this object.
	raw, ok := h.readCtoDObject(t, intentID)
	if !ok {
		t.Fatal("C->D atomic object not found in shared memory after intent")
	}
	rail, owner, asset, amount, decOK := decodeAtomicObject(raw)
	if !decOK {
		t.Fatal("C->D object malformed")
	}
	if rail != railSwap {
		t.Fatalf("a swap intent C->D object must be stamped railSwap, got rail=%d", rail)
	}
	if owner != h.caller {
		t.Fatalf("C->D object owner = %s, want caller %s", owner.Hex(), h.caller.Hex())
	}
	if asset != h.inAssetID() {
		t.Fatalf("C->D object asset mismatch")
	}
	if amount != 100 {
		t.Fatalf("C->D object amount = %d, want 100", amount)
	}
}

// Test9999Swap_DoesNotUseBLSReceiptPath — a hookData shaped like the OLD BLS
// settlement envelope ("D991" tag) must NOT settle a fill. In the native model
// that tag is just opaque bytes (Phase A treats it as an intent), so it locks
// input + creates an intent — it can NEVER credit an output from a "cert". This
// proves the BLS receipt path is gone from the value path.
func Test9999Swap_DoesNotUseBLSReceiptPath(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(1000)
	// Pre-fund the vault output so that IF a BLS-style credit path existed, it COULD
	// pay out — making the test meaningful (the credit is possible iff a path exists).
	h.fundVaultOut(10_000)

	callerOutBefore := h.wrapper().inner.tokenBalances[h.outToken()][h.caller]
	if callerOutBefore == nil {
		callerOutBefore = big.NewInt(0)
	}

	// A blob with the legacy BLS envelope tag + garbage. In the native model this is
	// opaque Phase-A body; it must NOT be interpreted as a cert/receipt.
	blsLike := append([]byte("D991"), bytes.Repeat([]byte{0xAB}, 200)...)
	out, err := h.runSwap(t, buildSwapCalldata(h.key, h.params, blsLike), false)
	if err != nil {
		t.Fatalf("swap with BLS-like hookData should be a benign intent, got: %v", err)
	}
	// It returned an intent id (Phase A), not a settled fill.
	if len(out) != 32 {
		t.Fatalf("expected a 32-byte intent id (Phase A), got %d bytes", len(out))
	}
	// The caller received NO output token (no cert path credited anything).
	callerOutAfter := h.wrapper().inner.tokenBalances[h.outToken()][h.caller]
	if callerOutAfter == nil {
		callerOutAfter = big.NewInt(0)
	}
	if callerOutAfter.Cmp(callerOutBefore) != 0 {
		t.Fatalf("BLS-like hookData must NOT credit output (BLS path is gone); credited %s",
			new(big.Int).Sub(callerOutAfter, callerOutBefore))
	}
}

// Test9999Swap_DoesNotUseEngineZAPValuePath — the synchronous Engine.Swap (the
// deprecated ZAP value backend) is NOT the 0x9999 value path. Even with a native
// client installed whose Engine.Swap refuses, the 0x9999 swap selector settles via
// the atomic seam (intent/settlement), never via a synchronous engine fill.
func Test9999Swap_DoesNotUseEngineZAPValuePath(t *testing.T) {
	// The native client's Engine.Swap MUST refuse (a synchronous in-block fill forks
	// consensus). Assert it does, proving the value path is not the engine.
	c := NewNativeDChainClient("Lux DEX")
	_, err := c.Swap(nil, common.Address{}, SwapParams{})
	if err != ErrDChainUnavailable {
		t.Fatalf("native client Engine.Swap must refuse (no synchronous value path), got: %v", err)
	}

	// And the 0x9999 swap selector still works via the atomic seam (Phase A intent),
	// confirming the money path is the atomic seam, not Engine.Swap.
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(500)
	out, serr := h.runSwap(t, h.intentCalldata(), false)
	if serr != nil {
		t.Fatalf("0x9999 swap must settle via the atomic seam: %v", serr)
	}
	if len(out) != 32 {
		t.Fatal("0x9999 swap must return an intent id via the atomic seam")
	}
}

// Test9999Settle_ConsumesDToCAtomicOutputOnce — PHASE B: a settlement swap
// consumes a D->C atomic object ONCE, crediting the output. A second settle of the
// SAME object reverts (one-time settlement / replay protection).
func Test9999Settle_ConsumesDToCAtomicOutputOnce(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundVaultOut(10_000) // vault must back the output credit (no mint).

	// D exported a D->C object: owner=caller, asset=outToken, amount=250.
	outputID := ids.ID{0xDE, 0x01}
	h.putDtoCObject(t, h.caller, outputID, h.outAssetID(), 250)

	callerOutBefore := h.tokenBal(h.outToken(), h.caller)

	// First settle credits exactly 250.
	if _, err := h.runSwap(t, h.settlementCalldata(outputID, 250), false); err != nil {
		t.Fatalf("first settle: %v", err)
	}
	callerOutAfter := h.tokenBal(h.outToken(), h.caller)
	if new(big.Int).Sub(callerOutAfter, callerOutBefore).Cmp(big.NewInt(250)) != 0 {
		t.Fatalf("settle must credit exactly 250, credited %s", new(big.Int).Sub(callerOutAfter, callerOutBefore))
	}

	// Second settle of the SAME object must REVERT (consumed once) AND credit nothing
	// more. The object is removed from shared memory after the first consume, so the
	// guard fires on either the consumed-set OR the absent object.
	_, err := h.runSwap(t, h.settlementCalldata(outputID, 250), false)
	if err == nil {
		t.Fatal("second settle of the same D->C object must revert (one-time settlement)")
	}
	callerOutFinal := h.tokenBal(h.outToken(), h.caller)
	if callerOutFinal.Cmp(callerOutAfter) != 0 {
		t.Fatalf("replayed settle must credit nothing; credited %s", new(big.Int).Sub(callerOutFinal, callerOutAfter))
	}
}

// Test9999Settle_BindsDOutputAssetOwnerAmount — the credit is BOUND to the RECORDED
// D->C object: a claim whose asset / owner / amount does not match the recorded
// object reverts (the asset/owner-aliasing fix). Exercised via ImportSettlement
// directly so each axis can be perturbed.
func Test9999Settle_BindsDOutputAssetOwnerAmount(t *testing.T) {
	h := newSettleHarness(t)
	h.fundVaultOut(10_000)
	h.fundVaultNativeOut(10_000)

	outputID := ids.ID{0xDE, 0x02}
	// Recorded object: owner=caller, asset=outToken, amount=300.
	h.putDtoCObject(t, h.caller, outputID, h.outAssetID(), 300)

	// (a) AMOUNT mismatch: claim 301 against recorded 300 -> reject.
	_, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: outputID, Asset: h.outAssetID(), AssetAddr: h.outToken(), Amount: 301, Recipient: h.caller,
	})
	if err != ErrNativeSettleAmount {
		t.Fatalf("amount mismatch must reject with ErrNativeSettleAmount, got: %v", err)
	}

	// (b) ASSET mismatch: claim native asset against a token-recorded object -> reject.
	_, err = h.c.atomicImport(h.state, SettlementClaim{
		OutputID: outputID, Asset: [32]byte{}, AssetAddr: common.Address{}, Amount: 300, Recipient: h.caller,
	})
	if err != ErrNativeSettleAsset {
		t.Fatalf("asset mismatch must reject with ErrNativeSettleAsset, got: %v", err)
	}

	// (c) OWNER mismatch: claim recipient = a different account -> reject (a tx cannot
	// consume a victim's object).
	attacker := common.HexToAddress("0x9999999999999999999999999999999999999999")
	_, err = h.c.atomicImport(h.state, SettlementClaim{
		OutputID: outputID, Asset: h.outAssetID(), AssetAddr: h.outToken(), Amount: 300, Recipient: attacker,
	})
	if err != ErrNativeSettleOwner {
		t.Fatalf("owner mismatch must reject with ErrNativeSettleOwner, got: %v", err)
	}

	// (d) the FULLY-bound claim succeeds and credits 300.
	before := h.tokenBal(h.outToken(), h.caller)
	credited, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: outputID, Asset: h.outAssetID(), AssetAddr: h.outToken(), Amount: 300, Recipient: h.caller,
	})
	if err != nil {
		t.Fatalf("fully-bound claim must succeed: %v", err)
	}
	if credited != 300 {
		t.Fatalf("credited = %d, want 300", credited)
	}
	after := h.tokenBal(h.outToken(), h.caller)
	if new(big.Int).Sub(after, before).Cmp(big.NewInt(300)) != 0 {
		t.Fatalf("bound claim must credit 300, credited %s", new(big.Int).Sub(after, before))
	}
}

// Test9999ModifyLiquidity_CommitsCToDAtomicFunds — SubmitModifyLiquidity LOCKS the
// LP's funds on C and writes a C->D atomic object so D opens a FUNDED position.
func Test9999ModifyLiquidity_CommitsCToDAtomicFunds(t *testing.T) {
	h := newSettleHarness(t)
	h.fundCallerNative(2000)

	callerBefore := h.state.stateDB.GetBalance(h.caller).ToBig()
	positionID, err := h.c.atomicModifyLiquidity(h.state, IntentRequest{
		Account:      h.caller,
		AssetIn:      h.inAssetID(),
		AmountIn:     500,
		AssetInAddr:  common.Address{},
		MarketID:     h.key.ID(),
		MinAmountOut: big.NewInt(0),
		Recipient:    h.caller,
	})
	if err != nil {
		t.Fatalf("modifyLiquidity commit: %v", err)
	}
	if positionID == ids.Empty {
		t.Fatal("position id must be non-zero")
	}
	// LP funds locked into the vault.
	callerAfter := h.state.stateDB.GetBalance(h.caller).ToBig()
	if new(big.Int).Sub(callerBefore, callerAfter).Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("LP must be debited 500, debited %s", new(big.Int).Sub(callerBefore, callerAfter))
	}
	// Flush the staged C->D object (host block-accept), then assert it is present.
	h.flushStaged(t)

	// C->D atomic object present (D opens a funded position from it).
	raw, ok := h.readCtoDObject(t, positionID)
	if !ok {
		t.Fatal("C->D position-funding object not found in shared memory")
	}
	rail, owner, asset, amount, _ := decodeAtomicObject(raw)
	if rail != railLP || owner != h.caller || asset != h.inAssetID() || amount != 500 {
		t.Fatalf("C->D position object mismatch: rail=%d owner=%s asset=%x amount=%d", rail, owner.Hex(), asset, amount)
	}
}

// Test9999Collect_ImportsDExportToC — a collect's accrued proceeds return as a
// D->C atomic object that ImportSettlement consumes and credits to C. (Collect
// itself only emits a routing event; the value returns via the atomic object.)
func Test9999Collect_ImportsDExportToC(t *testing.T) {
	h := newSettleHarness(t)
	h.fundVaultOut(5_000)

	// SubmitCollect emits the routing event (no value moves here).
	if err := h.c.atomicCollect(h.state, ids.ID{0xC0}, h.key.ID(), h.caller); err != nil {
		t.Fatalf("collect submit: %v", err)
	}

	// D exports the collected proceeds as a D->C object; C imports + credits.
	outputID := ids.ID{0xC0, 0x11}
	h.putDtoCObject(t, h.caller, outputID, h.outAssetID(), 120)
	before := h.tokenBal(h.outToken(), h.caller)
	credited, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: outputID, Asset: h.outAssetID(), AssetAddr: h.outToken(), Amount: 120, Recipient: h.caller,
	})
	if err != nil {
		t.Fatalf("collect import: %v", err)
	}
	if credited != 120 {
		t.Fatalf("collect credited %d, want 120", credited)
	}
	after := h.tokenBal(h.outToken(), h.caller)
	if new(big.Int).Sub(after, before).Cmp(big.NewInt(120)) != 0 {
		t.Fatalf("collect must credit 120, credited %s", new(big.Int).Sub(after, before))
	}
}

// Test9999Cancel_ImportsDRefundToC — a cancel's refund of locked funds returns as a
// D->C atomic object that ImportSettlement consumes and credits to C.
func Test9999Cancel_ImportsDRefundToC(t *testing.T) {
	h := newSettleHarness(t)
	h.fundVaultNativeOut(5_000) // refund is the native input asset.

	if err := h.c.atomicCancel(h.state, ids.ID{0xCA}, h.key.ID(), h.caller); err != nil {
		t.Fatalf("cancel submit: %v", err)
	}

	// D refunds the cancelled order's locked input as a native D->C object.
	outputID := ids.ID{0xCA, 0x22}
	h.putDtoCObject(t, h.caller, outputID, h.inAssetID(), 75)
	before := h.state.stateDB.GetBalance(h.caller).ToBig()
	credited, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: outputID, Asset: h.inAssetID(), AssetAddr: common.Address{}, Amount: 75, Recipient: h.caller,
	})
	if err != nil {
		t.Fatalf("cancel refund import: %v", err)
	}
	if credited != 75 {
		t.Fatalf("cancel refund credited %d, want 75", credited)
	}
	after := h.state.stateDB.GetBalance(h.caller).ToBig()
	if new(big.Int).Sub(after, before).Cmp(big.NewInt(75)) != 0 {
		t.Fatalf("cancel must refund 75 native, credited %s", new(big.Int).Sub(after, before))
	}
}

// Test9999RoundTrip_CToDMatchDToC — the FULL native round trip across the real
// shared-memory channel:
//
//	C creates a C->D intent (locks input, writes C->D object)
//	  -> the D side reads the C->D object (executeImport semantics) and "matches"
//	     -> the D side writes a D->C settlement object (executeExport semantics)
//	       -> C imports the D->C object and credits the taker.
//
// Conservation: the input the taker locked on C leaves the caller; the output the
// taker receives comes out of the vault (no mint).
func Test9999RoundTrip_CToDMatchDToC(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(1000) // taker funds the native input.
	h.fundVaultOut(10_000)   // the vault backs the output credit (maker-seeded reserve).

	// --- C: PHASE A intent. Locks 100 native, writes the C->D object. ---
	out, err := h.runSwap(t, h.intentCalldata(), false)
	if err != nil {
		t.Fatalf("round-trip intent: %v", err)
	}
	var intentID ids.ID
	copy(intentID[:], out)

	// Host flushes the staged C->D object to shared memory at block accept.
	h.flushStaged(t)

	// --- D: read the C->D object (what dexvm.executeImport consumes to fund) ---
	raw, ok := h.readCtoDObject(t, intentID)
	if !ok {
		t.Fatal("round-trip: D could not read the C->D object")
	}
	dRail, dOwner, dAsset, dAmount, _ := decodeAtomicObject(raw)
	if dRail != railSwap || dOwner != h.caller || dAsset != h.inAssetID() || dAmount != 100 {
		t.Fatalf("round-trip: C->D object mismatch on the D side (rail=%d)", dRail)
	}

	// --- D: "match" 100 native-in for 90 token-out, EXPORT a D->C object. The dexvm
	// derives the output UTXO id from its settlement tx; here we use a fresh id. ---
	settleID := ids.ID{0x5E, 0x77, 0x1E}
	h.putDtoCObject(t, h.caller, settleID, h.outAssetID(), 90)

	// --- C: PHASE B settlement. Consumes the D->C object, credits 90 token-out. ---
	callerOutBefore := h.tokenBal(h.outToken(), h.caller)
	if _, err := h.runSwap(t, h.settlementCalldata(settleID, 90), false); err != nil {
		t.Fatalf("round-trip settle: %v", err)
	}
	callerOutAfter := h.tokenBal(h.outToken(), h.caller)
	if new(big.Int).Sub(callerOutAfter, callerOutBefore).Cmp(big.NewInt(90)) != 0 {
		t.Fatalf("round-trip: taker must receive 90 output, got %s", new(big.Int).Sub(callerOutAfter, callerOutBefore))
	}

	// Conservation: caller paid 100 native in (Phase A) and received 90 token out
	// (Phase B). The vault holds the 100 native (taker's input) and paid 90 token
	// from its reserve — no mint on either leg.
	if h.state.stateDB.GetBalance(poolManagerAddr9999).ToBig().Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("round-trip: vault must hold the taker's 100 native input")
	}
}

// TestRED_9999_LiveMatcherAnswerCannotCreditC — THE CRITICAL TEST. It proves the
// ship rule: it is IMPOSSIBLE to credit C unless a D->C shared-memory object is
// consumed. We hand the precompile every "live matcher answer" an attacker could
// fabricate — a settlement claim naming a huge amount, the right asset, the right
// recipient — but WITHOUT a real D->C object in shared memory. The credit MUST NOT
// happen.
func TestRED_9999_LiveMatcherAnswerCannotCreditC(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	// Pre-fund the vault generously so that IF any path could credit without an
	// object, it physically could (the vault can back it). This makes the negative
	// result meaningful: the ONLY thing missing is the D->C object.
	h.fundVaultOut(1_000_000)
	h.fundVaultNativeOut(1_000_000)
	// Fund the caller BEFORE the baseline so the Phase-A intent's lock (a debit) and
	// any (impossible) settlement credit are the ONLY post-baseline deltas measured.
	h.fundCallerNative(1000)

	attackerOutBefore := h.tokenBal(h.outToken(), h.caller)
	attackerNativeBefore := h.state.stateDB.GetBalance(h.caller).ToBig()

	// (1) Via the 0x9999 swap selector: a settlement-phase hookData naming an object
	// id that was NEVER written to shared memory. ImportSettlement's Get returns no
	// object -> revert, NO credit.
	fakeID := ids.ID{0xBA, 0xD0}
	if _, err := h.runSwap(t, h.settlementCalldata(fakeID, 999_999), false); err == nil {
		t.Fatal("settle of a non-existent D->C object MUST revert (no object => no credit)")
	}

	// (2) Directly via ImportSettlement with a fully-formed claim (the strongest
	// "live matcher answer": correct asset, correct recipient, huge amount) but no
	// object in shared memory. MUST revert ErrNativeNoSettlement.
	_, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID:  fakeID,
		Asset:     h.outAssetID(),
		AssetAddr: h.outToken(),
		Amount:    999_999,
		Recipient: h.caller,
	})
	if err != ErrNativeNoSettlement {
		t.Fatalf("a fabricated live-matcher answer with NO D->C object MUST revert ErrNativeNoSettlement, got: %v", err)
	}

	// (3) Even a Phase-A intent (the only other swap path) credits NOTHING — it can
	// only LOCK input + create a C->D object; it returns an intent id, never output.
	out, ierr := h.runSwap(t, h.intentCalldata(), false)
	if ierr != nil {
		t.Fatalf("intent: %v", ierr)
	}
	if len(out) != 32 {
		t.Fatal("intent must return an id, not a fill")
	}

	// FINAL ASSERTION: across every path tried, the caller's OUTPUT balance is
	// unchanged (no token credited) — C cannot be credited without consuming a real
	// D->C object. (The native balance only DECREASED by the intent lock, never
	// increased from a fabricated settlement.)
	attackerOutAfter := h.tokenBal(h.outToken(), h.caller)
	if attackerOutAfter.Cmp(attackerOutBefore) != 0 {
		t.Fatalf("SHIP RULE VIOLATED: C output credited without a D->C object (delta %s)",
			new(big.Int).Sub(attackerOutAfter, attackerOutBefore))
	}
	attackerNativeAfter := h.state.stateDB.GetBalance(h.caller).ToBig()
	if attackerNativeAfter.Cmp(attackerNativeBefore) > 0 {
		t.Fatalf("SHIP RULE VIOLATED: C native credited without a D->C object (before %s after %s)",
			attackerNativeBefore, attackerNativeAfter)
	}
}

// TestRED_9999_AtomicOpsAreDeferredNotImmediate — proves the CROSS-DOMAIN
// ATOMICITY fix: a swap intent (and a settlement consume) does NOT touch shared
// memory MID-TX; it STAGES the atomic op in StateDB and the host flushes it at
// block accept. This is what makes the op revert-safe: a tx that reverts rolls back
// its StateDB staging (geth snapshot/revert), so NOTHING reaches shared memory —
// closing the mint (C->D Put with no backing debit) and loss (D->C Remove with no
// credit) holes a direct, immediate sm.Apply would open.
func TestRED_9999_AtomicOpsAreDeferredNotImmediate(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(1000)

	out, err := h.runSwap(t, h.intentCalldata(), false)
	if err != nil {
		t.Fatalf("intent: %v", err)
	}
	var intentID ids.ID
	copy(intentID[:], out)

	// BEFORE the host flush: the C->D object must NOT be in shared memory yet (the
	// intent only STAGED it in StateDB). A direct sm.Apply would have made it visible
	// here — and a subsequent tx revert could not undo it. Deferral is the fix.
	if _, ok := h.readCtoDObject(t, intentID); ok {
		t.Fatal("ATOMICITY VIOLATED: C->D object reached shared memory mid-tx (must be staged until block accept)")
	}

	// The staged op IS present in StateDB (revert-aware) — collectible by the host.
	staged := CollectStagedAtomic(newPoolStateAdapter(h.state))
	if len(staged) == 0 {
		t.Fatal("intent must stage a C->D op in StateDB for the host to flush at accept")
	}

	// AFTER the host flush (block accept): the object reaches shared memory.
	h.flushStaged(t)
	if _, ok := h.readCtoDObject(t, intentID); !ok {
		t.Fatal("host flush at accept must make the staged C->D object visible to D")
	}

	// Simulate a REVERTED tx: discard the StateDB staging (what the EVM snapshot/
	// revert does) by clearing it, then flush — shared memory gains NOTHING new.
	h2 := newSettleHarness(t)
	h2.registerMarket(t)
	h2.fundCallerNative(1000)
	out2, _ := h2.runSwap(t, h2.intentCalldata(), false)
	var intent2 ids.ID
	copy(intent2[:], out2)
	// "revert": clear the staged ops without flushing (StateDB rollback equivalent).
	ClearStagedAtomic(newPoolStateAdapter(h2.state))
	h2.flushStaged(t) // nothing staged -> nothing applied.
	if _, ok := h2.readCtoDObject(t, intent2); ok {
		t.Fatal("ATOMICITY VIOLATED: a reverted (staging-discarded) intent leaked a C->D object to shared memory")
	}
}

// --- test-only thin wrappers exposing the native client ops with the harness's
// atomic state, so a test does not have to thread (state, atomicState) twice.

func (c *SettleContract) atomicImport(s *nativeAtomicState, claim SettlementClaim) (uint64, error) {
	// Auto-bind to a standing per-taker intent for the recipient (ample principal, no
	// deadline) when the caller didn't name one, so the object-bind / replay / rail
	// axis tests satisfy the per-taker cap (MEDIUM) without each restating it. Cap /
	// deadline tests set claim.IntentID explicitly to a precisely-seeded intent.
	if claim.IntentID == ([32]byte{}) {
		db := newPoolStateAdapter(s)
		// Per-recipient standing intent id (no cross-recipient contamination): derive a
		// stable id from the recipient so owner-mismatch tests still bind owner==recipient.
		var id ids.ID
		id[0], id[1], id[2] = 0x57, 0x7A, 0x11
		copy(id[12:32], claim.Recipient.Bytes())
		rec := loadSwapIntentRecord(db, id)
		if rec.Status != swapIntentOpen || rec.Remaining < claim.Amount {
			putSwapIntentRecord(db, id, swapIntentRecord{
				Owner: claim.Recipient, AssetIn: claim.Asset, Remaining: 1_000_000_000, Status: swapIntentOpen,
			})
		}
		claim.IntentID = id
	}
	return nativeClient.ImportSettlement(s, s, claim)
}
func (c *SettleContract) atomicModifyLiquidity(s *nativeAtomicState, req IntentRequest) (ids.ID, error) {
	return nativeClient.SubmitModifyLiquidity(s, s, req)
}
func (c *SettleContract) atomicCancel(s *nativeAtomicState, orderID ids.ID, marketID [32]byte, owner common.Address) error {
	// Cancel is a keeper-routing notification emitted at the withdraw lifecycle site
	// (requestPositionWithdraw); the test exercises the resulting D->C refund import.
	emitNativeCancelEvent(newPoolStateAdapter(s), orderID, marketID, owner)
	return nil
}
func (c *SettleContract) atomicCollect(s *nativeAtomicState, positionID ids.ID, marketID [32]byte, owner common.Address) error {
	emitNativeCollectEvent(newPoolStateAdapter(s), positionID, marketID, owner)
	return nil
}

// tokenBal reads a holder's balance of an ERC-20 test token (0 if absent).
func (h *settleHarness) tokenBal(token, holder common.Address) *big.Int {
	m := h.wrapper().inner.tokenBalances[token]
	if m == nil || m[holder] == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(m[holder])
}

var _ = uint256.NewInt
