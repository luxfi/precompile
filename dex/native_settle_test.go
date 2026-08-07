// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
	"errors"
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
	owner, asset, amount, op, decOK := decodeIntentObject(raw)
	if !decOK {
		t.Fatalf("C->D object malformed (len=%d, want %d)", len(raw), intentObjectSize9999)
	}
	// THE OPERATION rides with the value. Without it D credits the taker's account
	// and stops — nothing places an order, nothing crosses, no proceeds exist, and
	// no D->C settlement object is ever produced. That is the whole reason the seam
	// was unreachable, so the operation is asserted here, not just the value.
	if op.Market != h.key.ID() {
		t.Fatalf("C->D op market = %x, want the swapped pool %x", op.Market[:8], func() []byte { m := h.key.ID(); return m[:8] }())
	}
	if op.Side != seamSideSell {
		t.Fatalf("a ZeroForOne (currency0-in) swap is a SELL, got side=%d", op.Side)
	}
	if op.LimitPrice == 0 {
		t.Fatal("C->D op carries no price limit: an unbounded cross-chain order must never be minted")
	}
	if op.Size != 100 {
		t.Fatalf("C->D op size = %d, want the 100 base units the SELL locked", op.Size)
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

// Test9999Swap_DoesNotUseBLSReceiptPath — a hookData shaped like the OLD BLS settlement
// envelope ("D991" tag) must NOT settle a fill from a "cert". After the decomplect that tag
// is neither DI01 nor DS02, so decodeSwapPhase treats it as a PHASE A intent (opaque body
// ignored): the input is LOCKED and an intent id is returned — there is no synchronous
// matcher and no BLS cert/receipt credit path. The decisive property: the caller is NEVER
// credited an output. An opaque/unknown blob can, at most, lock input into a reclaimable
// intent; it can never produce an output credit. The BLS receipt path is gone from the value
// path.
func Test9999Swap_DoesNotUseBLSReceiptPath(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(1000)
	// Pre-fund the vault output so that IF a BLS-style credit path existed, it COULD
	// pay out — making the "no output credit" assertion meaningful.
	h.fundVaultOut(10_000)

	callerOutBefore := h.wrapper().inner.tokenBalances[h.outToken()][h.caller]
	if callerOutBefore == nil {
		callerOutBefore = big.NewInt(0)
	}

	// A blob with the legacy BLS envelope tag ("D991") + garbage. It is NOT a recognized
	// cross-chain phase tag, so it is treated as a plain PHASE A intent (opaque body ignored):
	// input locked, intent id returned. No fill, no cert credit.
	blsLike := append([]byte("D991"), bytes.Repeat([]byte{0xAB}, 200)...)
	out, _, err := runWithEVMSnapshot(h.c, h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, blsLike)), 5_000_000, false)
	if err != nil {
		t.Fatalf("an unknown-tag swap must be treated as a Phase A intent (lock-only), got err: %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("Phase A intent must return a 32-byte intent id, got %d bytes", len(out))
	}
	// The decisive invariant: the caller received NO output token. The BLS-cert credit path
	// is gone — an opaque blob cannot settle a fill.
	callerOutAfter := h.wrapper().inner.tokenBalances[h.outToken()][h.caller]
	if callerOutAfter == nil {
		callerOutAfter = big.NewInt(0)
	}
	if callerOutAfter.Cmp(callerOutBefore) != 0 {
		t.Fatalf("unknown-tag hookData must NOT credit output (BLS path is gone); credited %s",
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

// Test9999Settle_BindsDOutputAssetOwnerAmount — the credit is BOUND to the D->C object
// bytes the TRANSACTION carries: a claim whose asset or owner disagrees with those bytes
// reverts at execution (the asset/owner-aliasing fix). The AMOUNT axis moved one level up:
// execution can no longer read shared memory (that read is what made a settled swap
// unsyncable — see settle_import.go), so an object claiming more than D exported EXECUTES.
// It is caught at Block.Verify, where the declaration this execution emitted fails to
// authenticate against the recorded object and the BLOCK is rejected. Exercised via
// ImportSettlement directly so each axis can be perturbed; each sub-case owns its outputID
// because a sub-case that executes CONSUMES one.
func Test9999Settle_BindsDOutputAssetOwnerAmount(t *testing.T) {
	h := newSettleHarness(t)
	h.fundVaultOut(10_000)
	h.fundVaultNativeOut(10_000)

	// (a) AMOUNT: shared memory records 300; the transaction carries an object stating 301.
	// Execution credits the CARRIED amount — it has nothing else to bind to — and DECLARES
	// those bytes. The declaration is what convicts it: it commits to the 301-bytes while
	// shared memory holds the 300-bytes, so the two hashes differ.
	amountID := ids.ID{0xDE, 0x02}
	h.putDtoCObject(t, h.caller, amountID, h.outAssetID(), 300)
	credited, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: amountID, Asset: h.outAssetID(), AssetAddr: h.outToken(), Recipient: h.caller,
		Object: encodeAtomicObject(railSwap, h.caller, h.outAssetID(), 301),
	})
	if err != nil {
		t.Fatalf("execution must bind the carried bytes without consulting shared memory: %v", err)
	}
	if credited != 301 {
		t.Fatalf("execution credits the CARRIED object's amount: credited %d, want 301", credited)
	}
	imports := DecodeSettleImports(h.state.stateDB.Logs())
	if len(imports) != 1 {
		t.Fatalf("expected exactly 1 declared import, got %d", len(imports))
	}
	recorded, gerr := h.cSM.Get(h.dChainID, [][]byte{amountID[:]})
	if gerr != nil || len(recorded) != 1 {
		t.Fatalf("could not read the recorded object back: %v", gerr)
	}
	if SettleObjectHash(recorded[0]) == imports[0].ObjectHash {
		t.Fatal("an inflated amount produced the SAME commitment as the recorded object — the block rule would be unenforceable")
	}
	// A host running verifyDexAtomicImports over these logs rejects the block here.

	// (b) ASSET mismatch: claim the native asset against an object denominated in the
	// output token -> reject. Both sides ride in the transaction, so this stays an
	// execution-time refusal.
	_, err = h.c.atomicImport(h.state, SettlementClaim{
		OutputID: ids.ID{0xDE, 0x03}, Asset: [32]byte{}, AssetAddr: common.Address{}, Recipient: h.caller,
		Object: encodeAtomicObject(railSwap, h.caller, h.outAssetID(), 300),
	})
	if err != ErrNativeSettleAsset {
		t.Fatalf("asset mismatch must reject with ErrNativeSettleAsset, got: %v", err)
	}

	// (c) OWNER mismatch: claim recipient = a different account -> reject (a tx cannot
	// consume a victim's object).
	attacker := common.HexToAddress("0x9999999999999999999999999999999999999999")
	_, err = h.c.atomicImport(h.state, SettlementClaim{
		OutputID: ids.ID{0xDE, 0x04}, Asset: h.outAssetID(), AssetAddr: h.outToken(), Recipient: attacker,
		Object: encodeAtomicObject(railSwap, h.caller, h.outAssetID(), 300),
	})
	if err != ErrNativeSettleOwner {
		t.Fatalf("owner mismatch must reject with ErrNativeSettleOwner, got: %v", err)
	}

	// (d) the FULLY-bound claim succeeds and credits 300.
	boundID := ids.ID{0xDE, 0x05}
	h.putDtoCObject(t, h.caller, boundID, h.outAssetID(), 300)
	before := h.tokenBal(h.outToken(), h.caller)
	credited, err = h.c.atomicImport(h.state, SettlementClaim{
		OutputID: boundID, Asset: h.outAssetID(), AssetAddr: h.outToken(), Recipient: h.caller,
		Object: encodeAtomicObject(railSwap, h.caller, h.outAssetID(), 300),
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
	rail, owner, asset, amount, _, _ := decodeAtomicObject(raw)
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
		OutputID: outputID, Asset: h.outAssetID(), AssetAddr: h.outToken(), Recipient: h.caller,
		Object: encodeAtomicObject(railSwap, h.caller, h.outAssetID(), 120),
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
		OutputID: outputID, Asset: h.inAssetID(), AssetAddr: common.Address{}, Recipient: h.caller,
		Object: encodeAtomicObject(railSwap, h.caller, h.inAssetID(), 75),
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
	dOwner, dAsset, dAmount, dOp, dOK := decodeIntentObject(raw)
	if !dOK || dOwner != h.caller || dAsset != h.inAssetID() || dAmount != 100 {
		t.Fatalf("round-trip: C->D object mismatch on the D side (ok=%v)", dOK)
	}
	if dOp.Market != h.key.ID() || dOp.Side != seamSideSell || dOp.LimitPrice == 0 || dOp.Size != 100 {
		t.Fatalf("round-trip: C->D operation mismatch on the D side: %+v", dOp)
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

// TestRED_9999_LiveMatcherAnswerCannotCreditC — THE CRITICAL TEST. It proves the ship
// rule: it is IMPOSSIBLE to keep a C credit unless a D->C shared-memory object is
// consumed. We hand the precompile every "live matcher answer" an attacker could
// fabricate — a settlement claim naming a huge amount, the right asset, the right
// recipient — but WITHOUT a real D->C object in shared memory.
//
// The rule did not weaken, it MOVED. Execution keeps the refusals it can make on the
// bytes the transaction carries (an absent object is not the canonical width), and it
// can no longer read shared memory — that read is what made a settled swap unsyncable
// (settle_import.go). So a WELL-FORMED forgery executes; what it cannot do is survive.
// It necessarily DECLARES the bytes it used, shared memory holds nothing at that key,
// and every validator — including the producer, which verifies its own block before
// proposing it — rejects the BLOCK. Nothing it credited is ever accepted.
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

	// (1) Via the 0x9999 swap selector: a settlement-phase hookData naming an object id
	// that was NEVER written to shared memory. A keeper reads nothing off D for it, so the
	// hookData carries no object bytes and the fixed-width body gate refuses it -> NO credit.
	fakeID := ids.ID{0xBA, 0xD0}
	if _, err := h.runSwap(t, h.settlementCalldata(fakeID, 999_999), false); !errors.Is(err, ErrSettleBodyMalformed) {
		t.Fatalf("settle carrying no object bytes MUST fail closed, got: %v", err)
	}

	// (2) Directly via ImportSettlement with a fully-formed claim (the strongest
	// "live matcher answer": correct asset, correct recipient, huge amount) but no object
	// bytes at all. Execution has no shared memory to consult, so the refusal it CAN make
	// is on the bytes themselves: an absent object is not the canonical width.
	_, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID:  fakeID,
		Asset:     h.outAssetID(),
		AssetAddr: h.outToken(),
		Recipient: h.caller,
		// No object: nothing was ever exported at fakeID, so the claim carries none.
	})
	if !errors.Is(err, ErrImportObjectMalformed) {
		t.Fatalf("a fabricated live-matcher answer carrying NO object bytes MUST fail closed, got: %v", err)
	}

	// (2b) The same attack with WELL-FORMED fabricated bytes — run in a FRESH harness so
	// the balance assertions below stay clean. This one EXECUTES (it must: execution is a
	// pure function of the block), but it DECLARES the bytes it used, and shared memory
	// holds NOTHING at that key. Absence is itself the disproof: the declaration cannot
	// authenticate, so the block is rejected and the credit is never accepted.
	forgeH := newSettleHarness(t)
	forgeH.registerMarket(t)
	forgeH.fundVaultOut(1_000_000)
	forged := encodeAtomicObjectSpent(railSwap, forgeH.caller, forgeH.outAssetID(), 999_999, 0)
	forgedCalldata := buildSwapCalldata(forgeH.key, forgeH.params,
		EncodeSettlementHookData(fakeID, forgeH.standingIntent(999_999), forged))
	if _, ferr := forgeH.runSwap(t, forgedCalldata, false); ferr != nil {
		t.Fatalf("execution must bind the carried bytes without consulting shared memory: %v", ferr)
	}
	if n := len(DecodeSettleImports(forgeH.state.stateDB.Logs())); n != 1 {
		t.Fatalf("a forged settlement must still DECLARE what it consumed; got %d declarations", n)
	}
	if vals, gerr := forgeH.cSM.Get(forgeH.dChainID, [][]byte{fakeID[:]}); gerr == nil && len(vals) == 1 && len(vals[0]) > 0 {
		t.Fatal("the forged object must NOT be in shared memory — the test premise is broken")
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
		// The claimed value is the carried object's amount (no separate Amount field).
		_, _, _, objAmount, _, _ := decodeAtomicObject(claim.Object)
		if rec.Status != swapIntentOpen || rec.Remaining < objAmount {
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
