// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// settle_surface_test.go — one focused test per NEW V4 surface:
//   - 0x9999 initialize: create + reinit-revert + bad-params-revert + deterministic tick
//   - 0x9999 modifyLiquidity: lock/unlock conservation + cross-owner-cancel-reverts
//   - 0x9998 Quoter: usable quote + no-mutation-even-if-readOnly==false
//   - 0x9997 StateView: market/slot0/position/halt reads
//   - 0x9996 PositionManager: enumerate + cancel routes to 0x9999 (+ cross-owner gate)
// (0x9010 swap-reverts-PRECOMPILE_MOVED is covered in settle_consensus_test.go.)

// ── helpers ──────────────────────────────────────────────────────────────────

// initCalldata builds the 0x9999 initialize calldata (PoolKey + sqrtPriceX96).
func initCalldata(key PoolKey, sqrtPriceX96 *big.Int) []byte {
	args := make([]byte, 192)
	copy(args[0:160], EncodePoolKeyABI(key))
	sqrtPriceX96.FillBytes(args[160:192])
	return prependSelector(SelectorInitialize, args)
}

// modLiqCalldata builds the 0x9999 modifyLiquidity calldata with a maker-side hookData.
func modLiqCalldata(key PoolKey, tickLower, tickUpper int24, delta *big.Int, salt [32]byte, side MakerSide) []byte {
	hookData := []byte{makerEnvelopeTag[0], makerEnvelopeTag[1], makerEnvelopeTag[2], makerEnvelopeTag[3], byte(side)}
	args := buildModifyLiquidityArgs(key, tickLower, tickUpper, delta, salt, hookData)
	return prependSelector(SelectorModifyLiquidity, args)
}

// quoteCalldata builds a Quoter call (PoolKey, amount, zeroForOne).
func quoteCalldata(sel uint32, key PoolKey, amount *big.Int, zeroForOne bool) []byte {
	args := make([]byte, 224)
	copy(args[0:160], EncodePoolKeyABI(key))
	amount.FillBytes(args[160:192])
	if zeroForOne {
		args[223] = 1
	}
	return prependSelector(sel, args)
}

// pmLifecycleCalldata builds a PositionManager lifecycle call.
func pmLifecycleCalldata(sel uint32, key PoolKey, tickLower, tickUpper int24, delta *big.Int, salt [32]byte, side MakerSide) []byte {
	args := make([]byte, 320)
	copy(args[0:160], EncodePoolKeyABI(key))
	copy(args[160:192], encodeInt24Word(tickLower))
	copy(args[192:224], encodeInt24Word(tickUpper))
	copy(args[224:256], encodeSigned256(delta))
	copy(args[256:288], salt[:])
	args[319] = byte(side)
	return prependSelector(sel, args)
}

// registerMarket initializes the harness pool at price 1.0 (sqrtP = 2^96). Initialize is
// now real-asset-gated (C1 parity with the swap path), so it first installs a resolver that
// admits the key's currencies — exactly as a value-live node carries a registry. A test that
// wants to prove a FABRICATED market is refused installs its own (partial/wrong) resolver
// before calling Initialize directly, not via this helper.
func (h *settleHarness) registerMarket(t testing.TB) {
	t.Helper()
	h.admitMarketKey(t)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, initCalldata(h.key, new(big.Int).Set(Q96)), 5_000_000, false); err != nil {
		t.Fatalf("registerMarket: %v", err)
	}
}

// admitMarketKey installs a resolver that admits the harness key's two currencies (the
// native coin plus any non-zero ERC-20 address, which it also gives live on-chain code so
// the EXTCODESIZE verifier passes) — the test-side equivalent of a node's registry carrying
// this market's real assets. It is idempotent: re-installing for the SAME identity is allowed
// (installAssetResolverFor saves/restores the prior resolver on cleanup). Used by the market-
// creating helpers so a legitimate Initialize / maker-seed passes the C1 admission gate.
func (h *settleHarness) admitMarketKey(t testing.TB) {
	t.Helper()
	var tokens []common.Address
	if h.key.Currency0.Address != (common.Address{}) {
		tokens = append(tokens, h.key.Currency0.Address)
	}
	if h.key.Currency1.Address != (common.Address{}) {
		tokens = append(tokens, h.key.Currency1.Address)
	}
	h.installAssetResolverFor(t, tokens...)
}

// ── 0x9999 initialize ────────────────────────────────────────────────────────

func TestInitialize_CreateReinitBadParams(t *testing.T) {
	h := newSettleHarness(t)
	h.admitMarketKey(t) // Initialize is real-asset-gated; admit the key's assets so the CREATE succeeds.

	// CREATE: a fresh pool at price 1.0 registers and returns tick 0 (sqrtP=2^96).
	out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, initCalldata(h.key, new(big.Int).Set(Q96)), 5_000_000, false)
	if err != nil {
		t.Fatalf("initialize create: %v", err)
	}
	// tick at price 1.0 is 0.
	tick := decodeSigned256(out).Int64()
	if tick != 0 {
		t.Fatalf("price 1.0 must yield tick 0, got %d", tick)
	}
	// The C-authoritative record exists and matches.
	rec := loadMarket(newPoolStateAdapter(h.state), h.key.ID())
	if rec.Status != MarketStatusActive {
		t.Fatal("market must be active after initialize")
	}
	if rec.Tick != 0 || rec.SqrtPriceX96.Cmp(Q96) != 0 {
		t.Fatalf("record tick/price mismatch: tick=%d price=%s", rec.Tick, rec.SqrtPriceX96)
	}
	if rec.Currency0 != h.key.Currency0.Address || rec.Currency1 != h.key.Currency1.Address {
		t.Fatal("record currencies mismatch")
	}
	if rec.Creator != h.caller {
		t.Fatal("record creator must be the initializer")
	}

	// RE-INIT: the same pool reverts ErrPoolAlreadyInitialized (idempotent).
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, initCalldata(h.key, new(big.Int).Set(Q96)), 5_000_000, false); err != ErrPoolAlreadyInitialized {
		t.Fatalf("re-init must revert ErrPoolAlreadyInitialized, got: %v", err)
	}

	// BAD PARAMS — fee too high.
	badFee := h.key
	badFee.Fee = FeeMax + 1
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, initCalldata(badFee, new(big.Int).Set(Q96)), 5_000_000, false); err != ErrInitFeeTooHigh {
		t.Fatalf("fee>FeeMax must revert ErrInitFeeTooHigh, got: %v", err)
	}

	// BAD PARAMS — sqrtPrice out of range (0 is below MinSqrtRatio).
	freshKey := h.key
	freshKey.Fee = 500 // distinct poolID so the not-already-init check passes first
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, initCalldata(freshKey, big.NewInt(0)), 5_000_000, false); err != ErrInitSqrtRange {
		t.Fatalf("sqrtPrice=0 must revert ErrInitSqrtRange, got: %v", err)
	}

	// BAD PARAMS — currencies not sorted (swap 0 and 1).
	unsorted := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x00000000000000000000000000000000000000FF")},
		Currency1:   Currency{Address: common.Address{}}, // native (0) < 0xFF, so this is unsorted
		Fee:         3000,
		TickSpacing: 60,
	}
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, initCalldata(unsorted, new(big.Int).Set(Q96)), 5_000_000, false); err != ErrCurrencyNotSorted {
		t.Fatalf("unsorted currencies must revert ErrCurrencyNotSorted, got: %v", err)
	}
}

// TestInitialize_Deterministic: the tick is computed identically on every call
// (pure GetTickAtSqrtRatio), with NO dependence on a D-Chain response. Two fresh
// "validators" (independent states) register the same pool and get byte-identical
// records.
func TestInitialize_Deterministic(t *testing.T) {
	price, _ := GetSqrtRatioAtTick(1000) // an arbitrary in-range tick's price.

	h1 := newSettleHarness(t)
	h2 := newSettleHarness(t)
	// Initialize is real-asset-gated; both "validators" carry the same registry (same fixed
	// harness identity) and each needs the ERC-20's code in its OWN stateDB for the verifier.
	h1.admitMarketKey(t)
	h2.admitMarketKey(t)
	out1, _, err1 := h1.c.Run(h1.state, h1.caller, poolManagerAddr9999, initCalldata(h1.key, price), 5_000_000, false)
	out2, _, err2 := h2.c.Run(h2.state, h2.caller, poolManagerAddr9999, initCalldata(h2.key, price), 5_000_000, false)
	if err1 != nil || err2 != nil {
		t.Fatalf("initialize errs: %v %v", err1, err2)
	}
	if decodeSigned256(out1).Int64() != decodeSigned256(out2).Int64() {
		t.Fatal("tick must be deterministic across validators")
	}
	r1 := loadMarket(newPoolStateAdapter(h1.state), h1.key.ID())
	r2 := loadMarket(newPoolStateAdapter(h2.state), h2.key.ID())
	if r1.Tick != r2.Tick || r1.SqrtPriceX96.Cmp(r2.SqrtPriceX96) != 0 {
		t.Fatal("market records must be identical across validators")
	}
}

// ── 0x9999 modifyLiquidity ───────────────────────────────────────────────────

func TestModifyLiquidity_CommitConservation(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)

	// The LP funds its CSpendable balance of currency0 (the BID-side asset = native).
	// The committed model debits the caller's REAL balance (no prior deposit needed).
	bidAsset := assetID(h.key.Currency0)
	db := newPoolStateAdapter(h.state)
	h.fundCallerNative(1000)

	callerBefore := h.state.stateDB.GetBalance(h.caller).ToBig()
	committedBefore := loadCustody(db, bidAsset)
	h.vaultInvariantNative(t, "before commit")

	var salt [32]byte
	salt[31] = 0x07

	// COMMIT 400: caller CSpendable -= 400, committedPositions += 400 (the unit moves
	// from CSpendable to DCommitted — never both).
	out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		modLiqCalldata(h.key, -60, 60, big.NewInt(400), salt, MakerSideBid), 5_000_000, false)
	if err != nil {
		t.Fatalf("modifyLiquidity COMMIT: %v", err)
	}
	if len(out) < 32 {
		t.Fatal("modifyLiquidity must return (positionID, committed)")
	}
	callerAfter := h.state.stateDB.GetBalance(h.caller).ToBig()
	committedAfter := loadCustody(db, bidAsset)
	if new(big.Int).Sub(callerBefore, callerAfter).Int64() != 400 {
		t.Fatalf("commit must debit caller CSpendable by exactly 400, got %s", new(big.Int).Sub(callerBefore, callerAfter))
	}
	if new(big.Int).Sub(committedAfter, committedBefore).Int64() != 400 {
		t.Fatalf("commit must add 400 to committedPositions, got %s", new(big.Int).Sub(committedAfter, committedBefore))
	}
	h.vaultInvariantNative(t, "after commit")
	// The position is recorded OPEN (Committed) in the owner index.
	orderID := MakerOrderID(h.caller, h.key.ID(), salt, -60, 60)
	if loadRestingOrder(db, orderID).Status != OrderStatusOpen {
		t.Fatal("position must be OPEN (Committed) after commit")
	}
	if len(OwnerOrderIDs(db, h.caller)) != 1 {
		t.Fatal("owner index must have exactly one position")
	}

	// REMOVE (withdraw request): marks the position CLOSING and emits the D->C withdraw
	// request — it moves NO C value here (funds are on D; they return via collectPosition).
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		modLiqCalldata(h.key, -60, 60, big.NewInt(-400), salt, MakerSideBid), 5_000_000, false); err != nil {
		t.Fatalf("modifyLiquidity REMOVE (withdraw request): %v", err)
	}
	if loadRestingOrder(db, orderID).Status != OrderStatusClosing {
		t.Fatal("position must be CLOSING after a withdraw request")
	}
	// committedPositions is UNCHANGED by the withdraw request (the debit happens only
	// when the LP consumes the D->C collect object). Conservation still holds.
	if loadCustody(db, bidAsset).Int64() != committedAfter.Int64() {
		t.Fatal("a withdraw request must not change committedPositions (D->C collect debits it)")
	}
	h.vaultInvariantNative(t, "after withdraw request")
}

// TestModifyLiquidity_InsufficientBalanceReverts: a COMMIT beyond the caller's
// CSpendable balance reverts (the funds must come from the caller's real balance —
// no mint, no commit of value the LP does not hold).
func TestModifyLiquidity_InsufficientBalanceReverts(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(100)

	var salt [32]byte
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		modLiqCalldata(h.key, -60, 60, big.NewInt(500), salt, MakerSideBid), 5_000_000, false); err != ErrNativeFundsShort {
		t.Fatalf("COMMIT beyond balance must revert ErrNativeFundsShort, got: %v", err)
	}
}

// TestModifyLiquidity_CrossOwnerCancelReverts: account B cannot cancel account A's
// position. The positionID binds owner; B's derived id is a DIFFERENT (empty)
// position, so a withdraw request for it reverts ErrMakerNotOwner.
func TestModifyLiquidity_CrossOwnerCancelReverts(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	alice := h.caller
	bob := common.HexToAddress("0xB0B0000000000000000000000000000000000000")
	db := newPoolStateAdapter(h.state)
	h.fundCallerNative(1000)

	var salt [32]byte
	salt[31] = 0x09
	// Alice commits.
	if _, _, err := h.c.Run(h.state, alice, poolManagerAddr9999,
		modLiqCalldata(h.key, -60, 60, big.NewInt(300), salt, MakerSideBid), 5_000_000, false); err != nil {
		t.Fatalf("alice COMMIT: %v", err)
	}
	// Bob tries to cancel WITH ALICE'S salt/range. Bob's derived positionID differs
	// (owner is folded into the id), so there is no such position for Bob => revert.
	if _, _, err := h.c.Run(h.state, bob, poolManagerAddr9999,
		modLiqCalldata(h.key, -60, 60, big.NewInt(-300), salt, MakerSideBid), 5_000_000, false); err != ErrMakerNotOwner {
		t.Fatalf("cross-owner cancel must revert ErrMakerNotOwner, got: %v", err)
	}
	// Alice's position is still OPEN (Committed) — bob's failed cancel did not close it.
	aliceOrder := MakerOrderID(alice, h.key.ID(), salt, -60, 60)
	if loadRestingOrder(db, aliceOrder).Status != OrderStatusOpen {
		t.Fatal("alice's position must remain OPEN (Committed) after bob's failed cancel")
	}
}

// TestModifyLiquidity_ReentrancyGuard: while the shared 0x9999 custody guard is
// held (as inside a malicious token's transferFrom callback during a custody op), a
// nested modifyLiquidity reverts ErrCustodyReentrant before committing any value.
func TestModifyLiquidity_ReentrancyGuard(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	bidAsset := assetID(h.key.Currency0)
	db := newPoolStateAdapter(h.state)
	h.fundCallerNative(1000)

	// Simulate "a custody op is already in progress" (the guard is held).
	db.SetState(poolManagerAddr9999, custodyGuardKey9999, common.Hash{31: 1})

	var salt [32]byte
	salt[31] = 0x21
	balBefore := h.state.stateDB.GetBalance(h.caller).ToBig()
	committedBefore := loadCustody(db, bidAsset)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		modLiqCalldata(h.key, -60, 60, big.NewInt(100), salt, MakerSideBid), 5_000_000, false); err != ErrCustodyReentrant {
		t.Fatalf("nested modifyLiquidity must revert ErrCustodyReentrant, got: %v", err)
	}
	if h.state.stateDB.GetBalance(h.caller).ToBig().Cmp(balBefore) != 0 {
		t.Fatal("reentrant-refused modifyLiquidity must move no value")
	}
	if loadCustody(db, bidAsset).Cmp(committedBefore) != 0 {
		t.Fatal("reentrant-refused modifyLiquidity must not commit to the LP pot")
	}
}

// ── 0x9999 donate / extsload ──────────────────────────────────────────────────

// TestDonate_Unsupported: donate explicitly reverts ErrUnsupported in the receipt
// model (LP fee growth is D-authoritative; no safe C-only donate exists).
func TestDonate_Unsupported(t *testing.T) {
	h := newSettleHarness(t)
	// donate(PoolKey, amount0, amount1, hookData) — any args revert unsupported.
	args := make([]byte, 160+32+32+32)
	copy(args[0:160], EncodePoolKeyABI(h.key))
	calldata := prependSelector(SelectorDonate, args)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 5_000_000, false); err != ErrUnsupported {
		t.Fatalf("donate must revert ErrUnsupported, got: %v", err)
	}
}

// TestExtsload_RawReads: extsload/extsloadArray read raw 0x9999 slots. We write a
// known slot via the registry then read it back through extsload.
func TestExtsload_RawReads(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	poolID := h.key.ID()
	// The market price slot is a known 0x9999 slot holding the initialized sqrtPrice.
	priceSlot := marketSlot(poolID, marketPriceSuffix)

	// extsload(slot) -> the slot's value.
	out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorExtsload, priceSlot[:]), 5_000_000, true)
	if err != nil || len(out) != 32 {
		t.Fatalf("extsload: err=%v len=%d", err, len(out))
	}
	if new(big.Int).SetBytes(out).Cmp(Q96) != 0 {
		t.Fatalf("extsload of the price slot must return the initialized price, got %s", new(big.Int).SetBytes(out))
	}

	// extsloadArray([priceSlot, metaSlot]) -> 2 words.
	metaSlot := marketSlot(poolID, marketMetaSuffix)
	arrInput := make([]byte, 0, 32+32+64)
	arrInput = append(arrInput, leftPad32([]byte{0x20})...) // offset 0x20
	arrInput = append(arrInput, leftPad32([]byte{0x02})...) // length 2
	arrInput = append(arrInput, priceSlot[:]...)
	arrInput = append(arrInput, metaSlot[:]...)
	outArr, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorExtsloadArray, arrInput), 5_000_000, true)
	if err != nil {
		t.Fatalf("extsloadArray: %v", err)
	}
	// offset(0x20) | len(2) | word0 | word1.
	if new(big.Int).SetBytes(outArr[32:64]).Int64() != 2 {
		t.Fatalf("extsloadArray must return 2 words, len-word=%s", new(big.Int).SetBytes(outArr[32:64]))
	}
	if new(big.Int).SetBytes(outArr[64:96]).Cmp(Q96) != 0 {
		t.Fatal("extsloadArray word0 must be the price")
	}

	// A malformed (oversized length) array reverts rather than over-reading.
	badInput := make([]byte, 0, 64)
	badInput = append(badInput, leftPad32([]byte{0x20})...)
	huge := make([]byte, 32)
	huge[24] = 0xFF // length ~2^39, far beyond input
	badInput = append(badInput, huge...)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorExtsloadArray, badInput), 5_000_000, true); err == nil {
		t.Fatal("extsloadArray with oversized length must revert")
	}
}

// ── 0x9998 Quoter ────────────────────────────────────────────────────────────

func TestQuoter_QuoteAndNoMutation(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)

	q := QuoterPrecompile
	amount := big.NewInt(1_000_000)

	// A plain exact-input quote returns a usable (non-revert) preview.
	out, _, err := q.Run(h.state, h.caller, quoterAddr, quoteCalldata(SelQExactInput, h.key, amount, true), 5_000_000, true)
	if err != nil {
		t.Fatalf("quoteExactInput: %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("quote must return a uint256, got %d bytes", len(out))
	}
	amountOut := new(big.Int).SetBytes(out)
	if amountOut.Sign() < 0 {
		t.Fatal("quote amountOut must be non-negative")
	}

	// NO MUTATION even with readOnly==false: capture a state fingerprint before/after
	// a CALL (not staticcall) to the Quoter. The market record + any 0x9999 slots
	// must be unchanged — the Quoter is write-incapable by construction.
	db := newPoolStateAdapter(h.state)
	recBefore := loadMarket(db, h.key.ID())
	consumedSlotBefore := db.GetState(poolManagerAddr9999, claimConsumedKey(ids.ID{0xAB}))
	if _, _, err := q.Run(h.state, h.caller, quoterAddr, quoteCalldata(SelQExactInput, h.key, amount, true), 5_000_000, false /*NOT read-only*/); err != nil {
		t.Fatalf("quote (readOnly=false) must still succeed: %v", err)
	}
	recAfter := loadMarket(db, h.key.ID())
	if recAfter.Status != recBefore.Status || recAfter.SqrtPriceX96.Cmp(recBefore.SqrtPriceX96) != 0 || recAfter.Tick != recBefore.Tick {
		t.Fatal("Quoter must NOT mutate the market record even with readOnly=false")
	}
	if db.GetState(poolManagerAddr9999, claimConsumedKey(ids.ID{0xAB})) != consumedSlotBefore {
		t.Fatal("Quoter must NOT write any 0x9999 slot")
	}

	// quoteWithFees returns (amountOut, feeAmount).
	outFees, _, err := q.Run(h.state, h.caller, quoterAddr, quoteCalldata(SelQWithFees, h.key, amount, true), 5_000_000, true)
	if err != nil || len(outFees) != 64 {
		t.Fatalf("quoteWithFees: err=%v len=%d", err, len(outFees))
	}
	fee := new(big.Int).SetBytes(outFees[32:64])
	wantFee := feeOnInput(amount, h.key.Fee)
	if fee.Cmp(wantFee) != 0 {
		t.Fatalf("quoteWithFees fee=%s want %s", fee, wantFee)
	}

	// A quote for an UNREGISTERED market reverts (advisory, but only for real pools).
	other := h.key
	other.Fee = 100
	if _, _, err := q.Run(h.state, h.caller, quoterAddr, quoteCalldata(SelQExactInput, other, amount, true), 5_000_000, true); err != ErrQuoteNoMarket {
		t.Fatalf("quote for unregistered market must revert ErrQuoteNoMarket, got: %v", err)
	}
}

// TestQuoter_WriteTripwire: the read-only view's SetState tripwire panics — proving
// the structural write-incapability is enforced, not just documented.
func TestQuoter_WriteTripwire(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("readOnlyView.SetState must panic (write-incapability tripwire)")
		}
	}()
	rv := readOnlyView{state: newSettleHarness(t).state}
	rv.SetState(poolManagerAddr9999, common.Hash{}, common.Hash{1})
}

// ── 0x9997 StateView ─────────────────────────────────────────────────────────

func TestStateView_Reads(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	sv := StateViewPrecompile

	poolID := h.key.ID()

	// getPoolId(PoolKey) == key.ID().
	out, _, err := sv.Run(h.state, h.caller, stateViewAddr, prependSelector(SelectorGetPoolId, EncodePoolKeyABI(h.key)), 5_000_000, true)
	if err != nil || common.BytesToHash(out) != common.BytesToHash(poolID[:]) {
		t.Fatalf("getPoolId: err=%v out=%x want=%x", err, out, poolID)
	}

	// getMarket(poolID) returns the active record.
	mOut, _, err := sv.Run(h.state, h.caller, stateViewAddr, prependSelector(SelectorGetMarket, poolID[:]), 5_000_000, true)
	if err != nil {
		t.Fatalf("getMarket: %v", err)
	}
	if MarketStatus(mOut[31]) != MarketStatusActive {
		t.Fatal("getMarket must report active")
	}

	// getSlot0(poolID) -> (sqrtPriceX96, tick).
	s0, _, err := sv.Run(h.state, h.caller, stateViewAddr, prependSelector(SelectorGetSlot0, poolID[:]), 5_000_000, true)
	if err != nil || len(s0) != 64 {
		t.Fatalf("getSlot0: err=%v len=%d", err, len(s0))
	}
	if new(big.Int).SetBytes(s0[0:32]).Cmp(Q96) != 0 {
		t.Fatal("getSlot0 sqrtPrice must equal the initialized price")
	}

	// getReceiptStatus(unknown) -> false.
	rs, _, err := sv.Run(h.state, h.caller, stateViewAddr, prependSelector(SelectorGetReceiptStatus, make([]byte, 32)), 5_000_000, true)
	if err != nil || rs[31] != 0 {
		t.Fatalf("getReceiptStatus(unknown) must be false: err=%v", err)
	}

	// getHaltStatus(id): global off, scope off initially.
	hs, _, err := sv.Run(h.state, h.caller, stateViewAddr, prependSelector(SelectorGetHaltStatus, poolID[:]), 5_000_000, true)
	if err != nil || hs[31] != 0 || hs[63] != 0 {
		t.Fatalf("getHaltStatus must be all-off initially: err=%v", err)
	}
	// Halt the market, re-read: scope on.
	SetHaltMarket(newPoolStateAdapter(h.state), poolID, true)
	hs2, _, _ := sv.Run(h.state, h.caller, stateViewAddr, prependSelector(SelectorGetHaltStatus, poolID[:]), 5_000_000, true)
	if hs2[63] != 1 {
		t.Fatal("getHaltStatus must report the market halted after SetHaltMarket")
	}

	// getMarket(unregistered) reverts.
	var unknown [32]byte
	unknown[0] = 0xEE
	if _, _, err := sv.Run(h.state, h.caller, stateViewAddr, prependSelector(SelectorGetMarket, unknown[:]), 5_000_000, true); err != ErrViewNoMarket {
		t.Fatalf("getMarket(unregistered) must revert ErrViewNoMarket, got: %v", err)
	}
}

// ── 0x9996 PositionManager ───────────────────────────────────────────────────

func TestPositionManager_EnumerateAndCancelRoutesTo9999(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	pm := PositionManagerPrecompile

	bidAsset := assetID(h.key.Currency0)
	db := newPoolStateAdapter(h.state)
	h.fundCallerNative(1000)

	var salt [32]byte
	salt[31] = 0x11

	// openPosition (ADD via 0x9996) routes into the 0x9999 kernel: COMMITS to D.
	if _, _, err := pm.Run(h.state, h.caller, positionManagerAddr,
		pmLifecycleCalldata(SelectorPMOpenPosition, h.key, -120, 120, big.NewInt(500), salt, MakerSideBid), 5_000_000, false); err != nil {
		t.Fatalf("openPosition: %v", err)
	}
	if loadCustody(db, bidAsset).Int64() != 500 {
		t.Fatal("openPosition must commit to D via the 0x9999 kernel (committedPositions += 500)")
	}
	orderID := MakerOrderID(h.caller, h.key.ID(), salt, -120, 120)
	if loadRestingOrder(db, orderID).Status != OrderStatusOpen {
		t.Fatal("openPosition must record an OPEN (Committed) position in 0x9999 state")
	}

	// positionsOf(owner) enumerates the OPEN position.
	out, _, err := pm.Run(h.state, h.caller, positionManagerAddr, prependSelector(SelectorPMPositionsOf, leftPad32(h.caller.Bytes())), 5_000_000, true)
	if err != nil {
		t.Fatalf("positionsOf: %v", err)
	}
	// bytes32[]: offset(0x20) | len | elems.
	n := new(big.Int).SetBytes(out[32:64]).Int64()
	if n != 1 {
		t.Fatalf("positionsOf must list 1 open position, got %d", n)
	}
	if common.BytesToHash(out[64:96]) != common.BytesToHash(orderID[:]) {
		t.Fatal("positionsOf must list the opened positionID")
	}

	// positionInfo(orderID) returns the record.
	pi, _, err := pm.Run(h.state, h.caller, positionManagerAddr, prependSelector(SelectorPMPositionInfo, orderID[:]), 5_000_000, true)
	if err != nil {
		t.Fatalf("positionInfo: %v", err)
	}
	if common.BytesToAddress(pi[12:32]) != h.caller {
		t.Fatal("positionInfo owner mismatch")
	}
	if new(big.Int).SetBytes(pi[128:160]).Int64() != 500 {
		t.Fatal("positionInfo committed amount must be 500")
	}

	// collect (via 0x9996) emits a D->C collect REQUEST (returns the positionID) — the
	// actual C credit lands when the LP consumes the resulting object via collectPosition.
	cOut, _, err := pm.Run(h.state, h.caller, positionManagerAddr,
		pmLifecycleCalldata(SelectorPMCollect, h.key, -120, 120, big.NewInt(1), salt, MakerSideBid), 5_000_000, false)
	if err != nil {
		t.Fatalf("collect request must succeed (emit event), got: %v", err)
	}
	if common.BytesToHash(cOut) != common.BytesToHash(orderID[:]) {
		t.Fatal("collect request must return the positionID")
	}

	// cancelLimit (REMOVE via 0x9996) routes into the kernel: marks the position
	// CLOSING (the withdraw request); positionsOf drops it (only OPEN listed).
	if _, _, err := pm.Run(h.state, h.caller, positionManagerAddr,
		pmLifecycleCalldata(SelectorPMCancelLimit, h.key, -120, 120, big.NewInt(500), salt, MakerSideBid), 5_000_000, false); err != nil {
		t.Fatalf("cancelLimit: %v", err)
	}
	if loadRestingOrder(db, orderID).Status != OrderStatusClosing {
		t.Fatal("cancelLimit must mark the position CLOSING (withdraw requested)")
	}
	out2, _, _ := pm.Run(h.state, h.caller, positionManagerAddr, prependSelector(SelectorPMPositionsOf, leftPad32(h.caller.Bytes())), 5_000_000, true)
	if new(big.Int).SetBytes(out2[32:64]).Int64() != 0 {
		t.Fatal("positionsOf must be empty after cancel (only OPEN listed)")
	}
}

// TestPositionManager_CrossOwnerCancelReverts: cancel through 0x9996 is bound by
// caller==owner (enforced at the 0x9999 kernel it routes into).
func TestPositionManager_CrossOwnerCancelReverts(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	pm := PositionManagerPrecompile
	alice := h.caller
	bob := common.HexToAddress("0xB0B0000000000000000000000000000000000000")
	h.fundCallerNative(1000)

	var salt [32]byte
	salt[31] = 0x13
	if _, _, err := pm.Run(h.state, alice, positionManagerAddr,
		pmLifecycleCalldata(SelectorPMOpenPosition, h.key, -60, 60, big.NewInt(200), salt, MakerSideBid), 5_000_000, false); err != nil {
		t.Fatalf("alice open: %v", err)
	}
	if _, _, err := pm.Run(h.state, bob, positionManagerAddr,
		pmLifecycleCalldata(SelectorPMCancelLimit, h.key, -60, 60, big.NewInt(200), salt, MakerSideBid), 5_000_000, false); err != ErrMakerNotOwner {
		t.Fatalf("bob cancelling alice's position must revert ErrMakerNotOwner, got: %v", err)
	}
}
