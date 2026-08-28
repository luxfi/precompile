// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/chains/atomic"
)

// zzmop_dchain_test.go covers native_dchain_client.go — the C side of the C<->D atomic
// seam. The SHIP RULE is what is under test:
//
//   - C is credited ONLY by consuming a D->C atomic object of the MATCHING rail, ONCE,
//     bound to the RECORDED owner / asset / amount. A claim can neither invent value nor
//     re-denominate an object, nor consume a victim's.
//   - D is funded ONLY by a C->D object backed by a C-side debit, and the same intent id
//     can never be submitted twice.
//   - The two object-id derivations are INJECTIVE over every field they claim to bind
//     (each field is varied on its own) and live in disjoint domains.

// zzmpClient is a fresh client (never the package singleton, so a test cannot disturb
// the live money path).
func zzmpClient() *NativeDChainClient { return NewNativeDChainClient("zzmp test") }

// zzmpPutRaw writes an arbitrary D->C shared-memory value under outputID, so a test can
// present a MALFORMED object the decoder must refuse.
func zzmpPutRaw(t *testing.T, h *settleHarness, outputID ids.ID, value []byte) {
	t.Helper()
	reqs := map[ids.ID]*atomic.Requests{
		h.cChainID: {PutRequests: []*atomic.Element{{
			Key:    outputID[:],
			Value:  value,
			Traits: [][]byte{h.caller[:]},
		}}},
	}
	if err := h.dSM.Apply(reqs); err != nil {
		t.Fatalf("zzmpPutRaw: %v", err)
	}
}

// zzmpIntentReq is a well-formed native C->D intent request for the harness's market.
func zzmpIntentReq(h *settleHarness, amount uint64, nonce uint64) IntentRequest {
	return IntentRequest{
		Account:     h.caller,
		AssetIn:     h.inAssetID(),
		AmountIn:    amount,
		AssetInAddr: h.key.Currency0.Address,
		MarketID:    h.key.ID(),
		Recipient:   h.caller,
		Deadline:    harnessBlockTime + 3_600,
		Nonce:       nonce,
	}
}

// ---------------------------------------------------------------------------
// brand + the closed synchronous Engine surface
// ---------------------------------------------------------------------------

// TestZzmpNativeClientBrandAndClosedEngineSurface pins the white-label default and the
// deliberately-closed synchronous surface: a live in-block matcher forks consensus, so
// every synchronous Engine method REFUSES rather than moving value.
func TestZzmpNativeClientBrandAndClosedEngineSurface(t *testing.T) {
	if got := NewNativeDChainClient("").Brand(); got != "Lux DEX" {
		t.Fatalf("an empty brand must default to the OSS identity, got %q", got)
	}
	if got := NewNativeDChainClient("Acme DEX").Brand(); got != "Acme DEX" {
		t.Fatalf("a tenant brand must be kept, got %q", got)
	}

	c := zzmpClient()
	if tick, err := c.Initialize(big.NewInt(1)); !errors.Is(err, ErrDChainUnavailable) || tick != 0 {
		t.Fatalf("Engine.Initialize: want 0/ErrDChainUnavailable, got %d/%v", tick, err)
	}
	if d, err := c.Swap(nil, common.Address{}, SwapParams{}); !errors.Is(err, ErrDChainUnavailable) || !d.IsZero() {
		t.Fatalf("Engine.Swap: want zero/ErrDChainUnavailable, got %+v/%v", d, err)
	}
	if a, b, err := c.ModifyLiquidity(nil, common.Address{}, ModifyLiquidityParams{}); !errors.Is(err, ErrDChainUnavailable) || !a.IsZero() || !b.IsZero() {
		t.Fatalf("Engine.ModifyLiquidity: want zero/ErrDChainUnavailable, got %+v %+v/%v", a, b, err)
	}
	if d, err := c.Donate(nil, big.NewInt(1), big.NewInt(1)); !errors.Is(err, ErrDChainUnavailable) || !d.IsZero() {
		t.Fatalf("Engine.Donate: want zero/ErrDChainUnavailable, got %+v/%v", d, err)
	}
	if q := c.Quote(nil, big.NewInt(1_000), true); q == nil || q.Sign() != 0 {
		t.Fatalf("Engine.Quote must answer 0 (no synchronous quote), got %v", q)
	}
}

// ---------------------------------------------------------------------------
// C->D: SubmitSwapIntent / SubmitPositionCommit
// ---------------------------------------------------------------------------

// TestZzmpSubmitRefusesAClosedSeamAndAZeroAmount pins the fail-closed on-ramp: with no
// atomic memory, or no D peer resolved, or a zero size, nothing is locked and no object
// is staged.
func TestZzmpSubmitRefusesAClosedSeamAndAZeroAmount(t *testing.T) {
	c := zzmpClient()

	// (a) No atomic memory at all.
	h := newSettleHarness(t)
	h.fundCallerNative(1_000)
	h.state.sm = nil
	if _, err := c.SubmitSwapIntent(h.state, h.state, zzmpIntentReq(h, 100, 1)); !errors.Is(err, ErrNativeNoAtomicMemory) {
		t.Fatalf("SubmitSwapIntent with no atomic memory: want ErrNativeNoAtomicMemory, got %v", err)
	}
	if _, _, err := c.SubmitPositionCommit(h.state, h.state, zzmpIntentReq(h, 100, 1)); !errors.Is(err, ErrNativeNoAtomicMemory) {
		t.Fatalf("SubmitPositionCommit with no atomic memory: want ErrNativeNoAtomicMemory, got %v", err)
	}
	if _, err := c.ImportSettlement(h.state, h.state, SettlementClaim{}); !errors.Is(err, ErrNativeNoAtomicMemory) {
		t.Fatalf("ImportSettlement with no atomic memory: want ErrNativeNoAtomicMemory, got %v", err)
	}
	if _, err := c.ImportPositionCollect(h.state, h.state, SettlementClaim{}); !errors.Is(err, ErrNativeNoAtomicMemory) {
		t.Fatalf("ImportPositionCollect with no atomic memory: want ErrNativeNoAtomicMemory, got %v", err)
	}
	if _, err := c.ReclaimIntent(h.state, h.state, h.caller, ids.ID{1}); !errors.Is(err, ErrNativeNoAtomicMemory) {
		t.Fatalf("ReclaimIntent with no atomic memory: want ErrNativeNoAtomicMemory, got %v", err)
	}

	// (b) A zero-size intent / commit locks nothing.
	h2 := newSettleHarness(t)
	h2.fundCallerNative(1_000)
	if _, err := c.SubmitSwapIntent(h2.state, h2.state, zzmpIntentReq(h2, 0, 1)); !errors.Is(err, ErrNativeBadAmount) {
		t.Fatalf("zero-size intent: want ErrNativeBadAmount, got %v", err)
	}
	if _, _, err := c.SubmitPositionCommit(h2.state, h2.state, zzmpIntentReq(h2, 0, 1)); !errors.Is(err, ErrNativeBadAmount) {
		t.Fatalf("zero-size commit: want ErrNativeBadAmount, got %v", err)
	}
	if got := h2.state.stateDB.GetBalance(h2.caller).Uint64(); got != 1_000 {
		t.Fatalf("a refused submit moved the caller's balance to %d", got)
	}

	// (c) No D peer resolved on this network: the seam stays closed (no mint).
	h3 := newSettleHarness(t)
	h3.fundCallerNative(1_000)
	h3.state.dChainID = ids.Empty
	for name, call := range map[string]func() error{
		"SubmitSwapIntent": func() error { _, err := c.SubmitSwapIntent(h3.state, h3.state, zzmpIntentReq(h3, 100, 1)); return err },
		"SubmitPositionCommit": func() error {
			_, _, err := c.SubmitPositionCommit(h3.state, h3.state, zzmpIntentReq(h3, 100, 1))
			return err
		},
		"ImportSettlement":      func() error { _, err := c.ImportSettlement(h3.state, h3.state, SettlementClaim{}); return err },
		"ImportPositionCollect": func() error { _, err := c.ImportPositionCollect(h3.state, h3.state, SettlementClaim{}); return err },
		"ReclaimIntent":         func() error { _, err := c.ReclaimIntent(h3.state, h3.state, h3.caller, ids.ID{1}); return err },
	} {
		if err := call(); !errors.Is(err, ErrNativeNoAtomicMemory) {
			t.Fatalf("%s with no D peer: want ErrNativeNoAtomicMemory, got %v", name, err)
		}
	}
	if got := h3.state.stateDB.GetBalance(h3.caller).Uint64(); got != 1_000 {
		t.Fatalf("a peer-less submit moved the caller's balance to %d", got)
	}
	if got := loadSeamReserve(zzmpDB(h3), h3.inAssetID()); got.Sign() != 0 {
		t.Fatalf("a peer-less submit credited the seam reserve: %s", got)
	}
}

// TestZzmpSubmitIsIdempotentUnderReplay pins the replay guard on BOTH rails: the same
// (identity, asset, amount, market, nonce) derives the same id, and the second submit is
// refused rather than double-funding D.
func TestZzmpSubmitIsIdempotentUnderReplay(t *testing.T) {
	c := zzmpClient()

	// SWAP rail.
	h := newSettleHarness(t)
	h.fundCallerNative(2_000)
	req := zzmpIntentReq(h, 500, 42)
	first, err := c.SubmitSwapIntent(h.state, h.state, req)
	if err != nil {
		t.Fatalf("first SubmitSwapIntent: %v", err)
	}
	if !isIntentSubmitted(zzmpDB(h), first) {
		t.Fatal("the first submit did not mark the intent id")
	}
	if _, err := c.SubmitSwapIntent(h.state, h.state, req); !errors.Is(err, ErrNativeIntentReplay) {
		t.Fatalf("replayed SubmitSwapIntent: want ErrNativeIntentReplay, got %v", err)
	}
	// A DIFFERENT nonce is a different intent and is admitted.
	second, err := c.SubmitSwapIntent(h.state, h.state, zzmpIntentReq(h, 500, 43))
	if err != nil {
		t.Fatalf("a distinct nonce must be admitted, got %v", err)
	}
	if second == first {
		t.Fatal("two distinct nonces derived the same intent id")
	}

	// LP rail: the commit id binds txID + callIndex, so a replay of the SAME call is
	// refused while a distinct callIndex is a distinct commit.
	h2 := newSettleHarness(t)
	h2.fundCallerNative(2_000)
	creq := zzmpIntentReq(h2, 400, 0)
	pos, locked, err := c.SubmitPositionCommit(h2.state, h2.state, creq)
	if err != nil {
		t.Fatalf("first SubmitPositionCommit: %v", err)
	}
	if locked != 400 {
		t.Fatalf("committed %d, want 400", locked)
	}
	if got := loadCommittedPositions(zzmpDB(h2), h2.inAssetID()); got.Int64() != 400 {
		t.Fatalf("committedPositions after the commit: want 400, got %s", got)
	}
	if _, _, err := c.SubmitPositionCommit(h2.state, h2.state, creq); !errors.Is(err, ErrLPCommitReplay) {
		t.Fatalf("replayed SubmitPositionCommit: want ErrLPCommitReplay, got %v", err)
	}
	h2.state.callIndex++
	pos2, _, err := c.SubmitPositionCommit(h2.state, h2.state, creq)
	if err != nil {
		t.Fatalf("a distinct call index must be admitted, got %v", err)
	}
	if pos2 == pos {
		t.Fatal("two distinct call indexes derived the same commit id")
	}
	// The two rails' pots stay orthogonal: an LP commit never lands in the swap pot.
	if got := loadSeamReserve(zzmpDB(h2), h2.inAssetID()); got.Sign() != 0 {
		t.Fatalf("an LP commit credited the SWAP pot: %s", got)
	}
	// SubmitModifyLiquidity is the alias onto the same rail.
	h2.state.callIndex++
	if _, err := c.SubmitModifyLiquidity(h2.state, h2.state, creq); err != nil {
		t.Fatalf("SubmitModifyLiquidity: %v", err)
	}
}

// TestZzmpSubmitPropagatesTheLockFailure pins that an unfundable lock surfaces as a
// refusal from the submit (never swallowed into a staged object with no backing debit).
func TestZzmpSubmitPropagatesTheLockFailure(t *testing.T) {
	c := zzmpClient()
	h := newSettleHarness(t)
	// The caller has NOTHING, so the native lock fails fast.
	if _, err := c.SubmitSwapIntent(h.state, h.state, zzmpIntentReq(h, 100, 1)); !errors.Is(err, ErrNativeFundsShort) {
		t.Fatalf("unfunded SubmitSwapIntent: want ErrNativeFundsShort, got %v", err)
	}
	if _, _, err := c.SubmitPositionCommit(h.state, h.state, zzmpIntentReq(h, 100, 1)); !errors.Is(err, ErrNativeFundsShort) {
		t.Fatalf("unfunded SubmitPositionCommit: want ErrNativeFundsShort, got %v", err)
	}
	db := zzmpDB(h)
	if got := loadSeamReserve(db, h.inAssetID()); got.Sign() != 0 {
		t.Fatalf("an unfunded intent credited the seam pot: %s", got)
	}
	if got := loadCommittedPositions(db, h.inAssetID()); got.Sign() != 0 {
		t.Fatalf("an unfunded commit credited the LP pot: %s", got)
	}
}

// ---------------------------------------------------------------------------
// D->C: ImportSettlement binds the RECORDED value
// ---------------------------------------------------------------------------

// TestZzmpImportSettlementBindsTheRecordedObject walks EVERY bind the swap-rail consume
// enforces. Each is exercised on its own so a single weakened check is visible.
func TestZzmpImportSettlementBindsTheRecordedObject(t *testing.T) {
	c := zzmpClient()
	h := newSettleHarness(t)
	h.fundVaultOut(10_000)
	intentID := h.standingIntent(1_000)
	outputID := ids.ID{0xA0}

	claim := func(mutate func(*SettlementClaim)) SettlementClaim {
		cl := SettlementClaim{
			OutputID:  outputID,
			Asset:     h.outAssetID(),
			AssetAddr: h.outToken(),
			Amount:    1_000,
			Recipient: h.caller,
			IntentID:  intentID,
		}
		if mutate != nil {
			mutate(&cl)
		}
		return cl
	}

	// (1) No object at all => never credit.
	if _, err := c.ImportSettlement(h.state, h.state, claim(nil)); !errors.Is(err, ErrNativeNoSettlement) {
		t.Fatalf("missing object: want ErrNativeNoSettlement, got %v", err)
	}

	// (2) A MALFORMED recorded value is never reinterpreted into a credit.
	for _, width := range []int{0, 1, exportedOutputSize9999 - 1, exportedOutputSize9999 + 1} {
		id := ids.ID{0xB0, byte(width)}
		zzmpPutRaw(t, h, id, make([]byte, width))
		if _, err := c.ImportSettlement(h.state, h.state, claim(func(cl *SettlementClaim) { cl.OutputID = id })); err == nil {
			t.Fatalf("a %d-byte object was accepted", width)
		} else if width > 0 && !errors.Is(err, ErrNativeSettleMalformed) {
			t.Fatalf("a %d-byte object: want ErrNativeSettleMalformed, got %v", width, err)
		}
	}

	// (3) RAIL gate: an LP-rail object can never reach the swap pot.
	lpID := ids.ID{0xC0}
	h.putDtoCLPObject(t, h.caller, lpID, h.outAssetID(), 1_000)
	if _, err := c.ImportSettlement(h.state, h.state, claim(func(cl *SettlementClaim) { cl.OutputID = lpID })); !errors.Is(err, ErrSettleWrongRail) {
		t.Fatalf("cross-rail consume: want ErrSettleWrongRail, got %v", err)
	}

	// (4) The recorded value is authoritative: asset, owner and amount each bind.
	h.putDtoCObject(t, h.caller, outputID, h.outAssetID(), 1_000)
	for _, tc := range []struct {
		name string
		mut  func(*SettlementClaim)
		want error
	}{
		{"asset", func(cl *SettlementClaim) { cl.Asset = h.inAssetID() }, ErrNativeSettleAsset},
		{"recipient", func(cl *SettlementClaim) {
			cl.Recipient = common.HexToAddress("0x00000000000000000000000000000000000000AA")
		}, ErrNativeSettleOwner},
		{"amount (under)", func(cl *SettlementClaim) { cl.Amount = 999 }, ErrNativeSettleAmount},
		{"amount (over)", func(cl *SettlementClaim) { cl.Amount = 1_001 }, ErrNativeSettleAmount},
	} {
		if _, err := c.ImportSettlement(h.state, h.state, claim(tc.mut)); !errors.Is(err, tc.want) {
			t.Fatalf("tampered %s: want %v, got %v", tc.name, tc.want, err)
		}
	}

	// (5) A ZERO-amount recorded object is refused outright (nothing to settle).
	zeroID := ids.ID{0xD0}
	h.putDtoCObject(t, h.caller, zeroID, h.outAssetID(), 0)
	if _, err := c.ImportSettlement(h.state, h.state, claim(func(cl *SettlementClaim) { cl.OutputID = zeroID; cl.Amount = 0 })); !errors.Is(err, ErrNativeSettleAmount) {
		t.Fatalf("zero-amount object: want ErrNativeSettleAmount, got %v", err)
	}

	// (6) The honest consume credits exactly the RECORDED amount, once.
	before := h.wrapper().TokenBalanceOf(h.outToken(), h.caller)
	credited, err := c.ImportSettlement(h.state, h.state, claim(nil))
	if err != nil {
		t.Fatalf("honest ImportSettlement: %v", err)
	}
	if credited != 1_000 {
		t.Fatalf("credited %d, want the recorded 1000", credited)
	}
	if got := new(big.Int).Sub(h.wrapper().TokenBalanceOf(h.outToken(), h.caller), before); got.Int64() != 1_000 {
		t.Fatalf("the taker received %s, want 1000", got)
	}
	// (7) REPLAY: the same object can never be consumed twice.
	if _, err := c.ImportSettlement(h.state, h.state, claim(nil)); !errors.Is(err, ErrNativeSettleReplay) {
		t.Fatalf("replayed consume: want ErrNativeSettleReplay, got %v", err)
	}
	if got := new(big.Int).Sub(h.wrapper().TokenBalanceOf(h.outToken(), h.caller), before); got.Int64() != 1_000 {
		t.Fatalf("a replayed consume paid out again: %s", got)
	}
}

// ---------------------------------------------------------------------------
// D->C: ImportPositionCollect binds the RECORDED value AND the named position
// ---------------------------------------------------------------------------

func TestZzmpImportPositionCollectBindsTheRecordedObjectAndThePosition(t *testing.T) {
	c := zzmpClient()
	h := newSettleHarness(t)
	db := zzmpDB(h)
	aid := h.inAssetID()

	// A funded LP position: pot, record and owner reserve all agree at 1000.
	posID := [32]byte{0x0E}
	recordCommittedLock(db, aid, 1_000)
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(1_000))
	storeRestingOrder(db, posID, RestingOrder{
		Owner: h.caller, LockedAsset: aid, LockedAmt: big.NewInt(1_000), Status: OrderStatusOpen,
	})
	storeLockedReserve(db, h.caller, aid, big.NewInt(1_000))

	outputID := ids.ID{0xE0}
	claim := func(mutate func(*SettlementClaim)) SettlementClaim {
		cl := SettlementClaim{
			OutputID:   outputID,
			Asset:      aid,
			Amount:     400,
			Recipient:  h.caller,
			PositionID: posID,
		}
		if mutate != nil {
			mutate(&cl)
		}
		return cl
	}

	// A missing object never credits.
	if _, err := c.ImportPositionCollect(h.state, h.state, claim(nil)); !errors.Is(err, ErrNativeNoSettlement) {
		t.Fatalf("missing LP object: want ErrNativeNoSettlement, got %v", err)
	}
	// A malformed object is never reinterpreted.
	badID := ids.ID{0xE1}
	zzmpPutRaw(t, h, badID, make([]byte, exportedOutputSize9999-1))
	if _, err := c.ImportPositionCollect(h.state, h.state, claim(func(cl *SettlementClaim) { cl.OutputID = badID })); !errors.Is(err, ErrNativeSettleMalformed) {
		t.Fatalf("malformed LP object: want ErrNativeSettleMalformed, got %v", err)
	}
	// RAIL gate: a swap-fill object can never reach the LP pot.
	swapID := ids.ID{0xE2}
	h.putDtoCObject(t, h.caller, swapID, aid, 400)
	if _, err := c.ImportPositionCollect(h.state, h.state, claim(func(cl *SettlementClaim) { cl.OutputID = swapID })); !errors.Is(err, ErrLPCollectWrongRail) {
		t.Fatalf("cross-rail LP consume: want ErrLPCollectWrongRail, got %v", err)
	}

	h.putDtoCLPObject(t, h.caller, outputID, aid, 400)
	for _, tc := range []struct {
		name string
		mut  func(*SettlementClaim)
		want error
	}{
		{"asset", func(cl *SettlementClaim) { cl.Asset = h.outAssetID() }, ErrNativeSettleAsset},
		{"recipient", func(cl *SettlementClaim) {
			cl.Recipient = common.HexToAddress("0x00000000000000000000000000000000000000BB")
		}, ErrNativeSettleOwner},
		{"amount", func(cl *SettlementClaim) { cl.Amount = 401 }, ErrNativeSettleAmount},
		{"unknown position", func(cl *SettlementClaim) { cl.PositionID = [32]byte{0xFF} }, ErrLPCollectNoPosition},
	} {
		if _, err := c.ImportPositionCollect(h.state, h.state, claim(tc.mut)); !errors.Is(err, tc.want) {
			t.Fatalf("tampered %s: want %v, got %v", tc.name, tc.want, err)
		}
	}

	// A position owned by SOMEONE ELSE cannot back this owner's collect — this is what
	// stops an over-export for one owner drawing on another's committed principal.
	foreign := [32]byte{0x0F}
	storeRestingOrder(db, foreign, RestingOrder{
		Owner:       common.HexToAddress("0x00000000000000000000000000000000000000CC"),
		LockedAsset: aid, LockedAmt: big.NewInt(10_000), Status: OrderStatusOpen,
	})
	if _, err := c.ImportPositionCollect(h.state, h.state, claim(func(cl *SettlementClaim) { cl.PositionID = foreign })); !errors.Is(err, ErrLPCollectNoPosition) {
		t.Fatalf("collect against another owner's position: want ErrLPCollectNoPosition, got %v", err)
	}

	// An amount past the named position's own backing is refused.
	small := [32]byte{0x10}
	storeRestingOrder(db, small, RestingOrder{
		Owner: h.caller, LockedAsset: aid, LockedAmt: big.NewInt(399), Status: OrderStatusOpen,
	})
	if _, err := c.ImportPositionCollect(h.state, h.state, claim(func(cl *SettlementClaim) { cl.PositionID = small })); !errors.Is(err, ErrLPCollectExceedsPosition) {
		t.Fatalf("collect past the position backing: want ErrLPCollectExceedsPosition, got %v", err)
	}

	// The honest collect credits the LP and drives the record + reserve down together.
	credited, err := c.ImportPositionCollect(h.state, h.state, claim(nil))
	if err != nil {
		t.Fatalf("honest ImportPositionCollect: %v", err)
	}
	if credited != 400 {
		t.Fatalf("credited %d, want 400", credited)
	}
	if got := h.state.stateDB.GetBalance(h.caller).Uint64(); got != 400 {
		t.Fatalf("the LP received %d, want 400", got)
	}
	if got := loadRestingOrder(db, posID).LockedAmt.Int64(); got != 600 {
		t.Fatalf("record LockedAmt after the collect: want 600, got %d", got)
	}
	if got := loadLockedReserve(db, h.caller, aid).Int64(); got != 600 {
		t.Fatalf("owner reserve after the collect: want 600, got %d", got)
	}
	if got := loadCommittedPositions(db, aid).Int64(); got != 600 {
		t.Fatalf("committedPositions after the collect: want 600, got %d", got)
	}
	// REPLAY refused.
	if _, err := c.ImportPositionCollect(h.state, h.state, claim(nil)); !errors.Is(err, ErrNativeSettleReplay) {
		t.Fatalf("replayed collect: want ErrNativeSettleReplay, got %v", err)
	}
}

// TestZzmpImportPositionCollectRefusesAnUnbackedPot pins the no-mint gate on the LP
// credit: the record may say 1000 while the pot is empty, and the credit must refuse.
func TestZzmpImportPositionCollectRefusesAnUnbackedPot(t *testing.T) {
	c := zzmpClient()
	h := newSettleHarness(t)
	db := zzmpDB(h)
	aid := h.inAssetID()

	posID := [32]byte{0x20}
	storeRestingOrder(db, posID, RestingOrder{
		Owner: h.caller, LockedAsset: aid, LockedAmt: big.NewInt(1_000), Status: OrderStatusOpen,
	})
	// committedPositions is deliberately EMPTY.
	outputID := ids.ID{0xF0}
	h.putDtoCLPObject(t, h.caller, outputID, aid, 500)

	if _, err := c.ImportPositionCollect(h.state, h.state, SettlementClaim{
		OutputID: outputID, Asset: aid, Amount: 500, Recipient: h.caller, PositionID: posID,
	}); !errors.Is(err, ErrLPCollectUnbacked) {
		t.Fatalf("collect against an empty pot: want ErrLPCollectUnbacked, got %v", err)
	}
	if got := h.state.stateDB.GetBalance(h.caller).Uint64(); got != 0 {
		t.Fatalf("an unbacked collect still paid the LP %d", got)
	}
}

// TestZzmpCollectPositionRecordClampsTheOwnerReserve covers the defence-in-depth floor
// on the per-owner accumulator: if the reserve is somehow below the collected amount it
// clamps to zero rather than going negative through the 32-byte-word encoding.
func TestZzmpCollectPositionRecordClampsTheOwnerReserve(t *testing.T) {
	db := NewMockStateDB()
	owner := common.HexToAddress("0x0000000000000000000000000000000000000701")
	aid := [32]byte{0x09}
	id := [32]byte{0x30}

	order := RestingOrder{Owner: owner, LockedAsset: aid, LockedAmt: big.NewInt(1_000), Status: OrderStatusOpen}
	storeRestingOrder(db, id, order)
	storeLockedReserve(db, owner, aid, big.NewInt(10)) // SHORT of the collected 400

	collectPositionRecord(db, id, order, aid, 400)
	if got := loadLockedReserve(db, owner, aid); got.Sign() != 0 {
		t.Fatalf("a short owner reserve must clamp to 0, got %s", got)
	}
	if got := loadRestingOrder(db, id); got.LockedAmt.Int64() != 600 || got.Status != OrderStatusOpen {
		t.Fatalf("record after a partial collect: LockedAmt=%s status=%d", got.LockedAmt, got.Status)
	}

	// Collecting the remainder closes the position (terminal) and zeroes the reserve.
	storeLockedReserve(db, owner, aid, big.NewInt(600))
	collectPositionRecord(db, id, loadRestingOrder(db, id), aid, 600)
	got := loadRestingOrder(db, id)
	if got.LockedAmt.Sign() != 0 {
		t.Fatalf("a fully collected record must reach 0, got %s", got.LockedAmt)
	}
	if got.Status != OrderStatusCancelled {
		t.Fatalf("a fully collected record must be terminal (Closed), got status %d", got.Status)
	}
	if r := loadLockedReserve(db, owner, aid); r.Sign() != 0 {
		t.Fatalf("owner reserve after the full collect: want 0, got %s", r)
	}
}

// ---------------------------------------------------------------------------
// ReclaimIntent — the replay slot and the unbacked refund
// ---------------------------------------------------------------------------

func TestZzmpReclaimRefusesAReplayedOrUnbackedRefund(t *testing.T) {
	c := zzmpClient()

	// (a) An intent whose reclaimed-marker is already set is refused even though its
	//     record still reads Open — the explicit single-claim slot is authoritative.
	h := newSettleHarness(t)
	db := zzmpDB(h)
	id := ids.ID{0x40}
	h.seedSwapIntent(h.caller, h.inAssetID(), 500, harnessBlockTime-1, id)
	recordSeamLock(db, h.inAssetID(), 500)
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(500))
	markSwapIntentReclaimed(db, id, 1)
	if _, err := c.ReclaimIntent(h.state, h.state, h.caller, id); !errors.Is(err, ErrReclaimReplay) {
		t.Fatalf("reclaim of an already-claimed intent: want ErrReclaimReplay, got %v", err)
	}
	if got := h.state.stateDB.GetBalance(h.caller).Uint64(); got != 0 {
		t.Fatalf("a replayed reclaim paid out %d", got)
	}

	// (b) A reclaim the seam pot cannot back refuses rather than minting.
	h2 := newSettleHarness(t)
	id2 := ids.ID{0x41}
	h2.seedSwapIntent(h2.caller, h2.inAssetID(), 700, harnessBlockTime-1, id2)
	// seamReserve is deliberately EMPTY.
	if _, err := c.ReclaimIntent(h2.state, h2.state, h2.caller, id2); !errors.Is(err, ErrNativeSettleUnbacked) {
		t.Fatalf("unbacked reclaim: want ErrNativeSettleUnbacked, got %v", err)
	}
	if got := h2.state.stateDB.GetBalance(h2.caller).Uint64(); got != 0 {
		t.Fatalf("an unbacked reclaim paid out %d", got)
	}

	// (c) An intent with NO deadline can never be reclaimed (settlement is still live),
	//     and an intent with nothing remaining refunds nothing.
	h3 := newSettleHarness(t)
	noDeadline := ids.ID{0x42}
	h3.seedSwapIntent(h3.caller, h3.inAssetID(), 100, 0, noDeadline)
	if _, err := c.ReclaimIntent(h3.state, h3.state, h3.caller, noDeadline); !errors.Is(err, ErrReclaimNoDeadline) {
		t.Fatalf("reclaim with no deadline: want ErrReclaimNoDeadline, got %v", err)
	}
	empty := ids.ID{0x43}
	h3.seedSwapIntent(h3.caller, h3.inAssetID(), 0, harnessBlockTime-1, empty)
	if _, err := c.ReclaimIntent(h3.state, h3.state, h3.caller, empty); !errors.Is(err, ErrReclaimNothingLocked) {
		t.Fatalf("reclaim of a fully-settled intent: want ErrReclaimNothingLocked, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// the two credit helpers, fail-closed without a vault
// ---------------------------------------------------------------------------

// TestZzmpCreditHelpersFailClosedWithoutAnERC20Vault covers the last arm of both credit
// paths: the pot is debited, the asset is an ERC-20, and the StateDB cannot move tokens.
func TestZzmpCreditHelpersFailClosedWithoutAnERC20Vault(t *testing.T) {
	aid := assetID(Currency{Address: zzmpToken})
	to := common.HexToAddress("0x0000000000000000000000000000000000000801")

	db := NewMockStateDB() // no erc20Vault capability
	recordSeamLock(db, aid, 1_000)
	if err := creditSettlementOutput(db, to, aid, 500); !errors.Is(err, ErrNativeERC20Vault) {
		t.Fatalf("erc20 settlement credit with no vault: want ErrNativeERC20Vault, got %v", err)
	}
	recordCommittedLock(db, aid, 1_000)
	if err := creditPositionCollect(db, to, aid, 500); !errors.Is(err, ErrNativeERC20Vault) {
		t.Fatalf("erc20 collect credit with no vault: want ErrNativeERC20Vault, got %v", err)
	}

	// With a real vault, both credits move the token and draw ONLY their own pot.
	v := zzmpNewVaultDB()
	v.mint(zzmpToken, poolManagerAddr9999, 10_000)
	recordSeamLock(v, aid, 1_000)
	recordCommittedLock(v, aid, 1_000)
	if err := creditSettlementOutput(v, to, aid, 400); err != nil {
		t.Fatalf("erc20 settlement credit: %v", err)
	}
	if got := v.TokenBalanceOf(zzmpToken, to); got.Int64() != 400 {
		t.Fatalf("settlement credit delivered %s, want 400", got)
	}
	if got := loadSeamReserve(v, aid).Int64(); got != 600 {
		t.Fatalf("seamReserve after the settlement credit: want 600, got %d", got)
	}
	if got := loadCommittedPositions(v, aid).Int64(); got != 1_000 {
		t.Fatalf("the settlement credit drew down the LP pot: %d", got)
	}
	if err := creditPositionCollect(v, to, aid, 250); err != nil {
		t.Fatalf("erc20 collect credit: %v", err)
	}
	if got := v.TokenBalanceOf(zzmpToken, to).Int64(); got != 650 {
		t.Fatalf("collect credit delivered a total of %d, want 650", got)
	}
	if got := loadCommittedPositions(v, aid).Int64(); got != 750 {
		t.Fatalf("committedPositions after the collect credit: want 750, got %d", got)
	}
	if got := loadSeamReserve(v, aid).Int64(); got != 600 {
		t.Fatalf("the collect credit drew down the SWAP pot: %d", got)
	}
	// Neither credit can exceed its own pot.
	if err := creditSettlementOutput(v, to, aid, 601); !errors.Is(err, ErrNativeSettleUnbacked) {
		t.Fatalf("over-sized settlement credit: want ErrNativeSettleUnbacked, got %v", err)
	}
	if err := creditPositionCollect(v, to, aid, 751); !errors.Is(err, ErrLPCollectUnbacked) {
		t.Fatalf("over-sized collect credit: want ErrLPCollectUnbacked, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// object-id derivations — every field bound, disjoint domains
// ---------------------------------------------------------------------------

// TestZzmpDeriveIntentIDBindsEveryField varies EACH input on its own and demands a
// different id. A field the hash ignored would let two economically different intents
// share a shared-memory key — an object-substitution bypass.
func TestZzmpDeriveIntentIDBindsEveryField(t *testing.T) {
	base := struct {
		networkID uint32
		cChain    ids.ID
		dChain    ids.ID
		account   common.Address
		asset     [32]byte
		amount    uint64
		market    [32]byte
		nonce     uint64
	}{7, ids.ID{0xC1}, ids.ID{0xD1}, common.HexToAddress("0x0000000000000000000000000000000000000901"), [32]byte{0x11}, 1_000, [32]byte{0x22}, 3}

	want := DeriveIntentID(base.networkID, base.cChain, base.dChain, base.account, base.asset, base.amount, base.market, base.nonce)

	// Deterministic: the same inputs always derive byte-identical bytes.
	for i := 0; i < 128; i++ {
		if got := DeriveIntentID(base.networkID, base.cChain, base.dChain, base.account, base.asset, base.amount, base.market, base.nonce); got != want {
			t.Fatalf("DeriveIntentID is not deterministic on iteration %d", i)
		}
	}
	if want == ids.Empty {
		t.Fatal("DeriveIntentID returned the empty id")
	}

	variants := map[string]ids.ID{
		"networkID": DeriveIntentID(base.networkID+1, base.cChain, base.dChain, base.account, base.asset, base.amount, base.market, base.nonce),
		"cChainID":  DeriveIntentID(base.networkID, ids.ID{0xC2}, base.dChain, base.account, base.asset, base.amount, base.market, base.nonce),
		"dChainID":  DeriveIntentID(base.networkID, base.cChain, ids.ID{0xD2}, base.account, base.asset, base.amount, base.market, base.nonce),
		"account":   DeriveIntentID(base.networkID, base.cChain, base.dChain, common.HexToAddress("0x0000000000000000000000000000000000000902"), base.asset, base.amount, base.market, base.nonce),
		"assetIn":   DeriveIntentID(base.networkID, base.cChain, base.dChain, base.account, [32]byte{0x12}, base.amount, base.market, base.nonce),
		"amountIn":  DeriveIntentID(base.networkID, base.cChain, base.dChain, base.account, base.asset, base.amount+1, base.market, base.nonce),
		"marketID":  DeriveIntentID(base.networkID, base.cChain, base.dChain, base.account, base.asset, base.amount, [32]byte{0x23}, base.nonce),
		"nonce":     DeriveIntentID(base.networkID, base.cChain, base.dChain, base.account, base.asset, base.amount, base.market, base.nonce+1),
	}
	seen := map[ids.ID]string{want: "base"}
	for field, got := range variants {
		if got == want {
			t.Fatalf("changing %s did NOT change the intent id — the derivation does not bind that field", field)
		}
		if prev, dup := seen[got]; dup {
			t.Fatalf("varying %s collided with %s", field, prev)
		}
		seen[got] = field
	}
}

func TestZzmpDerivePositionCommitIDBindsEveryFieldAndIsDomainSeparated(t *testing.T) {
	var (
		networkID = uint32(7)
		cChain    = ids.ID{0xC1}
		dChain    = ids.ID{0xD1}
		txID      = ids.ID{0x7A}
		callIndex = uint32(2)
		account   = common.HexToAddress("0x0000000000000000000000000000000000000A01")
		asset     = [32]byte{0x11}
		amount    = uint64(1_000)
		pool      = [32]byte{0x22}
	)
	want := DerivePositionCommitID(networkID, cChain, dChain, txID, callIndex, account, asset, amount, pool)
	for i := 0; i < 128; i++ {
		if got := DerivePositionCommitID(networkID, cChain, dChain, txID, callIndex, account, asset, amount, pool); got != want {
			t.Fatalf("DerivePositionCommitID is not deterministic on iteration %d", i)
		}
	}

	variants := map[string]ids.ID{
		"networkID": DerivePositionCommitID(networkID+1, cChain, dChain, txID, callIndex, account, asset, amount, pool),
		"cChainID":  DerivePositionCommitID(networkID, ids.ID{0xC2}, dChain, txID, callIndex, account, asset, amount, pool),
		"dChainID":  DerivePositionCommitID(networkID, cChain, ids.ID{0xD2}, txID, callIndex, account, asset, amount, pool),
		"txID":      DerivePositionCommitID(networkID, cChain, dChain, ids.ID{0x7B}, callIndex, account, asset, amount, pool),
		"callIndex": DerivePositionCommitID(networkID, cChain, dChain, txID, callIndex+1, account, asset, amount, pool),
		"account":   DerivePositionCommitID(networkID, cChain, dChain, txID, callIndex, common.HexToAddress("0x0000000000000000000000000000000000000A02"), asset, amount, pool),
		"assetIn":   DerivePositionCommitID(networkID, cChain, dChain, txID, callIndex, account, [32]byte{0x12}, amount, pool),
		"amountIn":  DerivePositionCommitID(networkID, cChain, dChain, txID, callIndex, account, asset, amount+1, pool),
		"poolID":    DerivePositionCommitID(networkID, cChain, dChain, txID, callIndex, account, asset, amount, [32]byte{0x23}),
	}
	seen := map[ids.ID]string{want: "base"}
	for field, got := range variants {
		if got == want {
			t.Fatalf("changing %s did NOT change the commit id — the derivation does not bind that field", field)
		}
		if prev, dup := seen[got]; dup {
			t.Fatalf("varying %s collided with %s", field, prev)
		}
		seen[got] = field
	}

	// DOMAIN SEPARATION: the same economic tuple in the two rails yields DIFFERENT ids,
	// so a swap intent object can never be consumed as a position commit or vice versa.
	swap := DeriveIntentID(networkID, cChain, dChain, account, asset, amount, pool, 0)
	commitZero := DerivePositionCommitID(networkID, cChain, dChain, ids.Empty, 0, account, asset, amount, pool)
	if swap == commitZero {
		t.Fatal("the swap-intent and position-commit id domains collide")
	}
}

// ---------------------------------------------------------------------------
// the taker-authenticated MEV floor — exact integers, both directions
// ---------------------------------------------------------------------------

// TestZzmpProceedsPriceFloorIsExactInBothDirections pins the floor's arithmetic against
// an independent rational comparison, at the exact boundary and on either side, for both
// the SELL floor and the BUY ceiling.
func TestZzmpProceedsPriceFloorIsExactInBothDirections(t *testing.T) {
	const limit = 50 * priceScale // 50 quote per base

	// SELL (limitIsUpper == false): realized = out/spent must be >= 50.
	for _, tc := range []struct {
		spent, out uint64
		ok         bool
	}{
		{100, 5_000, true},  // exactly 50 — the boundary is inclusive
		{100, 5_001, true},  // better than the floor
		{100, 4_999, false}, // one unit worse — refused
		{3, 150, true},      // exactly 50 again
		{3, 149, false},
	} {
		err := enforceProceedsPriceFloor(limit, false, tc.spent, tc.out)
		if tc.ok && err != nil {
			t.Fatalf("SELL spent=%d out=%d (realized %.6f) must be accepted, got %v", tc.spent, tc.out, float64(tc.out)/float64(tc.spent), err)
		}
		if !tc.ok && !errors.Is(err, ErrSettlePriceLimit) {
			t.Fatalf("SELL spent=%d out=%d must be refused, got %v", tc.spent, tc.out, err)
		}
	}

	// BUY (limitIsUpper == true): realized = spent/out must be <= 50.
	for _, tc := range []struct {
		spent, out uint64
		ok         bool
	}{
		{5_000, 100, true},  // exactly 50
		{4_999, 100, true},  // cheaper
		{5_001, 100, false}, // one unit dearer — refused
	} {
		err := enforceProceedsPriceFloor(limit, true, tc.spent, tc.out)
		if tc.ok && err != nil {
			t.Fatalf("BUY spent=%d out=%d must be accepted, got %v", tc.spent, tc.out, err)
		}
		if !tc.ok && !errors.Is(err, ErrSettlePriceLimit) {
			t.Fatalf("BUY spent=%d out=%d must be refused, got %v", tc.spent, tc.out, err)
		}
	}

	// EDGE CASES (fail-secure): no limit is unbounded; a limit with an unprovable price
	// is refused rather than credited.
	if err := enforceProceedsPriceFloor(0, false, 0, 0); err != nil {
		t.Fatalf("no limit must be unbounded, got %v", err)
	}
	if err := enforceProceedsPriceFloor(0, true, 1, 1<<62); err != nil {
		t.Fatalf("no limit must be unbounded in either direction, got %v", err)
	}
	for _, tc := range []struct{ spent, out uint64 }{{0, 100}, {100, 0}, {0, 0}} {
		for _, upper := range []bool{true, false} {
			if err := enforceProceedsPriceFloor(limit, upper, tc.spent, tc.out); !errors.Is(err, ErrSettlePriceLimit) {
				t.Fatalf("an unprovable price (spent=%d out=%d, upper=%v) must be refused, got %v", tc.spent, tc.out, upper, err)
			}
		}
	}

	// ABOVE 2^53 (where float64 stops representing consecutive integers): a float64
	// reconstruction silently drops low bits and would ACCEPT a fill one unit BELOW the
	// taker's floor — exactly the MEV the floor exists to refuse. The exact integer
	// comparison must accept the boundary and refuse one unit under it.
	spent := uint64(1) << 54 // > 2^53
	exactOut := 50 * spent   // realized exactly 50, still inside uint64
	if float64(exactOut) == float64(exactOut-1) {
		// The premise of the test: at this magnitude float64 cannot tell the two apart,
		// so only exact integer arithmetic can separate accept from refuse.
		t.Logf("float64 cannot distinguish %d from %d — exact integers are load-bearing here", exactOut, exactOut-1)
	}
	if err := enforceProceedsPriceFloor(limit, false, spent, exactOut); err != nil {
		t.Fatalf("a fill EXACTLY at the taker's floor must be accepted (the limit is inclusive), got %v", err)
	}
	if err := enforceProceedsPriceFloor(limit, false, spent, exactOut-1); !errors.Is(err, ErrSettlePriceLimit) {
		t.Fatalf("a fill ONE UNIT below the floor must be refused (a float64 reconstruction would accept it), got %v", err)
	}
	// The BUY ceiling is inclusive at its own boundary too, at the same magnitude.
	if err := enforceProceedsPriceFloor(limit, true, exactOut, spent); err != nil {
		t.Fatalf("a BUY exactly at the taker's ceiling must be accepted, got %v", err)
	}
	if err := enforceProceedsPriceFloor(limit, true, exactOut+1, spent); !errors.Is(err, ErrSettlePriceLimit) {
		t.Fatalf("a BUY one unit above the ceiling must be refused, got %v", err)
	}
}

// TestZzmpAtomicObjectWireRoundTripsAndRefusesEveryOtherWidth pins the shared-memory
// object codec both ways: an encoded object decodes to exactly its inputs, and ANY other
// width is refused rather than reinterpreted into a credit.
func TestZzmpAtomicObjectWireRoundTripsAndRefusesEveryOtherWidth(t *testing.T) {
	owner := common.HexToAddress("0x0000000000000000000000000000000000000B01")
	asset := [32]byte{0x33, 0x44}

	for _, rail := range []Rail{railSwap, railLP} {
		enc := encodeAtomicObjectSpent(rail, owner, asset, 12_345, 678)
		if len(enc) != exportedOutputSize9999 {
			t.Fatalf("encoded object is %d bytes, want %d", len(enc), exportedOutputSize9999)
		}
		gotRail, gotOwner, gotAsset, gotAmount, gotSpent, ok := decodeAtomicObject(enc)
		if !ok {
			t.Fatal("a freshly encoded object failed to decode")
		}
		if gotRail != rail || gotOwner != owner || gotAsset != asset || gotAmount != 12_345 || gotSpent != 678 {
			t.Fatalf("object did not round-trip: rail=%d owner=%s asset=%x amount=%d spent=%d", gotRail, gotOwner.Hex(), gotAsset, gotAmount, gotSpent)
		}
		// The C->D encoder always writes spent=0 (no match has happened yet).
		if _, _, _, _, spent, _ := decodeAtomicObject(encodeAtomicObject(rail, owner, asset, 1)); spent != 0 {
			t.Fatalf("a C->D object carried a spent witness of %d", spent)
		}
		// Deterministic bytes.
		for i := 0; i < 64; i++ {
			if string(encodeAtomicObjectSpent(rail, owner, asset, 12_345, 678)) != string(enc) {
				t.Fatalf("encodeAtomicObjectSpent is not deterministic on iteration %d", i)
			}
		}
	}
	// Every other width is refused.
	for _, n := range []int{0, 1, exportedOutputSize9999 - 1, exportedOutputSize9999 + 1, 128} {
		if _, _, _, _, _, ok := decodeAtomicObject(make([]byte, n)); ok {
			t.Fatalf("a %d-byte value decoded as a valid object", n)
		}
	}
	if _, _, _, _, _, ok := decodeAtomicObject(nil); ok {
		t.Fatal("a nil value decoded as a valid object")
	}
}
