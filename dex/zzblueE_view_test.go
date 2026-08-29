// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
)

// zzblueE_view_test.go covers the three READ modules a chain exposes — 0x9997
// StateView, 0x9998 Quoter, 0x9996 PositionManager — plus the 0x9999 LP-commit
// kernel they route into (position_commit.go).
//
// The property that holds all of this together: a precompile is handed calldata it
// does not own. geth's CALL path passes `scope.Memory.GetPtr(off, size)`, a two-index
// slice of EVM memory, so cap(input) is the rest of memory and every byte past len is
// attacker-chosen. A missing length check therefore does NOT panic in production — it
// reads bytes the caller planted and answers over input that was never declared. So
// every bound below is asserted on len, and every refusal is re-asserted against an
// input whose spare capacity is poisoned: the verdict has to be identical.

// blueEPoisoned returns b with `spare` bytes of attacker-chosen 0xA5 past its length,
// modelling EVM memory the caller wrote before the CALL. len is unchanged; cap is not.
func blueEPoisoned(b []byte, spare int) []byte {
	full := make([]byte, len(b)+spare)
	for i := range full {
		full[i] = 0xA5
	}
	copy(full, b)
	return full[:len(b)]
}

// blueENoBlockCtx is a harness state that reports NO block context — the shape a host
// hands a precompile outside a block. Every module must refuse rather than proceed
// with a nil context it would later dereference.
type blueENoBlockCtx struct{ *nativeAtomicState }

func (blueENoBlockCtx) GetBlockContext() contract.BlockContext { return nil }

// blueECountingDB counts GetState calls so a handler's real storage-read work can be
// compared against the gas it charged for that work.
type blueECountingDB struct {
	contract.StateDB
	reads *int
}

func (d blueECountingDB) GetState(a common.Address, k common.Hash) common.Hash {
	*d.reads++
	return d.StateDB.GetState(a, k)
}

type blueECountingState struct {
	*nativeAtomicState
	reads *int
}

func (s blueECountingState) GetStateDB() contract.StateDB {
	return blueECountingDB{StateDB: s.nativeAtomicState.GetStateDB(), reads: s.reads}
}

func blueEStateView() *StateViewContract { return &StateViewContract{} }
func blueEQuoter() *QuoterContract       { return &QuoterContract{} }
func blueEPositions() *PositionManagerContract {
	return &PositionManagerContract{}
}

// ---------------------------------------------------------------------------
// Dispatch bounds: shorter than a selector, and no block context.
// ---------------------------------------------------------------------------

// TestBlueEViewModulesRefuseTruncatedSelector sweeps every input shorter than the
// 4-byte selector on all three read modules, and then re-runs each one with the SAME
// declared length over poisoned spare capacity. A handler that reads past len would
// find a real selector in the poison and dispatch; the verdict must not move.
func TestBlueEViewModulesRefuseTruncatedSelector(t *testing.T) {
	h := newSettleHarness(t)
	sv, q, pm := blueEStateView(), blueEQuoter(), blueEPositions()

	mods := []struct {
		name string
		run  func(input []byte, gas uint64) ([]byte, uint64, error)
	}{
		{"stateview", func(in []byte, gas uint64) ([]byte, uint64, error) {
			return sv.Run(h.state, h.caller, stateViewAddr, in, gas, true)
		}},
		{"quoter", func(in []byte, gas uint64) ([]byte, uint64, error) {
			return q.Run(h.state, h.caller, common.HexToAddress(DEXQuoterAddress), in, gas, true)
		}},
		{"positionmanager", func(in []byte, gas uint64) ([]byte, uint64, error) {
			return pm.Run(h.state, h.caller, positionManagerAddr, in, gas, false)
		}},
	}

	// A real selector planted in the poison. If any module reads past len it will
	// dispatch this instead of refusing.
	bait := []byte{byte(SelectorGetPoolId >> 24), byte(SelectorGetPoolId >> 16), byte(SelectorGetPoolId >> 8), byte(SelectorGetPoolId)}

	for _, m := range mods {
		for n := 0; n < 4; n++ {
			clean := bytes.Repeat([]byte{0x11}, n)
			_, gasLeft, err := m.run(clean, 5_000_000)
			if err == nil {
				t.Fatalf("%s accepted a %d-byte input — shorter than its own selector", m.name, n)
			}
			// Refusals here precede any work, so the module hands the gas back; geth
			// then zeroes it because the error is not ErrExecutionReverted. Pin the
			// contract the module actually has: it charges nothing for a refusal it
			// makes before reading state.
			if gasLeft != 5_000_000 {
				t.Fatalf("%s charged %d gas for a pre-dispatch refusal", m.name, 5_000_000-gasLeft)
			}

			poisoned := blueEPoisoned(clean, 64)
			copy(poisoned[:cap(poisoned)][n:], bait) // plant a valid selector past len
			_, _, perr := m.run(poisoned, 5_000_000)
			if perr == nil {
				t.Fatalf("%s accepted a %d-byte input once its spare capacity held a real "+
					"selector — it is dispatching on bytes the caller never declared", m.name, n)
			}
		}
	}
}

// TestBlueEViewModulesRefuseWithoutBlockContext: a host that supplies no block context
// must get a refusal, not a nil dereference. All three read modules check it before
// they decode anything.
func TestBlueEViewModulesRefuseWithoutBlockContext(t *testing.T) {
	h := newSettleHarness(t)
	st := blueENoBlockCtx{h.state}
	if st.GetBlockContext() != nil {
		t.Fatal("the fixture still reports a block context")
	}

	svIn := append(selectorBytes(SelectorGetPoolId), EncodePoolKeyABI(h.key)...)
	if _, gasLeft, err := blueEStateView().Run(st, h.caller, stateViewAddr, svIn, 5_000_000, true); err == nil {
		t.Fatal("stateview ran with no block context")
	} else if gasLeft != 5_000_000 {
		t.Fatalf("stateview charged %d gas before the block-context check", 5_000_000-gasLeft)
	}

	qIn := append(selectorBytes(SelQExactInput), quoteBody(h.key, big.NewInt(1000), true)...)
	if _, gasLeft, err := blueEQuoter().Run(st, h.caller, common.HexToAddress(DEXQuoterAddress), qIn, 5_000_000, true); err == nil {
		t.Fatal("quoter ran with no block context")
	} else if gasLeft != 5_000_000 {
		t.Fatalf("quoter charged %d gas before the block-context check", 5_000_000-gasLeft)
	}

	pmIn := append(selectorBytes(SelectorPMPositionsOf), make([]byte, 32)...)
	if _, gasLeft, err := blueEPositions().Run(st, h.caller, positionManagerAddr, pmIn, 5_000_000, false); err == nil {
		t.Fatal("position manager ran with no block context")
	} else if gasLeft != 5_000_000 {
		t.Fatalf("position manager charged %d gas before the block-context check", 5_000_000-gasLeft)
	}
}

// ---------------------------------------------------------------------------
// 0x9997 StateView — receipt, halt, open orders, position encoding.
// ---------------------------------------------------------------------------

// TestBlueEStateViewReceiptStatusTracksTheConsumedSet: getReceiptStatus is the public
// read of the one-time settlement guard. It must report false for an unseen object and
// true once that exact object is consumed — and it must not report true for a NEIGHBOUR
// id, which would let a keeper believe a settlement already landed and drop it.
func TestBlueEStateViewReceiptStatusTracksTheConsumedSet(t *testing.T) {
	h := newSettleHarness(t)
	sv := blueEStateView()
	db := newPoolStateAdapter(h.state)

	consumed := ids.ID{0x11, 0x22}
	neighbour := ids.ID{0x11, 0x23}

	ask := func(id ids.ID) bool {
		in := append(selectorBytes(SelectorGetReceiptStatus), id[:]...)
		out, _, err := sv.Run(h.state, h.caller, stateViewAddr, in, 5_000_000, true)
		if err != nil {
			t.Fatalf("getReceiptStatus: %v", err)
		}
		if len(out) != 32 {
			t.Fatalf("getReceiptStatus returned %d bytes, want one word", len(out))
		}
		return out[31] == 1
	}

	if ask(consumed) || ask(neighbour) {
		t.Fatal("an unconsumed settlement object already reports consumed")
	}
	markClaimConsumed(db, consumed, 7)
	if !ask(consumed) {
		t.Fatal("a consumed settlement object reports NOT consumed — the replay guard is invisible to the view")
	}
	if ask(neighbour) {
		t.Fatal("consuming one object marked a different id consumed")
	}

	// Short input is refused rather than read out of the poison.
	for n := 0; n < 32; n++ {
		in := append(selectorBytes(SelectorGetReceiptStatus), bytes.Repeat([]byte{0x11}, n)...)
		if _, _, err := sv.Run(h.state, h.caller, stateViewAddr, in, 5_000_000, true); !errors.Is(err, ErrViewBadInput) {
			t.Fatalf("getReceiptStatus with %d argument bytes = %v, want ErrViewBadInput", n, err)
		}
		if _, _, err := sv.Run(h.state, h.caller, stateViewAddr, blueEPoisoned(in, 64), 5_000_000, true); !errors.Is(err, ErrViewBadInput) {
			t.Fatalf("getReceiptStatus with %d argument bytes over poisoned capacity = %v, want ErrViewBadInput", n, err)
		}
	}
}

// TestBlueEStateViewHaltStatusReportsBothScopes: getHaltStatus returns two independent
// words — the GLOBAL halt and whether the named id is halted as a market OR an asset.
// The two must not bleed: halting one market must not make the global word read halted,
// or an operator reading this view cannot tell a single frozen market from a frozen chain.
func TestBlueEStateViewHaltStatusReportsBothScopes(t *testing.T) {
	h := newSettleHarness(t)
	sv := blueEStateView()
	db := newPoolStateAdapter(h.state)

	market := [32]byte{0xA1}
	other := [32]byte{0xB2}

	ask := func(id [32]byte) (global, scoped bool) {
		in := append(selectorBytes(SelectorGetHaltStatus), id[:]...)
		out, _, err := sv.Run(h.state, h.caller, stateViewAddr, in, 5_000_000, true)
		if err != nil {
			t.Fatalf("getHaltStatus: %v", err)
		}
		if len(out) != 64 {
			t.Fatalf("getHaltStatus returned %d bytes, want two words", len(out))
		}
		return out[31] == 1, out[63] == 1
	}

	if g, s := ask(market); g || s {
		t.Fatalf("a fresh chain already reports halted (global=%v scoped=%v)", g, s)
	}

	// Market halt: scoped only.
	SetHaltMarket(db, market, true)
	if g, s := ask(market); g || !s {
		t.Fatalf("after a MARKET halt: global=%v scoped=%v, want false/true", g, s)
	}
	if _, s := ask(other); s {
		t.Fatal("halting one market reported a different id halted")
	}
	SetHaltMarket(db, market, false)

	// Asset halt on the same id: also scoped only, and reached through the second
	// arm of the OR — so both arms are load-bearing.
	SetHaltAsset(db, market, true)
	if g, s := ask(market); g || !s {
		t.Fatalf("after an ASSET halt: global=%v scoped=%v, want false/true", g, s)
	}
	SetHaltAsset(db, market, false)

	// Global halt: reported globally for EVERY id, including ids that were never
	// individually halted.
	SetHaltGlobal(db, true)
	for _, id := range [][32]byte{market, other, {}} {
		if g, _ := ask(id); !g {
			t.Fatalf("the global halt is invisible for id %x", id[:4])
		}
	}
	SetHaltGlobal(db, false)
	if g, _ := ask(market); g {
		t.Fatal("clearing the global halt left it reading halted")
	}

	for n := 0; n < 32; n++ {
		in := append(selectorBytes(SelectorGetHaltStatus), bytes.Repeat([]byte{0x11}, n)...)
		if _, _, err := sv.Run(h.state, h.caller, stateViewAddr, in, 5_000_000, true); !errors.Is(err, ErrViewBadInput) {
			t.Fatalf("getHaltStatus with %d argument bytes = %v, want ErrViewBadInput", n, err)
		}
		if _, _, err := sv.Run(h.state, h.caller, stateViewAddr, blueEPoisoned(in, 64), 5_000_000, true); !errors.Is(err, ErrViewBadInput) {
			t.Fatalf("getHaltStatus over poisoned capacity (%d bytes) = %v, want ErrViewBadInput", n, err)
		}
	}
}

// blueESeedOrder writes a resting order and indexes it under its owner, the shape
// runSettleModifyLiquidity leaves behind.
func blueESeedOrder(db stateKV, owner common.Address, id [32]byte, status OrderStatus, amt *big.Int) {
	storeRestingOrder(db, id, RestingOrder{
		Owner:       owner,
		PoolID:      [32]byte{0xB0},
		Side:        MakerSideBid,
		LockedAsset: [32]byte{0x01},
		LockedAmt:   amt,
		TickLower:   -60,
		TickUpper:   60,
		Status:      status,
	})
	appendOwnerOrder(db, owner, id)
}

// TestBlueEStateViewOpenOrdersReportsOnlyOpen: getOpenOrders enumerates the owner's
// index and returns only the OPEN ones. A closed or cancelled order that still showed
// up would tell a keeper to act on a position that no longer exists.
func TestBlueEStateViewOpenOrdersReportsOnlyOpen(t *testing.T) {
	h := newSettleHarness(t)
	sv := blueEStateView()
	db := newPoolStateAdapter(h.state)
	owner := common.HexToAddress("0x00000000000000000000000000000000000000E1")

	open1 := [32]byte{0x01}
	closing := [32]byte{0x02}
	cancelled := [32]byte{0x03}
	open2 := [32]byte{0x04}
	blueESeedOrder(db, owner, open1, OrderStatusOpen, big.NewInt(1000))
	blueESeedOrder(db, owner, closing, OrderStatusClosing, big.NewInt(2000))
	blueESeedOrder(db, owner, cancelled, OrderStatusCancelled, big.NewInt(3000))
	blueESeedOrder(db, owner, open2, OrderStatusOpen, big.NewInt(4000))

	in := append(selectorBytes(SelectorGetOpenOrders), common.LeftPadBytes(owner.Bytes(), 32)...)
	out, _, err := sv.Run(h.state, h.caller, stateViewAddr, in, 5_000_000, true)
	if err != nil {
		t.Fatalf("getOpenOrders: %v", err)
	}
	// ABI dynamic array: offset word, length word, then the elements.
	if len(out) < 64 {
		t.Fatalf("getOpenOrders returned %d bytes", len(out))
	}
	n := new(big.Int).SetBytes(out[32:64]).Uint64()
	if n != 2 {
		t.Fatalf("getOpenOrders returned %d ids, want the 2 OPEN ones out of 4", n)
	}
	var got [][32]byte
	for i := uint64(0); i < n; i++ {
		var id [32]byte
		copy(id[:], out[64+32*i:64+32*(i+1)])
		got = append(got, id)
	}
	if got[0] != open1 || got[1] != open2 {
		t.Fatalf("getOpenOrders returned %x, want the two OPEN ids in insertion order", got)
	}

	// Enumeration order is the index's insertion order, not a map's. Repeat it: a
	// map-ordered enumeration would eventually disagree with itself, and two
	// validators would return different bytes for the same state.
	for i := 0; i < 32; i++ {
		again, _, err := sv.Run(h.state, h.caller, stateViewAddr, in, 5_000_000, true)
		if err != nil {
			t.Fatalf("getOpenOrders repeat %d: %v", i, err)
		}
		if !bytes.Equal(again, out) {
			t.Fatalf("getOpenOrders is not deterministic — repeat %d returned different bytes", i)
		}
	}

	// An owner with nothing gets an empty array, not an error.
	empty := append(selectorBytes(SelectorGetOpenOrders), common.LeftPadBytes(common.HexToAddress("0xdead").Bytes(), 32)...)
	eout, _, err := sv.Run(h.state, h.caller, stateViewAddr, empty, 5_000_000, true)
	if err != nil {
		t.Fatalf("getOpenOrders for an unknown owner: %v", err)
	}
	if new(big.Int).SetBytes(eout[32:64]).Sign() != 0 {
		t.Fatal("an owner with no orders got a non-empty array")
	}

	for n := 0; n < 32; n++ {
		short := append(selectorBytes(SelectorGetOpenOrders), bytes.Repeat([]byte{0x11}, n)...)
		if _, _, err := sv.Run(h.state, h.caller, stateViewAddr, short, 5_000_000, true); !errors.Is(err, ErrViewBadInput) {
			t.Fatalf("getOpenOrders with %d argument bytes = %v, want ErrViewBadInput", n, err)
		}
		if _, _, err := sv.Run(h.state, h.caller, stateViewAddr, blueEPoisoned(short, 64), 5_000_000, true); !errors.Is(err, ErrViewBadInput) {
			t.Fatalf("getOpenOrders over poisoned capacity (%d bytes) = %v, want ErrViewBadInput", n, err)
		}
	}
}

// TestBlueEOpenOrdersDoesTheWorkBeforeItChargesForIt is a DEFECT WITNESS, not a
// property test.
//
// getOpenOrders charges GasStateView per indexed order — but it enumerates the index
// and loads every order FIRST, and only then compares the total against suppliedGas.
// So a caller who supplies the base fee alone still makes the node perform a storage
// read for every order the owner holds. The refusal costs the caller its whole
// (small) budget while the node's work scales with a number the caller does not pay
// for. settle_maker.go already carries a comment about closing exactly this class on
// the WRITE path ("a compute-griefing vector"); the read path still has it.
//
// This test pins the current behaviour — reads happen, then the refusal — so the fix
// (hoist the count read and the gas check above the loop; the returned error and the
// zeroed gas are unchanged) is a visible, deliberate change rather than a silent one.
func TestBlueEOpenOrdersDoesTheWorkBeforeItChargesForIt(t *testing.T) {
	h := newSettleHarness(t)
	sv := blueEStateView()
	db := newPoolStateAdapter(h.state)
	owner := common.HexToAddress("0x00000000000000000000000000000000000000E2")

	const orders = 24
	for i := 0; i < orders; i++ {
		var id [32]byte
		id[0], id[1] = 0xE2, byte(i)
		blueESeedOrder(db, owner, id, OrderStatusOpen, big.NewInt(int64(i+1)))
	}

	in := append(selectorBytes(SelectorGetOpenOrders), common.LeftPadBytes(owner.Bytes(), 32)...)

	reads := 0
	counting := blueECountingState{nativeAtomicState: h.state, reads: &reads}
	// Supply exactly the base fee: strictly less than GasStateView*(1+orders), so the
	// call MUST refuse.
	_, gasLeft, err := sv.Run(counting, h.caller, stateViewAddr, in, GasStateView, true)
	if err == nil {
		t.Fatalf("getOpenOrders for %d orders succeeded on the base fee alone", orders)
	}
	if gasLeft != 0 {
		t.Fatalf("the out-of-gas refusal returned %d gas; it must consume the budget", gasLeft)
	}
	if reads <= orders {
		t.Fatalf("the refusal performed %d storage reads for %d orders; expected the "+
			"enumeration to have already run (this test is the witness for that defect "+
			"— if the charge now precedes the work, reads should be ~1 and this "+
			"assertion is the thing to update)", reads, orders)
	}

	// And the same call WITH enough gas succeeds and charges per order, so the fee
	// schedule itself is right — only its position relative to the work is wrong.
	want := GasStateView * (1 + orders)
	_, gasLeft, err = sv.Run(h.state, h.caller, stateViewAddr, in, want, true)
	if err != nil {
		t.Fatalf("getOpenOrders at exactly the per-order fee: %v", err)
	}
	if gasLeft != 0 {
		t.Fatalf("gasLeft = %d at exactly the computed fee, want 0", gasLeft)
	}
	// One gas short of the schedule is refused — the boundary is inclusive on the
	// paying side and exclusive one wei of gas below it.
	if _, _, err := sv.Run(h.state, h.caller, stateViewAddr, in, want-1, true); err == nil {
		t.Fatal("one gas below the per-order schedule was accepted")
	}
}

// TestBlueEStateViewPositionEncodesTheLockedAmount: getPosition packs the resting
// order into six words. The locked amount lands in word 3; an order with no amount
// leaves it zero rather than reading a neighbouring field.
func TestBlueEStateViewPositionEncodesTheLockedAmount(t *testing.T) {
	h := newSettleHarness(t)
	sv := blueEStateView()
	db := newPoolStateAdapter(h.state)
	owner := common.HexToAddress("0x00000000000000000000000000000000000000E3")

	funded := [32]byte{0xF1}
	blueESeedOrder(db, owner, funded, OrderStatusOpen, big.NewInt(0x1234567890))

	read := func(id [32]byte) []byte {
		in := append(selectorBytes(SelectorGetPosition), id[:]...)
		out, _, err := sv.Run(h.state, h.caller, stateViewAddr, in, 5_000_000, true)
		if err != nil {
			t.Fatalf("getPosition: %v", err)
		}
		return out
	}

	out := read(funded)
	if !bytes.Equal(out[0:32], funded[:]) {
		t.Fatalf("word 0 is not the order id: %x", out[0:32])
	}
	if common.BytesToAddress(out[44:64]) != owner {
		t.Fatalf("word 1 is not the owner: %x", out[32:64])
	}
	if got := new(big.Int).SetBytes(out[96:128]); got.Cmp(big.NewInt(0x1234567890)) != 0 {
		t.Fatalf("word 3 (locked amount) = %s, want 0x1234567890", got)
	}

	// An unknown order id reads back as the zero record, and in particular the amount
	// word stays zero — a nil LockedAmt must not leave the previous caller's bytes or
	// spill an adjacent field into the amount slot.
	unknown := read([32]byte{0xFE})
	if !bytes.Equal(unknown[96:128], make([]byte, 32)) {
		t.Fatalf("an unknown order reported a locked amount: %x", unknown[96:128])
	}
	if unknown[63] != 0 {
		t.Fatalf("an unknown order reported an owner: %x", unknown[32:64])
	}
}

// ---------------------------------------------------------------------------
// 0x9998 Quoter — the degenerate-price arm.
// ---------------------------------------------------------------------------

// TestBlueEQuoterZeroPriceQuotesZeroInBothDirections: the token1->token0 leg divides
// by sqrtP^2, and a division by zero from inside a precompile is a validator halt. The
// single guard at the top of spotOutput is what stands between an unpriced market and
// that halt, so it has to hold for BOTH directions — a guard that only covered the
// multiply direction would leave the divide direction live.
//
// (The second `sq.Sign() == 0` check further down that same function is unreachable:
// sq is SqrtPriceX96 squared, and the only value whose square is zero is zero, which
// the first guard already returned on.)
func TestBlueEQuoterZeroPriceQuotesZeroInBothDirections(t *testing.T) {
	for _, rec := range []MarketRecord{{SqrtPriceX96: big.NewInt(0)}, {SqrtPriceX96: nil}} {
		for _, zeroForOne := range []bool{true, false} {
			got := spotOutput(rec, big.NewInt(1_000_000), zeroForOne)
			if got == nil || got.Sign() != 0 {
				t.Fatalf("an unpriced market quoted %v (zeroForOne=%v), want zero", got, zeroForOne)
			}
		}
	}
	// A real price quotes a real amount in both directions, so the zero arms are not
	// masking a dead happy path.
	priced := MarketRecord{SqrtPriceX96: new(big.Int).Lsh(big.NewInt(1), 96)}
	for _, zeroForOne := range []bool{true, false} {
		if got := spotOutput(priced, big.NewInt(1_000_000), zeroForOne); got.Sign() <= 0 {
			t.Fatalf("a unit sqrt price quoted %s (zeroForOne=%v), want a positive amount", got, zeroForOne)
		}
	}
}

// ---------------------------------------------------------------------------
// 0x9996 PositionManager — argument bounds on the read arms and the zero delta.
// ---------------------------------------------------------------------------

// TestBlueEPositionManagerReadArmsRefuseShortArgs sweeps every argument length below
// one word on positionsOf and positionInfo, clean and poisoned. positionInfo also has
// a gas floor it must charge before it decodes.
func TestBlueEPositionManagerReadArmsRefuseShortArgs(t *testing.T) {
	h := newSettleHarness(t)
	pm := blueEPositions()

	for _, arm := range []struct {
		name string
		sel  uint32
	}{{"positionsOf", SelectorPMPositionsOf}, {"positionInfo", SelectorPMPositionInfo}} {
		for n := 0; n < 32; n++ {
			in := append(selectorBytes(arm.sel), bytes.Repeat([]byte{0x11}, n)...)
			if _, _, err := pm.Run(h.state, h.caller, positionManagerAddr, in, 5_000_000, false); !errors.Is(err, ErrPMBadInput) {
				t.Fatalf("%s with %d argument bytes = %v, want ErrPMBadInput", arm.name, n, err)
			}
			if _, _, err := pm.Run(h.state, h.caller, positionManagerAddr, blueEPoisoned(in, 64), 5_000_000, false); !errors.Is(err, ErrPMBadInput) {
				t.Fatalf("%s with %d argument bytes over poisoned capacity = %v, want ErrPMBadInput", arm.name, n, err)
			}
		}
		// One full word is accepted — the sweep above is bounding a real edge, not
		// refusing everything.
		in := append(selectorBytes(arm.sel), make([]byte, 32)...)
		if _, _, err := pm.Run(h.state, h.caller, positionManagerAddr, in, 5_000_000, false); err != nil {
			t.Fatalf("%s with a full word: %v", arm.name, err)
		}
	}

	// positionInfo refuses below its own read fee, and consumes the budget when it does.
	in := append(selectorBytes(SelectorPMPositionInfo), make([]byte, 32)...)
	if _, gasLeft, err := pm.Run(h.state, h.caller, positionManagerAddr, in, GasPositionRead-1, false); err == nil {
		t.Fatal("positionInfo ran below its read fee")
	} else if gasLeft != 0 {
		t.Fatalf("the out-of-gas refusal returned %d gas", gasLeft)
	}
}

// blueEPMLifecycle builds the 320-byte 0x9996 lifecycle calldata.
func blueEPMLifecycle(key PoolKey, lower, upper int32, delta *big.Int, salt byte, side MakerSide) []byte {
	out := make([]byte, 0, 320)
	out = append(out, EncodePoolKeyABI(key)...)
	out = append(out, encodeInt24Word(int24(lower))...)
	out = append(out, encodeInt24Word(int24(upper))...)
	out = append(out, encodeSigned256(delta)...)
	s := make([]byte, 32)
	s[31] = salt
	out = append(out, s...)
	sideWord := make([]byte, 32)
	sideWord[31] = byte(side)
	return append(out, sideWord...)
}

// TestBlueEPositionManagerRefusesZeroDelta: every lifecycle op coerces the delta's
// SIGN but never its magnitude, so a zero delta would route a no-op into the 0x9999
// kernel and consume the custody guard for nothing. It is refused at the adapter.
func TestBlueEPositionManagerRefusesZeroDelta(t *testing.T) {
	h := newSettleHarness(t)
	pm := blueEPositions()

	body := blueEPMLifecycle(h.key, -60, 60, big.NewInt(0), 0x01, MakerSideBid)
	for _, sel := range []uint32{
		SelectorPMMint, SelectorPMOpenPosition, SelectorPMIncreaseLiquidity, SelectorPMPlaceLimit,
		SelectorPMDecreaseLiquidity, SelectorPMBurn, SelectorPMClosePosition, SelectorPMCancelLimit,
		SelectorPMModifyPosition,
	} {
		in := append(selectorBytes(sel), body...)
		_, _, err := pm.Run(h.state, h.caller, positionManagerAddr, in, 5_000_000, false)
		if !errors.Is(err, ErrPMZeroDelta) {
			t.Fatalf("selector %08x with a zero delta = %v, want ErrPMZeroDelta", sel, err)
		}
		if _, _, perr := pm.Run(h.state, h.caller, positionManagerAddr, blueEPoisoned(in, 96), 5_000_000, false); !errors.Is(perr, ErrPMZeroDelta) {
			t.Fatalf("selector %08x with a zero delta over poisoned capacity = %v, want ErrPMZeroDelta", sel, perr)
		}
	}

	// Short lifecycle calldata is refused across the whole span below 320 bytes.
	for _, n := range []int{0, 1, 159, 160, 287, 288, 319} {
		in := append(selectorBytes(SelectorPMMint), bytes.Repeat([]byte{0x22}, n)...)
		if _, _, err := pm.Run(h.state, h.caller, positionManagerAddr, in, 5_000_000, false); !errors.Is(err, ErrPMBadInput) {
			t.Fatalf("lifecycle with %d argument bytes = %v, want ErrPMBadInput", n, err)
		}
		if _, _, err := pm.Run(h.state, h.caller, positionManagerAddr, blueEPoisoned(in, 512), 5_000_000, false); !errors.Is(err, ErrPMBadInput) {
			t.Fatalf("lifecycle with %d argument bytes over poisoned capacity = %v, want ErrPMBadInput", n, err)
		}
	}
}

// ---------------------------------------------------------------------------
// 0x9999 LP-commit kernel (position_commit.go).
// ---------------------------------------------------------------------------

// blueEModifyLiquidityCalldata builds the V4 modifyLiquidity argument buffer.
func blueEModifyLiquidityCalldata(key PoolKey, lower, upper int32, delta *big.Int, salt byte) []byte {
	out := make([]byte, 0, 288)
	out = append(out, EncodePoolKeyABI(key)...)
	out = append(out, encodeInt24Word(int24(lower))...)
	out = append(out, encodeInt24Word(int24(upper))...)
	out = append(out, encodeSigned256(delta)...)
	s := make([]byte, 32)
	s[31] = salt
	return append(out, s...)
}

// TestBlueEModifyLiquidityArgumentGate walks every refusal the LP-commit kernel makes
// before it touches the custody guard: short calldata, a zero delta, a delta wider than
// a word, and an inverted or out-of-domain tick range. Each must refuse with its OWN
// error — a caller distinguishes "you sent nothing" from "your range is upside down",
// and collapsing them would hide a decode bug behind a range complaint.
func TestBlueEModifyLiquidityArgumentGate(t *testing.T) {
	h := newSettleHarness(t)
	sel := SelectorModifyLiquidity

	run := func(body []byte) error {
		_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(sel, body), 5_000_000, false)
		return err
	}

	// Short: the decoder's own refusal, surfaced through the kernel.
	for _, n := range []int{0, 1, 159, 160, 287} {
		if err := run(bytes.Repeat([]byte{0x33}, n)); err == nil {
			t.Fatalf("modifyLiquidity accepted %d argument bytes", n)
		}
		if err := run(blueEPoisoned(bytes.Repeat([]byte{0x33}, n), 512)); err == nil {
			t.Fatalf("modifyLiquidity accepted %d argument bytes over poisoned capacity — it is "+
				"decoding bytes past the declared input", n)
		}
	}

	// Zero delta.
	if err := run(blueEModifyLiquidityCalldata(h.key, -60, 60, big.NewInt(0), 1)); !errors.Is(err, ErrMakerZeroDelta) {
		t.Fatalf("zero delta = %v, want ErrMakerZeroDelta", err)
	}

	// The amount bound the kernel leans on: |delta| must fit one word. A 256-bit word
	// is the largest thing calldata can carry, so the bound is only reachable through
	// isWord itself — assert it there, at both sides of the edge, since the kernel's
	// ErrMakerAmountRange arm is exactly this predicate negated.
	maxWord := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	if !isWord(maxWord) {
		t.Fatal("isWord refused the largest 256-bit magnitude; the kernel would reject every maximal delta")
	}
	if isWord(new(big.Int).Add(maxWord, big.NewInt(1))) {
		t.Fatal("isWord accepted a 257-bit magnitude; the kernel's amount bound is not a bound")
	}

	// Tick range: inverted, equal, and both domain edges. Sweep rather than
	// point-check — an off-by-one here admits a degenerate range that the D book
	// cannot represent.
	for _, tc := range []struct {
		name         string
		lower, upper int32
	}{
		{"inverted", 60, -60},
		{"equal", 60, 60},
		{"lower below MinTick", MinTick - 1, 60},
		{"upper above MaxTick", -60, MaxTick + 1},
		{"both outside", MinTick - 1, MaxTick + 1},
	} {
		err := run(blueEModifyLiquidityCalldata(h.key, tc.lower, tc.upper, big.NewInt(1000), 1))
		if !errors.Is(err, ErrMakerBadTickRange) {
			t.Fatalf("%s tick range (%d,%d) = %v, want ErrMakerBadTickRange", tc.name, tc.lower, tc.upper, err)
		}
	}
	// The inclusive edges themselves are ACCEPTED — the refusals above are bounding a
	// real domain, not swallowing the whole of it. (It gets past the range gate; what
	// it fails on next is a different, later check.)
	if err := run(blueEModifyLiquidityCalldata(h.key, MinTick, MaxTick, big.NewInt(1000), 1)); errors.Is(err, ErrMakerBadTickRange) {
		t.Fatal("the inclusive tick bounds MinTick/MaxTick were refused as out of range")
	}
}

// TestBlueEModifyLiquidityRequiresTheAtomicSeam: the LP rail moves value ONLY as
// cross-chain atomic objects. A host with no atomic capability must be refused — a
// C-side-only lock would take the LP's funds with no D-side claim to return them.
func TestBlueEModifyLiquidityRequiresTheAtomicSeam(t *testing.T) {
	h := newSettleHarness(t)
	plain := &blueEPlainState{inner: h.state}
	if _, ok := interface{}(plain).(contract.AtomicState); ok {
		t.Fatal("the fixture still advertises the atomic capability")
	}

	body := blueEModifyLiquidityCalldata(h.key, -60, 60, big.NewInt(1000), 1)
	_, _, err := h.c.Run(plain, h.caller, poolManagerAddr9999, prependSelector(SelectorModifyLiquidity, body), 5_000_000, false)
	if !errors.Is(err, ErrLPNoAtomicState) {
		t.Fatalf("modifyLiquidity without the atomic seam = %v, want ErrLPNoAtomicState", err)
	}

	// collectPosition is the other half of the rail and must refuse identically —
	// otherwise a chain could credit an LP out of the pot with no object to consume.
	claim := make([]byte, 128)
	_, _, err = h.c.Run(plain, h.caller, poolManagerAddr9999, prependSelector(SelectorCollectPosition, claim), 5_000_000, false)
	if !errors.Is(err, ErrLPNoAtomicState) {
		t.Fatalf("collectPosition without the atomic seam = %v, want ErrLPNoAtomicState", err)
	}
}

// blueEPlainState is an AccessibleState with NO cross-chain atomic capability — a
// single-chain dev host. It must be refused by both LP rail legs.
type blueEPlainState struct{ inner *nativeAtomicState }

func (p *blueEPlainState) GetStateDB() contract.StateDB { return p.inner.GetStateDB() }
func (p *blueEPlainState) GetBlockContext() contract.BlockContext {
	return p.inner.GetBlockContext()
}
func (p *blueEPlainState) GetConsensusContext() context.Context { return p.inner.GetConsensusContext() }
func (p *blueEPlainState) GetChainConfig() precompileconfig.ChainConfig {
	return p.inner.GetChainConfig()
}
func (p *blueEPlainState) GetPrecompileEnv() contract.PrecompileEnvironment {
	return p.inner.GetPrecompileEnv()
}

var _ contract.AccessibleState = (*blueEPlainState)(nil)

// TestBlueECollectPositionRefusesAReentrantClaim: the collect path takes the ONE
// global custody guard before it credits, because the credit's ERC-20 transfer can
// hand control to a malicious token. With the guard already set — the state a
// re-entrant call sees — the claim must be refused outright rather than proceeding to
// a second read-modify-write of the same pot.
func TestBlueECollectPositionRefusesAReentrantClaim(t *testing.T) {
	h := newSettleHarness(t)
	db := newPoolStateAdapter(h.state)

	if !enterCustodyKV(db) {
		t.Fatal("the custody guard was already held on a fresh harness")
	}
	defer exitCustodyKV(db)

	claim := make([]byte, 128)
	claim[31] = 0x01                                    // outputID
	new(big.Int).SetUint64(500).FillBytes(claim[64:96]) // amount
	claim[127] = 0x02                                   // positionID
	_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorCollectPosition, claim), 5_000_000, false)
	if !errors.Is(err, ErrCustodyReentrant) {
		t.Fatalf("a collect made while the custody guard is held = %v, want ErrCustodyReentrant", err)
	}
}

// TestBlueECollectPositionAmountDomain: the claimed amount is a uint256 word but the
// pot is uint64. Anything that does not fit, and anything non-positive, is refused —
// a silent truncation would credit the low 64 bits of an arbitrarily large claim.
func TestBlueECollectPositionAmountDomain(t *testing.T) {
	h := newSettleHarness(t)

	build := func(amount *big.Int) []byte {
		c := make([]byte, 128)
		c[31] = 0x01
		amount.FillBytes(c[64:96])
		c[127] = 0x02
		return c
	}

	for _, tc := range []struct {
		name   string
		amount *big.Int
	}{
		{"zero", big.NewInt(0)},
		{"one past uint64", new(big.Int).Lsh(big.NewInt(1), 64)},
		{"a full word", new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))},
	} {
		_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
			prependSelector(SelectorCollectPosition, build(tc.amount)), 5_000_000, false)
		if !errors.Is(err, ErrLPCollectBadAmount) {
			t.Fatalf("collect amount %s (%s) = %v, want ErrLPCollectBadAmount", tc.name, tc.amount, err)
		}
	}

	// The top of the uint64 domain is INSIDE the accepted set: the refusals above are
	// a real boundary, not a blanket. It fails later (no such object), never on range.
	max64 := new(big.Int).SetUint64(^uint64(0))
	_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorCollectPosition, build(max64)), 5_000_000, false)
	if errors.Is(err, ErrLPCollectBadAmount) {
		t.Fatal("the largest representable uint64 amount was refused as out of range")
	}

	// Short claim calldata across the whole span below the fixed 128-byte layout.
	for _, n := range []int{0, 1, 31, 32, 95, 96, 127} {
		_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
			prependSelector(SelectorCollectPosition, bytes.Repeat([]byte{0x44}, n)), 5_000_000, false)
		if !errors.Is(err, ErrLPBadCollectInput) {
			t.Fatalf("collect with %d argument bytes = %v, want ErrLPBadCollectInput", n, err)
		}
		poisoned := blueEPoisoned(bytes.Repeat([]byte{0x44}, n), 256)
		_, _, err = h.c.Run(h.state, h.caller, poolManagerAddr9999,
			prependSelector(SelectorCollectPosition, poisoned), 5_000_000, false)
		if !errors.Is(err, ErrLPBadCollectInput) {
			t.Fatalf("collect with %d argument bytes over poisoned capacity = %v, want ErrLPBadCollectInput", n, err)
		}
	}
}

// blueEActivateMarket registers the harness pool so the LP kernel gets past its
// market gate and reaches the commit/withdraw legs under test.
func blueEActivateMarket(h *settleHarness) [32]byte {
	poolID := h.key.ID()
	storeMarket(newPoolStateAdapter(h.state), poolID, MarketRecord{
		Status:       MarketStatusActive,
		SqrtPriceX96: new(big.Int).Lsh(big.NewInt(1), 96),
		Tick:         0,
		Currency0:    h.key.Currency0.Address,
		Currency1:    h.key.Currency1.Address,
		Fee:          h.key.Fee,
		TickSpacing:  int24(h.key.TickSpacing),
		Creator:      h.caller,
	})
	return poolID
}

// blueECommitCalldata is the V4 modifyLiquidity argument buffer with the maker
// envelope the kernel reads the side from.
func blueECommitCalldata(h *settleHarness, lower, upper int24, delta *big.Int, salt [32]byte, side MakerSide) []byte {
	hookData := []byte{makerEnvelopeTag[0], makerEnvelopeTag[1], makerEnvelopeTag[2], makerEnvelopeTag[3], byte(side)}
	return buildModifyLiquidityArgs(h.key, lower, upper, delta, salt, hookData)
}

// TestBlueECommitRefusesAHaltedAsset: halting an asset must stop NEW commitments while
// leaving withdrawals open — funds already committed have to stay releasable, or a halt
// becomes a confiscation. Both halves are asserted, and the halt is asserted to be
// scoped: halting the OTHER side of the same pool must not block this side.
func TestBlueECommitRefusesAHaltedAsset(t *testing.T) {
	h := newSettleHarness(t)
	blueEActivateMarket(h)
	db := newPoolStateAdapter(h.state)
	h.fundCallerNative(10_000)

	bidAsset := lockedAssetForSide(h.key, MakerSideBid)
	askAsset := lockedAssetForSide(h.key, MakerSideAsk)
	if bidAsset == askAsset {
		t.Fatal("the harness pool's two sides share one asset id; the scoping assertion below is vacuous")
	}
	salt := [32]byte{0x51}

	commit := func() error {
		_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
			prependSelector(SelectorModifyLiquidity, blueECommitCalldata(h, -60, 60, big.NewInt(1000), salt, MakerSideBid)),
			5_000_000, false)
		return err
	}

	// Halting the OTHER side leaves this commit alone.
	SetHaltAsset(db, askAsset, true)
	if err := commit(); errors.Is(err, ErrAssetHalted) {
		t.Fatal("halting the ask asset blocked a bid-side commit — the halt is not scoped to the asset")
	}
	SetHaltAsset(db, askAsset, false)

	// Halting THIS side refuses the commit.
	SetHaltAsset(db, bidAsset, true)
	if err := commit(); !errors.Is(err, ErrAssetHalted) {
		t.Fatalf("commit against a halted asset = %v, want ErrAssetHalted", err)
	}

	// The custody guard is not left held by the refusal: a second call reaches the
	// same halt refusal rather than ErrCustodyReentrant. A refusal that leaked the
	// guard would wedge the WHOLE 0x9999 custody surface for the rest of the block.
	if err := commit(); !errors.Is(err, ErrAssetHalted) {
		t.Fatalf("the second commit after a halted refusal = %v — the first refusal leaked the custody guard", err)
	}

	// And a WITHDRAW of an existing position is still permitted while the asset is
	// halted: the funds stay releasable.
	orderID := MakerOrderID(h.caller, h.key.ID(), salt, -60, 60)
	storeRestingOrder(db, orderID, RestingOrder{
		Owner: h.caller, PoolID: h.key.ID(), Side: MakerSideBid, LockedAsset: bidAsset,
		LockedAmt: big.NewInt(1000), TickLower: -60, TickUpper: 60, Status: OrderStatusOpen,
	})
	_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorModifyLiquidity, blueECommitCalldata(h, -60, 60, big.NewInt(-1000), salt, MakerSideBid)),
		5_000_000, false)
	if err != nil {
		t.Fatalf("withdraw while the asset is halted = %v, want it permitted so funds stay releasable", err)
	}
	if loadRestingOrder(db, orderID).Status != OrderStatusClosing {
		t.Fatal("the withdraw did not mark the position closing")
	}
}

// TestBlueECommitRefusesADeltaWiderThanThePot: the committedPositions pot is uint64.
// A signed-256 delta that survives the word bound but does not fit uint64 must be
// refused, never truncated — a truncation would commit the low 64 bits of an
// arbitrarily large number and leave the record disagreeing with the money.
func TestBlueECommitRefusesADeltaWiderThanThePot(t *testing.T) {
	h := newSettleHarness(t)
	blueEActivateMarket(h)
	h.fundCallerNative(1_000_000)

	for _, tc := range []struct {
		name  string
		delta *big.Int
	}{
		{"one past uint64", new(big.Int).Lsh(big.NewInt(1), 64)},
		{"2^128", new(big.Int).Lsh(big.NewInt(1), 128)},
		{"the largest positive signed word", new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1))},
	} {
		_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
			prependSelector(SelectorModifyLiquidity, blueECommitCalldata(h, -60, 60, tc.delta, [32]byte{0x52}, MakerSideBid)),
			5_000_000, false)
		if !errors.Is(err, ErrMakerAmountRange) {
			t.Fatalf("commit of %s (%s) = %v, want ErrMakerAmountRange", tc.name, tc.delta, err)
		}
	}

	// The top of the uint64 domain is inside the accepted set — the refusals above are
	// a real edge, not a blanket refusal of large numbers. It fails on funding, which
	// is a different, later check.
	max64 := new(big.Int).SetUint64(^uint64(0))
	_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorModifyLiquidity, blueECommitCalldata(h, -60, 60, max64, [32]byte{0x53}, MakerSideBid)),
		5_000_000, false)
	if errors.Is(err, ErrMakerAmountRange) {
		t.Fatal("the largest representable uint64 delta was refused as out of range")
	}
}

// TestBlueEWithdrawChecksTheRecordedOwnerAndTheClosedState covers the two guards the
// withdraw leg applies AFTER it has found a record.
//
// The order id is derived from the caller, so in normal operation the recorded owner
// always equals the caller and the `order.Owner != caller` check is defence in depth.
// It is exactly the kind of check that rots unnoticed, so it is exercised the only way
// it can be: by seeding a record whose owner field disagrees with the derivation. If a
// future change ever makes the id derivable without the owner, this guard is the thing
// standing between one LP and another LP's position — it has to work.
func TestBlueEWithdrawChecksTheRecordedOwnerAndTheClosedState(t *testing.T) {
	h := newSettleHarness(t)
	blueEActivateMarket(h)
	db := newPoolStateAdapter(h.state)
	poolID := h.key.ID()
	other := common.HexToAddress("0x00000000000000000000000000000000000000FF")

	withdraw := func(salt [32]byte) error {
		_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
			prependSelector(SelectorModifyLiquidity, blueECommitCalldata(h, -60, 60, big.NewInt(-1000), salt, MakerSideBid)),
			5_000_000, false)
		return err
	}

	// No record at all: refused as not-owner (there is nothing of the caller's here).
	if err := withdraw([32]byte{0x61}); !errors.Is(err, ErrMakerNotOwner) {
		t.Fatalf("withdraw with no record = %v, want ErrMakerNotOwner", err)
	}

	// A record at the caller's derived id whose OWNER is somebody else.
	foreign := [32]byte{0x62}
	fid := MakerOrderID(h.caller, poolID, foreign, -60, 60)
	storeRestingOrder(db, fid, RestingOrder{
		Owner: other, PoolID: poolID, Side: MakerSideBid, LockedAsset: lockedAssetForSide(h.key, MakerSideBid),
		LockedAmt: big.NewInt(1000), TickLower: -60, TickUpper: 60, Status: OrderStatusOpen,
	})
	if err := withdraw(foreign); !errors.Is(err, ErrMakerNotOwner) {
		t.Fatalf("withdraw of a record owned by another address = %v, want ErrMakerNotOwner", err)
	}
	if got := loadRestingOrder(db, fid); got.Status != OrderStatusOpen || got.Owner != other {
		t.Fatalf("the refused withdraw mutated the record: %+v", got)
	}

	// A record that is already CANCELLED is closed for good — withdrawing again must
	// not re-arm it, or the same position could be released twice.
	dead := [32]byte{0x63}
	did := MakerOrderID(h.caller, poolID, dead, -60, 60)
	storeRestingOrder(db, did, RestingOrder{
		Owner: h.caller, PoolID: poolID, Side: MakerSideBid, LockedAsset: lockedAssetForSide(h.key, MakerSideBid),
		LockedAmt: big.NewInt(1000), TickLower: -60, TickUpper: 60, Status: OrderStatusCancelled,
	})
	if err := withdraw(dead); !errors.Is(err, ErrMakerAlreadyClosed) {
		t.Fatalf("withdraw of a cancelled position = %v, want ErrMakerAlreadyClosed", err)
	}
	if loadRestingOrder(db, did).Status != OrderStatusCancelled {
		t.Fatal("the refused withdraw moved a cancelled position out of the cancelled state")
	}

	// An OPEN record the caller really owns goes to CLOSING, and a second withdraw is
	// idempotent rather than a second release: Closing is not Cancelled, so it passes
	// the guards and re-marks the same state.
	live := [32]byte{0x64}
	lid := MakerOrderID(h.caller, poolID, live, -60, 60)
	storeRestingOrder(db, lid, RestingOrder{
		Owner: h.caller, PoolID: poolID, Side: MakerSideBid, LockedAsset: lockedAssetForSide(h.key, MakerSideBid),
		LockedAmt: big.NewInt(1000), TickLower: -60, TickUpper: 60, Status: OrderStatusOpen,
	})
	if err := withdraw(live); err != nil {
		t.Fatalf("withdraw of the caller's own open position: %v", err)
	}
	if loadRestingOrder(db, lid).Status != OrderStatusClosing {
		t.Fatal("the withdraw did not mark the position closing")
	}
	if err := withdraw(live); err != nil {
		t.Fatalf("a repeated withdraw of a closing position = %v, want it idempotent", err)
	}
	if got := loadRestingOrder(db, lid); got.Status != OrderStatusClosing || got.LockedAmt.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("the repeated withdraw changed the record: %+v", got)
	}
}
