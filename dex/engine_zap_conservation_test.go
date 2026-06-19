// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"context"
	"encoding/binary"
	"math"
	"math/big"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/geth/common"
)

// =========================================================================
// Pure-Go value-conservation + atomicity coverage for the ZAP CLOB adapter.
//
// These tests drive the production ZAPEngine through the PUBLIC PoolManager
// surface against a fake in-memory CLOB that speaks the FROZEN ZAP wire frame
// (clob_ensure_market / clob_place / clob_cancel / clob_submit). They depend on
// NO external process and NO luxfi/dex import — the fake is wired via the
// zapDialer seam — so they run under `CGO_ENABLED=0 go test ./dex/` and keep the
// precompile a pure-Go leaf module (no replace in go.mod).
//
// They are the authored proof for the rip-out's exit criteria:
//   - VALUE CONSERVATION: every BalanceDelta is derived ONLY from server fills,
//     and taker+maker nets to (0,0).
//   - ATOMICITY: an unfilled marketable order yields a zero delta and rests
//     nothing; a transport failure yields an error and NO committed delta.
//   - IOC: a marketable order never rests its remainder.
//   - REPLAY-IDEMPOTENCY (RED H1): the same EVM tx submitted twice maps to ONE
//     match against the book.
//   - CANCEL-AUTH (RED H4): a caller cannot cancel another maker's order.
// =========================================================================

// fakeOrder is one resting order in the fake CLOB.
type fakeOrder struct {
	id    uint64
	side  uint8 // 0 = bid, 1 = ask
	price float64
	size  float64
	maker common.Address
}

// fakeCLOB is a minimal, deterministic in-memory central limit order book that
// implements exactly the ZAP CLOB wire contract the ZAPEngine speaks. It is a
// TEST DOUBLE for the d-chain gateway, not a second matcher shipped anywhere.
type fakeCLOB struct {
	mu       sync.Mutex
	markets  map[[32]byte][]*fakeOrder
	nextID   uint64
	submits  int // count of clob_submit calls actually matched (replay probe)
	failNext bool
	closed   bool
	// ledger is a minimal available-balance ledger keyed by user[16]||asset[32]
	// (the FULL injective asset id) so the clob_deposit/withdraw/balance methods the
	// precompile now drives have a deterministic test double. It is NOT the real
	// D-Chain ledger (that lives in lx/dex/pkg/dchain and is exercised by the LIVE
	// e2e); this only checks the precompile's adapter wire contract for the custody
	// methods. The key width mirrors the d-chain balance:<user:8><asset:32>
	// keyspace — distinct assets never collide.
	ledger map[string]uint64

	// custodySeen models the D-Chain's content-addressed idempotency index
	// (seen:<txID>, dchain/state.go). The REAL D-Chain computes txID =
	// Checksum256(type‖user‖asset‖amount‖ref) over the WHOLE custody frame and, on a
	// frame whose txID was already applied, returns the FIRST realized amount
	// VERBATIM via getSeenOutcome — WITHOUT touching the ledger again. This double
	// MUST reproduce that, because the vault-drain bug lives in exactly that replay:
	// a withdraw whose content was already seen returns the prior realized even
	// though available is now 0. Keyed on the full frame bytes (which include the
	// 32-byte ref) so two frames identical in (user,asset,amount) but distinct in
	// ref are DISTINCT here, exactly as on-chain.
	//
	// (The PRE-fix double live-debited on every call, so a second content-identical
	// withdraw saw avail=0 and returned 0 — which MASKED the bug. Modeling seen:
	// faithfully is what lets the regression test expose it.)
	custodySeen map[string]uint64
}

func newFakeCLOB() *fakeCLOB {
	return &fakeCLOB{
		markets:     make(map[[32]byte][]*fakeOrder),
		ledger:      make(map[string]uint64),
		custodySeen: make(map[string]uint64),
	}
}

// ledgerKey keys the fake ledger by user[16]||asset[32] — the FULL 32-byte
// injective asset id (native == all-zero), byte-faithful to the d-chain
// balance:<user:8><asset:32> keyspace so distinct assets never collide.
func ledgerKey(user []byte, asset [32]byte) string {
	var b [zapUserSize + zapAssetIDSize]byte
	copy(b[0:zapUserSize], user)
	copy(b[zapUserSize:], asset[:])
	return string(b[:])
}

// custodyTxID models the D-Chain content-addressed tx identity for a custody
// frame: the FULL frame bytes (type-agnostic here; the method already separates
// deposit vs withdraw). The d-chain hashes [type]‖body with Checksum256; the
// distinguishing input that matters for dedup is the body (which now carries the
// ref), so keying on method‖payload is byte-faithful to "same op?" on-chain.
func custodyTxID(method string, payload []byte) string {
	return method + string(payload)
}

// conn returns a zapConn bound to this book for the zapDialer seam.
func (f *fakeCLOB) conn() zapConn { return &fakeConn{clob: f} }

type fakeConn struct{ clob *fakeCLOB }

func (c *fakeConn) Close() error { return nil }

func (c *fakeConn) Call(_ context.Context, method string, payload []byte) ([]byte, error) {
	return c.clob.dispatch(method, payload)
}

func (f *fakeCLOB) dispatch(method string, payload []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext {
		f.failNext = false
		return nil, context.DeadlineExceeded // simulate a transport failure
	}
	switch method {
	case ZAPMethodEnsureMarket:
		var id [32]byte
		copy(id[:], payload[0:32])
		if _, ok := f.markets[id]; !ok {
			f.markets[id] = nil
		}
		return ackBytes(0, clobStatusPlaced, 1), nil
	case ZAPMethodPlace:
		return f.place(payload)
	case ZAPMethodCancel:
		return f.cancel(payload)
	case ZAPMethodSubmit:
		return f.submit(payload)
	case ZAPMethodOpenMarket:
		// poolId[32]+base[32]+quote[32]; bind is a no-op for this double — just ack.
		var id [32]byte
		copy(id[:], payload[0:32])
		if _, ok := f.markets[id]; !ok {
			f.markets[id] = nil
		}
		return ackBytes(0, clobStatusPlaced, 1), nil
	case ZAPMethodDeposit:
		// user[16]+asset[32]+amount[8]+ref[32]: credit available, echo credited.
		// seen:-replay (same content/ref already applied) -> return the FIRST
		// realized VERBATIM, crediting NOTHING again (models getSeenOutcome).
		txID := custodyTxID(method, payload)
		if prior, seen := f.custodySeen[txID]; seen {
			return balanceRespBytes(clobStatusPlaced, prior), nil
		}
		user := payload[0:16]
		var asset [32]byte
		copy(asset[:], payload[16:custodyAmountOff])
		amount := binary.BigEndian.Uint64(payload[custodyAmountOff:custodyRefOff])
		f.ledger[ledgerKey(user, asset)] += amount
		f.custodySeen[txID] = amount
		return balanceRespBytes(clobStatusPlaced, amount), nil
	case ZAPMethodWithdraw:
		// user[16]+asset[32]+want[8]+ref[32]: debit min(want,avail), return realized.
		// seen:-replay (same content/ref already applied) -> return the FIRST
		// realized VERBATIM, debiting NOTHING again (models getSeenOutcome). THIS is
		// the faithful model that exposes the vault-drain: a content-identical
		// withdraw returns the prior realized even though available is now 0. With
		// the fix, a GENUINE second withdraw carries a DISTINCT ref -> distinct txID
		// -> falls through to a fresh debit that clamps to the CURRENT (0) available.
		txID := custodyTxID(method, payload)
		if prior, seen := f.custodySeen[txID]; seen {
			return balanceRespBytes(clobStatusPlaced, prior), nil
		}
		user := payload[0:16]
		var asset [32]byte
		copy(asset[:], payload[16:custodyAmountOff])
		want := binary.BigEndian.Uint64(payload[custodyAmountOff:custodyRefOff])
		k := ledgerKey(user, asset)
		avail := f.ledger[k]
		realized := want
		if realized > avail {
			realized = avail
		}
		f.ledger[k] = avail - realized
		f.custodySeen[txID] = realized
		return balanceRespBytes(clobStatusPlaced, realized), nil
	case ZAPMethodBalance:
		// user[16]+asset[32]: available[8]+locked[8] (locked unused in this double).
		user := payload[0:16]
		var asset [32]byte
		copy(asset[:], payload[16:zapUserSize+zapAssetIDSize])
		out := make([]byte, 16)
		binary.BigEndian.PutUint64(out[0:8], f.ledger[ledgerKey(user, asset)])
		return out, nil
	default:
		return rejectBytes(0, "unknown method"), nil
	}
}

// balanceRespBytes builds a clob_deposit/withdraw response: status[1]+amount[8],
// byte-identical to zapwire.EncodeBalanceResp.
func balanceRespBytes(status uint8, amount uint64) []byte {
	out := make([]byte, 9)
	out[0] = status
	binary.BigEndian.PutUint64(out[1:9], amount)
	return out
}

func (f *fakeCLOB) place(payload []byte) ([]byte, error) {
	var id [32]byte
	copy(id[:], payload[0:32])
	side := payload[32]
	price := math.Float64frombits(binary.BigEndian.Uint64(payload[33:41]))
	size := math.Float64frombits(binary.BigEndian.Uint64(payload[41:49]))
	var maker common.Address
	copy(maker[:16], payload[49:65])
	f.nextID++
	o := &fakeOrder{id: f.nextID, side: side, price: price, size: size, maker: maker}
	f.markets[id] = append(f.markets[id], o)
	return ackBytes(o.id, clobStatusPlaced, f.nextID), nil
}

func (f *fakeCLOB) cancel(payload []byte) ([]byte, error) {
	var id [32]byte
	copy(id[:], payload[0:32])
	orderID := binary.BigEndian.Uint64(payload[32:40])
	book := f.markets[id]
	for i, o := range book {
		if o.id == orderID {
			f.markets[id] = append(book[:i], book[i+1:]...)
			return ackBytes(orderID, clobStatusCanceled, f.nextID), nil
		}
	}
	return rejectBytes(orderID, "unknown order"), nil
}

// submit matches a marketable order IOC against the resting book and returns
// the fills. Buy (side 0) crosses asks ascending; sell (side 1) crosses bids
// descending. Any unfilled remainder is DROPPED (IOC) — never rested.
func (f *fakeCLOB) submit(payload []byte) ([]byte, error) {
	var id [32]byte
	copy(id[:], payload[0:32])
	side := payload[32] // 0 buy, 1 sell
	isMarket := payload[33] == 1
	limit := math.Float64frombits(binary.BigEndian.Uint64(payload[34:42]))
	size := math.Float64frombits(binary.BigEndian.Uint64(payload[42:50]))
	f.submits++

	book := f.markets[id]
	// Candidates are the opposite side.
	var cands []*fakeOrder
	for _, o := range book {
		if side == 0 && o.side == 1 {
			cands = append(cands, o)
		} else if side == 1 && o.side == 0 {
			cands = append(cands, o)
		}
	}
	if side == 0 { // buy: cross cheapest asks first
		sort.Slice(cands, func(i, j int) bool { return cands[i].price < cands[j].price })
	} else { // sell: cross richest bids first
		sort.Slice(cands, func(i, j int) bool { return cands[i].price > cands[j].price })
	}

	remaining := size
	var fills [][3]float64 // price, size, side
	for _, o := range cands {
		if remaining <= 0 {
			break
		}
		if !isMarket {
			if side == 0 && o.price > limit {
				break
			}
			if side == 1 && o.price < limit {
				break
			}
		}
		take := math.Min(remaining, o.size)
		fills = append(fills, [3]float64{o.price, take, float64(o.side)})
		o.size -= take
		remaining -= take
	}
	// Drop fully-consumed resting orders. Remainder of the taker is NOT rested.
	pruned := book[:0]
	for _, o := range book {
		if o.size > 0 {
			pruned = append(pruned, o)
		}
	}
	f.markets[id] = pruned

	return fillsBytes(fills), nil
}

func (f *fakeCLOB) submitCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.submits
}

// --- wire encoders mirroring dex/pkg/api exactly ---

func ackBytes(orderID uint64, status uint8, seq uint64) []byte {
	b := make([]byte, 17)
	binary.BigEndian.PutUint64(b[0:8], orderID)
	b[8] = status
	binary.BigEndian.PutUint64(b[9:17], seq)
	return b
}

func rejectBytes(orderID uint64, reason string) []byte {
	b := make([]byte, 11+len(reason))
	binary.BigEndian.PutUint64(b[0:8], orderID)
	b[8] = clobStatusRejected
	binary.BigEndian.PutUint16(b[9:11], uint16(len(reason)))
	copy(b[11:], reason)
	return b
}

func fillsBytes(fills [][3]float64) []byte {
	b := make([]byte, 4+len(fills)*fillWireSize)
	binary.BigEndian.PutUint32(b[0:4], uint32(len(fills)))
	off := 4
	for _, fl := range fills {
		binary.BigEndian.PutUint64(b[off:off+8], math.Float64bits(fl[0]))
		binary.BigEndian.PutUint64(b[off+8:off+16], math.Float64bits(fl[1]))
		b[off+16] = byte(fl[2])
		off += fillWireSize
	}
	return b
}

// withFakeCLOB installs a fake-CLOB-backed zapDialer for the duration of a test
// and restores the canonical dialer after.
func withFakeCLOB(t *testing.T, f *fakeCLOB) {
	t.Helper()
	orig := zapDialer
	zapDialer = func(_ context.Context, _ string) (zapConn, error) { return f.conn(), nil }
	t.Cleanup(func() { zapDialer = orig })
}

// tickForPriceLocal snaps a target price to the nearest TickSpacing030 tick.
func tickForPriceLocal(t *testing.T, want float64) int24 {
	t.Helper()
	raw := int(math.Log(want)/math.Log(1.0001) + 0.5)
	spacing := int(TickSpacing030)
	snapped := (raw / spacing) * spacing
	if _, err := tickToPrice(int24(snapped)); err != nil {
		t.Fatalf("tickToPrice(%d): %v", snapped, err)
	}
	return int24(snapped)
}

func priceForTickLocal(t *testing.T, tick int24) float64 {
	t.Helper()
	p, err := tickToPrice(tick)
	if err != nil {
		t.Fatalf("tickToPrice(%d): %v", tick, err)
	}
	return p
}

// ceilQuote is the test oracle for a BUY's owed-quote leg: the taker OWES quote,
// so the engine rounds it UP (ceilToBig) — the conservation-safe direction that
// matches the cross-chain proxy leg. Mirrors fillsToDelta exactly.
func ceilQuote(f float64) *big.Int {
	bf := new(big.Float).SetFloat64(math.Ceil(f))
	i, _ := bf.Int(nil)
	return i
}

// txStateDB is a MockStateDB that also names a transaction (txIdentified seam),
// exercising the durable StateDB-backed swap idempotency end-to-end through the
// PoolManager.
type txStateDB struct {
	*MockStateDB
	txHash common.Hash
}

func (s *txStateDB) TxHash() common.Hash { return s.txHash }

func conservationPoolKey() PoolKey {
	return PoolKey{
		Currency0:   NativeCurrency,
		Currency1:   Currency{Address: common.HexToAddress("0x000000000000000000000000000000000000C0DE")},
		Fee:         Fee030,
		TickSpacing: TickSpacing030,
		Hooks:       common.Address{},
	}
}

// TestZAPConservationSingleCross drives a marketable buy against one resting ask
// through the full PoolManager and asserts the taker delta is derived only from
// the server fill and that taker+maker conserves value exactly.
func TestZAPConservationSingleCross(t *testing.T) {
	f := newFakeCLOB()
	withFakeCLOB(t, f)

	zap := NewZAPEngine("fake:0", 2*time.Second)
	defer zap.Close()
	pm := NewPoolManager(zap)
	stateDB := NewMockStateDB()
	key := conservationPoolKey()
	lp := common.HexToAddress("0x2222222222222222222222222222222222222222")
	taker := common.HexToAddress("0x1111111111111111111111111111111111111111")

	if _, err := pm.Initialize(stateDB, key, new(big.Int).Set(Q96), nil); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	askTick := tickForPriceLocal(t, 2.0)
	askPrice := priceForTickLocal(t, askTick)
	_, _, err := pm.ModifyLiquidity(stateDB, lp, key, ModifyLiquidityParams{
		TickLower:      askTick,
		TickUpper:      askTick + TickSpacing030,
		LiquidityDelta: big.NewInt(100),
	}, nil)
	if err != nil {
		t.Fatalf("ModifyLiquidity ask: %v", err)
	}

	const takeBase = int64(40)
	delta, err := pm.Swap(stateDB, taker, key, SwapParams{
		ZeroForOne:        false,
		AmountSpecified:   big.NewInt(-takeBase),
		SqrtPriceLimitX96: MaxSqrtRatio,
	}, nil)
	if err != nil {
		t.Fatalf("Swap: %v", err)
	}

	// Buy: taker receives base (Amount0<0), pays quote (Amount1>0).
	if delta.Amount0.Cmp(big.NewInt(-takeBase)) != 0 {
		t.Fatalf("base = %s, want -%d", delta.Amount0, takeBase)
	}
	wantQuote := ceilQuote(askPrice * float64(takeBase))
	if delta.Amount1.Cmp(wantQuote) != 0 {
		t.Fatalf("quote = %s, want %s", delta.Amount1, wantQuote)
	}

	// Cross-counterparty conservation: maker delta is the exact negation.
	makerRealized := NewBalanceDelta(big.NewInt(takeBase), new(big.Int).Neg(wantQuote))
	if net := delta.Add(makerRealized); !net.IsZero() {
		t.Fatalf("value NOT conserved: net = (%s,%s)", net.Amount0, net.Amount1)
	}
}

// TestZAPConservationMultiLevel sweeps two ask levels and asserts the aggregate
// quote is the sum of fills, conserved across counterparties.
func TestZAPConservationMultiLevel(t *testing.T) {
	f := newFakeCLOB()
	withFakeCLOB(t, f)

	zap := NewZAPEngine("fake:0", 2*time.Second)
	defer zap.Close()
	pm := NewPoolManager(zap)
	stateDB := NewMockStateDB()
	key := conservationPoolKey()
	lp := common.HexToAddress("0x2222222222222222222222222222222222222222")
	taker := common.HexToAddress("0x1111111111111111111111111111111111111111")

	if _, err := pm.Initialize(stateDB, key, new(big.Int).Set(Q96), nil); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	tk0 := tickForPriceLocal(t, 2.0)
	tk1 := tickForPriceLocal(t, 4.0)
	p0 := priceForTickLocal(t, tk0)
	p1 := priceForTickLocal(t, tk1)
	for _, lvl := range []struct {
		tick int24
		size int64
	}{{tk0, 30}, {tk1, 30}} {
		if _, _, err := pm.ModifyLiquidity(stateDB, lp, key, ModifyLiquidityParams{
			TickLower:      lvl.tick,
			TickUpper:      lvl.tick + TickSpacing030,
			LiquidityDelta: big.NewInt(lvl.size),
		}, nil); err != nil {
			t.Fatalf("ModifyLiquidity @ %d: %v", lvl.tick, err)
		}
	}

	delta, err := pm.Swap(stateDB, taker, key, SwapParams{
		ZeroForOne:        false,
		AmountSpecified:   big.NewInt(-50),
		SqrtPriceLimitX96: MaxSqrtRatio,
	}, nil)
	if err != nil {
		t.Fatalf("Swap: %v", err)
	}

	if delta.Amount0.Cmp(big.NewInt(-50)) != 0 {
		t.Fatalf("base = %s, want -50", delta.Amount0)
	}
	wantQuote := ceilQuote(30*p0 + 20*p1)
	if delta.Amount1.Cmp(wantQuote) != 0 {
		t.Fatalf("quote = %s, want %s", delta.Amount1, wantQuote)
	}
	if net := delta.Add(NewBalanceDelta(big.NewInt(50), new(big.Int).Neg(wantQuote))); !net.IsZero() {
		t.Fatalf("value NOT conserved: net = (%s,%s)", net.Amount0, net.Amount1)
	}
}

// TestZAPConservationPartialFill proves the C-side never fabricates the unfilled
// portion of a marketable order: the book rests only 30 base but the taker
// requests 50. The IOC order crosses the 30 available and the remainder is
// dropped. The taker BalanceDelta MUST reflect ONLY the 30 that filled (-30 base,
// +60 quote at price 2), NOT the 50 requested, and taker+maker conserve exactly.
// A delta built from the requested size instead of the server fills would debit
// the taker for value that never moved — minting.
func TestZAPConservationPartialFill(t *testing.T) {
	f := newFakeCLOB()
	withFakeCLOB(t, f)

	zap := NewZAPEngine("fake:0", 2*time.Second)
	defer zap.Close()
	pm := NewPoolManager(zap)
	stateDB := NewMockStateDB()
	key := conservationPoolKey()
	lp := common.HexToAddress("0x2222222222222222222222222222222222222222")
	taker := common.HexToAddress("0x1111111111111111111111111111111111111111")

	if _, err := pm.Initialize(stateDB, key, new(big.Int).Set(Q96), nil); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	askTick := tickForPriceLocal(t, 2.0)
	askPrice := priceForTickLocal(t, askTick)
	if _, _, err := pm.ModifyLiquidity(stateDB, lp, key, ModifyLiquidityParams{
		TickLower:      askTick,
		TickUpper:      askTick + TickSpacing030,
		LiquidityDelta: big.NewInt(30), // only 30 base rests
	}, nil); err != nil {
		t.Fatalf("ModifyLiquidity: %v", err)
	}

	const requested = int64(50) // taker asks for 50; only 30 can fill
	delta, err := pm.Swap(stateDB, taker, key, SwapParams{
		ZeroForOne:        false,
		AmountSpecified:   big.NewInt(-requested),
		SqrtPriceLimitX96: MaxSqrtRatio,
	}, nil)
	if err != nil {
		t.Fatalf("Swap: %v", err)
	}

	// Delta reflects ONLY the 30 filled, never the 50 requested.
	const filledBase = int64(30)
	if delta.Amount0.Cmp(big.NewInt(-filledBase)) != 0 {
		t.Fatalf("base = %s, want -%d (only the filled portion, NOT the %d requested)", delta.Amount0, filledBase, requested)
	}
	wantQuote := ceilQuote(askPrice * float64(filledBase))
	if delta.Amount1.Cmp(wantQuote) != 0 {
		t.Fatalf("quote = %s, want %s", delta.Amount1, wantQuote)
	}
	// Cross-counterparty conservation on the FILLED portion.
	makerRealized := NewBalanceDelta(big.NewInt(filledBase), new(big.Int).Neg(wantQuote))
	if net := delta.Add(makerRealized); !net.IsZero() {
		t.Fatalf("value NOT conserved on partial fill: net = (%s,%s)", net.Amount0, net.Amount1)
	}
}

// TestZAPAtomicEmptyBook proves a marketable order against an empty book yields
// a ZERO delta and rests nothing — no half-applied state, no fabricated fill.
func TestZAPAtomicEmptyBook(t *testing.T) {
	f := newFakeCLOB()
	withFakeCLOB(t, f)

	zap := NewZAPEngine("fake:0", 2*time.Second)
	defer zap.Close()
	pm := NewPoolManager(zap)
	stateDB := NewMockStateDB()
	key := conservationPoolKey()
	taker := common.HexToAddress("0x1111111111111111111111111111111111111111")

	if _, err := pm.Initialize(stateDB, key, new(big.Int).Set(Q96), nil); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	delta, err := pm.Swap(stateDB, taker, key, SwapParams{
		ZeroForOne:        false,
		AmountSpecified:   big.NewInt(-10),
		SqrtPriceLimitX96: MaxSqrtRatio,
	}, nil)
	if err != nil {
		t.Fatalf("Swap empty book: %v", err)
	}
	if !delta.IsZero() {
		t.Fatalf("empty-book delta = (%s,%s), want (0,0)", delta.Amount0, delta.Amount1)
	}
}

// TestZAPAtomicTransportFailureNoDelta proves a transport failure on submit
// yields an error and NO committed delta — the C-side commits nothing when the
// d-chain leg did not return fills (atomicity-or-reversal, RED C2).
func TestZAPAtomicTransportFailureNoDelta(t *testing.T) {
	f := newFakeCLOB()
	withFakeCLOB(t, f)

	zap := NewZAPEngine("fake:0", 2*time.Second)
	defer zap.Close()
	pm := NewPoolManager(zap)
	stateDB := NewMockStateDB()
	key := conservationPoolKey()
	lp := common.HexToAddress("0x2222222222222222222222222222222222222222")
	taker := common.HexToAddress("0x1111111111111111111111111111111111111111")

	if _, err := pm.Initialize(stateDB, key, new(big.Int).Set(Q96), nil); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if _, _, err := pm.ModifyLiquidity(stateDB, lp, key, ModifyLiquidityParams{
		TickLower:      tickForPriceLocal(t, 2.0),
		TickUpper:      tickForPriceLocal(t, 2.0) + TickSpacing030,
		LiquidityDelta: big.NewInt(100),
	}, nil); err != nil {
		t.Fatalf("ModifyLiquidity: %v", err)
	}

	f.mu.Lock()
	f.failNext = true
	f.mu.Unlock()

	delta, err := pm.Swap(stateDB, taker, key, SwapParams{
		ZeroForOne:        false,
		AmountSpecified:   big.NewInt(-40),
		SqrtPriceLimitX96: MaxSqrtRatio,
	}, nil)
	if err == nil {
		t.Fatal("Swap with transport failure must error")
	}
	if !delta.IsZero() {
		t.Fatalf("failed swap returned non-zero delta (%s,%s) — must commit nothing", delta.Amount0, delta.Amount1)
	}
}

// TestZAPReplayIdempotency proves the SAME EVM tx submitted twice maps to ONE
// match against the book: the second call returns the committed delta WITHOUT a
// second submit (RED H1).
func TestZAPReplayIdempotency(t *testing.T) {
	f := newFakeCLOB()
	withFakeCLOB(t, f)

	zap := NewZAPEngine("fake:0", 2*time.Second)
	defer zap.Close()
	pm := NewPoolManager(zap)
	base := NewMockStateDB()
	stateDB := &txStateDB{MockStateDB: base, txHash: common.HexToHash("0xdeadbeef")}
	key := conservationPoolKey()
	lp := common.HexToAddress("0x2222222222222222222222222222222222222222")
	taker := common.HexToAddress("0x1111111111111111111111111111111111111111")

	if _, err := pm.Initialize(stateDB, key, new(big.Int).Set(Q96), nil); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if _, _, err := pm.ModifyLiquidity(stateDB, lp, key, ModifyLiquidityParams{
		TickLower:      tickForPriceLocal(t, 2.0),
		TickUpper:      tickForPriceLocal(t, 2.0) + TickSpacing030,
		LiquidityDelta: big.NewInt(100),
	}, nil); err != nil {
		t.Fatalf("ModifyLiquidity: %v", err)
	}

	params := SwapParams{ZeroForOne: false, AmountSpecified: big.NewInt(-40), SqrtPriceLimitX96: MaxSqrtRatio}

	d1, err := pm.Swap(stateDB, taker, key, params, nil)
	if err != nil {
		t.Fatalf("Swap #1: %v", err)
	}
	submitsAfter1 := f.submitCount()

	d2, err := pm.Swap(stateDB, taker, key, params, nil)
	if err != nil {
		t.Fatalf("Swap #2 (replay): %v", err)
	}

	if f.submitCount() != submitsAfter1 {
		t.Fatalf("replay submitted again: submits went %d -> %d, want stable (idempotent)", submitsAfter1, f.submitCount())
	}
	if d1.Amount0.Cmp(d2.Amount0) != 0 || d1.Amount1.Cmp(d2.Amount1) != 0 {
		t.Fatalf("replay delta mismatch: #1 (%s,%s) vs #2 (%s,%s)", d1.Amount0, d1.Amount1, d2.Amount0, d2.Amount1)
	}

	// A DIFFERENT tx hash must submit afresh against whatever still rests.
	stateDB2 := &txStateDB{MockStateDB: base, txHash: common.HexToHash("0xfeedface")}
	if _, err := pm.Swap(stateDB2, taker, key, params, nil); err != nil {
		t.Fatalf("Swap (new tx): %v", err)
	}
	if f.submitCount() != submitsAfter1+1 {
		t.Fatalf("new tx did not submit: submits=%d, want %d", f.submitCount(), submitsAfter1+1)
	}
}

// TestSwapIdempotencySurvivesRestart is the regression for the RED-H1 finding:
// the idempotency guard MUST be durable, not an in-memory per-node cache. It runs
// a swap through one PoolManager+ZAPEngine, then DISCARDS both and replays the
// SAME EVM tx through a FRESH PoolManager+ZAPEngine against the SAME committed
// StateDB — modelling a node restart (or block re-verification by a process that
// never saw the first execution). The d-chain must NOT be submitted to a second
// time, and the replay must return the byte-identical committed delta.
//
// Under the old in-memory txBind map this test could not pass: the fresh engine
// starts with an empty map and re-submits. With the binding in StateDB it is
// served from the durable record.
func TestSwapIdempotencySurvivesRestart(t *testing.T) {
	f := newFakeCLOB()
	withFakeCLOB(t, f)

	key := conservationPoolKey()
	lp := common.HexToAddress("0x2222222222222222222222222222222222222222")
	taker := common.HexToAddress("0x1111111111111111111111111111111111111111")
	// One shared, committed StateDB — the chain state that survives a restart.
	base := NewMockStateDB()
	stateDB := &txStateDB{MockStateDB: base, txHash: common.HexToHash("0xabc123")}
	params := SwapParams{ZeroForOne: false, AmountSpecified: big.NewInt(-40), SqrtPriceLimitX96: MaxSqrtRatio}

	// --- pre-restart process: init market, rest liquidity, take it.
	zap1 := NewZAPEngine("fake:0", 2*time.Second)
	pm1 := NewPoolManager(zap1)
	if _, err := pm1.Initialize(stateDB, key, new(big.Int).Set(Q96), nil); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if _, _, err := pm1.ModifyLiquidity(stateDB, lp, key, ModifyLiquidityParams{
		TickLower:      tickForPriceLocal(t, 2.0),
		TickUpper:      tickForPriceLocal(t, 2.0) + TickSpacing030,
		LiquidityDelta: big.NewInt(100),
	}, nil); err != nil {
		t.Fatalf("ModifyLiquidity: %v", err)
	}
	d1, err := pm1.Swap(stateDB, taker, key, params, nil)
	if err != nil {
		t.Fatalf("Swap #1: %v", err)
	}
	submitsAfterRestart1 := f.submitCount()
	zap1.Close()

	// --- RESTART: brand-new engine + pool manager, ZERO in-memory carryover,
	// reading the SAME committed StateDB. Replay the SAME tx.
	zap2 := NewZAPEngine("fake:0", 2*time.Second)
	defer zap2.Close()
	pm2 := NewPoolManager(zap2)
	d2, err := pm2.Swap(stateDB, taker, key, params, nil)
	if err != nil {
		t.Fatalf("Swap #2 (post-restart replay): %v", err)
	}

	if f.submitCount() != submitsAfterRestart1 {
		t.Fatalf("post-restart replay re-submitted: submits %d -> %d, want stable (durable idempotency)",
			submitsAfterRestart1, f.submitCount())
	}
	if d1.Amount0.Cmp(d2.Amount0) != 0 || d1.Amount1.Cmp(d2.Amount1) != 0 {
		t.Fatalf("post-restart delta mismatch: #1 (%s,%s) vs #2 (%s,%s)",
			d1.Amount0, d1.Amount1, d2.Amount0, d2.Amount1)
	}
}

// TestSwapIdempotencyAcrossValidators proves the durable guard also closes the
// N-fold fan-out: two INDEPENDENT validators (two PoolManager+ZAPEngine pairs,
// no shared memory) verifying the SAME ordered block against the SAME consensus
// StateDB submit the user's swap to the single d-chain venue EXACTLY ONCE. The
// first validator to execute records the binding in StateDB; the second reads it
// and serves the committed delta without a second submit.
func TestSwapIdempotencyAcrossValidators(t *testing.T) {
	f := newFakeCLOB()
	withFakeCLOB(t, f)

	key := conservationPoolKey()
	lp := common.HexToAddress("0x2222222222222222222222222222222222222222")
	taker := common.HexToAddress("0x1111111111111111111111111111111111111111")
	base := NewMockStateDB()
	stateDB := &txStateDB{MockStateDB: base, txHash: common.HexToHash("0xdecafbad")}
	params := SwapParams{ZeroForOne: false, AmountSpecified: big.NewInt(-40), SqrtPriceLimitX96: MaxSqrtRatio}

	// Validator A creates the market + rests liquidity (shared consensus state).
	zapA := NewZAPEngine("fake:0", 2*time.Second)
	defer zapA.Close()
	pmA := NewPoolManager(zapA)
	if _, err := pmA.Initialize(stateDB, key, new(big.Int).Set(Q96), nil); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if _, _, err := pmA.ModifyLiquidity(stateDB, lp, key, ModifyLiquidityParams{
		TickLower:      tickForPriceLocal(t, 2.0),
		TickUpper:      tickForPriceLocal(t, 2.0) + TickSpacing030,
		LiquidityDelta: big.NewInt(100),
	}, nil); err != nil {
		t.Fatalf("ModifyLiquidity: %v", err)
	}

	// Validator A executes the swap.
	dA, err := pmA.Swap(stateDB, taker, key, params, nil)
	if err != nil {
		t.Fatalf("validator A swap: %v", err)
	}
	submitsAfterA := f.submitCount()

	// Validator B — a separate engine + manager — verifies the SAME block over
	// the SAME StateDB. It must NOT submit again.
	zapB := NewZAPEngine("fake:0", 2*time.Second)
	defer zapB.Close()
	pmB := NewPoolManager(zapB)
	dB, err := pmB.Swap(stateDB, taker, key, params, nil)
	if err != nil {
		t.Fatalf("validator B swap: %v", err)
	}

	if f.submitCount() != submitsAfterA {
		t.Fatalf("validator B fanned out a duplicate submit: submits %d -> %d, want one total",
			submitsAfterA, f.submitCount())
	}
	if dA.Amount0.Cmp(dB.Amount0) != 0 || dA.Amount1.Cmp(dB.Amount1) != 0 {
		t.Fatalf("validators disagree on delta: A (%s,%s) vs B (%s,%s)",
			dA.Amount0, dA.Amount1, dB.Amount0, dB.Amount1)
	}
}

// TestSwapBindingSignedDeltaRoundTrips proves a NEGATIVE BalanceDelta leg (pool
// owes the user — the common case for a buy) is stored and reloaded EXACTLY by
// the durable binding, i.e. the two's-complement slot codec is correct. A
// sell-side replay (Amount1 < 0) is the canonical negative-leg case.
func TestSwapBindingSignedDeltaRoundTrips(t *testing.T) {
	f := newFakeCLOB()
	withFakeCLOB(t, f)

	key := conservationPoolKey()
	lp := common.HexToAddress("0x2222222222222222222222222222222222222222")
	taker := common.HexToAddress("0x1111111111111111111111111111111111111111")
	base := NewMockStateDB()
	stateDB := &txStateDB{MockStateDB: base, txHash: common.HexToHash("0x0ddba11")}

	zap := NewZAPEngine("fake:0", 2*time.Second)
	defer zap.Close()
	pm := NewPoolManager(zap)
	if _, err := pm.Initialize(stateDB, key, new(big.Int).Set(Q96), nil); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	// Rest a BID so a sell crosses it: the taker sells base (Amount0>0), receives
	// quote (Amount1<0) — a negative leg to round-trip.
	if _, _, err := pm.ModifyLiquidity(stateDB, lp, key, ModifyLiquidityParams{
		TickLower:      tickForPriceLocal(t, 0.5),
		TickUpper:      tickForPriceLocal(t, 0.5) + TickSpacing030,
		LiquidityDelta: big.NewInt(100),
	}, nil); err != nil {
		t.Fatalf("ModifyLiquidity bid: %v", err)
	}
	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-40), SqrtPriceLimitX96: MinSqrtRatio}

	d1, err := pm.Swap(stateDB, taker, key, params, nil)
	if err != nil {
		t.Fatalf("Swap: %v", err)
	}
	if d1.Amount1.Sign() >= 0 {
		t.Fatalf("expected a negative quote leg (pool owes user), got Amount1=%s", d1.Amount1)
	}

	// Replay through a fresh manager: the stored signed delta must reload exactly.
	pm2 := NewPoolManager(zap)
	d2, err := pm2.Swap(stateDB, taker, key, params, nil)
	if err != nil {
		t.Fatalf("replay swap: %v", err)
	}
	if d1.Amount0.Cmp(d2.Amount0) != 0 || d1.Amount1.Cmp(d2.Amount1) != 0 {
		t.Fatalf("signed delta did not round-trip: stored (%s,%s) reloaded (%s,%s)",
			d1.Amount0, d1.Amount1, d2.Amount0, d2.Amount1)
	}
}

// TestSwapBindingNotWrittenOnFailedSubmit proves an aborted swap leaves NO
// durable binding: a transport failure commits nothing, so a subsequent retry of
// the same tx legitimately re-submits (the first attempt never settled). This is
// the correct boundary — idempotency suppresses a SECOND match only after a FIRST
// one actually committed.
func TestSwapBindingNotWrittenOnFailedSubmit(t *testing.T) {
	f := newFakeCLOB()
	withFakeCLOB(t, f)

	key := conservationPoolKey()
	lp := common.HexToAddress("0x2222222222222222222222222222222222222222")
	taker := common.HexToAddress("0x1111111111111111111111111111111111111111")
	base := NewMockStateDB()
	stateDB := &txStateDB{MockStateDB: base, txHash: common.HexToHash("0xf00dface")}
	params := SwapParams{ZeroForOne: false, AmountSpecified: big.NewInt(-40), SqrtPriceLimitX96: MaxSqrtRatio}

	zap := NewZAPEngine("fake:0", 2*time.Second)
	defer zap.Close()
	pm := NewPoolManager(zap)
	if _, err := pm.Initialize(stateDB, key, new(big.Int).Set(Q96), nil); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if _, _, err := pm.ModifyLiquidity(stateDB, lp, key, ModifyLiquidityParams{
		TickLower:      tickForPriceLocal(t, 2.0),
		TickUpper:      tickForPriceLocal(t, 2.0) + TickSpacing030,
		LiquidityDelta: big.NewInt(100),
	}, nil); err != nil {
		t.Fatalf("ModifyLiquidity: %v", err)
	}

	// Force the submit leg to fail.
	f.mu.Lock()
	f.failNext = true
	f.mu.Unlock()
	if _, err := pm.Swap(stateDB, taker, key, params, nil); err == nil {
		t.Fatal("expected transport failure to surface as an error")
	}

	// No binding should have been written: a retry must actually submit now.
	submitsBefore := f.submitCount()
	if _, err := pm.Swap(stateDB, taker, key, params, nil); err != nil {
		t.Fatalf("retry after failed submit: %v", err)
	}
	if f.submitCount() != submitsBefore+1 {
		t.Fatalf("retry after a FAILED submit did not re-submit: submits=%d, want %d (failed attempt must not bind)",
			f.submitCount(), submitsBefore+1)
	}
}

// TestSwapDistinctSwapsInSameTxEachSubmit proves the durable key does NOT over-
// suppress: two DIFFERENT marketable orders carried by the SAME EVM tx (a router
// / multicall) each get their own binding slot and each submit to the book. The
// idempotency boundary is per (tx, pool, order) — not per tx — so legitimate
// distinct swaps are never collapsed into one.
func TestSwapDistinctSwapsInSameTxEachSubmit(t *testing.T) {
	f := newFakeCLOB()
	withFakeCLOB(t, f)

	key := conservationPoolKey()
	lp := common.HexToAddress("0x2222222222222222222222222222222222222222")
	taker := common.HexToAddress("0x1111111111111111111111111111111111111111")
	base := NewMockStateDB()
	// One tx hash shared by BOTH swaps — the router/multicall case.
	stateDB := &txStateDB{MockStateDB: base, txHash: common.HexToHash("0xc0ffee")}

	zap := NewZAPEngine("fake:0", 2*time.Second)
	defer zap.Close()
	pm := NewPoolManager(zap)
	if _, err := pm.Initialize(stateDB, key, new(big.Int).Set(Q96), nil); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	// Rest enough asks for two separate takes.
	if _, _, err := pm.ModifyLiquidity(stateDB, lp, key, ModifyLiquidityParams{
		TickLower:      tickForPriceLocal(t, 2.0),
		TickUpper:      tickForPriceLocal(t, 2.0) + TickSpacing030,
		LiquidityDelta: big.NewInt(1000),
	}, nil); err != nil {
		t.Fatalf("ModifyLiquidity: %v", err)
	}

	// Two DISTINCT swaps (different sizes) under the SAME tx hash.
	if _, err := pm.Swap(stateDB, taker, key, SwapParams{
		ZeroForOne: false, AmountSpecified: big.NewInt(-40), SqrtPriceLimitX96: MaxSqrtRatio,
	}, nil); err != nil {
		t.Fatalf("swap A: %v", err)
	}
	if _, err := pm.Swap(stateDB, taker, key, SwapParams{
		ZeroForOne: false, AmountSpecified: big.NewInt(-50), SqrtPriceLimitX96: MaxSqrtRatio,
	}, nil); err != nil {
		t.Fatalf("swap B: %v", err)
	}

	if f.submitCount() != 2 {
		t.Fatalf("two distinct swaps in one tx submitted %d times, want 2 (per-order idempotency, not per-tx)", f.submitCount())
	}

	// But replaying swap A's EXACT params under the same tx is still suppressed.
	submitsBeforeReplay := f.submitCount()
	if _, err := pm.Swap(stateDB, taker, key, SwapParams{
		ZeroForOne: false, AmountSpecified: big.NewInt(-40), SqrtPriceLimitX96: MaxSqrtRatio,
	}, nil); err != nil {
		t.Fatalf("replay swap A: %v", err)
	}
	if f.submitCount() != submitsBeforeReplay {
		t.Fatalf("replay of swap A re-submitted: submits %d -> %d, want stable", submitsBeforeReplay, f.submitCount())
	}
}

// TestZAPCancelAuthCannotCancelOthersOrder proves the IDOR is closed: a caller
// who did not place an order cannot cancel it via a guessed/forged salt — the
// adapter resolves the server orderID only from the caller's OWN authenticated
// (maker, poolId, salt) handle (RED H4).
func TestZAPCancelAuthCannotCancelOthersOrder(t *testing.T) {
	f := newFakeCLOB()
	withFakeCLOB(t, f)

	zap := NewZAPEngine("fake:0", 2*time.Second)
	defer zap.Close()
	pm := NewPoolManager(zap)
	stateDB := NewMockStateDB()
	key := conservationPoolKey()
	lp := common.HexToAddress("0x2222222222222222222222222222222222222222")
	attacker := common.HexToAddress("0x3333333333333333333333333333333333333333")

	if _, err := pm.Initialize(stateDB, key, new(big.Int).Set(Q96), nil); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	askParams := ModifyLiquidityParams{
		TickLower:      tickForPriceLocal(t, 2.0),
		TickUpper:      tickForPriceLocal(t, 2.0) + TickSpacing030,
		LiquidityDelta: big.NewInt(100),
		Salt:           [32]byte{0x01},
	}
	if _, _, err := pm.ModifyLiquidity(stateDB, lp, key, askParams, nil); err != nil {
		t.Fatalf("LP place: %v", err)
	}

	poolId := key.ID()
	if got := len(f.markets[poolId]); got != 1 {
		t.Fatalf("resting orders = %d, want 1", got)
	}

	// Attacker tries to cancel the LP's order: same ticks/salt, but as a
	// DIFFERENT caller. The handle is keyed by caller identity, so no order
	// resolves for the attacker -> cancel must fail and the order must remain.
	cancelParams := ModifyLiquidityParams{
		TickLower:      askParams.TickLower,
		TickUpper:      askParams.TickUpper,
		LiquidityDelta: big.NewInt(-100),
		Salt:           [32]byte{0x01}, // forged: copy of the LP's salt
	}
	if _, _, err := pm.ModifyLiquidity(stateDB, attacker, key, cancelParams, nil); err == nil {
		t.Fatal("attacker cancel must fail (IDOR) — no order is bound to the attacker")
	}
	if got := len(f.markets[poolId]); got != 1 {
		t.Fatalf("LP order vanished after attacker cancel: resting = %d, want 1", got)
	}

	// The real maker CAN cancel its own order.
	if _, _, err := pm.ModifyLiquidity(stateDB, lp, key, cancelParams, nil); err != nil {
		t.Fatalf("maker self-cancel: %v", err)
	}
	if got := len(f.markets[poolId]); got != 0 {
		t.Fatalf("maker cancel did not remove order: resting = %d, want 0", got)
	}
}

// TestZAPCancelSurvivesMultiExec is the regression for the EVM-path cancel revert
// ("no resting order for caller"). A place and its later cancel are DIFFERENT EVM
// txs, and the EVM runs each tx ~5x (gas-estimate / validate / build / verify /
// canonical — only canonical commits). The owner<->order binding the place wrote
// to the backend's PROCESS MEMORY (ZAPEngine.orderRef) did not survive to the
// cancel's executions, so the cancel resolved nothing and reverted — even though
// the order rested fine on the venue and the funds were locked.
//
// This models that hazard the same way TestSwapIdempotencySurvivesRestart does:
// place through one PoolManager+ZAPEngine, then DISCARD both and cancel through a
// FRESH PoolManager+ZAPEngine (ZERO in-memory carryover) against the SAME committed
// StateDB and the SAME venue book. The cancel MUST now succeed by reading the
// DURABLE cancel-authorization binding from StateDB and re-seeding the backend
// cache — and the unfilled order must be removed from the book.
//
// Under the old in-memory-only orderRef this could not pass: the fresh engine
// starts with an empty map and reverts "no resting order for caller".
func TestZAPCancelSurvivesMultiExec(t *testing.T) {
	f := newFakeCLOB()
	withFakeCLOB(t, f)

	key := conservationPoolKey()
	lp := common.HexToAddress("0x2222222222222222222222222222222222222222")
	poolId := key.ID()
	// One shared, committed StateDB — the chain state that survives across the
	// EVM's separate executions / a node restart.
	base := NewMockStateDB()
	// The place tx and the cancel tx have DIFFERENT tx hashes (they are different
	// transactions); the durable cancel-auth binding is keyed by the maker handle,
	// not the txHash, so it bridges them.
	placeDB := &txStateDB{MockStateDB: base, txHash: common.HexToHash("0x9001")}
	cancelDB := &txStateDB{MockStateDB: base, txHash: common.HexToHash("0x9002")}

	salt := [32]byte{0xAB}
	placeParams := ModifyLiquidityParams{
		TickLower:      tickForPriceLocal(t, 2.0),
		TickUpper:      tickForPriceLocal(t, 2.0) + TickSpacing030,
		LiquidityDelta: big.NewInt(100),
		Salt:           salt,
	}

	// --- execution #1: init + place the resting order.
	zap1 := NewZAPEngine("fake:0", 2*time.Second)
	pm1 := NewPoolManager(zap1)
	if _, err := pm1.Initialize(placeDB, key, new(big.Int).Set(Q96), nil); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if _, _, err := pm1.ModifyLiquidity(placeDB, lp, key, placeParams, nil); err != nil {
		t.Fatalf("place: %v", err)
	}
	if got := len(f.markets[poolId]); got != 1 {
		t.Fatalf("after place: resting = %d, want 1", got)
	}
	// The durable binding must exist in StateDB after the place.
	if _, ok := loadCancelAuth(base, lp, poolId, salt); !ok {
		t.Fatal("place did not record a durable cancel-auth binding")
	}
	zap1.Close()

	// --- execution #2 (later tx / restart): brand-new engine + pool manager, ZERO
	// in-memory carryover, reading the SAME committed StateDB + the SAME venue book.
	// The cancel must succeed off the durable binding.
	zap2 := NewZAPEngine("fake:0", 2*time.Second)
	defer zap2.Close()
	pm2 := NewPoolManager(zap2)

	// Sanity: the fresh engine genuinely has NO in-memory binding — proving the
	// authorization comes from durable StateDB, not process memory.
	if _, ok := zap2.OrderHandle(lp, poolId, salt); ok {
		t.Fatal("fresh engine unexpectedly has an in-memory order handle")
	}

	cancelParams := ModifyLiquidityParams{
		TickLower:      placeParams.TickLower,
		TickUpper:      placeParams.TickUpper,
		LiquidityDelta: big.NewInt(-100),
		Salt:           salt,
	}
	delta, _, err := pm2.ModifyLiquidity(cancelDB, lp, key, cancelParams, nil)
	if err != nil {
		t.Fatalf("cancel across multi-exec MUST succeed off the durable binding, got: %v", err)
	}
	// Removing liquidity returns funds to the LP: the delta must be non-zero (pool
	// owes the maker the unfilled posted amount) — the funds are unlocked.
	if delta.Amount0.Sign() == 0 && delta.Amount1.Sign() == 0 {
		t.Fatalf("cancel returned a zero delta — the unfilled amount was not unlocked")
	}
	if got := len(f.markets[poolId]); got != 0 {
		t.Fatalf("cancel did not remove the resting order: resting = %d, want 0", got)
	}
	// The durable binding must be cleared after a successful cancel so it cannot be
	// replayed against a recycled orderID.
	if _, ok := loadCancelAuth(base, lp, poolId, salt); ok {
		t.Fatal("cancel did not clear the durable cancel-auth binding")
	}
}

// TestZAPCancelAuthRejectsOthersAcrossMultiExec proves the IDOR stays closed even
// with the DURABLE binding and across a fresh process. A maker places; then a
// DIFFERENT caller (attacker), through a brand-new PoolManager+ZAPEngine reading
// the same committed StateDB, tries to cancel with the maker's exact ticks+salt.
// The attacker's authenticated handle is keyed by the ATTACKER's address, so it
// has no durable binding — the cancel must reject WITHOUT touching the venue, the
// maker's order must remain, and the maker (also from a fresh process) can still
// cancel its own order off the durable binding (RED H4).
func TestZAPCancelAuthRejectsOthersAcrossMultiExec(t *testing.T) {
	f := newFakeCLOB()
	withFakeCLOB(t, f)

	key := conservationPoolKey()
	poolId := key.ID()
	lp := common.HexToAddress("0x2222222222222222222222222222222222222222")
	attacker := common.HexToAddress("0x3333333333333333333333333333333333333333")
	base := NewMockStateDB()
	stateDB := &txStateDB{MockStateDB: base, txHash: common.HexToHash("0xa001")}

	salt := [32]byte{0x01}
	placeParams := ModifyLiquidityParams{
		TickLower:      tickForPriceLocal(t, 2.0),
		TickUpper:      tickForPriceLocal(t, 2.0) + TickSpacing030,
		LiquidityDelta: big.NewInt(100),
		Salt:           salt,
	}

	// Maker places (process #1).
	zap1 := NewZAPEngine("fake:0", 2*time.Second)
	pm1 := NewPoolManager(zap1)
	if _, err := pm1.Initialize(stateDB, key, new(big.Int).Set(Q96), nil); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if _, _, err := pm1.ModifyLiquidity(stateDB, lp, key, placeParams, nil); err != nil {
		t.Fatalf("maker place: %v", err)
	}
	zap1.Close()

	cancelParams := ModifyLiquidityParams{
		TickLower:      placeParams.TickLower,
		TickUpper:      placeParams.TickUpper,
		LiquidityDelta: big.NewInt(-100),
		Salt:           salt, // forged: a copy of the maker's salt
	}

	// Attacker tries to cancel from a FRESH process reading the durable state.
	zapA := NewZAPEngine("fake:0", 2*time.Second)
	pmA := NewPoolManager(zapA)
	submitsBefore := f.submitCount()
	if _, _, err := pmA.ModifyLiquidity(stateDB, attacker, key, cancelParams, nil); err == nil {
		t.Fatal("attacker cancel must fail (IDOR) — no durable binding under the attacker's handle")
	}
	if got := len(f.markets[poolId]); got != 1 {
		t.Fatalf("maker order vanished after attacker cancel: resting = %d, want 1", got)
	}
	// The rejection must be decided in the PoolManager from durable state, BEFORE
	// any venue delegation — no ZAP traffic for the unauthorized cancel.
	if f.submitCount() != submitsBefore {
		t.Fatal("attacker cancel reached the venue — authorization must reject before delegation")
	}
	zapA.Close()

	// The real maker, from yet another fresh process, CAN cancel off the binding.
	zap2 := NewZAPEngine("fake:0", 2*time.Second)
	defer zap2.Close()
	pm2 := NewPoolManager(zap2)
	if _, _, err := pm2.ModifyLiquidity(stateDB, lp, key, cancelParams, nil); err != nil {
		t.Fatalf("maker self-cancel across multi-exec: %v", err)
	}
	if got := len(f.markets[poolId]); got != 0 {
		t.Fatalf("maker cancel did not remove order: resting = %d, want 0", got)
	}
}
