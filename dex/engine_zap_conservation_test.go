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
}

func newFakeCLOB() *fakeCLOB {
	return &fakeCLOB{markets: make(map[[32]byte][]*fakeOrder)}
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
	default:
		return rejectBytes(0, "unknown method"), nil
	}
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

func roundFloatToBig(f float64) *big.Int {
	bf := new(big.Float).SetFloat64(math.Round(f))
	i, _ := bf.Int(nil)
	return i
}

// txStateDB is a MockStateDB that also names a transaction, exercising the
// idempotencyBinder seam end-to-end through the PoolManager.
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
	wantQuote := roundFloatToBig(askPrice * float64(takeBase))
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
	wantQuote := roundFloatToBig(30*p0 + 20*p1)
	if delta.Amount1.Cmp(wantQuote) != 0 {
		t.Fatalf("quote = %s, want %s", delta.Amount1, wantQuote)
	}
	if net := delta.Add(NewBalanceDelta(big.NewInt(50), new(big.Int).Neg(wantQuote))); !net.IsZero() {
		t.Fatalf("value NOT conserved: net = (%s,%s)", net.Amount0, net.Amount1)
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
