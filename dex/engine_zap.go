// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"sync"
	"time"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/rpc"
	"github.com/zeebo/blake3"
)

// ZAP CLOB method names. These MUST match the server handlers registered by the
// lux/dex ZAP server (github.com/luxfi/dex/pkg/api). The V4 PoolManager facade
// at LP-9010 is a CENTRAL LIMIT ORDER BOOK, not an AMM: this adapter translates
// V4 PoolManager calls into CLOB operations and keeps NO canonical order/pool
// state — the resting book lives server-side on the D-Chain DEX.
//
// Mapping:
//   - initialize(poolKey)        -> clob_ensure_market (create the book)
//   - modifyLiquidity(+delta)    -> clob_place   (rest a limit order)
//   - modifyLiquidity(-delta)    -> clob_cancel  (pull a resting order)
//   - swap(params)               -> clob_submit  (marketable order -> fills)
//
// Market identity on the wire is the 32-byte V4 poolId.
const (
	ZAPMethodEnsureMarket = "clob_ensure_market"
	ZAPMethodPlace        = "clob_place"
	ZAPMethodCancel       = "clob_cancel"
	ZAPMethodSubmit       = "clob_submit"
)

// brandFallback is the neutral, brand-free identity surfaced by ZAPEngine. The
// CLOB ZAP surface advertises no brand on the wire (the matcher is brand-free),
// so this is what Brand() always returns on the ZAP path.
const brandFallback = "DEX"

// fillWireSize is one fill in a clob_submit response: price[8]+size[8]+side[1].
const fillWireSize = 17

// zapConn is the connection contract used by ZAPEngine. Production uses
// *rpc.ZAPConn; the interface lets tests drive the engine without a socket.
type zapConn interface {
	Call(ctx context.Context, method string, payload []byte) ([]byte, error)
	Close() error
}

// zapDialer establishes a zapConn to addr. Overridable in tests; defaults to
// the canonical rpc.ZAPDial.
var zapDialer = func(ctx context.Context, addr string) (zapConn, error) {
	return rpc.ZAPDial(ctx, addr)
}

// ZAPEngine is the V4 PoolManager -> D-Chain CLOB adapter. It implements the
// Engine contract by forwarding every operation to the canonical order book over
// ZAP (github.com/luxfi/rpc). It holds NO canonical state: the only per-pool
// data it keeps is a routing handle (poolId), so the resting book lives
// exclusively server-side.
//
// The precompile's *PoolState (sourced from C-Chain StateDB) is a thin
// read-through view: this adapter mirrors V4 surface onto a CLOB, where there is
// no continuous sqrtPrice/liquidity curve. So PoolState's AMM scalars are NOT
// synced from a curve — they are left as the initialize-time values; the
// authoritative truth is the server-side book, queried per operation.
type ZAPEngine struct {
	addr    string
	timeout time.Duration

	mu   sync.Mutex
	conn zapConn

	// routes maps a precompile PoolState (by pointer identity, valid within the
	// process) to the V4 poolId the server keys its market by. Set via
	// SetPoolID before delegating; a routing handle, NOT state.
	routes map[*PoolState][32]byte

	// initPrice records the initialize-time price (currency1 per currency0) for
	// each market, used to decide whether a single-tick LP order rests as a bid
	// or an ask. It is a routing aid, not canonical state — the book is.
	initPrice map[[32]byte]float64

	// orderRef maps an authenticated maker order handle to the server-side
	// orderID returned at place time. The key is BLAKE3(maker||poolId||salt) —
	// a value derived from the EVM caller's own identity, NEVER from a
	// caller-supplied raw orderID. Cancel resolves the orderID through this map
	// so a caller can only cancel orders keyed to its OWN maker tuple (fixes the
	// IDOR — RED H4). It is a routing handle, not canonical book state.
	orderRef map[[32]byte]uint64
	// orderMaker records, per server orderID, the maker that placed it, so cancel
	// re-verifies caller==maker as defense in depth even after a resolve.
	orderMaker map[uint64]common.Address
}

// Compile-time assertions: ZAPEngine satisfies the Engine contract and the
// internal poolRouter seam the PoolManager uses to thread the canonical poolId.
// Replay-idempotency is the PoolManager's StateDB concern, not the engine's, so
// there is no binder seam here.
var (
	_ Engine     = (*ZAPEngine)(nil)
	_ poolRouter = (*ZAPEngine)(nil)
)

// NewZAPEngine creates a ZAP adapter targeting the DEX engine's ZAP endpoint
// (e.g. "localhost:9100"). Signature is stable: the EVM plugin constructs it as
// NewZAPEngine(endpoint, timeout).
func NewZAPEngine(addr string, timeout time.Duration) *ZAPEngine {
	return &ZAPEngine{
		addr:       addr,
		timeout:    timeout,
		routes:     make(map[*PoolState][32]byte),
		initPrice:  make(map[[32]byte]float64),
		orderRef:   make(map[[32]byte]uint64),
		orderMaker: make(map[uint64]common.Address),
	}
}

// makerOrderKey derives the authenticated order handle from the maker's own
// identity (owner), the market (poolId) and the position salt. Because the key
// is bound to the caller's address, a caller can address ONLY its own resting
// orders — the raw server orderID never crosses the ABI from the caller.
func makerOrderKey(owner common.Address, poolID [32]byte, salt [32]byte) [32]byte {
	h := blake3.New()
	h.Write(owner.Bytes())
	h.Write(poolID[:])
	h.Write(salt[:])
	var k [32]byte
	h.Digest().Read(k[:])
	return k
}

// SetPoolID records the canonical poolId for a PoolState so subsequent
// place/cancel/submit forward to the right server-side market. Called by the
// PoolManager (poolRouter seam) before each engine delegation.
func (z *ZAPEngine) SetPoolID(ps *PoolState, poolID [32]byte) {
	z.mu.Lock()
	z.routes[ps] = poolID
	z.mu.Unlock()
}

// poolID returns the routing handle recorded for a PoolState, or an error when
// none was set — which means the PoolManager delegated without routing.
func (z *ZAPEngine) poolID(ps *PoolState) ([32]byte, error) {
	z.mu.Lock()
	id, ok := z.routes[ps]
	z.mu.Unlock()
	if !ok {
		return [32]byte{}, fmt.Errorf("ZAP: no poolId routed for pool state (init not forwarded?)")
	}
	return id, nil
}

func (z *ZAPEngine) dial(ctx context.Context) (zapConn, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.conn != nil {
		return z.conn, nil
	}
	c, err := zapDialer(ctx, z.addr)
	if err != nil {
		return nil, fmt.Errorf("ZAP dial %s: %w", z.addr, err)
	}
	z.conn = c
	return c, nil
}

func (z *ZAPEngine) call(ctx context.Context, method string, payload []byte) ([]byte, error) {
	c, err := z.dial(ctx)
	if err != nil {
		return nil, err
	}
	return c.Call(ctx, method, payload)
}

// =========================================================================
// Engine contract — every method forwards to the canonical CLOB server.
// =========================================================================

// Initialize computes the initial tick from sqrtPriceX96 with the shared V4
// TickMath. It creates no state (the market is created server-side by
// InitializePool on the ZAP path), so the Engine.Initialize contract stays a
// pure tick computation.
func (z *ZAPEngine) Initialize(sqrtPriceX96 *big.Int) (int24, error) {
	tick, err := GetTickAtSqrtRatio(sqrtPriceX96)
	if err != nil {
		return 0, fmt.Errorf("ZAP Initialize: %w", err)
	}
	return tick, nil
}

// InitializePool ensures the canonical market (order book) exists on the server,
// keyed by poolID, and records the routing handle + the initialize-time price
// for the given PoolState. Returns the authoritative initial tick (recomputed
// from sqrtPriceX96 with the shared V4 math — the CLOB has no curve to report).
func (z *ZAPEngine) InitializePool(ps *PoolState, poolID [32]byte, sqrtPriceX96 *big.Int, tickSpacing int32, lpFee uint32) (int24, error) {
	ctx, cancel := context.WithTimeout(context.Background(), z.timeout)
	defer cancel()

	tick, err := GetTickAtSqrtRatio(sqrtPriceX96)
	if err != nil {
		return 0, fmt.Errorf("ZAP InitializePool: %w", err)
	}

	payload := make([]byte, 32)
	copy(payload[0:32], poolID[:])

	resp, err := z.call(ctx, ZAPMethodEnsureMarket, payload)
	if err != nil {
		return 0, fmt.Errorf("ZAP InitializePool: %w", err)
	}
	if _, status, reason, derr := decodeAck(resp); derr != nil {
		return 0, fmt.Errorf("ZAP InitializePool ack: %w", derr)
	} else if status == clobStatusRejected {
		return 0, fmt.Errorf("ZAP InitializePool rejected: %s", reason)
	}

	z.mu.Lock()
	z.routes[ps] = poolID
	z.initPrice[poolID] = sqrtPriceX96ToPrice(sqrtPriceX96)
	z.mu.Unlock()
	return tick, nil
}

// Swap submits a MARKETABLE order against the book and derives the V4
// BalanceDelta from the server-returned FILLS — never from any client-supplied
// amount. The delta is value-conserving by construction (see fillsToDelta).
//
// V4 sign convention (taker perspective): positive = user owes the pool,
// negative = pool owes the user.
//   - zeroForOne (sell currency0 for currency1): Amount0 > 0, Amount1 < 0.
//   - !zeroForOne (buy currency0 with currency1): Amount0 < 0, Amount1 > 0.
//
// AmountSpecified < 0 = exact input, > 0 = exact output (V4 convention). The
// CLOB taker size is |AmountSpecified| in base (currency0) units for exact-input
// of a sell / exact-output of a buy; for the cross-cases we still submit the
// magnitude as base size, which is the faithful single-leg CLOB primitive.
func (z *ZAPEngine) Swap(pool *PoolState, params SwapParams) (BalanceDelta, error) {
	// Replay-idempotency is enforced UPSTREAM by the PoolManager against StateDB
	// (durable + consensus-shared), so by the time a Swap reaches this adapter it
	// is the unique submit for its EVM tx. This method therefore stays a pure,
	// stateless forward of one marketable order to the d-chain book.
	id, err := z.poolID(pool)
	if err != nil {
		return ZeroBalanceDelta(), err
	}
	if params.AmountSpecified == nil || params.AmountSpecified.Sign() == 0 {
		return ZeroBalanceDelta(), fmt.Errorf("ZAP Swap: zero amountSpecified")
	}

	size := new(big.Int).Abs(params.AmountSpecified)
	sizeF := bigToFloat(size)
	if sizeF <= 0 {
		return ZeroBalanceDelta(), fmt.Errorf("ZAP Swap: non-positive size")
	}

	// zeroForOne sells currency0 -> CLOB side Sell (1); else Buy (0).
	var side uint8
	if params.ZeroForOne {
		side = 1
	}

	// SqrtPriceLimitX96 becomes a CLOB worst-acceptable price bound. A limit at
	// or beyond the global min/max is treated as a pure market order. A
	// marketable order is IOC server-side: it crosses what it can and the
	// remainder is dropped, never rested (SubmitMarketable on the d-chain).
	limitPrice, isMarket := priceLimitToCLOB(params.ZeroForOne, params.SqrtPriceLimitX96)

	payload := make([]byte, 66)
	copy(payload[0:32], id[:])
	payload[32] = side
	if isMarket {
		payload[33] = 1
	}
	putFloat64(payload[34:42], limitPrice)
	putFloat64(payload[42:50], sizeF)
	// user left zero: the taker identity is the EVM caller, settled on-chain.

	ctx, cancel := context.WithTimeout(context.Background(), z.timeout)
	defer cancel()
	resp, err := z.call(ctx, ZAPMethodSubmit, payload)
	if err != nil {
		return ZeroBalanceDelta(), fmt.Errorf("ZAP Swap: %w", err)
	}

	fills, err := decodeFills(resp)
	if err != nil {
		return ZeroBalanceDelta(), fmt.Errorf("ZAP Swap decode: %w", err)
	}
	delta, err := fillsToDelta(params.ZeroForOne, fills)
	if err != nil {
		return ZeroBalanceDelta(), fmt.Errorf("ZAP Swap delta: %w", err)
	}
	return delta, nil
}

// ModifyLiquidity maps to placing (+delta) or cancelling (-delta) a RESTING
// limit order — "liquidity" in a CLOB is resting orders. The order price is the
// price at TickLower; its side is bid if that price is below the market's
// initialize-time price, ask if above (a single-tick point of liquidity, the
// faithful CLOB analog of a V4 single-tick range).
//
// Returns the caller's BalanceDelta for the resting order (what the LP must post
// to the book) and zero fees: a resting maker order accrues no fee until it is
// taken, which happens via a counterparty's Swap.
func (z *ZAPEngine) ModifyLiquidity(pool *PoolState, owner common.Address, params ModifyLiquidityParams) (BalanceDelta, BalanceDelta, error) {
	id, err := z.poolID(pool)
	if err != nil {
		return ZeroBalanceDelta(), ZeroBalanceDelta(), err
	}
	if params.LiquidityDelta == nil || params.LiquidityDelta.Sign() == 0 {
		return ZeroBalanceDelta(), ZeroBalanceDelta(), fmt.Errorf("ZAP ModifyLiquidity: zero delta")
	}

	ctx, cancel := context.WithTimeout(context.Background(), z.timeout)
	defer cancel()

	price, err := tickToPrice(params.TickLower)
	if err != nil {
		return ZeroBalanceDelta(), ZeroBalanceDelta(), fmt.Errorf("ZAP ModifyLiquidity: %w", err)
	}

	// The maker order handle is derived from the CALLER's own identity (owner),
	// the market, and the position salt — never from caller-supplied raw order
	// bytes. A caller can therefore only address resting orders it placed itself.
	refKey := makerOrderKey(owner, id, params.Salt)

	if params.LiquidityDelta.Sign() < 0 {
		// Cancel: resolve the server orderID through the authenticated handle.
		// Reading it from caller-controlled Salt bytes was an IDOR — any caller
		// could cancel any LP's order by guessing the sequential id (RED H4).
		orderID, ok := z.lookupOrder(refKey, owner)
		if !ok {
			return ZeroBalanceDelta(), ZeroBalanceDelta(), fmt.Errorf("ZAP cancel: no resting order for caller at this position")
		}
		payload := make([]byte, 40)
		copy(payload[0:32], id[:])
		binary.BigEndian.PutUint64(payload[32:40], orderID)
		resp, cerr := z.call(ctx, ZAPMethodCancel, payload)
		if cerr != nil {
			return ZeroBalanceDelta(), ZeroBalanceDelta(), fmt.Errorf("ZAP ModifyLiquidity cancel: %w", cerr)
		}
		if _, status, reason, derr := decodeAck(resp); derr != nil {
			return ZeroBalanceDelta(), ZeroBalanceDelta(), derr
		} else if status == clobStatusRejected {
			return ZeroBalanceDelta(), ZeroBalanceDelta(), fmt.Errorf("ZAP cancel rejected: %s", reason)
		}
		z.forgetOrder(refKey, orderID)
		// Removing liquidity returns funds to the LP: negative delta (pool owes).
		delta := restingOrderDelta(z.side(id, price), price, bigToFloat(new(big.Int).Abs(params.LiquidityDelta)))
		return delta.Negate(), ZeroBalanceDelta(), nil
	}

	// Place a resting limit order.
	side := z.side(id, price)
	sizeF := bigToFloat(params.LiquidityDelta)
	payload := make([]byte, 65)
	copy(payload[0:32], id[:])
	payload[32] = side
	putFloat64(payload[33:41], price)
	putFloat64(payload[41:49], sizeF)
	copy(payload[49:65], owner.Bytes()[:16]) // 16-byte maker identity

	resp, err := z.call(ctx, ZAPMethodPlace, payload)
	if err != nil {
		return ZeroBalanceDelta(), ZeroBalanceDelta(), fmt.Errorf("ZAP ModifyLiquidity place: %w", err)
	}
	orderID, status, reason, derr := decodeAck(resp)
	if derr != nil {
		return ZeroBalanceDelta(), ZeroBalanceDelta(), derr
	}
	if status == clobStatusRejected {
		return ZeroBalanceDelta(), ZeroBalanceDelta(), fmt.Errorf("ZAP place rejected: %s", reason)
	}

	// Bind the server orderID to the authenticated maker handle so only this
	// maker can later cancel exactly this order. The position salt (owner+ticks)
	// keys the handle, so a maker can hold one resting order per V4 position.
	z.recordOrder(refKey, orderID, owner)

	// Posting a resting order requires the LP to fund it: positive delta (LP owes
	// the book).
	delta := restingOrderDelta(side, price, sizeF)
	return delta, ZeroBalanceDelta(), nil
}

// recordOrder binds an authenticated maker handle to the server orderID at place
// time, and records the maker per orderID for the cancel-time re-check.
func (z *ZAPEngine) recordOrder(refKey [32]byte, orderID uint64, maker common.Address) {
	z.mu.Lock()
	z.orderRef[refKey] = orderID
	z.orderMaker[orderID] = maker
	z.mu.Unlock()
}

// lookupOrder resolves the server orderID for an authenticated maker handle and
// re-verifies the recorded maker matches the caller (defense in depth). It
// returns ok=false if no order is bound to this caller's handle.
func (z *ZAPEngine) lookupOrder(refKey [32]byte, caller common.Address) (uint64, bool) {
	z.mu.Lock()
	defer z.mu.Unlock()
	orderID, ok := z.orderRef[refKey]
	if !ok {
		return 0, false
	}
	if maker, ok := z.orderMaker[orderID]; !ok || maker != caller {
		return 0, false
	}
	return orderID, true
}

// forgetOrder drops the binding after a successful cancel so a stale handle
// cannot be replayed against a recycled server orderID.
func (z *ZAPEngine) forgetOrder(refKey [32]byte, orderID uint64) {
	z.mu.Lock()
	delete(z.orderRef, refKey)
	delete(z.orderMaker, orderID)
	z.mu.Unlock()
}

// Donate has no CLOB analog: a central limit order book has no shared liquidity
// pool to gift fees into. It is a no-op that returns a zero delta — never a
// silent value transfer.
func (z *ZAPEngine) Donate(pool *PoolState, amount0, amount1 *big.Int) (BalanceDelta, error) {
	if _, err := z.poolID(pool); err != nil {
		return ZeroBalanceDelta(), err
	}
	return ZeroBalanceDelta(), nil
}

// Quote estimates output for amountIn by reading the resting book's best price.
// It does not mutate the book. A CLOB quote is the marginal price at the top of
// book; without walking depth it is a first-level estimate, used by the router.
func (z *ZAPEngine) Quote(pool *Pool, amountIn *big.Int, zeroForOne bool) *big.Int {
	id, ok := z.poolIDForBase(pool)
	if !ok {
		return big.NewInt(0)
	}
	z.mu.Lock()
	price := z.initPrice[id]
	z.mu.Unlock()
	if price <= 0 || amountIn == nil || amountIn.Sign() <= 0 {
		return big.NewInt(0)
	}
	in := bigToFloat(amountIn)
	var out float64
	if zeroForOne {
		out = in * price // sell base -> quote
	} else {
		out = in / price // buy base with quote
	}
	return roundToBig(out)
}

// poolIDForBase resolves a routing handle from a base *Pool by matching the
// embedded *Pool of a routed PoolState.
func (z *ZAPEngine) poolIDForBase(pool *Pool) ([32]byte, bool) {
	z.mu.Lock()
	defer z.mu.Unlock()
	for ps, id := range z.routes {
		if ps.Pool == pool {
			return id, true
		}
	}
	return [32]byte{}, false
}

// side decides whether a resting order at price rests as a bid (0) or ask (1):
// below the market's reference price -> bid; at/above -> ask.
func (z *ZAPEngine) side(id [32]byte, price float64) uint8 {
	z.mu.Lock()
	ref := z.initPrice[id]
	z.mu.Unlock()
	if ref > 0 && price < ref {
		return 0 // buy / bid
	}
	return 1 // sell / ask
}

// Brand returns the neutral identity. The CLOB matcher advertises no brand on
// the wire, so the ZAP path is always the brand-free fallback.
func (z *ZAPEngine) Brand() string { return brandFallback }

// Close closes the ZAP connection.
func (z *ZAPEngine) Close() error {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.conn != nil {
		err := z.conn.Close()
		z.conn = nil
		return err
	}
	return nil
}

// =========================================================================
// Fill -> BalanceDelta (value-conserving by construction)
// =========================================================================

// fill is one server-produced execution: price (currency1/currency0) and size
// (currency0 base units).
type fill struct {
	price float64
	size  float64
}

// decodeFills parses a clob_submit response: count[4] then count×(price[8] +
// size[8] + side[1]). Every numeric is range-checked: a backend that lies (or a
// MITM on the socket) cannot inject a NaN/Inf or negative fill.
func decodeFills(data []byte) ([]fill, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("fills response too short: %d", len(data))
	}
	n := int(binary.BigEndian.Uint32(data[0:4]))
	if 4+n*fillWireSize > len(data) {
		return nil, fmt.Errorf("fills response truncated: count=%d len=%d", n, len(data))
	}
	fills := make([]fill, 0, n)
	off := 4
	for i := 0; i < n; i++ {
		p := getFloat64(data[off : off+8])
		s := getFloat64(data[off+8 : off+16])
		off += fillWireSize
		if math.IsNaN(p) || math.IsInf(p, 0) || p <= 0 {
			return nil, fmt.Errorf("fill %d: invalid price %v", i, p)
		}
		if math.IsNaN(s) || math.IsInf(s, 0) || s <= 0 {
			return nil, fmt.Errorf("fill %d: invalid size %v", i, s)
		}
		fills = append(fills, fill{price: p, size: s})
	}
	return fills, nil
}

// fillsToDelta turns server-returned fills into the taker's V4 BalanceDelta and
// ASSERTS value conservation: base traded = sum(size); quote traded =
// sum(price*size); both must be non-negative and finite. The two legs are equal
// and opposite across the taker/maker boundary by construction (the taker
// receives exactly what makers give), so the cross-counterparty net is zero —
// we encode the taker's half here and the makers' half is the negation that the
// resting orders represent.
//
// Sign convention (taker):
//   - zeroForOne (sell base): Amount0 = +base (owes pool), Amount1 = -quote.
//   - !zeroForOne (buy base): Amount0 = -base (pool owes), Amount1 = +quote.
//
// DIRECTIONAL ROUNDING — must match the cross-chain proxy leg EXACTLY (RED
// debit!=credit). Fills cross the ZAP wire as float64; both the C-Chain taker
// debit produced HERE and the proxy's cross-chain credit (chains/dexvm
// settleFromFills via quantToCredit/quantToCharge) settle the SAME fill stream,
// so they MUST round with the SAME asymmetric, conservation-safe rule or the two
// legs diverge per fill (a 4.5 notional that this leg round-to-nearests to 5
// while the proxy floors to 4 burns a unit; reverse the fraction and a unit is
// minted). The invariant for BOTH legs: a quantity the taker OWES the pool
// (positive delta) rounds UP (ceil); a quantity the pool OWES the taker
// (negative delta) rounds DOWN in magnitude (floor). The taker is therefore
// never credited a sub-unit it did not realize and never charged less than it
// truly consumed — the EVM leg, like the proxy leg, never mints in the taker's
// favor. Each leg's float aggregate is summed ONCE then rounded ONCE at the
// asset boundary (per-fill rounding would accumulate a directional leak).
func fillsToDelta(zeroForOne bool, fills []fill) (BalanceDelta, error) {
	base := 0.0
	quote := 0.0
	for _, f := range fills {
		base += f.size
		quote += f.price * f.size
	}
	if base < 0 || quote < 0 || math.IsInf(base, 0) || math.IsInf(quote, 0) {
		return ZeroBalanceDelta(), fmt.Errorf("non-conserving fills: base=%v quote=%v", base, quote)
	}

	var amount0, amount1 *big.Int
	if zeroForOne {
		// sell base: taker OWES base (ceil), RECEIVES quote (floor).
		amount0 = ceilToBig(base)
		amount1 = new(big.Int).Neg(floorToBig(quote))
	} else {
		// buy base: taker RECEIVES base (floor), OWES quote (ceil).
		amount0 = new(big.Int).Neg(floorToBig(base))
		amount1 = ceilToBig(quote)
	}
	return NewBalanceDelta(amount0, amount1), nil
}

// restingOrderDelta is the BalanceDelta an LP must post to back a resting order
// of `size` base at `price`. A bid (side 0) funds quote (Amount1); an ask
// (side 1) funds base (Amount0). Positive = LP owes the book. The funded amount
// the LP OWES rounds UP (ceil) — the same conservation-safe direction as an
// owed leg in fillsToDelta — so an LP can never back an order for more value
// than it posted. (The mirror cancel returns this exact delta negated, so the
// place/cancel pair is symmetric and nets to zero for an untaken order.)
func restingOrderDelta(side uint8, price, size float64) BalanceDelta {
	if side == 0 { // bid: post quote = price*size
		return NewBalanceDelta(big.NewInt(0), ceilToBig(price*size))
	}
	// ask: post base = size
	return NewBalanceDelta(ceilToBig(size), big.NewInt(0))
}

// =========================================================================
// V4<->CLOB numeric conversions
// =========================================================================

// sqrtPriceX96ToPrice converts a Q64.96 sqrt price to a float price
// (currency1 per currency0): price = (sqrtP / 2^96)^2.
func sqrtPriceX96ToPrice(sqrtPriceX96 *big.Int) float64 {
	if sqrtPriceX96 == nil || sqrtPriceX96.Sign() <= 0 {
		return 0
	}
	sp := bigToFloat(sqrtPriceX96)
	q96 := math.Ldexp(1, 96) // 2^96
	r := sp / q96
	return r * r
}

// tickToPrice converts a V4 tick to a float price via the shared TickMath.
func tickToPrice(tick int24) (float64, error) {
	sqrtRatio, err := GetSqrtRatioAtTick(tick)
	if err != nil {
		return 0, err
	}
	return sqrtPriceX96ToPrice(sqrtRatio), nil
}

// priceLimitToCLOB converts a V4 SqrtPriceLimitX96 into a CLOB worst-acceptable
// price bound. A limit at/over the global min (zeroForOne) or max (!zeroForOne)
// means "no bound" -> pure market order. Otherwise the bound is the squared
// sqrt-price, the worst price the taker accepts.
func priceLimitToCLOB(zeroForOne bool, limit *big.Int) (price float64, isMarket bool) {
	if limit == nil {
		return 0, true
	}
	if zeroForOne {
		// price decreases; a limit at MinSqrtRatio+1 (or below) is unbounded.
		if limit.Cmp(new(big.Int).Add(MinSqrtRatio, big.NewInt(2))) <= 0 {
			return 0, true
		}
	} else {
		if limit.Cmp(new(big.Int).Sub(MaxSqrtRatio, big.NewInt(2))) >= 0 {
			return 0, true
		}
	}
	return sqrtPriceX96ToPrice(limit), false
}

// bigToFloat converts a big.Int to float64 (the CLOB price grid is float64).
func bigToFloat(v *big.Int) float64 {
	if v == nil {
		return 0
	}
	f, _ := new(big.Float).SetInt(v).Float64()
	return f
}

// settlementRoundEpsilon is the relative tolerance for snapping a float aggregate
// to a neighboring integer before directional floor/ceil. It mirrors the proxy's
// constant of the same name (chains/dexvm atomic.go) so the two settlement legs
// snap identically: ~1e-9 dwarfs the ~1e-13 double-rounding error of summing a
// realistic fill stream yet is far below one asset unit, so it never moves a
// genuinely fractional notional across an integer. Deterministic over
// deterministic float inputs, so every node rounds the same.
const settlementRoundEpsilon = 1e-9

// snapNearInt returns the integer f is within settlementRoundEpsilon of, else f
// unchanged — so a mathematically-integral aggregate (e.g. 1.5*3+2.5*3 == 12 but
// evaluating to 12±1e-13) floors/ceils to that integer rather than to 11/13.
func snapNearInt(f float64) float64 {
	r := math.Round(f)
	if math.Abs(f-r) <= settlementRoundEpsilon*math.Max(1, math.Abs(f)) {
		return r
	}
	return f
}

// floorToBig converts a non-negative float64 to a big.Int rounding DOWN — for a
// quantity the taker/LP RECEIVES (never credit a unit not realized). Mirrors the
// proxy's quantToCredit so the two settlement legs agree to the unit.
func floorToBig(f float64) *big.Int {
	if f <= 0 || math.IsNaN(f) || math.IsInf(f, 0) {
		return big.NewInt(0)
	}
	bf := new(big.Float).SetFloat64(math.Floor(snapNearInt(f)))
	i, _ := bf.Int(nil)
	return i
}

// ceilToBig converts a non-negative float64 to a big.Int rounding UP — for a
// quantity the taker/LP OWES the book (never understate what is owed). Mirrors
// the proxy's quantToCharge so the two settlement legs agree to the unit.
func ceilToBig(f float64) *big.Int {
	if f <= 0 || math.IsNaN(f) || math.IsInf(f, 0) {
		return big.NewInt(0)
	}
	bf := new(big.Float).SetFloat64(math.Ceil(snapNearInt(f)))
	i, _ := bf.Int(nil)
	return i
}

// roundToBig converts a non-negative float64 to a big.Int rounding to nearest.
// Used ONLY for non-settlement estimates (Quote), where neither over- nor
// under-statement touches conservation — it never produces a settlement delta.
func roundToBig(f float64) *big.Int {
	if f <= 0 || math.IsNaN(f) || math.IsInf(f, 0) {
		return big.NewInt(0)
	}
	bf := new(big.Float).SetFloat64(math.Round(f))
	i, _ := bf.Int(nil)
	return i
}

// =========================================================================
// ZAP ack / float wire codec (mirrors dex/pkg/api + maker/dex.go exactly)
// =========================================================================

const (
	clobStatusPlaced   uint8 = 0
	clobStatusCanceled uint8 = 1
	clobStatusRejected uint8 = 2
)

// decodeAck parses an ack/reject: order_id(8)+status(1)+seq(8), or a reject
// order_id(8)+status(1)+len(2)+reason.
func decodeAck(b []byte) (orderID uint64, status uint8, reason string, err error) {
	if len(b) < 9 {
		return 0, 0, "", fmt.Errorf("short ack: %d bytes", len(b))
	}
	orderID = binary.BigEndian.Uint64(b[0:8])
	status = b[8]
	if status == clobStatusRejected && len(b) >= 11 {
		n := int(binary.BigEndian.Uint16(b[9:11]))
		if 11+n <= len(b) {
			reason = string(b[11 : 11+n])
		}
	}
	return orderID, status, reason, nil
}

func putFloat64(b []byte, f float64) {
	binary.BigEndian.PutUint64(b, math.Float64bits(f))
}

func getFloat64(b []byte) float64 {
	return math.Float64frombits(binary.BigEndian.Uint64(b))
}
