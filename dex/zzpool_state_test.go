// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// zzpool_state_test.go covers the pool lifecycle half of pool_manager.go:
// Initialize, ModifyLiquidity, Donate, Flash, the StateDB<->cache discipline
// (getPool / getPoolState / routePool), and the durable cancel authorization
// ModifyLiquidity drives.
//
// The recurring invariant is that StateDB, not process memory, decides what
// exists. The EVM runs one tx ~5x and only the last execution commits, so a
// process cache that outlives a reverted write turns a speculative Initialize
// into a permanent "already initialized" — the exact reason getPool and
// getPoolState re-read StateDB before trusting their caches.

func zzpInit(t *testing.T, pm *PoolManager, db StateDB, key PoolKey) {
	t.Helper()
	if _, err := pm.Initialize(db, key, new(big.Int).Set(Q96), nil); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
}

// =========================================================================
// Initialize
// =========================================================================

func TestZzpInitializeRequiresSortedDistinctCurrencies(t *testing.T) {
	// currency0 < currency1 is what makes a pool key CANONICAL: without it the
	// same market has two ids, so liquidity and price split across two pools and
	// the "already initialized" guard never fires for the mirrored key.
	pm := newTestPoolManager()
	db := NewMockStateDB()

	canonical := zzpKey()
	mirrored := PoolKey{
		Currency0:   canonical.Currency1,
		Currency1:   canonical.Currency0,
		Fee:         canonical.Fee,
		TickSpacing: canonical.TickSpacing,
	}
	if _, err := pm.Initialize(db, mirrored, new(big.Int).Set(Q96), nil); !errors.Is(err, ErrCurrencyNotSorted) {
		t.Errorf("mirrored currency order: got %v, want ErrCurrencyNotSorted", err)
	}
	// A pool of one currency against itself is not a market at all.
	same := PoolKey{Currency0: canonical.Currency1, Currency1: canonical.Currency1, Fee: canonical.Fee, TickSpacing: canonical.TickSpacing}
	if _, err := pm.Initialize(db, same, new(big.Int).Set(Q96), nil); !errors.Is(err, ErrCurrencyNotSorted) {
		t.Errorf("a currency paired with itself: got %v, want ErrCurrencyNotSorted", err)
	}
	// Neither refusal may have committed anything.
	for name, k := range map[string]PoolKey{"mirrored": mirrored, "self-paired": same} {
		if _, err := pm.GetPool(db, k); !errors.Is(err, ErrPoolNotInitialized) {
			t.Errorf("the refused %s key still created a pool", name)
		}
	}
	// The canonical order is accepted.
	if _, err := pm.Initialize(db, canonical, new(big.Int).Set(Q96), nil); err != nil {
		t.Errorf("the canonical currency order was rejected: %v", err)
	}
}

func TestZzpInitializeRejectsOutOfRangeParameters(t *testing.T) {
	pm := newTestPoolManager()
	db := NewMockStateDB()

	over := zzpKey()
	over.Fee = FeeMax + 1
	if _, err := pm.Initialize(db, over, new(big.Int).Set(Q96), nil); !errors.Is(err, ErrInvalidFee) {
		t.Errorf("fee above FeeMax: got %v, want ErrInvalidFee", err)
	}
	// FeeMax itself must be ACCEPTED — the boundary belongs to the valid side.
	atMax := zzpKey()
	atMax.Fee = FeeMax
	if _, err := pm.Initialize(db, atMax, new(big.Int).Set(Q96), nil); err != nil {
		t.Errorf("fee exactly FeeMax: %v, want accepted", err)
	}

	// Price limits: one below the floor and one above the ceiling.
	below := new(big.Int).Sub(MinSqrtRatio, big.NewInt(1))
	if _, err := pm.Initialize(db, zzpKey(), below, nil); !errors.Is(err, ErrInvalidSqrtPrice) {
		t.Errorf("sqrtPrice below MinSqrtRatio: got %v, want ErrInvalidSqrtPrice", err)
	}
	above := new(big.Int).Add(MaxSqrtRatio, big.NewInt(1))
	if _, err := pm.Initialize(db, zzpKey(), above, nil); !errors.Is(err, ErrInvalidSqrtPrice) {
		t.Errorf("sqrtPrice above MaxSqrtRatio: got %v, want ErrInvalidSqrtPrice", err)
	}
	// Both ends of the valid range must be accepted.
	for name, p := range map[string]*big.Int{"MinSqrtRatio": MinSqrtRatio, "MaxSqrtRatio": MaxSqrtRatio} {
		k := zzpKey()
		k.TickSpacing = int24(len(name)) // a distinct pool id per case
		if _, err := pm.Initialize(NewMockStateDB(), k, new(big.Int).Set(p), nil); err != nil {
			t.Errorf("sqrtPrice exactly %s: %v, want accepted", name, err)
		}
	}
}

func TestZzpInitializeRefusesToReopenALivePool(t *testing.T) {
	// Re-initializing a live pool would reset its price and zero its liquidity
	// and fee growth — every LP's accrued position, gone, and the price handed to
	// whoever called last.
	pm := newTestPoolManager()
	db := NewMockStateDB()
	key := zzpKey()
	zzpInit(t, pm, db, key)

	add := ModifyLiquidityParams{TickLower: -120, TickUpper: 120, LiquidityDelta: big.NewInt(1_000_000)}
	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, add, nil); err != nil {
		t.Fatalf("seed liquidity: %v", err)
	}

	elsewhere := new(big.Int).Mul(Q96, big.NewInt(2))
	if _, err := pm.Initialize(db, key, elsewhere, nil); !errors.Is(err, ErrPoolAlreadyInitialized) {
		t.Fatalf("second Initialize: got %v, want ErrPoolAlreadyInitialized", err)
	}
	pool, err := pm.GetPool(db, key)
	if err != nil {
		t.Fatalf("GetPool: %v", err)
	}
	if pool.SqrtPriceX96.Cmp(Q96) != 0 {
		t.Errorf("the refused re-initialize moved the price to %s", pool.SqrtPriceX96)
	}
	if pool.Liquidity.Cmp(big.NewInt(1_000_000)) != 0 {
		t.Errorf("the refused re-initialize left liquidity at %s, want 1000000", pool.Liquidity)
	}
	// And a FRESH manager (no process cache at all) must reach the same verdict
	// from StateDB alone.
	if _, err := newTestPoolManager().Initialize(db, key, elsewhere, nil); !errors.Is(err, ErrPoolAlreadyInitialized) {
		t.Errorf("re-initialize from a cold manager: got %v, want ErrPoolAlreadyInitialized", err)
	}
}

func TestZzpInitializeSurfacesEngineFailure(t *testing.T) {
	boom := errors.New("engine down")
	pm := NewPoolManager(&zzpBadEngine{err: boom})
	db := NewMockStateDB()

	if _, err := pm.Initialize(db, zzpKey(), new(big.Int).Set(Q96), nil); !errors.Is(err, boom) {
		t.Fatalf("engine failure: got %v, want the engine error", err)
	}
	// Nothing was committed, so the pool still does not exist.
	if _, err := pm.GetPool(db, zzpKey()); !errors.Is(err, ErrPoolNotInitialized) {
		t.Errorf("after a failed Initialize the pool exists: %v", err)
	}
}

func TestZzpInitializeTakesTheRouterTickAsAuthoritative(t *testing.T) {
	// With a routing backend the SERVER's tick wins: the local engine's answer is
	// only a placeholder, and a node that kept its own would diverge from the
	// canonical pool.
	router := zzpNewRouter()
	router.initTick = 4_242
	pm := NewPoolManager(router)
	db := NewMockStateDB()
	key := zzpKey()

	tick, err := pm.Initialize(db, key, new(big.Int).Set(Q96), nil)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if tick != 4_242 {
		t.Errorf("returned tick %d, want the router's 4242", tick)
	}
	pool, err := pm.GetPool(db, key)
	if err != nil {
		t.Fatalf("GetPool: %v", err)
	}
	if pool.Tick != 4_242 {
		t.Errorf("persisted tick %d, want the router's 4242", pool.Tick)
	}
	if got, ok := router.routed[pm.poolStates[key.ID()]]; !ok || got != key.ID() {
		t.Error("the pool state was not routed to its canonical pool id")
	}
}

func TestZzpInitializeAbortsOnRouterAndMarketFailure(t *testing.T) {
	boom := errors.New("server refused")

	router := zzpNewRouter()
	router.initErr = boom
	pm := NewPoolManager(router)
	db := NewMockStateDB()
	if _, err := pm.Initialize(db, zzpKey(), new(big.Int).Set(Q96), nil); !errors.Is(err, boom) {
		t.Fatalf("router failure: got %v, want the router error", err)
	}
	if _, err := pm.GetPool(db, zzpKey()); !errors.Is(err, ErrPoolNotInitialized) {
		t.Error("a pool whose canonical creation failed was still committed — a half-built pool")
	}

	// Custody OpenMarket is the other abort: without bound asset handles the
	// D-Chain cannot value-check orders, so a pool that skipped it would accept
	// trades it cannot settle.
	ledger := zzpNewLedger()
	ledger.openErr = boom
	pmc := NewPoolManager(ledger)
	dbc := NewMockStateDB()
	if _, err := pmc.Initialize(dbc, zzpKey(), new(big.Int).Set(Q96), nil); !errors.Is(err, boom) {
		t.Fatalf("OpenMarket failure: got %v, want the market error", err)
	}
	if _, err := pmc.GetPool(dbc, zzpKey()); !errors.Is(err, ErrPoolNotInitialized) {
		t.Error("a pool whose market failed to open was still committed")
	}
}

func TestZzpInitializeOpensTheMarketWithSortedCurrencies(t *testing.T) {
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)
	db := NewMockStateDB()
	key := zzpKey()
	zzpInit(t, pm, db, key)
	if !ledger.opened[key.ID()] {
		t.Fatal("Initialize did not bind the market's asset handles — the D-Chain would fall back to no custody")
	}
}

func TestZzpInitializeRunsHooksWhenTheKeyNamesThem(t *testing.T) {
	pm := newTestPoolManager()
	db := NewMockStateDB()
	key := zzpKey()
	key.Hooks = common.HexToAddress("0x000000000000000000000000000000000000BEEF")
	zzpInit(t, pm, db, key)
	// The hooked pool is a DIFFERENT pool: the hook address is part of the id, so
	// a hookless key must not resolve to it.
	if _, err := pm.GetPool(db, zzpKey()); !errors.Is(err, ErrPoolNotInitialized) {
		t.Error("a hooked pool is reachable through the hookless key — the hook address is not part of the identity")
	}
}

// =========================================================================
// getPool / getPoolState / routePool — StateDB is the authority
// =========================================================================

func TestZzpPoolStateCacheDefersToStateDB(t *testing.T) {
	pm := newTestPoolManager()
	db := NewMockStateDB()
	id := [32]byte{0xAA}

	// Nothing cached and nothing committed: a fresh, uninitialized state.
	ps := pm.getPoolState(db, id, 60, Fee030)
	if ps == nil || ps.Pool.IsInitialized() {
		t.Fatal("getPoolState invented an initialized pool for an uncommitted id")
	}
	if ps.TickSpacing != 60 || ps.LPFee != Fee030 {
		t.Errorf("pool state carries spacing %d fee %d, want 60/%d", ps.TickSpacing, ps.LPFee, Fee030)
	}

	// Now it IS cached, but StateDB still has nothing: the stale entry must be
	// dropped and rebuilt, not served. This is the reverted-Initialize case.
	pm.poolStates[id].LPFee = 999_999 // poison the cache so a stale serve is visible
	again := pm.getPoolState(db, id, 60, Fee030)
	if again.LPFee == 999_999 {
		t.Fatal("a cached pool state contradicted by StateDB was served — a reverted Initialize would look committed")
	}

	// Once committed, the cache IS authoritative (it carries tick-level state the
	// StateDB words do not).
	key := zzpKey()
	zzpInit(t, pm, db, key)
	cached := pm.poolStates[key.ID()]
	if got := pm.getPoolState(db, key.ID(), key.TickSpacing, key.Fee); got != cached {
		t.Error("a committed pool state was rebuilt instead of served from cache — tick state would be lost")
	}
}

func TestZzpGetPoolRestoresEveryPersistedWord(t *testing.T) {
	// setPool/getPool are the LP accounting boundary across a restart: fee growth
	// and protocol fees must survive, or LPs lose accrued fees.
	pm := newTestPoolManager()
	db := NewMockStateDB()
	id := [32]byte{0xBE, 0xEF}

	want := NewPool()
	want.SqrtPriceX96 = new(big.Int).Set(Q96)
	want.Tick = -887_000 // negative, so the int24 word round-trip is exercised
	want.Liquidity = big.NewInt(123_456)
	want.FeeGrowth0X128 = big.NewInt(11)
	want.FeeGrowth1X128 = big.NewInt(22)
	want.ProtocolFees0 = big.NewInt(33)
	want.ProtocolFees1 = big.NewInt(44)
	pm.setPool(db, id, want)

	// A FRESH manager (the restart) must reconstruct the pool from StateDB alone.
	fresh := newTestPoolManager()
	got := fresh.getPool(db, id)
	if got.SqrtPriceX96.Cmp(want.SqrtPriceX96) != 0 {
		t.Errorf("sqrtPrice: got %s, want %s", got.SqrtPriceX96, want.SqrtPriceX96)
	}
	if got.Tick != want.Tick {
		t.Errorf("tick: got %d, want %d", got.Tick, want.Tick)
	}
	for name, pair := range map[string][2]*big.Int{
		"liquidity":    {got.Liquidity, want.Liquidity},
		"feeGrowth0":   {got.FeeGrowth0X128, want.FeeGrowth0X128},
		"feeGrowth1":   {got.FeeGrowth1X128, want.FeeGrowth1X128},
		"protocolFee0": {got.ProtocolFees0, want.ProtocolFees0},
		"protocolFee1": {got.ProtocolFees1, want.ProtocolFees1},
	} {
		if pair[0].Cmp(pair[1]) != 0 {
			t.Errorf("%s did not survive the round-trip: got %s, want %s", name, pair[0], pair[1])
		}
	}
}

func TestZzpRoutePoolAssertsTheRouteEveryCall(t *testing.T) {
	// The cache PoolState may be rebuilt between calls, so the route must be
	// re-asserted on every operation or a later swap forwards to the wrong pool.
	router := zzpNewRouter()
	pm := NewPoolManager(router)
	db := NewMockStateDB()
	key := zzpKey()
	zzpInit(t, pm, db, key)

	ps := pm.poolStates[key.ID()]
	delete(router.routed, ps) // simulate the backend losing the route
	pm.routePool(key.ID(), ps)
	if got, ok := router.routed[ps]; !ok || got != key.ID() {
		t.Error("routePool did not re-assert the route")
	}

	// A backend with no routing seam must be a clean no-op, not a panic.
	NewPoolManager(&mockEngine{}).routePool(key.ID(), ps)
}

func TestZzpGetOrCreateTickIsIdempotent(t *testing.T) {
	ps := NewPoolState(NewPool(), 60, Fee030)
	first := ps.getOrCreateTick(-120)
	if first == nil {
		t.Fatal("getOrCreateTick returned nil")
	}
	if again := ps.getOrCreateTick(-120); again != first {
		t.Error("getOrCreateTick replaced an existing tick — accrued per-tick state would be lost")
	}
	other := ps.getOrCreateTick(120)
	if other == first {
		t.Error("two distinct ticks share one TickInfo")
	}
	if len(ps.Ticks) != 2 {
		t.Errorf("tick map holds %d entries, want 2", len(ps.Ticks))
	}
}

// =========================================================================
// ModifyLiquidity
// =========================================================================

func TestZzpModifyLiquidityRejectsTicksOutsideTheProtocolRange(t *testing.T) {
	pm := newTestPoolManager()
	db := NewMockStateDB()
	key := zzpKey()
	zzpInit(t, pm, db, key)

	for name, p := range map[string]ModifyLiquidityParams{
		"lower below MinTick": {TickLower: MinTick - 1, TickUpper: 0, LiquidityDelta: big.NewInt(1)},
		"upper above MaxTick": {TickLower: 0, TickUpper: MaxTick + 1, LiquidityDelta: big.NewInt(1)},
	} {
		if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, p, nil); !errors.Is(err, ErrTickOutOfRange) {
			t.Errorf("%s: got %v, want ErrTickOutOfRange", name, err)
		}
	}
	// The exact bounds are INSIDE the range and must be accepted.
	full := ModifyLiquidityParams{TickLower: MinTick, TickUpper: MaxTick, LiquidityDelta: big.NewInt(1_000)}
	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, full, nil); err != nil {
		t.Errorf("the full MinTick..MaxTick range was rejected: %v", err)
	}
	// An inverted range and a degenerate one are both refused.
	for name, p := range map[string]ModifyLiquidityParams{
		"equal ticks":    {TickLower: 60, TickUpper: 60, LiquidityDelta: big.NewInt(1)},
		"inverted range": {TickLower: 60, TickUpper: -60, LiquidityDelta: big.NewInt(1)},
	} {
		if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, p, nil); !errors.Is(err, ErrInvalidTickRange) {
			t.Errorf("%s: got %v, want ErrInvalidTickRange", name, err)
		}
	}
}

func TestZzpModifyLiquidityPauseGateLetsLPsExit(t *testing.T) {
	// A frozen pool must not seize principal: freeze halts price discovery, so a
	// BURN stays permitted while a MINT does not. Only the DEX-level kill switch
	// blocks an exit.
	pm := newTestPoolManager()
	db := NewMockStateDB()
	key := zzpKey()
	zzpInit(t, pm, db, key)
	admin := common.Address{} // the default protocolFeeController

	add := ModifyLiquidityParams{TickLower: -120, TickUpper: 120, LiquidityDelta: big.NewInt(1_000_000)}
	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, add, nil); err != nil {
		t.Fatalf("seed add: %v", err)
	}
	burn := ModifyLiquidityParams{TickLower: -120, TickUpper: 120, LiquidityDelta: big.NewInt(-1)}

	if err := pm.FreezePool(db, admin, key.ID()); err != nil {
		t.Fatalf("FreezePool: %v", err)
	}
	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, add, nil); !errors.Is(err, ErrPoolFrozen) {
		t.Errorf("mint on a frozen pool: got %v, want ErrPoolFrozen", err)
	}
	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, burn, nil); err != nil {
		t.Errorf("burn on a frozen pool was blocked (%v) — that is a rug, the LP cannot exit", err)
	}

	// The DEX-level stop blocks BOTH directions; that is the deliberate semantic.
	if err := pm.PauseDEX(db, admin); err != nil {
		t.Fatalf("PauseDEX: %v", err)
	}
	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, burn, nil); !errors.Is(err, ErrDEXPaused) {
		t.Errorf("burn under the DEX-level stop: got %v, want ErrDEXPaused", err)
	}
	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, add, nil); !errors.Is(err, ErrDEXPaused) {
		t.Errorf("mint under the DEX-level stop: got %v, want ErrDEXPaused", err)
	}
}

func TestZzpModifyLiquidityRefusesUnknownPool(t *testing.T) {
	pm := newTestPoolManager()
	db := NewMockStateDB()
	params := ModifyLiquidityParams{TickLower: -120, TickUpper: 120, LiquidityDelta: big.NewInt(1_000)}
	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, zzpKey(), params, nil); !errors.Is(err, ErrPoolNotInitialized) {
		t.Errorf("modify on a pool that was never initialized: got %v, want ErrPoolNotInitialized", err)
	}
}

func TestZzpModifyLiquiditySurfacesEngineFailure(t *testing.T) {
	boom := errors.New("venue refused")
	bad := &zzpBadEngine{err: boom}
	pm := NewPoolManager(bad)
	db := NewMockStateDB()
	key := zzpKey()
	// Initialize with a healthy engine, then swap in the failing one.
	good := newTestPoolManager()
	zzpInit(t, good, db, key)
	pm.pools = good.pools
	pm.poolStates = good.poolStates

	params := ModifyLiquidityParams{TickLower: -120, TickUpper: 120, LiquidityDelta: big.NewInt(1_000)}
	callerDelta, fees, err := pm.ModifyLiquidity(db, zzpAlice, key, params, nil)
	if !errors.Is(err, boom) {
		t.Fatalf("engine failure: got %v, want the engine error", err)
	}
	if !callerDelta.IsZero() || !fees.IsZero() {
		t.Errorf("a failed modify reported deltas %v / %v, want zero", callerDelta, fees)
	}
}

func TestZzpModifyLiquidityIsExactlyOncePerTx(t *testing.T) {
	// A place/cancel is an irreversible venue op. The EVM's repeated executions of
	// one tx must issue it once and return the SAME delta every time.
	pm := newTestPoolManager()
	db := zzpNewTxDB(zzpTx1)
	key := zzpKey()
	zzpInit(t, pm, db, key)

	params := ModifyLiquidityParams{TickLower: -120, TickUpper: 120, LiquidityDelta: big.NewInt(1_000_000)}
	first, _, err := pm.ModifyLiquidity(db, zzpAlice, key, params, nil)
	if err != nil {
		t.Fatalf("first execution: %v", err)
	}
	poolAfterFirst := new(big.Int).Set(pm.getPool(db, key.ID()).Liquidity)

	for i := 0; i < 4; i++ {
		got, _, err := pm.ModifyLiquidity(db, zzpAlice, key, params, nil)
		if err != nil {
			t.Fatalf("re-execution %d: %v", i, err)
		}
		if got.Amount0.Cmp(first.Amount0) != 0 || got.Amount1.Cmp(first.Amount1) != 0 {
			t.Fatalf("re-execution %d returned (%s,%s), first returned (%s,%s)", i, got.Amount0, got.Amount1, first.Amount0, first.Amount1)
		}
	}
	if got := pm.getPool(db, key.ID()).Liquidity; got.Cmp(poolAfterFirst) != 0 {
		t.Fatalf("pool liquidity moved to %s across re-executions of ONE tx (was %s) — the position was added %d times",
			got, poolAfterFirst, new(big.Int).Div(got, big.NewInt(1_000_000)))
	}

	// A genuinely distinct tx is NOT short-circuited.
	db.tx = zzpTx2
	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, params, nil); err != nil {
		t.Fatalf("second genuine tx: %v", err)
	}
	if got := pm.getPool(db, key.ID()).Liquidity; got.Cmp(poolAfterFirst) == 0 {
		t.Fatal("a distinct modify tx was swallowed by the first one's binding")
	}
}

func TestZzpTwoDistinctModifiesInOneTxBothTakeEffect(t *testing.T) {
	// A router or multicall issues several modifyLiquidity calls inside ONE EVM
	// tx. The binding is per (tx, pool, PARAMS), so each distinct position gets
	// its own slot. If it were keyed on the tx and pool alone, the second call
	// would be served from the first's binding and the LP would silently lose
	// the second position.
	pm := newTestPoolManager()
	db := zzpNewTxDB(zzpTx1)
	key := zzpKey()
	zzpInit(t, pm, db, key)

	narrow := ModifyLiquidityParams{TickLower: -60, TickUpper: 60, LiquidityDelta: big.NewInt(400_000), Salt: [32]byte{0x01}}
	wide := ModifyLiquidityParams{TickLower: -120, TickUpper: 120, LiquidityDelta: big.NewInt(700_000), Salt: [32]byte{0x02}}

	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, narrow, nil); err != nil {
		t.Fatalf("first position: %v", err)
	}
	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, wide, nil); err != nil {
		t.Fatalf("second position: %v", err)
	}

	fresh := newTestPoolManager()
	for name, p := range map[string]ModifyLiquidityParams{"narrow": narrow, "wide": wide} {
		pos, err := fresh.GetPosition(db, key, zzpAlice, p.TickLower, p.TickUpper, p.Salt)
		if err != nil {
			t.Fatalf("GetPosition(%s): %v", name, err)
		}
		if pos.Liquidity.Cmp(p.LiquidityDelta) != 0 {
			t.Errorf("%s position holds %s, want %s — the second call in the tx collided with the first's binding",
				name, pos.Liquidity, p.LiquidityDelta)
		}
	}
	// Both positions are in range, so the pool carries the sum.
	if got := fresh.getPool(db, key.ID()).Liquidity; got.Cmp(big.NewInt(1_100_000)) != 0 {
		t.Errorf("pool liquidity %s, want 1100000 (both positions)", got)
	}
}

func TestZzpModifyLiquidityRunsHooksOnBothDirections(t *testing.T) {
	pm := newTestPoolManager()
	db := NewMockStateDB()
	key := zzpKey()
	key.Hooks = common.HexToAddress("0x000000000000000000000000000000000000BEEF")
	zzpInit(t, pm, db, key)

	add := ModifyLiquidityParams{TickLower: -120, TickUpper: 120, LiquidityDelta: big.NewInt(1_000_000)}
	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, add, []byte("hook payload")); err != nil {
		t.Fatalf("hooked add: %v", err)
	}
	remove := ModifyLiquidityParams{TickLower: -120, TickUpper: 120, LiquidityDelta: big.NewInt(-500_000)}
	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, remove, []byte("hook payload")); err != nil {
		t.Fatalf("hooked remove: %v", err)
	}
	if got := pm.getPool(db, key.ID()).Liquidity; got.Cmp(big.NewInt(500_000)) != 0 {
		t.Errorf("pool liquidity after add 1000000 / remove 500000: got %s, want 500000", got)
	}
}

func TestZzpModifyLiquidityPersistsThePosition(t *testing.T) {
	pm := newTestPoolManager()
	db := NewMockStateDB()
	key := zzpKey()
	zzpInit(t, pm, db, key)

	salt := [32]byte{0x5A}
	params := ModifyLiquidityParams{TickLower: -120, TickUpper: 120, LiquidityDelta: big.NewInt(750_000), Salt: salt}
	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, params, nil); err != nil {
		t.Fatalf("add: %v", err)
	}
	// A FRESH manager (the restart) must find the position in StateDB.
	fresh := newTestPoolManager()
	pos, err := fresh.GetPosition(db, key, zzpAlice, params.TickLower, params.TickUpper, salt)
	if err != nil {
		t.Fatalf("GetPosition: %v", err)
	}
	if pos.Liquidity.Cmp(big.NewInt(750_000)) != 0 {
		t.Errorf("persisted position liquidity: got %s, want 750000", pos.Liquidity)
	}
	// The POOL's active liquidity must survive the same restart: the position and
	// the pool total are written together, and a pool that forgot the total would
	// price every later swap against liquidity it does not know it has.
	if got := fresh.getPool(db, key.ID()).Liquidity; got.Cmp(big.NewInt(750_000)) != 0 {
		t.Errorf("persisted pool liquidity: got %s, want 750000", got)
	}
	// Another owner's handle at the same ticks is a DIFFERENT position.
	other, _ := fresh.GetPosition(db, key, zzpBob, params.TickLower, params.TickUpper, salt)
	if other.Liquidity.Sign() != 0 {
		t.Errorf("another owner reads %s of Alice's position", other.Liquidity)
	}
	// So is the same owner with a different salt.
	saltB, _ := fresh.GetPosition(db, key, zzpAlice, params.TickLower, params.TickUpper, [32]byte{0x5B})
	if saltB.Liquidity.Sign() != 0 {
		t.Errorf("a different salt reads %s of the original position", saltB.Liquidity)
	}
}

// =========================================================================
// ModifyLiquidity — durable cancel authorization (the IDOR gate)
// =========================================================================

func TestZzpCancelRequiresADurableBindingForThisCaller(t *testing.T) {
	auth := zzpNewAuth()
	pm := NewPoolManager(auth)
	db := zzpNewTxDB(zzpTx1)
	key := zzpKey()
	zzpInit(t, pm, db, key)
	salt := [32]byte{0x5A}

	// A cancel with nothing placed must be refused WITHOUT reaching the backend.
	cancel := ModifyLiquidityParams{TickLower: -120, TickUpper: 120, LiquidityDelta: big.NewInt(-1_000), Salt: salt}
	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, cancel, nil); err == nil {
		t.Fatal("a cancel with no resting order was accepted")
	}

	// Place: the durable binding is written from the backend's handle.
	place := ModifyLiquidityParams{TickLower: -120, TickUpper: 120, LiquidityDelta: big.NewInt(1_000), Salt: salt}
	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, place, nil); err != nil {
		t.Fatalf("place: %v", err)
	}
	orderID, ok := loadCancelAuth(db, zzpAlice, key.ID(), salt)
	if !ok || orderID != auth.nextID {
		t.Fatalf("after a place the durable binding is id=%d ok=%v, want %d true", orderID, ok, auth.nextID)
	}

	// IDOR: Bob, forging Alice's salt, has no binding under HIS address.
	db.tx = zzpTx2
	if _, _, err := pm.ModifyLiquidity(db, zzpBob, key, cancel, nil); err == nil {
		t.Fatal("another maker cancelled Alice's resting order using her salt — the IDOR is open")
	}

	// Alice's own cancel resolves through the durable binding, which is seeded
	// into the backend cache (the place's in-memory binding does not survive).
	auth.seeded = map[string]uint64{}
	db.tx = common.HexToHash("0x33")
	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, cancel, nil); err != nil {
		t.Fatalf("the owner's cancel: %v", err)
	}
	if got, ok := auth.seeded[zzpHandleKey(zzpAlice, key.ID(), salt)]; !ok || got != orderID {
		t.Errorf("the backend cache was not primed from the durable binding: got %d ok=%v", got, ok)
	}
	// Consumed: the binding is cleared so a stale handle cannot be replayed
	// against a recycled server order id.
	if _, ok := loadCancelAuth(db, zzpAlice, key.ID(), salt); ok {
		t.Fatal("the cancel authorization survived the cancel — a stale handle is replayable")
	}
	db.tx = common.HexToHash("0x44")
	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, cancel, nil); err == nil {
		t.Fatal("the same cancel was accepted a second time")
	}
}

func TestZzpPlaceWithoutABackendHandleStoresNoAuthorization(t *testing.T) {
	// A backend that placed but exposes no handle must leave NO durable binding —
	// otherwise a later cancel would be authorized against an unknown order.
	auth := zzpNewAuth()
	auth.bindPlace = false
	pm := NewPoolManager(auth)
	db := zzpNewTxDB(zzpTx1)
	key := zzpKey()
	zzpInit(t, pm, db, key)
	salt := [32]byte{0x77}

	place := ModifyLiquidityParams{TickLower: -120, TickUpper: 120, LiquidityDelta: big.NewInt(1_000), Salt: salt}
	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, place, nil); err != nil {
		t.Fatalf("place: %v", err)
	}
	if _, ok := loadCancelAuth(db, zzpAlice, key.ID(), salt); ok {
		t.Fatal("a place with no backend handle still wrote a cancel authorization")
	}
}

// =========================================================================
// Donate / Flash
// =========================================================================

func TestZzpDonateGatesAndDelegates(t *testing.T) {
	pm := newTestPoolManager()
	db := NewMockStateDB()
	key := zzpKey()

	// Unknown pool.
	if _, err := pm.Donate(db, zzpAlice, key, big.NewInt(1), big.NewInt(1)); !errors.Is(err, ErrPoolNotInitialized) {
		t.Errorf("donate to an uninitialized pool: got %v, want ErrPoolNotInitialized", err)
	}

	zzpInit(t, pm, db, key)
	// A pool with no liquidity has no LPs to donate to.
	if _, err := pm.Donate(db, zzpAlice, key, big.NewInt(1), big.NewInt(1)); !errors.Is(err, ErrNoLiquidity) {
		t.Errorf("donate to an empty pool: got %v, want ErrNoLiquidity", err)
	}

	add := ModifyLiquidityParams{TickLower: -120, TickUpper: 120, LiquidityDelta: big.NewInt(1_000_000)}
	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, add, nil); err != nil {
		t.Fatalf("seed liquidity: %v", err)
	}

	// The variadic hookData argument is optional; supplying it must not change
	// the outcome (there is exactly one donate path).
	got, err := pm.Donate(db, zzpAlice, key, big.NewInt(10), big.NewInt(20), []byte("payload"))
	if err != nil {
		t.Fatalf("donate with hook data: %v", err)
	}
	if got.Amount0.Cmp(big.NewInt(10)) != 0 || got.Amount1.Cmp(big.NewInt(20)) != 0 {
		t.Errorf("donate delta (%s,%s), want (10,20)", got.Amount0, got.Amount1)
	}

	// The pause gate is checked BEFORE any state read.
	if err := pm.PausePool(db, common.Address{}, key.ID()); err != nil {
		t.Fatalf("PausePool: %v", err)
	}
	if _, err := pm.Donate(db, zzpAlice, key, big.NewInt(1), big.NewInt(1)); !errors.Is(err, ErrPoolPaused) {
		t.Errorf("donate to a paused pool: got %v, want ErrPoolPaused", err)
	}
}

func TestZzpDonateRunsHooksAndSurfacesEngineFailure(t *testing.T) {
	pm := newTestPoolManager()
	db := NewMockStateDB()
	key := zzpKey()
	key.Hooks = common.HexToAddress("0x000000000000000000000000000000000000BEEF")
	zzpInit(t, pm, db, key)
	add := ModifyLiquidityParams{TickLower: -120, TickUpper: 120, LiquidityDelta: big.NewInt(1_000_000)}
	if _, _, err := pm.ModifyLiquidity(db, zzpAlice, key, add, nil); err != nil {
		t.Fatalf("seed liquidity: %v", err)
	}
	if _, err := pm.Donate(db, zzpAlice, key, big.NewInt(5), big.NewInt(5), []byte("payload")); err != nil {
		t.Fatalf("hooked donate: %v", err)
	}

	boom := errors.New("venue refused")
	bad := NewPoolManager(&zzpBadEngine{err: boom})
	bad.pools = pm.pools
	bad.poolStates = pm.poolStates
	if _, err := bad.Donate(db, zzpAlice, key, big.NewInt(5), big.NewInt(5)); !errors.Is(err, boom) {
		t.Errorf("engine failure: got %v, want the engine error", err)
	}
}

func TestZzpFlashGatesAndChargesAFee(t *testing.T) {
	pm := newTestPoolManager()
	db := NewMockStateDB()
	key := zzpKey()

	params := FlashParams{Amount0: big.NewInt(1_000_000), Amount1: big.NewInt(0), Recipient: zzpAlice}
	if _, err := pm.Flash(db, zzpAlice, key, params, nil); !errors.Is(err, ErrPoolNotInitialized) {
		t.Errorf("flash on an uninitialized pool: got %v, want ErrPoolNotInitialized", err)
	}

	zzpInit(t, pm, db, key)
	delta, err := pm.Flash(db, zzpAlice, key, params, nil)
	if err != nil {
		t.Fatalf("flash: %v", err)
	}
	// The borrower owes principal + fee: strictly MORE than borrowed on the leg
	// that was drawn, and exactly zero on the leg that was not.
	if delta.Amount0.Cmp(params.Amount0) <= 0 {
		t.Errorf("owed %s for a %s loan — a flash loan that costs nothing is free leverage", delta.Amount0, params.Amount0)
	}
	if delta.Amount1.Sign() != 0 {
		t.Errorf("an undrawn leg owes %s, want 0", delta.Amount1)
	}

	if err := pm.PauseDEX(db, common.Address{}); err != nil {
		t.Fatalf("PauseDEX: %v", err)
	}
	if _, err := pm.Flash(db, zzpAlice, key, params, nil); !errors.Is(err, ErrDEXPaused) {
		t.Errorf("flash under the DEX-level stop: got %v, want ErrDEXPaused", err)
	}
}

func TestZzpFlashFeeRoundingDirection(t *testing.T) {
	// fee = amount * feePips / 1e6, and the division is a plain Div — it TRUNCATES
	// toward zero, so the borrower is charged the FLOOR. That direction favours the
	// BORROWER, not the pool (Uniswap V3 charges the ceiling here, mulDivRoundingUp).
	// This test states the direction the code actually implements, exactly, so the
	// day it is changed the change is visible rather than silent.
	pm := newTestPoolManager()

	if got := pm.calculateFlashFee(big.NewInt(0), Fee030); got.Sign() != 0 {
		t.Errorf("fee on a zero loan: got %s, want 0", got)
	}
	if got := pm.calculateFlashFee(big.NewInt(-1), Fee030); got.Sign() != 0 {
		t.Errorf("fee on a negative loan: got %s, want 0", got)
	}
	for _, amount := range []int64{1, 333, 1_000_000, 333_333, 7, 999_999_999} {
		got := pm.calculateFlashFee(big.NewInt(amount), Fee030)
		exactNum := new(big.Int).Mul(big.NewInt(amount), big.NewInt(int64(Fee030)))
		floor := new(big.Int).Div(exactNum, big.NewInt(1_000_000))
		if got.Cmp(floor) != 0 {
			t.Errorf("fee(%d): got %s, want the floor %s", amount, got, floor)
		}
		// The fee is never negative and never exceeds the principal.
		if got.Sign() < 0 || got.Cmp(big.NewInt(amount)) > 0 {
			t.Errorf("fee(%d) = %s is out of range", amount, got)
		}
	}
	// The consequence of flooring: any loan smaller than 1e6/feePips is FREE.
	// At 3000 pips that is every loan below 334 units.
	if got := pm.calculateFlashFee(big.NewInt(333), Fee030); got.Sign() != 0 {
		t.Errorf("fee(333) = %s; the floor makes sub-334 loans free at 0.30%%", got)
	}
	if got := pm.calculateFlashFee(big.NewInt(334), Fee030); got.Sign() == 0 {
		t.Error("fee(334) = 0; the first chargeable loan at 0.30% must not be free")
	}
}

// =========================================================================
// Pause / Freeze — the uninitialized-pool guard
// =========================================================================

func TestZzpPauseControlsRefuseUnknownPools(t *testing.T) {
	// Poisoning the pause slot of a never-initialized pool would leave a future
	// Initialize of that id permanently pre-paused with no way back.
	pm := newTestPoolManager()
	db := NewMockStateDB()
	admin := common.Address{}
	ghost := [32]byte{0xDE, 0xAD}

	for name, call := range map[string]func() error{
		"PausePool":  func() error { return pm.PausePool(db, admin, ghost) },
		"ResumePool": func() error { return pm.ResumePool(db, admin, ghost) },
		"FreezePool": func() error { return pm.FreezePool(db, admin, ghost) },
	} {
		if err := call(); !errors.Is(err, ErrPoolNotInitialized) {
			t.Errorf("%s on an unknown pool: got %v, want ErrPoolNotInitialized", name, err)
		}
	}
	if isPoolPaused(db, ghost) || isPoolFrozen(db, ghost) {
		t.Fatal("a refused admin call still poisoned the pool's pause/freeze slots")
	}

	// A non-admin is refused before anything else is even read.
	if err := pm.PausePool(db, zzpBob, ghost); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("PausePool by a non-admin: got %v, want ErrUnauthorized", err)
	}
}

func TestZzpGetPoolReportsUnknownPools(t *testing.T) {
	pm := newTestPoolManager()
	db := NewMockStateDB()
	if _, err := pm.GetPool(db, zzpKey()); !errors.Is(err, ErrPoolNotInitialized) {
		t.Errorf("GetPool on an unknown pool: got %v, want ErrPoolNotInitialized", err)
	}
}
