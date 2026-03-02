// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/geth/common"
)

// =========================================================================
// ExportState Tests
// =========================================================================

func TestExportStateEmpty(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()

	snap, err := pm.ExportState(stateDB)
	if err != nil {
		t.Fatalf("ExportState failed: %v", err)
	}
	if snap.Version != SnapshotVersion {
		t.Errorf("expected version %d, got %d", SnapshotVersion, snap.Version)
	}
	if len(snap.Pools) != 0 {
		t.Errorf("expected 0 pools, got %d", len(snap.Pools))
	}
	if snap.BlockNum != 1 {
		t.Errorf("expected block 1, got %d", snap.BlockNum)
	}
}

func TestExportStateWithPool(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()

	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000)

	snap, err := pm.ExportState(stateDB)
	if err != nil {
		t.Fatalf("ExportState failed: %v", err)
	}
	if len(snap.Pools) != 1 {
		t.Fatalf("expected 1 pool, got %d", len(snap.Pools))
	}

	poolSnap := snap.Pools[0]
	if poolSnap.Tick != 0 {
		t.Errorf("expected tick 0, got %d", poolSnap.Tick)
	}
	if poolSnap.Liquidity != "1000000" {
		t.Errorf("expected liquidity 1000000, got %s", poolSnap.Liquidity)
	}
	if poolSnap.TickSpacing != TickSpacing030 {
		t.Errorf("expected tick spacing %d, got %d", TickSpacing030, poolSnap.TickSpacing)
	}

	t.Logf("Exported pool: ID=%s, tick=%d, liquidity=%s, positions=%d, ticks=%d",
		poolSnap.PoolID, poolSnap.Tick, poolSnap.Liquidity,
		len(poolSnap.Positions), len(poolSnap.Ticks))
}

func TestExportStateWithPositions(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	sqrtPriceX96 := new(big.Int).Set(Q96)
	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Add two positions at different tick ranges
	params1 := ModifyLiquidityParams{
		TickLower:      -120,
		TickUpper:      120,
		LiquidityDelta: big.NewInt(500_000),
	}
	_, _, err = pm.ModifyLiquidity(stateDB, caller, key, params1, nil)
	if err != nil {
		t.Fatalf("ModifyLiquidity 1 failed: %v", err)
	}

	caller2 := common.HexToAddress("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	params2 := ModifyLiquidityParams{
		TickLower:      -240,
		TickUpper:      240,
		LiquidityDelta: big.NewInt(300_000),
	}
	_, _, err = pm.ModifyLiquidity(stateDB, caller2, key, params2, nil)
	if err != nil {
		t.Fatalf("ModifyLiquidity 2 failed: %v", err)
	}

	snap, err := pm.ExportState(stateDB)
	if err != nil {
		t.Fatalf("ExportState failed: %v", err)
	}
	if len(snap.Pools) != 1 {
		t.Fatalf("expected 1 pool, got %d", len(snap.Pools))
	}
	if len(snap.Pools[0].Positions) != 2 {
		t.Fatalf("expected 2 positions, got %d", len(snap.Pools[0].Positions))
	}

	t.Logf("Position 1: owner=%s, liquidity=%s",
		snap.Pools[0].Positions[0].Owner, snap.Pools[0].Positions[0].Liquidity)
	t.Logf("Position 2: owner=%s, liquidity=%s",
		snap.Pools[0].Positions[1].Owner, snap.Pools[0].Positions[1].Liquidity)
}

// =========================================================================
// Import/Export Roundtrip Tests
// =========================================================================

func TestExportImportRoundtrip(t *testing.T) {
	// Setup: create pool with liquidity and do a swap
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()

	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000)

	// Do a swap to change state
	swapParams := SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(-1000),
		SqrtPriceLimitX96: new(big.Int).Add(MinSqrtRatio, big.NewInt(1)),
	}
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")
	_, err := pm.Swap(stateDB, caller, key, swapParams, nil)
	if err != nil {
		t.Fatalf("Swap failed: %v", err)
	}

	// Export
	snap, err := pm.ExportState(stateDB)
	if err != nil {
		t.Fatalf("ExportState failed: %v", err)
	}

	// Record state before import
	poolBefore, _ := pm.GetPool(stateDB, key)
	sqrtPriceBefore := new(big.Int).Set(poolBefore.SqrtPriceX96)
	liqBefore := new(big.Int).Set(poolBefore.Liquidity)
	tickBefore := poolBefore.Tick
	fg0Before := new(big.Int).Set(poolBefore.FeeGrowth0X128)

	// Create new pool manager and import
	pm2 := NewPoolManager(&mockEngine{})
	stateDB2 := NewMockStateDB()
	err = pm2.ImportState(stateDB2, snap)
	if err != nil {
		t.Fatalf("ImportState failed: %v", err)
	}

	// Verify pool state matches
	poolAfter, err := pm2.GetPool(stateDB2, key)
	if err != nil {
		t.Fatalf("GetPool after import failed: %v", err)
	}

	if poolAfter.SqrtPriceX96.Cmp(sqrtPriceBefore) != 0 {
		t.Errorf("SqrtPriceX96 mismatch: got %s, want %s", poolAfter.SqrtPriceX96, sqrtPriceBefore)
	}
	if poolAfter.Tick != tickBefore {
		t.Errorf("Tick mismatch: got %d, want %d", poolAfter.Tick, tickBefore)
	}
	if poolAfter.Liquidity.Cmp(liqBefore) != 0 {
		t.Errorf("Liquidity mismatch: got %s, want %s", poolAfter.Liquidity, liqBefore)
	}
	if poolAfter.FeeGrowth0X128.Cmp(fg0Before) != 0 {
		t.Errorf("FeeGrowth0X128 mismatch: got %s, want %s", poolAfter.FeeGrowth0X128, fg0Before)
	}

	t.Logf("Roundtrip successful: price=%s, tick=%d, liquidity=%s",
		poolAfter.SqrtPriceX96, poolAfter.Tick, poolAfter.Liquidity)
}

func TestExportImportMultiplePools(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()

	// Create two pools with different parameters
	key1 := PoolKey{
		Currency0:   NativeCurrency,
		Currency1:   Currency{Address: common.HexToAddress("0x1111111111111111111111111111111111111111")},
		Fee:         Fee030,
		TickSpacing: TickSpacing030,
	}
	key2 := PoolKey{
		Currency0:   NativeCurrency,
		Currency1:   Currency{Address: common.HexToAddress("0x2222222222222222222222222222222222222222")},
		Fee:         Fee005,
		TickSpacing: TickSpacing005,
	}

	initPoolWithLiquidityKey(t, pm, stateDB, key1, 1_000_000)
	initPoolWithLiquidityKey(t, pm, stateDB, key2, 2_000_000)

	snap, err := pm.ExportState(stateDB)
	if err != nil {
		t.Fatalf("ExportState failed: %v", err)
	}
	if len(snap.Pools) != 2 {
		t.Fatalf("expected 2 pools, got %d", len(snap.Pools))
	}

	pm2 := NewPoolManager(&mockEngine{})
	stateDB2 := NewMockStateDB()
	err = pm2.ImportState(stateDB2, snap)
	if err != nil {
		t.Fatalf("ImportState failed: %v", err)
	}

	pool1, err := pm2.GetPool(stateDB2, key1)
	if err != nil {
		t.Fatalf("GetPool key1 after import: %v", err)
	}
	pool2, err := pm2.GetPool(stateDB2, key2)
	if err != nil {
		t.Fatalf("GetPool key2 after import: %v", err)
	}

	if pool1.Liquidity.Cmp(big.NewInt(1_000_000)) != 0 {
		t.Errorf("pool1 liquidity mismatch: got %s, want 1000000", pool1.Liquidity)
	}
	if pool2.Liquidity.Cmp(big.NewInt(2_000_000)) != 0 {
		t.Errorf("pool2 liquidity mismatch: got %s, want 2000000", pool2.Liquidity)
	}

	t.Logf("Multi-pool roundtrip: pool1 liq=%s, pool2 liq=%s", pool1.Liquidity, pool2.Liquidity)
}

// =========================================================================
// ZapDB Write/Read Roundtrip Tests
// =========================================================================

func TestZapDBWriteReadRoundtrip(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()

	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000)

	// Export to snapshot
	snap, err := pm.ExportState(stateDB)
	if err != nil {
		t.Fatalf("ExportState failed: %v", err)
	}

	// Write to memdb (same interface as ZapDB)
	db := memdb.New()
	defer db.Close()

	err = WriteToZapDB(db, snap)
	if err != nil {
		t.Fatalf("WriteToZapDB failed: %v", err)
	}

	// Read back
	snapRead, err := ReadFromZapDB(db)
	if err != nil {
		t.Fatalf("ReadFromZapDB failed: %v", err)
	}

	if snapRead.Version != snap.Version {
		t.Errorf("version mismatch: got %d, want %d", snapRead.Version, snap.Version)
	}
	if snapRead.BlockNum != snap.BlockNum {
		t.Errorf("block mismatch: got %d, want %d", snapRead.BlockNum, snap.BlockNum)
	}
	if len(snapRead.Pools) != len(snap.Pools) {
		t.Fatalf("pool count mismatch: got %d, want %d", len(snapRead.Pools), len(snap.Pools))
	}

	// Verify pool data survived the roundtrip
	for i, pool := range snapRead.Pools {
		orig := snap.Pools[i]
		if pool.PoolID != orig.PoolID {
			t.Errorf("pool[%d] ID mismatch: got %s, want %s", i, pool.PoolID, orig.PoolID)
		}
		if pool.Liquidity != orig.Liquidity {
			t.Errorf("pool[%d] liquidity mismatch: got %s, want %s", i, pool.Liquidity, orig.Liquidity)
		}
		if pool.Tick != orig.Tick {
			t.Errorf("pool[%d] tick mismatch: got %d, want %d", i, pool.Tick, orig.Tick)
		}
		if len(pool.Positions) != len(orig.Positions) {
			t.Errorf("pool[%d] position count mismatch: got %d, want %d",
				i, len(pool.Positions), len(orig.Positions))
		}
	}

	t.Logf("ZapDB roundtrip successful: %d pools, block=%d", len(snapRead.Pools), snapRead.BlockNum)
}

func TestZapDBFullRoundtrip(t *testing.T) {
	// Full path: PoolManager -> ExportState -> WriteToZapDB -> ReadFromZapDB -> ImportState -> verify
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()

	initPoolWithLiquidity(t, pm, stateDB, key, 5_000_000)

	// Do a swap to generate fee state
	swapParams := SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(-50_000),
		SqrtPriceLimitX96: new(big.Int).Add(MinSqrtRatio, big.NewInt(1)),
	}
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")
	_, err := pm.Swap(stateDB, caller, key, swapParams, nil)
	if err != nil {
		t.Fatalf("Swap failed: %v", err)
	}

	pool1, _ := pm.GetPool(stateDB, key)
	origPrice := pool1.SqrtPriceX96.String()
	origTick := pool1.Tick
	origLiq := pool1.Liquidity.String()

	// Export -> ZapDB -> Read -> Import
	snap, err := pm.ExportState(stateDB)
	if err != nil {
		t.Fatalf("ExportState failed: %v", err)
	}

	db := memdb.New()
	defer db.Close()
	if err := WriteToZapDB(db, snap); err != nil {
		t.Fatalf("WriteToZapDB failed: %v", err)
	}

	snapRead, err := ReadFromZapDB(db)
	if err != nil {
		t.Fatalf("ReadFromZapDB failed: %v", err)
	}

	pm2 := NewPoolManager(&mockEngine{})
	stateDB2 := NewMockStateDB()
	if err := pm2.ImportState(stateDB2, snapRead); err != nil {
		t.Fatalf("ImportState failed: %v", err)
	}

	pool2, err := pm2.GetPool(stateDB2, key)
	if err != nil {
		t.Fatalf("GetPool after full roundtrip: %v", err)
	}

	if pool2.SqrtPriceX96.String() != origPrice {
		t.Errorf("price mismatch: got %s, want %s", pool2.SqrtPriceX96, origPrice)
	}
	if pool2.Tick != origTick {
		t.Errorf("tick mismatch: got %d, want %d", pool2.Tick, origTick)
	}
	if pool2.Liquidity.String() != origLiq {
		t.Errorf("liquidity mismatch: got %s, want %s", pool2.Liquidity, origLiq)
	}

	t.Logf("Full ZapDB roundtrip: price=%s tick=%d liq=%s", origPrice, origTick, origLiq)
}

// =========================================================================
// Import Validation Tests
// =========================================================================

func TestImportRejectsWrongVersion(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()

	snap := &DEXStateSnapshot{
		Version: 999,
	}
	err := pm.ImportState(stateDB, snap)
	if err == nil {
		t.Fatal("expected version mismatch error")
	}
	t.Logf("Correctly rejected: %v", err)
}

func TestImportAtomicity(t *testing.T) {
	// Import with valid pools should succeed atomically
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()

	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000)

	snap, err := pm.ExportState(stateDB)
	if err != nil {
		t.Fatalf("ExportState failed: %v", err)
	}

	// Import into fresh manager
	pm2 := NewPoolManager(&mockEngine{})
	stateDB2 := NewMockStateDB()
	err = pm2.ImportState(stateDB2, snap)
	if err != nil {
		t.Fatalf("ImportState failed: %v", err)
	}

	// Verify the pool was imported
	pool, err := pm2.GetPool(stateDB2, key)
	if err != nil {
		t.Fatalf("pool not found after import: %v", err)
	}
	if pool.Liquidity.Cmp(big.NewInt(1_000_000)) != 0 {
		t.Errorf("expected liquidity 1000000, got %s", pool.Liquidity)
	}
}

// =========================================================================
// ExportPoolState Tests
// =========================================================================

func TestExportSinglePool(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()

	initPoolWithLiquidity(t, pm, stateDB, key, 750_000)

	poolSnap, err := pm.ExportPoolState(stateDB, key)
	if err != nil {
		t.Fatalf("ExportPoolState failed: %v", err)
	}

	if poolSnap.Liquidity != "750000" {
		t.Errorf("expected liquidity 750000, got %s", poolSnap.Liquidity)
	}
	if poolSnap.TickSpacing != TickSpacing030 {
		t.Errorf("expected tick spacing %d, got %d", TickSpacing030, poolSnap.TickSpacing)
	}

	t.Logf("Single pool export: ID=%s, liquidity=%s", poolSnap.PoolID, poolSnap.Liquidity)
}

func TestExportSinglePoolNotFound(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()

	key := newTestPoolKey()
	_, err := pm.ExportPoolState(stateDB, key)
	if err != ErrPoolNotFound {
		t.Errorf("expected ErrPoolNotFound, got: %v", err)
	}
}

// =========================================================================
// StateExporter Tests
// =========================================================================

func TestStateExporterExport(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()

	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000)

	db := memdb.New()
	defer db.Close()

	exporter := NewStateExporter(pm, db)
	err := exporter.Export(stateDB)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Verify data was written to db
	snap, err := ReadFromZapDB(db)
	if err != nil {
		t.Fatalf("ReadFromZapDB failed: %v", err)
	}
	if len(snap.Pools) != 1 {
		t.Fatalf("expected 1 pool in db, got %d", len(snap.Pools))
	}

	t.Logf("StateExporter: wrote %d pools to ZapDB", len(snap.Pools))
}

// =========================================================================
// Serialization Helpers
// =========================================================================

func TestBigIntSerialization(t *testing.T) {
	cases := []struct {
		name string
		val  *big.Int
	}{
		{"zero", big.NewInt(0)},
		{"positive", big.NewInt(123456789)},
		{"large", new(big.Int).Mul(big.NewInt(1e18), big.NewInt(1e18))},
		{"nil", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := bigIntToStr(tc.val)
			result := strToBigInt(s)

			expected := tc.val
			if expected == nil {
				expected = big.NewInt(0)
			}

			if result.Cmp(expected) != 0 {
				t.Errorf("roundtrip failed: got %s, want %s", result, expected)
			}
		})
	}
}

// =========================================================================
// Test Helpers
// =========================================================================

// initPoolWithLiquidityKey is like initPoolWithLiquidity but with an explicit key.
func initPoolWithLiquidityKey(t *testing.T, pm *PoolManager, stateDB *MockStateDB, key PoolKey, liq int64) {
	t.Helper()

	sqrtPriceX96 := new(big.Int).Set(Q96)
	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	params := ModifyLiquidityParams{
		TickLower:      -120,
		TickUpper:      120,
		LiquidityDelta: big.NewInt(liq),
	}
	caller := common.HexToAddress("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	_, _, err = pm.ModifyLiquidity(stateDB, caller, key, params, nil)
	if err != nil {
		t.Fatalf("ModifyLiquidity failed: %v", err)
	}
}
