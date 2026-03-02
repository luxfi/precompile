// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/luxfi/database"
	"github.com/luxfi/geth/common"
)

// State export errors
var (
	ErrExportInProgress = errors.New("state export already in progress")
	ErrImportFailed     = errors.New("state import failed: data integrity check failed")
	ErrInvalidSnapshot  = errors.New("invalid snapshot format")
	ErrVersionMismatch  = errors.New("snapshot version mismatch")
)

// SnapshotVersion is the current serialization format version.
// Bump this when the wire format changes to prevent silent corruption.
const SnapshotVersion uint32 = 1

// DB key prefixes for ZapDB state storage.
// Each prefix isolates a category of DEX state within the database.
var (
	dbPrefixMeta     = []byte("dex:meta:")
	dbPrefixPool     = []byte("dex:pool:")
	dbPrefixPosition = []byte("dex:posn:")
	dbPrefixTick     = []byte("dex:tick:")
	dbPrefixBitmap   = []byte("dex:bmap:")
)

// PoolSnapshot is the JSON-serializable representation of a single pool's state.
type PoolSnapshot struct {
	PoolID          string            `json:"poolId"`
	Key             PoolKeySnapshot   `json:"key"`
	SqrtPriceX96    string            `json:"sqrtPriceX96"`
	Tick            int32             `json:"tick"`
	Liquidity       string            `json:"liquidity"`
	FeeGrowth0X128  string            `json:"feeGrowth0X128"`
	FeeGrowth1X128  string            `json:"feeGrowth1X128"`
	ProtocolFees0   string            `json:"protocolFees0"`
	ProtocolFees1   string            `json:"protocolFees1"`
	TickSpacing     int32             `json:"tickSpacing"`
	LPFee           uint32            `json:"lpFee"`
	ProtocolFee     uint32            `json:"protocolFee"`
	Positions       []PositionSnapshot `json:"positions"`
	Ticks           []TickSnapshot    `json:"ticks"`
	BitmapWords     []BitmapWord      `json:"bitmapWords"`
}

// PoolKeySnapshot is the JSON-serializable representation of a pool key.
type PoolKeySnapshot struct {
	Currency0   string `json:"currency0"`
	Currency1   string `json:"currency1"`
	Fee         uint32 `json:"fee"`
	TickSpacing int32  `json:"tickSpacing"`
	Hooks       string `json:"hooks"`
}

// PositionSnapshot is the JSON-serializable representation of a position.
type PositionSnapshot struct {
	PositionID               string `json:"positionId"`
	Owner                    string `json:"owner"`
	TickLower                int32  `json:"tickLower"`
	TickUpper                int32  `json:"tickUpper"`
	Liquidity                string `json:"liquidity"`
	FeeGrowthInside0LastX128 string `json:"feeGrowthInside0LastX128"`
	FeeGrowthInside1LastX128 string `json:"feeGrowthInside1LastX128"`
	TokensOwed0              string `json:"tokensOwed0"`
	TokensOwed1              string `json:"tokensOwed1"`
}

// TickSnapshot is the JSON-serializable representation of a tick.
type TickSnapshot struct {
	Index                 int32  `json:"index"`
	LiquidityGross        string `json:"liquidityGross"`
	LiquidityNet          string `json:"liquidityNet"`
	FeeGrowthOutside0X128 string `json:"feeGrowthOutside0X128"`
	FeeGrowthOutside1X128 string `json:"feeGrowthOutside1X128"`
}

// BitmapWord is a single word in the tick bitmap.
type BitmapWord struct {
	WordIndex int16  `json:"wordIndex"`
	Value     string `json:"value"`
}

// DEXStateSnapshot is the top-level state snapshot containing all DEX state.
type DEXStateSnapshot struct {
	Version   uint32         `json:"version"`
	Timestamp int64          `json:"timestamp"`
	BlockNum  uint64         `json:"blockNum"`
	Pools     []PoolSnapshot `json:"pools"`
}

// ExportState creates an atomic snapshot of all DEX state from the PoolManager.
// The snapshot is taken under a read lock to ensure consistency.
// If stateDB is provided, it's used to get the current block number.
func (pm *PoolManager) ExportState(stateDB StateDB) (*DEXStateSnapshot, error) {
	snap := &DEXStateSnapshot{
		Version:   SnapshotVersion,
		Timestamp: time.Now().Unix(),
	}
	if stateDB != nil {
		snap.BlockNum = stateDB.GetBlockNumber()
	}

	// Iterate all pools — this is an in-memory read of the PoolManager's maps.
	// The PoolManager holds the authoritative in-memory state that was loaded
	// from the EVM stateDB. No mutation occurs here.
	for poolId, ps := range pm.poolStates {
		poolSnap := exportPoolState(poolId, ps)
		snap.Pools = append(snap.Pools, poolSnap)
	}

	// Deterministic ordering by pool ID for reproducible snapshots
	sort.Slice(snap.Pools, func(i, j int) bool {
		return snap.Pools[i].PoolID < snap.Pools[j].PoolID
	})

	return snap, nil
}

// ExportPoolState exports the state of a single pool identified by its PoolKey.
func (pm *PoolManager) ExportPoolState(stateDB StateDB, key PoolKey) (*PoolSnapshot, error) {
	poolId := key.ID()
	ps, ok := pm.poolStates[poolId]
	if !ok {
		return nil, ErrPoolNotFound
	}
	if !ps.Pool.IsInitialized() {
		return nil, ErrPoolNotInitialized
	}

	result := exportPoolState(poolId, ps)
	return &result, nil
}

// ImportState restores DEX state from a snapshot into the PoolManager.
// This is destructive — it replaces the current in-memory state.
// Caller must ensure no concurrent operations are in progress.
func (pm *PoolManager) ImportState(stateDB StateDB, snap *DEXStateSnapshot) error {
	if snap.Version != SnapshotVersion {
		return fmt.Errorf("%w: got %d, want %d", ErrVersionMismatch, snap.Version, SnapshotVersion)
	}

	// Build new state maps atomically. If any pool fails to parse,
	// the entire import is aborted — no partial state.
	newPools := make(map[[32]byte]*Pool)
	newPoolStates := make(map[[32]byte]*PoolState)
	newPositions := make(map[[32]byte]*Position)

	for _, poolSnap := range snap.Pools {
		poolId, ps, positions, err := importPoolSnapshot(poolSnap)
		if err != nil {
			return fmt.Errorf("%w: pool %s: %v", ErrImportFailed, poolSnap.PoolID, err)
		}
		newPools[poolId] = ps.Pool
		newPoolStates[poolId] = ps
		for k, v := range positions {
			newPositions[k] = v
		}
	}

	// Atomic swap — only replace state after all parsing succeeded.
	pm.pools = newPools
	pm.poolStates = newPoolStates
	pm.positions = newPositions

	// Persist to stateDB if provided
	if stateDB != nil {
		for poolId, pool := range newPools {
			pm.setPool(stateDB, poolId, pool)
		}
		for posKey, pos := range newPositions {
			pm.setPosition(stateDB, posKey, pos)
		}
	}

	return nil
}

// WriteToZapDB persists the full DEX state snapshot to a ZapDB database.
// Uses batch writes for atomicity — either all state is written or none.
func WriteToZapDB(db database.Database, snap *DEXStateSnapshot) error {
	batch := db.NewBatch()

	// Write metadata
	metaBytes, err := json.Marshal(struct {
		Version   uint32 `json:"version"`
		Timestamp int64  `json:"timestamp"`
		BlockNum  uint64 `json:"blockNum"`
		PoolCount int    `json:"poolCount"`
	}{
		Version:   snap.Version,
		Timestamp: snap.Timestamp,
		BlockNum:  snap.BlockNum,
		PoolCount: len(snap.Pools),
	})
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	if err := batch.Put(append(dbPrefixMeta, []byte("snapshot")...), metaBytes); err != nil {
		return fmt.Errorf("batch put metadata: %w", err)
	}

	for _, poolSnap := range snap.Pools {
		poolIDBytes := []byte(poolSnap.PoolID)

		// Write pool state
		poolBytes, err := json.Marshal(poolSnap)
		if err != nil {
			return fmt.Errorf("marshal pool %s: %w", poolSnap.PoolID, err)
		}
		if err := batch.Put(append(dbPrefixPool, poolIDBytes...), poolBytes); err != nil {
			return fmt.Errorf("batch put pool %s: %w", poolSnap.PoolID, err)
		}

		// Write positions individually for efficient single-position lookups
		for _, pos := range poolSnap.Positions {
			posBytes, err := json.Marshal(pos)
			if err != nil {
				return fmt.Errorf("marshal position %s: %w", pos.PositionID, err)
			}
			posKey := append(dbPrefixPosition, []byte(poolSnap.PoolID+":"+pos.PositionID)...)
			if err := batch.Put(posKey, posBytes); err != nil {
				return fmt.Errorf("batch put position: %w", err)
			}
		}

		// Write ticks individually for range queries
		for _, tick := range poolSnap.Ticks {
			tickBytes, err := json.Marshal(tick)
			if err != nil {
				return fmt.Errorf("marshal tick %d: %w", tick.Index, err)
			}
			tickKey := makeTickDBKey(poolIDBytes, tick.Index)
			if err := batch.Put(tickKey, tickBytes); err != nil {
				return fmt.Errorf("batch put tick: %w", err)
			}
		}

		// Write bitmap words
		for _, bw := range poolSnap.BitmapWords {
			bwBytes, err := json.Marshal(bw)
			if err != nil {
				return fmt.Errorf("marshal bitmap word %d: %w", bw.WordIndex, err)
			}
			bwKey := makeBitmapDBKey(poolIDBytes, bw.WordIndex)
			if err := batch.Put(bwKey, bwBytes); err != nil {
				return fmt.Errorf("batch put bitmap: %w", err)
			}
		}
	}

	return batch.Write()
}

// ReadFromZapDB reads a DEX state snapshot from a ZapDB database.
func ReadFromZapDB(db database.Database) (*DEXStateSnapshot, error) {
	// Read metadata
	metaKey := append(dbPrefixMeta, []byte("snapshot")...)
	metaBytes, err := db.Get(metaKey)
	if err != nil {
		return nil, fmt.Errorf("read metadata: %w", err)
	}

	var meta struct {
		Version   uint32 `json:"version"`
		Timestamp int64  `json:"timestamp"`
		BlockNum  uint64 `json:"blockNum"`
		PoolCount int    `json:"poolCount"`
	}
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}
	if meta.Version != SnapshotVersion {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrVersionMismatch, meta.Version, SnapshotVersion)
	}

	snap := &DEXStateSnapshot{
		Version:   meta.Version,
		Timestamp: meta.Timestamp,
		BlockNum:  meta.BlockNum,
	}

	// Read all pools using prefix iterator
	iter := db.NewIteratorWithPrefix(dbPrefixPool)
	defer iter.Release()

	for iter.Next() {
		var poolSnap PoolSnapshot
		if err := json.Unmarshal(iter.Value(), &poolSnap); err != nil {
			return nil, fmt.Errorf("unmarshal pool: %w", err)
		}
		snap.Pools = append(snap.Pools, poolSnap)
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("pool iterator error: %w", err)
	}

	// Sort for deterministic output
	sort.Slice(snap.Pools, func(i, j int) bool {
		return snap.Pools[i].PoolID < snap.Pools[j].PoolID
	})

	return snap, nil
}

// StateExporter manages periodic state exports to ZapDB.
type StateExporter struct {
	pm       *PoolManager
	db       database.Database
	mu       sync.Mutex
	exporting bool
}

// NewStateExporter creates a new state exporter.
func NewStateExporter(pm *PoolManager, db database.Database) *StateExporter {
	return &StateExporter{
		pm: pm,
		db: db,
	}
}

// Export performs a one-shot export of the current DEX state to ZapDB.
func (se *StateExporter) Export(stateDB StateDB) error {
	se.mu.Lock()
	if se.exporting {
		se.mu.Unlock()
		return ErrExportInProgress
	}
	se.exporting = true
	se.mu.Unlock()

	defer func() {
		se.mu.Lock()
		se.exporting = false
		se.mu.Unlock()
	}()

	snap, err := se.pm.ExportState(stateDB)
	if err != nil {
		return fmt.Errorf("export state: %w", err)
	}

	return WriteToZapDB(se.db, snap)
}

// =========================================================================
// Internal helpers
// =========================================================================

func exportPoolState(poolId [32]byte, ps *PoolState) PoolSnapshot {
	snap := PoolSnapshot{
		PoolID:         fmt.Sprintf("%x", poolId),
		SqrtPriceX96:   bigIntToStr(ps.SqrtPriceX96),
		Tick:           ps.Tick,
		Liquidity:      bigIntToStr(ps.Liquidity),
		FeeGrowth0X128: bigIntToStr(ps.FeeGrowth0X128),
		FeeGrowth1X128: bigIntToStr(ps.FeeGrowth1X128),
		ProtocolFees0:  bigIntToStr(ps.ProtocolFees0),
		ProtocolFees1:  bigIntToStr(ps.ProtocolFees1),
		TickSpacing:    ps.TickSpacing,
		LPFee:         ps.LPFee,
		ProtocolFee:   ps.ProtocolFee,
	}

	// Export positions
	for posKey, pos := range ps.Positions {
		snap.Positions = append(snap.Positions, PositionSnapshot{
			PositionID:               fmt.Sprintf("%x", posKey),
			Owner:                    pos.Owner.Hex(),
			TickLower:                pos.TickLower,
			TickUpper:                pos.TickUpper,
			Liquidity:                bigIntToStr(pos.Liquidity),
			FeeGrowthInside0LastX128: bigIntToStr(pos.FeeGrowthInside0LastX128),
			FeeGrowthInside1LastX128: bigIntToStr(pos.FeeGrowthInside1LastX128),
			TokensOwed0:              bigIntToStr(pos.TokensOwed0),
			TokensOwed1:              bigIntToStr(pos.TokensOwed1),
		})
	}
	sort.Slice(snap.Positions, func(i, j int) bool {
		return snap.Positions[i].PositionID < snap.Positions[j].PositionID
	})

	// Export ticks
	for tickIdx, tickInfo := range ps.Ticks {
		snap.Ticks = append(snap.Ticks, TickSnapshot{
			Index:                 tickIdx,
			LiquidityGross:        bigIntToStr(tickInfo.LiquidityGross),
			LiquidityNet:          bigIntToStr(tickInfo.LiquidityNet),
			FeeGrowthOutside0X128: bigIntToStr(tickInfo.FeeGrowthOutside0X128),
			FeeGrowthOutside1X128: bigIntToStr(tickInfo.FeeGrowthOutside1X128),
		})
	}
	sort.Slice(snap.Ticks, func(i, j int) bool {
		return snap.Ticks[i].Index < snap.Ticks[j].Index
	})

	// Export bitmap words
	if ps.TickBitmap != nil {
		for wordIdx, word := range ps.TickBitmap.Words {
			snap.BitmapWords = append(snap.BitmapWords, BitmapWord{
				WordIndex: wordIdx,
				Value:     bigIntToStr(word),
			})
		}
		sort.Slice(snap.BitmapWords, func(i, j int) bool {
			return snap.BitmapWords[i].WordIndex < snap.BitmapWords[j].WordIndex
		})
	}

	return snap
}

func importPoolSnapshot(snap PoolSnapshot) ([32]byte, *PoolState, map[[32]byte]*Position, error) {
	var poolId [32]byte
	if _, err := fmt.Sscanf(snap.PoolID, "%x", &poolId); err != nil {
		// Try hex decode directly
		idBytes := common.FromHex(snap.PoolID)
		if len(idBytes) != 32 {
			return poolId, nil, nil, fmt.Errorf("invalid pool ID: %s", snap.PoolID)
		}
		copy(poolId[:], idBytes)
	}

	pool := &Pool{
		SqrtPriceX96:   strToBigInt(snap.SqrtPriceX96),
		Tick:           snap.Tick,
		Liquidity:      strToBigInt(snap.Liquidity),
		FeeGrowth0X128: strToBigInt(snap.FeeGrowth0X128),
		FeeGrowth1X128: strToBigInt(snap.FeeGrowth1X128),
		ProtocolFees0:  strToBigInt(snap.ProtocolFees0),
		ProtocolFees1:  strToBigInt(snap.ProtocolFees1),
	}

	ps := &PoolState{
		Pool:        pool,
		Ticks:       make(map[int32]*TickInfo),
		TickBitmap:  NewTickBitmap(),
		Positions:   make(map[[32]byte]*Position),
		TickSpacing: snap.TickSpacing,
		LPFee:       snap.LPFee,
		ProtocolFee: snap.ProtocolFee,
	}

	positions := make(map[[32]byte]*Position)

	// Import positions
	for _, posSnap := range snap.Positions {
		var posKey [32]byte
		posIDBytes := common.FromHex(posSnap.PositionID)
		if len(posIDBytes) == 32 {
			copy(posKey[:], posIDBytes)
		}

		pos := &Position{
			Owner:                    common.HexToAddress(posSnap.Owner),
			TickLower:                posSnap.TickLower,
			TickUpper:                posSnap.TickUpper,
			Liquidity:                strToBigInt(posSnap.Liquidity),
			FeeGrowthInside0LastX128: strToBigInt(posSnap.FeeGrowthInside0LastX128),
			FeeGrowthInside1LastX128: strToBigInt(posSnap.FeeGrowthInside1LastX128),
			TokensOwed0:              strToBigInt(posSnap.TokensOwed0),
			TokensOwed1:              strToBigInt(posSnap.TokensOwed1),
		}
		ps.Positions[posKey] = pos
		positions[posKey] = pos
	}

	// Import ticks
	for _, tickSnap := range snap.Ticks {
		ps.Ticks[tickSnap.Index] = &TickInfo{
			LiquidityGross:        strToBigInt(tickSnap.LiquidityGross),
			LiquidityNet:          strToBigInt(tickSnap.LiquidityNet),
			FeeGrowthOutside0X128: strToBigInt(tickSnap.FeeGrowthOutside0X128),
			FeeGrowthOutside1X128: strToBigInt(tickSnap.FeeGrowthOutside1X128),
		}
	}

	// Import bitmap words
	for _, bw := range snap.BitmapWords {
		ps.TickBitmap.Words[bw.WordIndex] = strToBigInt(bw.Value)
	}

	return poolId, ps, positions, nil
}

func bigIntToStr(v *big.Int) string {
	if v == nil {
		return "0"
	}
	return v.String()
}

func strToBigInt(s string) *big.Int {
	if s == "" || s == "0" {
		return big.NewInt(0)
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return big.NewInt(0)
	}
	return v
}

func makeTickDBKey(poolID []byte, tickIndex int32) []byte {
	key := make([]byte, len(dbPrefixTick)+len(poolID)+1+4)
	n := copy(key, dbPrefixTick)
	n += copy(key[n:], poolID)
	key[n] = ':'
	n++
	binary.BigEndian.PutUint32(key[n:], uint32(tickIndex))
	return key[:n+4]
}

func makeBitmapDBKey(poolID []byte, wordIndex int16) []byte {
	key := make([]byte, len(dbPrefixBitmap)+len(poolID)+1+2)
	n := copy(key, dbPrefixBitmap)
	n += copy(key[n:], poolID)
	key[n] = ':'
	n++
	binary.BigEndian.PutUint16(key[n:], uint16(wordIndex))
	return key[:n+2]
}
