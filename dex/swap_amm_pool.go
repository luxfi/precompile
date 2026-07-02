// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"

	dexcore "github.com/luxfi/dex/pkg/dex"
)

// swap_amm_pool.go binds the router's V2/V3 AMM fallthrough to a pool's reserve
// state in the SAME cEVM. The constant-product MATH + routing live in dexcore (one
// place, both homes); this file is ONLY the precompile-specific reserve binding/read/
// write, expressed over the dexcore Store (which IS 0x9999 storage), so there is ONE
// binding and it is consensus-shared and reorg-safe.
//
// FIRST CUT — swap-only, AMM-fallthrough-by-binding: the AMM source is active for a
// market ONLY when a real pool's reserves are bound (BindAMMPool). Until then the
// router uses the CLOB alone. This ships the fallthrough WITHOUT ever fabricating a
// pool: an unbound market routes CLOB-only, a bound market routes CLOB+AMM. The bound
// reserves are synced from the real V2/V3 pool by the operator/maker seed path, so a
// validator replays the identical reserves from committed state — never a live query.

// ammRowKey is the ONE dexcore Store key for a market's AMM binding:
//
//	ammrow:<poolID:32> -> baseReserve(8) | quoteReserve(8) | feeBps(4) | bound(1)
//
// The row lives in 0x9999 storage via the evmStore adapter, so it is committed by the
// block root and reverted by snapshots alongside the CLOB and EVM-balance effects.
const ammRowPrefix = "ammrow:"

func ammRowKey(poolID [32]byte) []byte {
	k := make([]byte, 0, len(ammRowPrefix)+32)
	k = append(k, []byte(ammRowPrefix)...)
	k = append(k, poolID[:]...)
	return k
}

const ammRowLen = 8 + 8 + 4 + 1 // base | quote | fee | bound

// readAMMRow returns a market's bound (base, quote, feeBps), ok=false if unbound.
func readAMMRow(store dexcore.Store, poolID [32]byte) (base, quote uint64, feeBps uint32, ok bool) {
	v, err := store.Get(ammRowKey(poolID))
	if err != nil || len(v) != ammRowLen || v[20] != 1 {
		return 0, 0, 0, false
	}
	base = binary.BigEndian.Uint64(v[0:8])
	quote = binary.BigEndian.Uint64(v[8:16])
	feeBps = binary.BigEndian.Uint32(v[16:20])
	return base, quote, feeBps, true
}

// writeAMMRow persists a market's (base, quote, feeBps) binding (bound=1).
func writeAMMRow(store dexcore.Store, poolID [32]byte, base, quote uint64, feeBps uint32) error {
	v := make([]byte, ammRowLen)
	binary.BigEndian.PutUint64(v[0:8], base)
	binary.BigEndian.PutUint64(v[8:16], quote)
	binary.BigEndian.PutUint32(v[16:20], feeBps)
	v[20] = 1
	return store.Put(ammRowKey(poolID), v)
}

// BindAMMPool activates the AMM fallthrough for a market with a reserve snapshot
// synced from a real V2/V3 pool and the pool fee (bps). The analog of OpenMarket for
// the AMM side: a market gains an AMM route only when an operator binds a real pool's
// reserves. Idempotent (re-bind updates the snapshot).
func BindAMMPool(store dexcore.Store, poolID [32]byte, baseReserve, quoteReserve uint64, feeBps uint32) error {
	return writeAMMRow(store, poolID, baseReserve, quoteReserve, feeBps)
}

// buildRouter assembles the router for a market: the CLOB source always, plus the AMM
// source when a real pool is bound. The order is the priority (CLOB first); dexcore
// picks best-execution and splits across them.
func buildRouter(stateDB StateDB, poolID [32]byte) *dexcore.Router {
	store := newEVMStore(stateDB)
	sources := []dexcore.Source{dexcore.NewOrderBookSource()}
	if _, _, feeBps, ok := readAMMRow(store, poolID); ok {
		sources = append(sources, dexcore.NewAMMSource(newEVMAMMPool(feeBps)))
	}
	return dexcore.NewRouter(sources...)
}

// evmAMMPool implements dexcore.AMMPool over the 0x9999-stored reserve row of a bound
// pool. The reserves live in the dexcore Store (the same StateDB trie), so the read is
// from committed state (deterministic replay), and a fill writes the new reserves back
// into the same trie — committed by the block root alongside the CLOB + EVM-balance
// effects. The fee is per-market, read at router-build time and carried here.
type evmAMMPool struct{ feeBps uint32 }

func newEVMAMMPool(feeBps uint32) *evmAMMPool { return &evmAMMPool{feeBps: feeBps} }

// Reserves reads the bound pool's (base, quote) reserves from the dexcore Store row.
func (*evmAMMPool) Reserves(db dexcore.Store, poolID [32]byte) (uint64, uint64, bool, error) {
	base, quote, _, ok := readAMMRow(db, poolID)
	return base, quote, ok, nil
}

// SetReserves writes the post-fill reserves back, preserving the fee + bound flag.
func (p *evmAMMPool) SetReserves(db dexcore.Store, poolID [32]byte, base, quote uint64) error {
	return writeAMMRow(db, poolID, base, quote, p.feeBps)
}

// FeeBps returns the bound pool's fee (read at router-build time).
func (p *evmAMMPool) FeeBps() uint32 { return p.feeBps }
