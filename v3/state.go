// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package v3

import (
	"encoding/binary"
	"math/big"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/dex"
)

// State layout under v3Addr.
//
// The precompile is a SINGLETON serving MANY pools, each identified by a
// dex.PoolKey. All persistent state lives in the EVM trie under v3Addr using the
// mapping-slot idiom slot = keccak256(prefix ‖ key… ‖ field) — exactly the idiom
// swap/state.go uses, generalised to the (poolId, tick) and (poolId, position)
// composite keys a concentrated-liquidity AMM needs.
//
//   - pool scalars      keccak256("v3p"   ‖ poolId ‖ field)
//   - per-tick TickInfo keccak256("v3t"   ‖ poolId ‖ int32be(tick) ‖ field)
//   - tick bitmap word  keccak256("v3b"   ‖ poolId ‖ int16be(wordPos))
//   - per-position      keccak256("v3pos" ‖ poolId ‖ positionKey ‖ field)
//   - reserve[asset]    keccak256("v3r"   ‖ asset)        (custody ledger, global)
//   - reentrancy guard  keccak256("v3g")
//
// poolId == dex.PoolKey.ID() (keccak256 of the canonical V4 ABI encoding), so the
// pool identity is the SAME value the rest of the dex package uses — no second
// identity scheme. reserve[asset] is GLOBAL (across pools) because it shadows the
// precompile's REAL token balance of that asset, which is shared across every pool
// the precompile serves; that is the conservation anchor (reserve == balanceOf).

// pool scalar fields.
const (
	psSqrtPrice byte = 0 // sqrtPriceX96 (uint160)
	psTick      byte = 1 // current tick (int24, signed)
	psLiquidity byte = 2 // active in-range liquidity L (uint128)
	psFeeG0     byte = 3 // feeGrowthGlobal0X128 (Q128.128, mod 2^256)
	psFeeG1     byte = 4 // feeGrowthGlobal1X128 (Q128.128, mod 2^256)
)

// per-tick fields (dex.TickInfo).
const (
	tkGross byte = 0 // liquidityGross (uint128)
	tkNet   byte = 1 // liquidityNet (int128, signed)
	tkOut0  byte = 2 // feeGrowthOutside0X128 (mod 2^256)
	tkOut1  byte = 3 // feeGrowthOutside1X128 (mod 2^256)
)

// per-position fields (dex.Position mutable slots).
const (
	poLiquidity byte = 0 // position liquidity (uint128)
	poInside0   byte = 1 // feeGrowthInside0LastX128 (mod 2^256)
	poInside1   byte = 2 // feeGrowthInside1LastX128 (mod 2^256)
	poOwed0     byte = 3 // tokensOwed0 (uint128)
	poOwed1     byte = 4 // tokensOwed1 (uint128)
)

var (
	prefixPool     = []byte("v3p")
	prefixTick     = []byte("v3t")
	prefixBitmap   = []byte("v3b")
	prefixPosition = []byte("v3pos")
	prefixReserve  = []byte("v3r")
	prefixGuard    = []byte("v3g")
)

// salt is the V4 position salt. This precompile keys one position per
// (owner, tickLower, tickUpper); the salt is the fixed zero value so position
// identity is fully determined by those three fields (see dex.PositionKey).
var salt [32]byte

// ---------------------------------------------------------------------------
// 256-bit modular helpers. feeGrowth accumulators wrap mod 2^256 (Uniswap's
// `unchecked` convention): a tick's feeGrowthOutside can be "negative" in the
// wrapped sense, and the per-position delta sub256(now,last) recovers the true
// (small, in-range) growth even across a wrap. This is fee ACCOUNTING, not AMM
// math — the AMM math is composed wholesale from dex.* and never reimplemented.
// ---------------------------------------------------------------------------

var two256 = new(big.Int).Lsh(big.NewInt(1), 256)

func mod256(x *big.Int) *big.Int { return new(big.Int).Mod(x, two256) }
func add256(a, b *big.Int) *big.Int {
	return mod256(new(big.Int).Add(a, b))
}
func sub256(a, b *big.Int) *big.Int {
	return mod256(new(big.Int).Sub(a, b))
}

// ---------------------------------------------------------------------------
// Word codecs. Unsigned values are big-endian; signed values (tick, liquidityNet,
// amountSpecified) are 256-bit two's complement, the EVM/ABI convention.
// ---------------------------------------------------------------------------

// uintWord encodes a non-negative big.Int as a 32-byte big-endian word.
func uintWord(v *big.Int) common.Hash { return common.BigToHash(v) }

// intWord encodes a signed big.Int as a 32-byte two's-complement word.
func intWord(v *big.Int) common.Hash {
	if v.Sign() < 0 {
		return common.BigToHash(new(big.Int).Add(v, two256))
	}
	return common.BigToHash(v)
}

// wordToUint reads a 32-byte word as an unsigned big.Int.
func wordToUint(h common.Hash) *big.Int { return new(big.Int).SetBytes(h[:]) }

// wordToInt reads a 32-byte word as a signed (two's-complement) big.Int.
func wordToInt(h common.Hash) *big.Int {
	x := new(big.Int).SetBytes(h[:])
	if x.Bit(255) == 1 {
		x.Sub(x, two256)
	}
	return x
}

func int32be(v int32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(v))
	return b[:]
}

func int16be(v int16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(v))
	return b[:]
}

// ---------------------------------------------------------------------------
// Slot derivation.
// ---------------------------------------------------------------------------

func poolSlot(poolId common.Hash, field byte) common.Hash {
	return common.BytesToHash(crypto.Keccak256(prefixPool, poolId[:], []byte{field}))
}

func tickSlot(poolId common.Hash, tick int32, field byte) common.Hash {
	return common.BytesToHash(crypto.Keccak256(prefixTick, poolId[:], int32be(tick), []byte{field}))
}

func bitmapSlot(poolId common.Hash, wordPos int16) common.Hash {
	return common.BytesToHash(crypto.Keccak256(prefixBitmap, poolId[:], int16be(wordPos)))
}

func positionSlot(poolId common.Hash, posKey [32]byte, field byte) common.Hash {
	return common.BytesToHash(crypto.Keccak256(prefixPosition, poolId[:], posKey[:], []byte{field}))
}

func reserveSlot(asset common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(prefixReserve, asset.Bytes()))
}

func guardSlot() common.Hash { return common.BytesToHash(crypto.Keccak256(prefixGuard)) }

// stateRW is the minimal word-addressed StateDB surface the state layer touches
// (contract.StateDB satisfies it).
type stateRW interface {
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash) common.Hash
}

// ---------------------------------------------------------------------------
// Pool scalars.
// ---------------------------------------------------------------------------

func loadSqrtPrice(db stateRW, poolId common.Hash) *big.Int {
	return wordToUint(db.GetState(v3Addr, poolSlot(poolId, psSqrtPrice)))
}

func storeSqrtPrice(db stateRW, poolId common.Hash, v *big.Int) {
	db.SetState(v3Addr, poolSlot(poolId, psSqrtPrice), uintWord(v))
}

func loadPoolTick(db stateRW, poolId common.Hash) int32 {
	return int32(wordToInt(db.GetState(v3Addr, poolSlot(poolId, psTick))).Int64())
}

func storePoolTick(db stateRW, poolId common.Hash, tick int32) {
	db.SetState(v3Addr, poolSlot(poolId, psTick), intWord(big.NewInt(int64(tick))))
}

func loadLiquidity(db stateRW, poolId common.Hash) *big.Int {
	return wordToUint(db.GetState(v3Addr, poolSlot(poolId, psLiquidity)))
}

func storeLiquidity(db stateRW, poolId common.Hash, v *big.Int) {
	db.SetState(v3Addr, poolSlot(poolId, psLiquidity), uintWord(v))
}

func loadFeeGrowthGlobal0(db stateRW, poolId common.Hash) *big.Int {
	return wordToUint(db.GetState(v3Addr, poolSlot(poolId, psFeeG0)))
}

func storeFeeGrowthGlobal0(db stateRW, poolId common.Hash, v *big.Int) {
	db.SetState(v3Addr, poolSlot(poolId, psFeeG0), uintWord(v))
}

func loadFeeGrowthGlobal1(db stateRW, poolId common.Hash) *big.Int {
	return wordToUint(db.GetState(v3Addr, poolSlot(poolId, psFeeG1)))
}

func storeFeeGrowthGlobal1(db stateRW, poolId common.Hash, v *big.Int) {
	db.SetState(v3Addr, poolSlot(poolId, psFeeG1), uintWord(v))
}

// isInitialized reports whether a pool exists (V3: sqrtPriceX96 != 0).
func isInitialized(db stateRW, poolId common.Hash) bool {
	return loadSqrtPrice(db, poolId).Sign() > 0
}

// ---------------------------------------------------------------------------
// Per-tick TickInfo (dex.TickInfo). A tick is "initialized" iff LiquidityGross>0.
// ---------------------------------------------------------------------------

func loadTickInfo(db stateRW, poolId common.Hash, tick int32) *dex.TickInfo {
	return &dex.TickInfo{
		LiquidityGross:        wordToUint(db.GetState(v3Addr, tickSlot(poolId, tick, tkGross))),
		LiquidityNet:          wordToInt(db.GetState(v3Addr, tickSlot(poolId, tick, tkNet))),
		FeeGrowthOutside0X128: wordToUint(db.GetState(v3Addr, tickSlot(poolId, tick, tkOut0))),
		FeeGrowthOutside1X128: wordToUint(db.GetState(v3Addr, tickSlot(poolId, tick, tkOut1))),
	}
}

func storeTickInfo(db stateRW, poolId common.Hash, tick int32, info *dex.TickInfo) {
	db.SetState(v3Addr, tickSlot(poolId, tick, tkGross), uintWord(info.LiquidityGross))
	db.SetState(v3Addr, tickSlot(poolId, tick, tkNet), intWord(info.LiquidityNet))
	db.SetState(v3Addr, tickSlot(poolId, tick, tkOut0), uintWord(info.FeeGrowthOutside0X128))
	db.SetState(v3Addr, tickSlot(poolId, tick, tkOut1), uintWord(info.FeeGrowthOutside1X128))
}

// clearTickInfo zeroes a tick that has flipped to uninitialized (V3 Tick.clear),
// so stale feeGrowthOutside cannot leak into a future re-initialization.
func clearTickInfo(db stateRW, poolId common.Hash, tick int32) {
	storeTickInfo(db, poolId, tick, dex.NewTickInfo())
}

// ---------------------------------------------------------------------------
// Tick bitmap. A single word is loaded on demand into a one-entry dex.TickBitmap
// so the EXPORTED dex.FlipTick / dex.NextInitializedTickWithinOneWord operate on
// it directly — no bitmap traversal logic is reimplemented here.
// ---------------------------------------------------------------------------

func loadBitmapWord(db stateRW, poolId common.Hash, wordPos int16) *big.Int {
	return wordToUint(db.GetState(v3Addr, bitmapSlot(poolId, wordPos)))
}

func storeBitmapWord(db stateRW, poolId common.Hash, wordPos int16, word *big.Int) {
	db.SetState(v3Addr, bitmapSlot(poolId, wordPos), uintWord(word))
}

// flipTickBitmap toggles a tick's initialized bit, composing dex.FlipTick over a
// single stored word.
func flipTickBitmap(db stateRW, poolId common.Hash, tick, tickSpacing int32) {
	compressed := dex.Compress(tick, tickSpacing)
	wordPos, _ := dex.TickBitmapPosition(compressed)
	bm := &dex.TickBitmap{Words: map[int16]*big.Int{wordPos: loadBitmapWord(db, poolId, wordPos)}}
	dex.FlipTick(bm, tick, tickSpacing)
	storeBitmapWord(db, poolId, wordPos, bm.Words[wordPos])
}

// nextInitializedTick composes dex.NextInitializedTickWithinOneWord over the one
// stored bitmap word that the function will read. The word the function reads is
// fully determined by (Compress, lte): for lte it reads the word of compress(tick);
// for !lte it reads the word of compress(tick)+1 — replicated here ONLY to know
// which single word to load, never to reimplement the traversal.
func nextInitializedTick(db stateRW, poolId common.Hash, tick, tickSpacing int32, lte bool) (int32, bool) {
	compressed := dex.Compress(tick, tickSpacing)
	if !lte {
		compressed++
	}
	wordPos, _ := dex.TickBitmapPosition(compressed)
	bm := &dex.TickBitmap{Words: map[int16]*big.Int{wordPos: loadBitmapWord(db, poolId, wordPos)}}
	return dex.NextInitializedTickWithinOneWord(bm, tick, tickSpacing, lte)
}

// ---------------------------------------------------------------------------
// Per-position state (dex.Position mutable slots).
// ---------------------------------------------------------------------------

func loadPosition(db stateRW, poolId common.Hash, posKey [32]byte) *dex.Position {
	return &dex.Position{
		Liquidity:                wordToUint(db.GetState(v3Addr, positionSlot(poolId, posKey, poLiquidity))),
		FeeGrowthInside0LastX128: wordToUint(db.GetState(v3Addr, positionSlot(poolId, posKey, poInside0))),
		FeeGrowthInside1LastX128: wordToUint(db.GetState(v3Addr, positionSlot(poolId, posKey, poInside1))),
		TokensOwed0:              wordToUint(db.GetState(v3Addr, positionSlot(poolId, posKey, poOwed0))),
		TokensOwed1:              wordToUint(db.GetState(v3Addr, positionSlot(poolId, posKey, poOwed1))),
	}
}

func storePosition(db stateRW, poolId common.Hash, posKey [32]byte, pos *dex.Position) {
	db.SetState(v3Addr, positionSlot(poolId, posKey, poLiquidity), uintWord(pos.Liquidity))
	db.SetState(v3Addr, positionSlot(poolId, posKey, poInside0), uintWord(pos.FeeGrowthInside0LastX128))
	db.SetState(v3Addr, positionSlot(poolId, posKey, poInside1), uintWord(pos.FeeGrowthInside1LastX128))
	db.SetState(v3Addr, positionSlot(poolId, posKey, poOwed0), uintWord(pos.TokensOwed0))
	db.SetState(v3Addr, positionSlot(poolId, posKey, poOwed1), uintWord(pos.TokensOwed1))
}

// ---------------------------------------------------------------------------
// reserve[asset] — the custody conservation ledger (mirrors swap/state.go).
// ---------------------------------------------------------------------------

func loadReserve(db stateRW, asset common.Address) *big.Int {
	return wordToUint(db.GetState(v3Addr, reserveSlot(asset)))
}

func storeReserve(db stateRW, asset common.Address, v *big.Int) {
	db.SetState(v3Addr, reserveSlot(asset), uintWord(v))
}

func addReserve(db stateRW, asset common.Address, delta *big.Int) {
	storeReserve(db, asset, new(big.Int).Add(loadReserve(db, asset), delta))
}

// subReserve debits the per-asset reserve, refusing (false) on underflow — the
// conservation backstop: a pay-out can never exceed what the precompile holds.
func subReserve(db stateRW, asset common.Address, amount *big.Int) bool {
	cur := loadReserve(db, asset)
	if cur.Cmp(amount) < 0 {
		return false
	}
	storeReserve(db, asset, new(big.Int).Sub(cur, amount))
	return true
}

// ---------------------------------------------------------------------------
// Global non-reentrant guard (mirrors swap/state.go): makes the observed-delta
// custody measurement and the state mutation atomic against a malicious token's
// reentrant callback.
// ---------------------------------------------------------------------------

func enterGuard(db stateRW) bool {
	slot := guardSlot()
	if db.GetState(v3Addr, slot)[31] != 0 {
		return false
	}
	var w common.Hash
	w[31] = 1
	db.SetState(v3Addr, slot, w)
	return true
}

func exitGuard(db stateRW) {
	db.SetState(v3Addr, guardSlot(), common.Hash{})
}
