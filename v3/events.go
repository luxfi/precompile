// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package v3

import (
	"math/big"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	ethtypes "github.com/luxfi/geth/core/types"
)

// Event topic0 hashes, derived from the canonical signature strings (the single
// source of truth, mirroring swap/events.go and dex/events.go).
//
// These mirror Uniswap V3's Pool events (Initialize/Mint/Burn/Collect/Swap) with
// ONE structural change: because this precompile is a SINGLETON serving many
// pools (V3's pool is one-contract-per-pair, impossible for a precompile address),
// every event carries `bytes32 indexed poolId` as its first (indexed) topic so a
// subscriber can filter per pool. Owner is the second indexed topic on the
// liquidity events; the int24 ticks live in data (the EVM allows at most 3 indexed
// topics + topic0, and poolId+owner consume two).
var (
	initializeEventSig = common.BytesToHash(crypto.Keccak256([]byte("Initialize(bytes32,address,address,uint24,int24,uint160,int24)")))
	mintEventSig       = common.BytesToHash(crypto.Keccak256([]byte("Mint(bytes32,address,int24,int24,uint128,uint256,uint256)")))
	burnEventSig       = common.BytesToHash(crypto.Keccak256([]byte("Burn(bytes32,address,int24,int24,uint128,uint256,uint256)")))
	collectEventSig    = common.BytesToHash(crypto.Keccak256([]byte("Collect(bytes32,address,int24,int24,uint128,uint128)")))
	swapEventSig       = common.BytesToHash(crypto.Keccak256([]byte("Swap(bytes32,address,int256,int256,uint160,uint128,int24)")))
)

type logSink interface{ AddLog(*ethtypes.Log) }

// addressTopic / addressWord left-pads a 20-byte address into a 32-byte word.
func addressWord(a common.Address) []byte { return common.BytesToHash(a.Bytes()).Bytes() }

// emitInitialize: Initialize(bytes32 indexed poolId, address currency0,
// address currency1, uint24 fee, int24 tickSpacing, uint160 sqrtPriceX96, int24 tick).
func emitInitialize(db logSink, poolId common.Hash, c0, c1 common.Address, fee uint32, tickSpacing, tick int32, sqrtPriceX96 *big.Int) {
	data := make([]byte, 0, 6*32)
	data = append(data, addressWord(c0)...)
	data = append(data, addressWord(c1)...)
	data = append(data, uintWord(big.NewInt(int64(fee))).Bytes()...)
	data = append(data, intWord(big.NewInt(int64(tickSpacing))).Bytes()...)
	data = append(data, uintWord(sqrtPriceX96).Bytes()...)
	data = append(data, intWord(big.NewInt(int64(tick))).Bytes()...)
	db.AddLog(&ethtypes.Log{Address: v3Addr, Topics: []common.Hash{initializeEventSig, poolId}, Data: data})
}

// emitMint: Mint(bytes32 indexed poolId, address indexed owner, int24 tickLower,
// int24 tickUpper, uint128 amount, uint256 amount0, uint256 amount1).
func emitMint(db logSink, poolId common.Hash, owner common.Address, tickLower, tickUpper int32, amount, amount0, amount1 *big.Int) {
	data := make([]byte, 0, 5*32)
	data = append(data, intWord(big.NewInt(int64(tickLower))).Bytes()...)
	data = append(data, intWord(big.NewInt(int64(tickUpper))).Bytes()...)
	data = append(data, uintWord(amount).Bytes()...)
	data = append(data, uintWord(amount0).Bytes()...)
	data = append(data, uintWord(amount1).Bytes()...)
	db.AddLog(&ethtypes.Log{Address: v3Addr, Topics: []common.Hash{mintEventSig, poolId, common.BytesToHash(owner.Bytes())}, Data: data})
}

// emitBurn: Burn(bytes32 indexed poolId, address indexed owner, int24 tickLower,
// int24 tickUpper, uint128 amount, uint256 amount0, uint256 amount1).
func emitBurn(db logSink, poolId common.Hash, owner common.Address, tickLower, tickUpper int32, amount, amount0, amount1 *big.Int) {
	data := make([]byte, 0, 5*32)
	data = append(data, intWord(big.NewInt(int64(tickLower))).Bytes()...)
	data = append(data, intWord(big.NewInt(int64(tickUpper))).Bytes()...)
	data = append(data, uintWord(amount).Bytes()...)
	data = append(data, uintWord(amount0).Bytes()...)
	data = append(data, uintWord(amount1).Bytes()...)
	db.AddLog(&ethtypes.Log{Address: v3Addr, Topics: []common.Hash{burnEventSig, poolId, common.BytesToHash(owner.Bytes())}, Data: data})
}

// emitCollect: Collect(bytes32 indexed poolId, address indexed owner,
// int24 tickLower, int24 tickUpper, uint128 amount0, uint128 amount1).
func emitCollect(db logSink, poolId common.Hash, owner common.Address, tickLower, tickUpper int32, amount0, amount1 *big.Int) {
	data := make([]byte, 0, 4*32)
	data = append(data, intWord(big.NewInt(int64(tickLower))).Bytes()...)
	data = append(data, intWord(big.NewInt(int64(tickUpper))).Bytes()...)
	data = append(data, uintWord(amount0).Bytes()...)
	data = append(data, uintWord(amount1).Bytes()...)
	db.AddLog(&ethtypes.Log{Address: v3Addr, Topics: []common.Hash{collectEventSig, poolId, common.BytesToHash(owner.Bytes())}, Data: data})
}

// emitSwap: Swap(bytes32 indexed poolId, address indexed sender, int256 amount0,
// int256 amount1, uint160 sqrtPriceX96, uint128 liquidity, int24 tick).
func emitSwap(db logSink, poolId common.Hash, sender common.Address, amount0, amount1, sqrtPriceX96, liquidity *big.Int, tick int32) {
	data := make([]byte, 0, 5*32)
	data = append(data, intWord(amount0).Bytes()...)
	data = append(data, intWord(amount1).Bytes()...)
	data = append(data, uintWord(sqrtPriceX96).Bytes()...)
	data = append(data, uintWord(liquidity).Bytes()...)
	data = append(data, intWord(big.NewInt(int64(tick))).Bytes()...)
	db.AddLog(&ethtypes.Log{Address: v3Addr, Topics: []common.Hash{swapEventSig, poolId, common.BytesToHash(sender.Bytes())}, Data: data})
}
