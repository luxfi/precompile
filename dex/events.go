// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	ethtypes "github.com/luxfi/geth/core/types"
)

// DexSettleActivationTime is the layer-local mirror of the canonical 0x9999 DEX
// settlement activation boundary — unix 1766704800, i.e. 2025-12-25T23:20:00Z.
//
// DO NOT "round" this to midnight: the value (not the prose date) is the protocol
// constant. It is ALREADY LIVE — it gates 0x9999 dispatch on a settling devnet — so
// changing the number would move an activation boundary that historical receipts were
// already built against and FORK every chain that crossed it. Only the human-readable
// instant is annotated here; the number is authoritative.
//
// The CANONICAL definition lives in luxfi/evm params/extras.DexSettleActivationTime;
// that is the single source of truth the EVM dispatch gate and marker-installing
// state transition reference. This package (luxfi/precompile) sits BELOW evm in the
// import graph (evm imports precompile, never the reverse), so it cannot import the
// extras constant — it mirrors the value here. Drift between the two copies is a
// consensus bug, so an equality guard test in the evm layer (which imports BOTH)
// asserts dex.DexSettleActivationTime == extras.DexSettleActivationTime and fails CI
// if either moves. The value is a protocol constant (one decision), not config.
//
// Why the precompile gates on this AT ALL, given the EVM overrider already withholds
// 0x9999 from the enabled set pre-activation: defense in depth. The dispatch gate is
// in the high (evm) layer; a new consensus-visible log (one that changes the receipt
// root + bloom) is emitted in this low (precompile) layer. If any host dispatches
// SettleSwap at a pre-activation timestamp — a buggy overrider, a non-Lux EVM that
// integrates the precompile without the dated-fork gate, a future direct-call path —
// an ungated log would split the chain (a re-syncing node that did NOT emit the log
// would compute a different receipt root). Gating the log on the SAME timestamp the
// dispatch uses means: on every chain, every settlement that ever executes also emits
// the log, and no execution before the boundary ever can. No settlement-without-log
// window, no log-without-settlement window.
const DexSettleActivationTime uint64 = 1766704800 // 2025-12-25T23:20:00Z; canonical: evm extras.DexSettleActivationTime

// dexLogsActive reports whether 0x9999's new consensus-visible logs (DEXFill, and the
// V4 Initialize the native registry emits) may be written at blockTimestamp. It is the
// ONE policy predicate gating those logs; the emit functions stay pure log-builders.
func dexLogsActive(blockTimestamp uint64) bool { return blockTimestamp >= DexSettleActivationTime }

// Event signature hashes (topic0) matching standard Uniswap V4 events.
// Computed as keccak256 of the canonical event signature string.
var (
	initializeEventSig      = common.BytesToHash(crypto.Keccak256([]byte("Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)")))
	swapEventSig            = common.BytesToHash(crypto.Keccak256([]byte("Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)")))
	modifyLiquidityEventSig = common.BytesToHash(crypto.Keccak256([]byte("ModifyLiquidity(bytes32,address,int24,int24,int256,bytes32)")))

	// DEXFill is THE indexable native-CLOB settlement signal, emitted by the
	// 0x9999 settlement precompile on a Phase-B credit. Unlike the V4 Swap event
	// (read-only views at the deprecated 0x9010 pool manager), this fires on the
	// money path so the explorer's DEX graph and lux.exchange can index settled
	// fills via eth_getLogs. poolId + taker indexed; amountOut + blockNumber data.
	dexFillEventSig = common.BytesToHash(crypto.Keccak256([]byte("DEXFill(bytes32,address,uint256,uint256)")))

	// Pause/Freeze event signatures (ATS regulatory compliance)
	dexPausedEventSig   = common.BytesToHash(crypto.Keccak256([]byte("DEXPaused(address)")))
	dexResumedEventSig  = common.BytesToHash(crypto.Keccak256([]byte("DEXResumed(address)")))
	poolPausedEventSig  = common.BytesToHash(crypto.Keccak256([]byte("PoolPaused(bytes32,address)")))
	poolResumedEventSig = common.BytesToHash(crypto.Keccak256([]byte("PoolResumed(bytes32,address)")))
	poolFrozenEventSig  = common.BytesToHash(crypto.Keccak256([]byte("PoolFrozen(bytes32,address)")))
)

// abiEncodeInt24 writes an int24 value right-aligned into a 32-byte ABI word.
func abiEncodeInt24(v int24) []byte {
	word := make([]byte, 32)
	// Sign-extend int24 into int32, then write big-endian in last 4 bytes
	b := uint32(v)
	word[28] = byte(b >> 24)
	word[29] = byte(b >> 16)
	word[30] = byte(b >> 8)
	word[31] = byte(b)
	// Sign-extend: if negative, pad leading bytes with 0xff
	if v < 0 {
		for i := range 28 {
			word[i] = 0xff
		}
	}
	return word
}

// abiEncodeUint24 writes a uint24 value right-aligned into a 32-byte ABI word.
func abiEncodeUint24(v uint24) []byte {
	word := make([]byte, 32)
	word[29] = byte(v >> 16)
	word[30] = byte(v >> 8)
	word[31] = byte(v)
	return word
}

// abiEncodeBigInt writes a big.Int value right-aligned into a 32-byte ABI word.
// For negative values, two's complement representation is used.
func abiEncodeBigInt(v *big.Int) []byte {
	word := make([]byte, 32)
	if v == nil {
		return word
	}
	if v.Sign() >= 0 {
		b := v.Bytes()
		copy(word[32-len(b):], b)
	} else {
		// Two's complement for negative values
		// Compute 2^256 + v (since v is negative, this gives two's complement)
		twos := new(big.Int).Lsh(big.NewInt(1), 256)
		twos.Add(twos, v)
		b := twos.Bytes()
		// Pad with 0xff for sign extension
		for i := 0; i < 32-len(b); i++ {
			word[i] = 0xff
		}
		copy(word[32-len(b):], b)
	}
	return word
}

// abiEncodeAddress writes an address right-aligned into a 32-byte ABI word.
func abiEncodeAddress(addr common.Address) []byte {
	word := make([]byte, 32)
	copy(word[12:], addr.Bytes())
	return word
}

// abiEncodeBytes32 writes a [32]byte value into a 32-byte ABI word.
func abiEncodeBytes32(v [32]byte) []byte {
	word := make([]byte, 32)
	copy(word[:], v[:])
	return word
}

// emitInitializeEvent emits a standard Uniswap V4 Initialize event from `manager`.
// The emitting address is a property of WHICH manager fired the init, not of the
// event shape, so it is a parameter: the in-process V4 PoolManager passes its own
// (0x9010 read-only-view) address; the native 0x9999 registry passes 0x9999 so the
// graph's isPoolManager check creates the DEX Market for native pools. One builder,
// address-parameterized — no second copy of the V4-Initialize encoding.
func emitInitializeEvent(
	stateDB StateDB,
	manager common.Address,
	poolId [32]byte,
	key PoolKey,
	sqrtPriceX96 *big.Int,
	tick int24,
) {
	// Non-indexed data: fee(uint24), tickSpacing(int24), hooks(address), sqrtPriceX96(uint160), tick(int24)
	data := make([]byte, 0, 160)
	data = append(data, abiEncodeUint24(key.Fee)...)
	data = append(data, abiEncodeInt24(key.TickSpacing)...)
	data = append(data, abiEncodeAddress(key.Hooks)...)
	data = append(data, abiEncodeBigInt(sqrtPriceX96)...)
	data = append(data, abiEncodeInt24(tick)...)

	stateDB.AddLog(&ethtypes.Log{
		Address: manager,
		Topics: []common.Hash{
			initializeEventSig,
			common.BytesToHash(poolId[:]),
			common.BytesToHash(key.Currency0.Address.Bytes()),
			common.BytesToHash(key.Currency1.Address.Bytes()),
		},
		Data: data,
	})
}

// emitSwapEvent emits a standard Uniswap V4 Swap event.
func emitSwapEvent(
	stateDB StateDB,
	poolId [32]byte,
	sender common.Address,
	delta BalanceDelta,
	sqrtPriceX96 *big.Int,
	liquidity *big.Int,
	tick int24,
	fee uint24,
) {
	// Non-indexed data: amount0(int128), amount1(int128), sqrtPriceX96(uint160),
	//                   liquidity(uint128), tick(int24), fee(uint24)
	data := make([]byte, 0, 192)
	data = append(data, abiEncodeBigInt(delta.Amount0)...)
	data = append(data, abiEncodeBigInt(delta.Amount1)...)
	data = append(data, abiEncodeBigInt(sqrtPriceX96)...)
	data = append(data, abiEncodeBigInt(liquidity)...)
	data = append(data, abiEncodeInt24(tick)...)
	data = append(data, abiEncodeUint24(fee)...)

	stateDB.AddLog(&ethtypes.Log{
		Address: lxPoolAddr,
		Topics: []common.Hash{
			swapEventSig,
			common.BytesToHash(poolId[:]),
			common.BytesToHash(sender.Bytes()),
		},
		Data: data,
	})
}

// emitModifyLiquidityEvent emits a standard Uniswap V4 ModifyLiquidity event.
func emitModifyLiquidityEvent(
	stateDB StateDB,
	poolId [32]byte,
	sender common.Address,
	params ModifyLiquidityParams,
) {
	// Non-indexed data: tickLower(int24), tickUpper(int24), liquidityDelta(int256), salt(bytes32)
	data := make([]byte, 0, 128)
	data = append(data, abiEncodeInt24(params.TickLower)...)
	data = append(data, abiEncodeInt24(params.TickUpper)...)
	data = append(data, abiEncodeBigInt(params.LiquidityDelta)...)
	data = append(data, abiEncodeBytes32(params.Salt)...)

	stateDB.AddLog(&ethtypes.Log{
		Address: lxPoolAddr,
		Topics: []common.Hash{
			modifyLiquidityEventSig,
			common.BytesToHash(poolId[:]),
			common.BytesToHash(sender.Bytes()),
		},
		Data: data,
	})
}

// emitDEXFillEvent emits DEXFill(bytes32 indexed poolId, address indexed taker,
// uint256 amountOut, uint256 blockNumber) from the 0x9999 settlement precompile.
// This is the authoritative on-chain record of a settled native-CLOB fill — the
// signal the graph indexer ingests into the DEX (CLOB) schema. It is emitted at
// poolManagerAddr9999 (the money path), NOT lxPoolAddr (the deprecated 0x9010
// read-only views), so an indexer can scope CLOB fills to the settlement vault.
func emitDEXFillEvent(
	stateDB StateDB,
	poolId [32]byte,
	taker common.Address,
	amountOut *big.Int,
	blockNumber uint64,
) {
	data := make([]byte, 0, 64)
	data = append(data, abiEncodeBigInt(amountOut)...)
	data = append(data, abiEncodeBigInt(new(big.Int).SetUint64(blockNumber))...)

	stateDB.AddLog(&ethtypes.Log{
		Address: poolManagerAddr9999,
		Topics: []common.Hash{
			dexFillEventSig,
			common.BytesToHash(poolId[:]),
			common.BytesToHash(taker.Bytes()),
		},
		Data: data,
	})
}

// =========================================================================
// Pause/Freeze Events (ATS Regulatory Compliance)
// =========================================================================

// emitDEXPausedEvent emits DEXPaused(address caller).
func emitDEXPausedEvent(stateDB StateDB, caller common.Address) {
	stateDB.AddLog(&ethtypes.Log{
		Address: lxPoolAddr,
		Topics: []common.Hash{
			dexPausedEventSig,
			common.BytesToHash(caller.Bytes()),
		},
		Data: nil,
	})
}

// emitDEXResumedEvent emits DEXResumed(address caller).
func emitDEXResumedEvent(stateDB StateDB, caller common.Address) {
	stateDB.AddLog(&ethtypes.Log{
		Address: lxPoolAddr,
		Topics: []common.Hash{
			dexResumedEventSig,
			common.BytesToHash(caller.Bytes()),
		},
		Data: nil,
	})
}

// emitPoolPausedEvent emits PoolPaused(bytes32 poolId, address caller).
func emitPoolPausedEvent(stateDB StateDB, caller common.Address, poolId [32]byte) {
	stateDB.AddLog(&ethtypes.Log{
		Address: lxPoolAddr,
		Topics: []common.Hash{
			poolPausedEventSig,
			common.BytesToHash(poolId[:]),
			common.BytesToHash(caller.Bytes()),
		},
		Data: nil,
	})
}

// emitPoolResumedEvent emits PoolResumed(bytes32 poolId, address caller).
func emitPoolResumedEvent(stateDB StateDB, caller common.Address, poolId [32]byte) {
	stateDB.AddLog(&ethtypes.Log{
		Address: lxPoolAddr,
		Topics: []common.Hash{
			poolResumedEventSig,
			common.BytesToHash(poolId[:]),
			common.BytesToHash(caller.Bytes()),
		},
		Data: nil,
	})
}

// emitPoolFrozenEvent emits PoolFrozen(bytes32 poolId, address caller).
// This event is permanent — there is no corresponding "unfreeze" event.
func emitPoolFrozenEvent(stateDB StateDB, caller common.Address, poolId [32]byte) {
	stateDB.AddLog(&ethtypes.Log{
		Address: lxPoolAddr,
		Topics: []common.Hash{
			poolFrozenEventSig,
			common.BytesToHash(poolId[:]),
			common.BytesToHash(caller.Bytes()),
		},
		Data: nil,
	})
}
