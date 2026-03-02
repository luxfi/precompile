// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
)

// TickInfo stores per-tick state matching Uniswap V4 Pool.TickInfo.
// This is a thin state struct for PoolState — all math that operates
// on ticks lives in the DEX engine (~/work/lux/dex/pkg/lx/).
type TickInfo struct {
	LiquidityGross        *big.Int // Total liquidity referencing this tick
	LiquidityNet          *big.Int // Net liquidity change when tick is crossed
	FeeGrowthOutside0X128 *big.Int // Fee growth per unit of liquidity on the other side
	FeeGrowthOutside1X128 *big.Int
}

// NewTickInfo creates a zero-initialized TickInfo.
func NewTickInfo() *TickInfo {
	return &TickInfo{
		LiquidityGross:        big.NewInt(0),
		LiquidityNet:          big.NewInt(0),
		FeeGrowthOutside0X128: big.NewInt(0),
		FeeGrowthOutside1X128: big.NewInt(0),
	}
}

// TickBitmap tracks initialized tick state.
// This is a thin state container for PoolState — all bitmap traversal
// math lives in the DEX engine (~/work/lux/dex/pkg/lx/).
type TickBitmap struct {
	Words map[int16]*big.Int
}

// NewTickBitmap creates an empty tick bitmap.
func NewTickBitmap() *TickBitmap {
	return &TickBitmap{
		Words: make(map[int16]*big.Int),
	}
}
