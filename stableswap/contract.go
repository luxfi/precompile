// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// Package stableswap implements Curve-style StableSwap AMM as a precompile.
// Address: 0x0460 (DEX extended range)
//
// Implements the StableSwap invariant:
//   An^n * sum(x_i) + D = A * D^(n+1) / (n^n * prod(x_i))
//
// Operations:
//   - 0x01: GetDy(i, j, dx) -> output amount for swap i->j
//   - 0x02: AddLiquidity(amounts) -> LP tokens minted
//   - 0x03: RemoveLiquidity(lp_amount) -> underlying amounts
//   - 0x04: GetD(balances, amp) -> invariant D
//
// Gas: 5,000 base (vs ~50,000 in Solidity — 10x savings)
// Used for: LUSD/USDC, LETH/stETH, any pegged-asset pools
package stableswap

import "github.com/luxfi/precompile/contract"

var _ contract.StatefulPrecompiledContract = (*StableSwapPrecompile)(nil)

type StableSwapPrecompile struct{}
