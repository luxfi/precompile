// Package dex demonstrates DEX (Uniswap v4-style) and StableSwap precompiles.
package dex

import (
	"encoding/binary"
	"math/big"

	"github.com/luxfi/precompile/examples"
	"github.com/luxfi/precompile/stableswap"
)

type AllDEXDemos struct{}

func (d AllDEXDemos) Name() string { return "dex" }

func (d AllDEXDemos) Run() []examples.Result {
	var all []examples.Result
	all = append(all, StableSwapDemo()...)
	return all
}

// StableSwapDemo exercises the Curve-style StableSwap AMM precompile (0x0400..60).
func StableSwapDemo() []examples.Result {
	// OpGetD (0x04): compute invariant D from balances and amplification
	// Format: op(1) + numTokens(1) + balances(n * 32) + amp(32)
	numTokens := byte(2)
	balance1 := examples.PadLeft(new(big.Int).SetUint64(1_000_000).Bytes(), 32) // 1M
	balance2 := examples.PadLeft(new(big.Int).SetUint64(1_000_000).Bytes(), 32) // 1M
	amp := examples.PadLeft(new(big.Int).SetUint64(100).Bytes(), 32)            // A=100

	getDInput := make([]byte, 0, 1+1+64+32)
	getDInput = append(getDInput, stableswap.OpGetD)
	getDInput = append(getDInput, numTokens)
	getDInput = append(getDInput, balance1...)
	getDInput = append(getDInput, balance2...)
	getDInput = append(getDInput, amp...)

	// OpGetDy (0x01): compute output amount for swap i->j
	// Format: op(1) + i(1) + j(1) + dx(32) + numTokens(1) + balances(n*32) + amp(32)
	dx := examples.PadLeft(new(big.Int).SetUint64(1000).Bytes(), 32)

	getDyInput := make([]byte, 0, 1+1+1+32+1+64+32)
	getDyInput = append(getDyInput, stableswap.OpGetDy)
	getDyInput = append(getDyInput, 0)          // i = token 0
	getDyInput = append(getDyInput, 1)          // j = token 1
	getDyInput = append(getDyInput, dx...)       // swap 1000
	getDyInput = append(getDyInput, numTokens)
	getDyInput = append(getDyInput, balance1...)
	getDyInput = append(getDyInput, balance2...)
	getDyInput = append(getDyInput, amp...)

	_ = binary.BigEndian // suppress unused import

	return []examples.Result{
		examples.CallPrecompileResult(
			"StableSwap GetD",
			stableswap.Precompile,
			stableswap.ContractAddress,
			getDInput,
			func(out []byte) bool { return len(out) == 32 && examples.IsNonZero(out) },
		),
		examples.CallPrecompileResult(
			"StableSwap GetDy (swap)",
			stableswap.Precompile,
			stableswap.ContractAddress,
			getDyInput,
			func(out []byte) bool { return len(out) == 32 && examples.IsNonZero(out) },
		),
	}
}
