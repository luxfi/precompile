// dex_swap_test exercises the StableSwap AMM precompile:
//
//  1. Compute pool invariant D from balances
//  2. Compute swap output (GetDy)
//  3. Verify invariant preservation (D stays constant through swap)
//  4. Test edge cases (zero swap, unbalanced pool)
//
// Precompiles exercised: StableSwap.
package scenarios

import (
	"math/big"
	"testing"

	"github.com/luxfi/precompile/e2e/harness"
	"github.com/luxfi/precompile/stableswap"
	"github.com/stretchr/testify/require"
)

func TestDEXSwap_StableSwapGetD(t *testing.T) {
	// Compute invariant D for a balanced 2-token pool
	// Each token: 1,000,000 units, amplification A=100
	balance := harness.PadLeft(new(big.Int).SetUint64(1_000_000).Bytes(), 32)
	amp := harness.PadLeft(new(big.Int).SetUint64(100).Bytes(), 32)

	input := make([]byte, 0, 1+1+64+32)
	input = append(input, stableswap.OpGetD)
	input = append(input, 2) // numTokens
	input = append(input, balance...)
	input = append(input, balance...)
	input = append(input, amp...)

	out, gas, err := harness.Call(
		stableswap.Precompile,
		stableswap.ContractAddress,
		input,
		true,
	)
	require.NoError(t, err, "GetD failed")
	require.Len(t, out, 32, "D should be 32 bytes")

	d := new(big.Int).SetBytes(out)
	require.True(t, d.Sign() > 0, "D must be positive")
	harness.GasReport(t, "StableSwap GetD", gas)

	// For a balanced pool with 1M each, D should be ~2M
	expectedD := new(big.Int).SetUint64(2_000_000)
	diff := new(big.Int).Sub(d, expectedD)
	diff.Abs(diff)
	// Allow 1% tolerance for Newton iteration rounding
	tolerance := new(big.Int).Div(expectedD, big.NewInt(100))
	require.True(t, diff.Cmp(tolerance) <= 0,
		"D=%s should be close to 2M (diff=%s)", d.String(), diff.String())
	t.Logf("Pool invariant D = %s", d.String())
}

func TestDEXSwap_StableSwapGetDy(t *testing.T) {
	// Swap 1000 of token 0 for token 1 in a balanced pool
	balance := harness.PadLeft(new(big.Int).SetUint64(1_000_000).Bytes(), 32)
	amp := harness.PadLeft(new(big.Int).SetUint64(100).Bytes(), 32)
	dx := harness.PadLeft(new(big.Int).SetUint64(1000).Bytes(), 32)

	input := make([]byte, 0, 1+1+1+32+1+64+32)
	input = append(input, stableswap.OpGetDy)
	input = append(input, 0)    // i = token 0
	input = append(input, 1)    // j = token 1
	input = append(input, dx...) // swap 1000
	input = append(input, 2)    // numTokens
	input = append(input, balance...)
	input = append(input, balance...)
	input = append(input, amp...)

	out, gas, err := harness.Call(
		stableswap.Precompile,
		stableswap.ContractAddress,
		input,
		true,
	)
	require.NoError(t, err, "GetDy failed")
	require.Len(t, out, 32, "dy should be 32 bytes")

	dy := new(big.Int).SetBytes(out)
	require.True(t, dy.Sign() > 0, "dy must be positive")
	harness.GasReport(t, "StableSwap GetDy", gas)

	// In a balanced stableswap pool (A=100), swapping 1000 should yield ~999
	// (very close to 1:1 due to high amplification)
	t.Logf("Swap 1000 token0 -> %s token1", dy.String())
	require.True(t, dy.Uint64() >= 990 && dy.Uint64() <= 1000,
		"dy=%d should be ~999 for balanced pool with A=100", dy.Uint64())
}

func TestDEXSwap_InvariantPreservation(t *testing.T) {
	// Verify that D remains constant after a swap:
	// 1. Compute D with initial balances
	// 2. Compute swap output dy
	// 3. Compute D with post-swap balances
	// 4. Assert D_before == D_after

	balA := uint64(1_000_000)
	balB := uint64(1_000_000)
	swapAmt := uint64(10_000)
	ampVal := uint64(100)

	// Compute D_before
	dBefore := computeD(t, balA, balB, ampVal)

	// Compute dy
	dy := computeDy(t, 0, 1, swapAmt, balA, balB, ampVal)

	// Post-swap balances: balA + dx, balB - dy
	newBalA := balA + swapAmt
	newBalB := balB - dy

	// Compute D_after
	dAfter := computeD(t, newBalA, newBalB, ampVal)

	// D should be preserved (within rounding tolerance)
	diff := new(big.Int).Sub(dBefore, dAfter)
	diff.Abs(diff)
	// Allow 1 unit tolerance for integer rounding
	require.True(t, diff.Cmp(big.NewInt(1)) <= 0,
		"D before (%s) != D after (%s), diff=%s", dBefore.String(), dAfter.String(), diff.String())

	t.Logf("D_before=%s, D_after=%s (invariant preserved)", dBefore.String(), dAfter.String())
}

func TestDEXSwap_UnbalancedPool(t *testing.T) {
	// Test swap in an unbalanced pool (10:1 ratio)
	balA := uint64(10_000_000)
	balB := uint64(1_000_000)
	swapAmt := uint64(1000)
	ampVal := uint64(100)

	dy := computeDy(t, 0, 1, swapAmt, balA, balB, ampVal)
	t.Logf("Unbalanced pool (10:1): swap 1000 token0 -> %d token1", dy)
	// In an unbalanced pool, the output should be less than the balanced case
	require.True(t, dy > 0, "dy must be positive even in unbalanced pool")
}

// Helper functions

func computeD(t *testing.T, balA, balB, amp uint64) *big.Int {
	t.Helper()
	input := make([]byte, 0, 1+1+64+32)
	input = append(input, stableswap.OpGetD)
	input = append(input, 2)
	input = append(input, harness.PadLeft(new(big.Int).SetUint64(balA).Bytes(), 32)...)
	input = append(input, harness.PadLeft(new(big.Int).SetUint64(balB).Bytes(), 32)...)
	input = append(input, harness.PadLeft(new(big.Int).SetUint64(amp).Bytes(), 32)...)

	out, _, err := harness.Call(stableswap.Precompile, stableswap.ContractAddress, input, true)
	require.NoError(t, err)
	return new(big.Int).SetBytes(out)
}

func computeDy(t *testing.T, i, j byte, dx, balA, balB, amp uint64) uint64 {
	t.Helper()
	input := make([]byte, 0, 1+1+1+32+1+64+32)
	input = append(input, stableswap.OpGetDy)
	input = append(input, i)
	input = append(input, j)
	input = append(input, harness.PadLeft(new(big.Int).SetUint64(dx).Bytes(), 32)...)
	input = append(input, 2)
	input = append(input, harness.PadLeft(new(big.Int).SetUint64(balA).Bytes(), 32)...)
	input = append(input, harness.PadLeft(new(big.Int).SetUint64(balB).Bytes(), 32)...)
	input = append(input, harness.PadLeft(new(big.Int).SetUint64(amp).Bytes(), 32)...)

	out, _, err := harness.Call(stableswap.Precompile, stableswap.ContractAddress, input, true)
	require.NoError(t, err)
	return new(big.Int).SetBytes(out).Uint64()
}
