// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package stableswap

import (
	"math/big"
	"testing"

	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// balancedBalances returns n equal balances of 1e18 each.
func balancedBalances(n int) []*big.Int {
	out := make([]*big.Int, n)
	for i := range out {
		out[i] = big.NewInt(1e18)
	}
	return out
}

// TestStableSwap_TooManyTokensRejected proves the DoS dimension is closed: an attacker
// who supplies a token count above maxTokens is rejected CHEAPLY, before any Newton
// solve allocates big.Ints or iterates. Before the cap, a large n forced the solver into
// O(maxIterations*n) big.Int mul/div over operands growing ~O(n*256) bits — super-linear
// in-consensus compute paid for with flat gas, i.e. a one-transaction validator halt.
func TestStableSwap_TooManyTokensRejected(t *testing.T) {
	for _, n := range []int{maxTokens + 1, 64, 4096} {
		input := encodeGetD(n, big.NewInt(100), balancedBalances(n))
		// Plenty of gas — the point is that the CAP rejects, not gas exhaustion.
		_, _, err := Precompile.Run(nil, ContractAddress, ContractAddress, input, 100_000_000, false)
		require.ErrorIs(t, err, ErrTooManyTokens, "n=%d must be rejected by the maxTokens cap", n)
	}

	// maxTokens itself is still accepted (the cap is an upper bound, not off-by-one).
	input := encodeGetD(maxTokens, big.NewInt(100), balancedBalances(maxTokens))
	_, _, err := Precompile.Run(nil, ContractAddress, ContractAddress, input, 100_000_000, false)
	require.NoError(t, err, "n==maxTokens must be accepted")
}

// TestStableSwap_WorstCaseGasChargedUpfront proves gas reflects the BOUNDED WORST CASE
// (every iteration over every token) and is deducted BEFORE the solve runs — so the
// flat-gas mispricing is gone and the charge scales with n.
func TestStableSwap_WorstCaseGasChargedUpfront(t *testing.T) {
	// getD runs 1 Newton solve: worst case = GasBase + n*maxIterations*gasPerTokenIter.
	worst := func(n int) uint64 {
		return GasBase + uint64(n)*uint64(maxIterations)*gasPerTokenIter
	}
	require.Equal(t, uint64(10_120), worst(2))
	require.Equal(t, uint64(25_480), worst(8))

	run := func(n int, gas uint64) error {
		input := encodeGetD(n, big.NewInt(100), balancedBalances(n))
		_, _, err := Precompile.Run(nil, ContractAddress, ContractAddress, input, gas, false)
		return err
	}

	// Exactly worst-case gas succeeds; one less is out-of-gas — charged up front, even
	// though a balanced pool actually converges in a handful of iterations.
	require.NoError(t, run(8, worst(8)))
	require.ErrorIs(t, run(8, worst(8)-1), contract.ErrOutOfGas)

	// Gas scales with n: a budget that funds a 2-token solve cannot fund an 8-token one.
	require.NoError(t, run(2, worst(2)))
	require.ErrorIs(t, run(8, worst(2)), contract.ErrOutOfGas)
}

// TestStableSwap_NewtonBoundedAndTypedError proves the solver always TERMINATES and
// surfaces a TYPED error on a bad input — never an unbounded loop, never a panic, never a
// silent wrong answer. The maxIterations cap guarantees the call returns; a zero-balance
// pool exercises the typed-error path.
func TestStableSwap_NewtonBoundedAndTypedError(t *testing.T) {
	// Zero-balance token -> typed ErrZeroLiquidity from inside the Newton loop, not a
	// divide-by-zero panic.
	_, err := computeD([]*big.Int{big.NewInt(0), big.NewInt(1e18)}, big.NewInt(100), 2)
	require.ErrorIs(t, err, ErrZeroLiquidity)

	// Adversarial-but-valid pools must all RETURN (bounded loop) with either a value or a
	// typed error — the test completing at all is the termination proof.
	adversarial := [][]*big.Int{
		{big.NewInt(1), new(big.Int).Lsh(big.NewInt(1), 200)}, // 1 vs 2^200
		{big.NewInt(1e18), big.NewInt(1)},                     // extreme imbalance
		{new(big.Int).Lsh(big.NewInt(1), 250), big.NewInt(3)}, // near-uint256 vs tiny
	}
	for i, bal := range adversarial {
		d, derr := computeD(bal, big.NewInt(1), 2)
		if derr != nil {
			require.ErrorIs(t, derr, ErrConvergence, "case %d: non-convergence must be the typed ErrConvergence", i)
		} else {
			require.NotNil(t, d, "case %d: a nil result without an error would be a silent wrong answer", i)
		}
	}
}
