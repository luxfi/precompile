// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package xwing

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// Every reachable branch of RequiredGas charges something. A branch that
// charges nothing is an unmetered path: the caller pays only for the CALL
// itself while the node still does the work of refusing.
func TestGas_EveryBranchCharges(t *testing.T) {
	inputs := map[string][]byte{"nil": nil, "empty": {}, "encapsulate": {OpEncapsulate}}
	for op := range 256 {
		if byte(op) == OpEncapsulate {
			continue
		}
		inputs[string(rune('a'+op%26))+"-op"] = []byte{byte(op)}
	}
	for name, in := range inputs {
		require.NotZerof(t, XWingPrecompile.RequiredGas(in), "%s: unmetered branch", name)
	}
}

// Doing the work costs more than declining to.
func TestGas_WorkCostsMoreThanRefusal(t *testing.T) {
	work := XWingPrecompile.RequiredGas([]byte{OpEncapsulate})
	refuse := XWingPrecompile.RequiredGas([]byte{0xFF})
	require.Greater(t, work, refuse)
	require.Equal(t, uint64(GasEncapsulate), work)
	require.Equal(t, uint64(GasRefuse), refuse)
}

// The fee does not move with calldata length: X-Wing encapsulation is a
// fixed-size operation, so a longer frame is refused rather than charged for.
func TestGas_IndependentOfLength(t *testing.T) {
	base := XWingPrecompile.RequiredGas([]byte{OpEncapsulate})
	for _, n := range []int{1, 33, 1249, 100_000} {
		in := make([]byte, n)
		in[0] = OpEncapsulate
		require.Equal(t, base, XWingPrecompile.RequiredGas(in), "length %d", n)
	}
}

// One wei short of the fee and the call never reaches the crypto.
func TestGas_ExactFeeIsTheThreshold(t *testing.T) {
	in, _ := frame(t, 0x01)
	gas := XWingPrecompile.RequiredGas(in)

	_, remaining, err := XWingPrecompile.Run(nil, common.Address{}, ContractAddress, in, gas-1, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, remaining)

	_, remaining, err = XWingPrecompile.Run(nil, common.Address{}, ContractAddress, in, gas, true)
	require.NoError(t, err)
	require.Zero(t, remaining)

	_, remaining, err = XWingPrecompile.Run(nil, common.Address{}, ContractAddress, in, gas+7, true)
	require.NoError(t, err)
	require.Equal(t, uint64(7), remaining, "only the fee is consumed")
}

// Zero supplied gas is refused for every shape of input.
func TestGas_ZeroSuppliedIsRefused(t *testing.T) {
	in, _ := frame(t, 0x01)
	for name, calldata := range map[string][]byte{
		"valid frame": in,
		"unknown op":  {0xFF},
		"empty":       {},
	} {
		_, remaining, err := XWingPrecompile.Run(nil, common.Address{}, ContractAddress, calldata, 0, true)
		require.ErrorIsf(t, err, contract.ErrOutOfGas, "%s", name)
		require.Zerof(t, remaining, "%s", name)
	}
}
