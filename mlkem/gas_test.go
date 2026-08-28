// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mlkem

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// Nothing this precompile can be handed is free. Empty calldata, an
// unknown op and an unknown mode all fall back to the ML-KEM-768 fee
// rather than to zero -- a zero branch would be an unmetered path.
func TestGas_EveryBranchCharges(t *testing.T) {
	fixed := map[string][]byte{"nil": nil, "empty": {}, "op only": {OpEncapsulate}}
	for name, in := range fixed {
		require.NotZerof(t, MLKEMPrecompile.RequiredGas(in), "%s is an unmetered branch", name)
	}
	for op := range 256 {
		for _, mode := range []uint8{ModeMLKEM512, ModeMLKEM768, ModeMLKEM1024, 0x7F, 0xFF} {
			require.NotZerof(t, MLKEMPrecompile.RequiredGas([]byte{byte(op), mode}),
				"op 0x%02x mode 0x%02x is an unmetered branch", op, mode)
		}
	}
}

// Bigger parameter set, more lattice arithmetic, more gas.
func TestGas_RisesWithParameterSet(t *testing.T) {
	fee := func(mode uint8) uint64 {
		return MLKEMPrecompile.RequiredGas([]byte{OpEncapsulate, mode})
	}
	require.Equal(t, MLKEM512EncapsulateGas, fee(ModeMLKEM512))
	require.Equal(t, MLKEM768EncapsulateGas, fee(ModeMLKEM768))
	require.Equal(t, MLKEM1024EncapsulateGas, fee(ModeMLKEM1024))
	require.Less(t, fee(ModeMLKEM512), fee(ModeMLKEM768))
	require.Less(t, fee(ModeMLKEM768), fee(ModeMLKEM1024))
}

// The fee is flat in calldata length because the work is: the key size is
// fixed by the mode and any other length is refused. Charging per byte
// here would price a call that never happens. What must hold is that a
// long call cannot buy more work than it paid for -- so assert the fee is
// unmoved AND that the oversized call is refused rather than run.
func TestGas_FlatInLengthAndOversizeRefused(t *testing.T) {
	base := MLKEMPrecompile.RequiredGas([]byte{OpEncapsulate, ModeMLKEM768})
	for _, n := range []int{2, 100, MLKEM768PublicKeySize, 1 << 16} {
		in := make([]byte, n)
		in[0] = OpEncapsulate
		in[1] = ModeMLKEM768
		require.Equalf(t, base, MLKEMPrecompile.RequiredGas(in), "length %d moved the fee", n)

		_, _, err := MLKEMPrecompile.Run(nil, common.Address{}, ContractAddress, in, base, true)
		require.Errorf(t, err, "length %d was encapsulated against", n)
	}
}

// The quoted fee is exactly what the call consumes, and one unit short
// stops at the meter.
func TestGas_QuotedFeeIsCharged(t *testing.T) {
	in := encapFrame(t, ModeMLKEM768, 0x99)
	fee := MLKEMPrecompile.RequiredGas(in)
	require.Equal(t, MLKEM768EncapsulateGas, fee)

	_, remaining, err := MLKEMPrecompile.Run(nil, common.Address{}, ContractAddress, in, fee-1, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, remaining)

	_, remaining, err = MLKEMPrecompile.Run(nil, common.Address{}, ContractAddress, in, fee+5, true)
	require.NoError(t, err)
	require.Equal(t, uint64(5), remaining)
}

// Refusal consumes the fee: handing the node something unparseable is not
// free just because it failed.
func TestGas_RefusalConsumesTheFee(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty":        {},
		"unknown op":   {0xEE, ModeMLKEM768},
		"unknown mode": {OpEncapsulate, 0xEE},
		"short key":    {OpEncapsulate, ModeMLKEM768, 0x00},
	} {
		fee := MLKEMPrecompile.RequiredGas(in)
		_, remaining, err := MLKEMPrecompile.Run(nil, common.Address{}, ContractAddress, in, fee+2, true)
		require.Errorf(t, err, "%s", name)
		require.Equalf(t, uint64(2), remaining, "%s: fee not consumed on refusal", name)
	}
}

// Zero supplied gas is refused whatever the input looks like.
func TestGas_ZeroSuppliedIsRefused(t *testing.T) {
	for name, in := range map[string][]byte{
		"valid frame": encapFrame(t, ModeMLKEM512, 0xAB),
		"unknown op":  {0xEE},
		"empty":       {},
	} {
		_, remaining, err := MLKEMPrecompile.Run(nil, common.Address{}, ContractAddress, in, 0, true)
		require.ErrorIsf(t, err, contract.ErrOutOfGas, "%s", name)
		require.Zerof(t, remaining, "%s", name)
	}
}
