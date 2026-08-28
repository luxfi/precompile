// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hqc

import (
	"math"
	"testing"

	"github.com/luxfi/crypto/hqc"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// Nothing is free, including the empty call.
func TestGas_EveryInputCharges(t *testing.T) {
	for name, in := range map[string][]byte{
		"nil":         nil,
		"empty":       {},
		"op only":     {OpEncapsulate},
		"unknown op":  {0xEE, ModeHQC128},
		"bad mode":    {OpEncapsulate, 0xEE},
		"valid frame": frame(ModeHQC128, 0x01),
	} {
		require.NotZerof(t, HQCPrecompile.RequiredGas(in), "%s is an unmetered branch", name)
	}
	require.Equal(t, BaseEncapsulateGas, HQCPrecompile.RequiredGas(nil))
}

// The fee is base + len*k over the whole call, and it strictly rises with
// length -- HQC's polynomial multiplication is over the key, so a bigger
// key really is more work.
func TestGas_RisesWithInputLength(t *testing.T) {
	prev := HQCPrecompile.RequiredGas(nil)
	for _, n := range []int{1, 2, 34, 2251, 4556, 7279, 1 << 20} {
		got := HQCPrecompile.RequiredGas(make([]byte, n))
		require.Equal(t, BaseEncapsulateGas+uint64(n)*PerByteGas, got, "length %d", n)
		require.Greaterf(t, got, prev, "length %d cost no more than the length before it", n)
		prev = got
	}
}

// A larger parameter set costs more, because its key is longer and the fee
// is charged over the call.
func TestGas_RisesWithParameterSet(t *testing.T) {
	prev := uint64(0)
	for _, mode := range []uint8{ModeHQC128, ModeHQC192, ModeHQC256} {
		got := HQCPrecompile.RequiredGas(frame(mode, 0x01))
		require.Greaterf(t, got, prev, "mode 0x%02x cost no more than the set below it", mode)
		prev = got
	}
}

// The per-byte term is multiplied by len(input), which is the size of a
// buffer the caller actually paid the EVM to materialise -- not a number
// it declared. The ML-DSA precompile next door needs a saturating cap
// because its length is a 256-bit calldata field; this one cannot reach a
// wrap, and here is the arithmetic that says so.
func TestGas_LengthCannotWrapTheFee(t *testing.T) {
	wrapAt := (math.MaxUint64 - BaseEncapsulateGas) / PerByteGas
	require.Greater(t, wrapAt, uint64(1)<<60,
		"the fee would wrap at a length the EVM could plausibly reach")

	// Everything the fee is ever asked about is many orders below that,
	// and the largest legitimate call is a rounding error against it.
	widest := len(frame(ModeHQC256, 0x01))
	require.Less(t, uint64(widest), wrapAt/(1<<40))
	require.Greater(t, HQCPrecompile.RequiredGas(frame(ModeHQC256, 0x01)), BaseEncapsulateGas)
}

// The quoted fee is exactly what a call consumes, and one unit short is
// refused before the input is even looked at.
func TestGas_QuotedFeeIsCharged(t *testing.T) {
	in := frame(ModeHQC128, 0x01)
	fee := HQCPrecompile.RequiredGas(in)

	_, remaining, err := HQCPrecompile.Run(nil, common.Address{}, ContractAddress, in, fee-1, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, remaining)

	_, remaining, _ = HQCPrecompile.Run(nil, common.Address{}, ContractAddress, in, fee+6, true)
	require.Equal(t, uint64(6), remaining, "only the fee is consumed")
}

// Refused input keeps its fee: a malformed call is not a free call.
func TestGas_RefusalConsumesTheFee(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty":        {},
		"unknown op":   {0xEE, ModeHQC128},
		"unknown mode": frame(ModeHQC128, 0x01),
		"short key":    append([]byte{OpEncapsulate, ModeHQC128}, make([]byte, SeedSize+7)...),
	} {
		call := append([]byte{}, in...)
		if name == "unknown mode" {
			call[1] = 0xEE
		}
		fee := HQCPrecompile.RequiredGas(call)
		_, remaining, err := HQCPrecompile.Run(nil, common.Address{}, ContractAddress, call, fee+8, true)
		require.Errorf(t, err, "%s", name)
		require.Equalf(t, uint64(8), remaining, "%s: fee not consumed on refusal", name)
	}
}

func TestGas_ZeroSuppliedIsRefused(t *testing.T) {
	for name, in := range map[string][]byte{
		"valid frame": frame(ModeHQC128, 0x01),
		"unknown op":  {0xEE},
		"empty":       {},
	} {
		_, remaining, err := HQCPrecompile.Run(nil, common.Address{}, ContractAddress, in, 0, true)
		require.ErrorIsf(t, err, contract.ErrOutOfGas, "%s", name)
		require.Zerof(t, remaining, "%s", name)
	}
}

// The size constants this precompile frames against are the NIST IR 8528
// ones, read from the wrapped library rather than restated here.
func TestGas_ParameterSizesAreTheNISTOnes(t *testing.T) {
	for mode, want := range map[uint8][3]int{
		ModeHQC128: {2249, 4433, 64},
		ModeHQC192: {4522, 8978, 64},
		ModeHQC256: {7245, 14421, 64},
	} {
		p := hqc.MustParamsFor(modes[mode])
		require.Equalf(t, want[0], p.PublicKeySize, "mode 0x%02x public key", mode)
		require.Equalf(t, want[1], p.CiphertextSize, "mode 0x%02x ciphertext", mode)
		require.Equalf(t, want[2], p.SharedSecretSize, "mode 0x%02x shared secret", mode)
	}
}
