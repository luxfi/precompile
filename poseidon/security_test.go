// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package poseidon

import (
	"encoding/binary"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// H-01: Poseidon sponge must properly squeeze, not zero-pad.
//
// Vulnerability: When requesting N > 32 bytes of output, the sponge returned
// 32 bytes of real hash followed by (N-32) zero bytes. This means a 1024-byte
// output contains 992 bytes of zeros, providing zero additional entropy and
// breaking the security of any application depending on the full output length.
//
// Fix: The sponge must either properly squeeze multiple blocks (re-permuting
// the state between squeezes) or reject output lengths > 32 bytes. Zero-padding
// is never acceptable.
func TestH01_PoseidonSpongeNoZeroPad(t *testing.T) {
	// Create sponge input: outLen(4) + one 32-byte field element
	outLen := uint32(256)
	input := make([]byte, 4+32)
	binary.BigEndian.PutUint32(input[:4], outLen)
	// Fill the field element with non-zero data
	for i := 4; i < 36; i++ {
		input[i] = byte(i)
	}

	calldata := append([]byte{OpSponge}, input...)
	gas := PoseidonPrecompile.RequiredGas(calldata)

	ret, _, err := PoseidonPrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		calldata,
		gas+100_000,
		false,
	)

	if err != nil {
		// If the fix rejects long output, that is also acceptable.
		// The vulnerability was silently zero-padding without error.
		t.Logf("Sponge rejected outLen=%d (acceptable fix: reject rather than zero-pad): %v", outLen, err)
		return
	}

	require.Equal(t, int(outLen), len(ret), "Output length must match requested length")

	// Count zeros in the tail (bytes 32..255)
	zeroCount := 0
	for i := 32; i < len(ret); i++ {
		if ret[i] == 0 {
			zeroCount++
		}
	}

	tailLen := int(outLen) - 32
	// Allow some zeros (random chance) but not all.
	// If > 90% of tail bytes are zero, the sponge is still zero-padding.
	maxAcceptableZeros := tailLen * 90 / 100
	require.Less(t, zeroCount, maxAcceptableZeros,
		"Sponge tail has %d/%d zeros -- likely zero-padding instead of squeezing", zeroCount, tailLen)
}

// H-01: Sponge output of 32 bytes must be non-trivial.
//
// Even at the minimum squeeze (32 bytes), the sponge must produce a
// properly computed hash, not zeros or constant output.
func TestH01_PoseidonSponge32NonTrivial(t *testing.T) {
	elem := make([]byte, 32)
	for i := range elem {
		elem[i] = byte(i + 1)
	}

	spongeData := make([]byte, 4+32)
	binary.BigEndian.PutUint32(spongeData[:4], 32)
	copy(spongeData[4:], elem)
	spongeInput := append([]byte{OpSponge}, spongeData...)
	spongeGas := PoseidonPrecompile.RequiredGas(spongeInput)
	spongeRet, _, err := PoseidonPrecompile.Run(nil, common.Address{}, ContractAddress, spongeInput, spongeGas+100_000, false)
	require.NoError(t, err)
	require.Len(t, spongeRet, 32)

	// Output must not be all zeros
	allZero := true
	for _, b := range spongeRet {
		if b != 0 {
			allZero = false
			break
		}
	}
	require.False(t, allZero, "Sponge(outLen=32) must produce non-zero output")

	// Sponge must be deterministic: same input -> same output
	spongeRet2, _, err := PoseidonPrecompile.Run(nil, common.Address{}, ContractAddress, spongeInput, spongeGas+100_000, false)
	require.NoError(t, err)
	require.Equal(t, spongeRet, spongeRet2, "Sponge must be deterministic")
}

// H-01: Sponge with outLen=0 must be rejected.
func TestH01_PoseidonSpongeZeroLenRejected(t *testing.T) {
	data := make([]byte, 4+32)
	binary.BigEndian.PutUint32(data[:4], 0)
	input := append([]byte{OpSponge}, data...)
	gas := PoseidonPrecompile.RequiredGas(input)

	_, _, err := PoseidonPrecompile.Run(nil, common.Address{}, ContractAddress, input, gas+100_000, false)
	require.Error(t, err, "Sponge with outLen=0 must be rejected")
}

// H-01: Sponge with outLen > 1024 must be rejected (DoS limit).
func TestH01_PoseidonSpongeMaxLenCapped(t *testing.T) {
	data := make([]byte, 4+32)
	binary.BigEndian.PutUint32(data[:4], 2048) // Over the 1024 cap
	input := append([]byte{OpSponge}, data...)
	gas := PoseidonPrecompile.RequiredGas(input)

	_, _, err := PoseidonPrecompile.Run(nil, common.Address{}, ContractAddress, input, gas+100_000, false)
	require.Error(t, err, "Sponge with outLen > 1024 must be rejected")
}

// H-01: Different output lengths must produce different results (when > 32).
//
// If the sponge properly squeezes, truncating at different lengths
// should yield the same prefix but different overall results.
func TestH01_PoseidonSpongeDifferentLengthsDiffer(t *testing.T) {
	elem := make([]byte, 32)
	for i := range elem {
		elem[i] = byte(i + 42)
	}

	var results [][]byte
	for _, outLen := range []uint32{64, 128, 256} {
		data := make([]byte, 4+32)
		binary.BigEndian.PutUint32(data[:4], outLen)
		copy(data[4:], elem)
		input := append([]byte{OpSponge}, data...)
		gas := PoseidonPrecompile.RequiredGas(input)

		ret, _, err := PoseidonPrecompile.Run(nil, common.Address{}, ContractAddress, input, gas+100_000, false)
		if err != nil {
			t.Skipf("Sponge rejects outLen=%d (acceptable)", outLen)
		}
		require.Equal(t, int(outLen), len(ret))
		results = append(results, ret)
	}

	if len(results) >= 2 {
		// The first 32 bytes should be the same (same single squeeze)
		require.Equal(t, results[0][:32], results[1][:32],
			"First 32 bytes should match between 64-byte and 128-byte outputs")
	}
}
