// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quasar

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/vm"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Verkle Precompile Tests
// =============================================================================

func TestVerklePrecompile_Address(t *testing.T) {
	v := &verklePrecompile{}
	expected := common.HexToAddress(VerkleVerifyAddress)
	require.Equal(t, expected, v.Address())
}

func TestVerklePrecompile_RequiredGas(t *testing.T) {
	v := &verklePrecompile{}
	require.Equal(t, uint64(VerkleVerifyGas), v.RequiredGas(nil))
	require.Equal(t, uint64(VerkleVerifyGas), v.RequiredGas(make([]byte, 100)))
}

func TestVerklePrecompile_ValidWitness(t *testing.T) {
	v := &verklePrecompile{}

	// Input: [commitment(32)] [proof(32)] [threshold_met(1)]
	// Create matching commitment and proof for valid verification
	commitment := make([]byte, 32)
	for i := 0; i < 32; i++ {
		commitment[i] = byte(i)
	}
	proof := make([]byte, 32)
	copy(proof, commitment) // Same bytes = verifyVerkleLight returns true
	thresholdMet := byte(1)

	input := append(commitment, proof...)
	input = append(input, thresholdMet)

	ret, remainingGas, err := v.Run(nil, common.Address{}, v.Address(), input, VerkleVerifyGas, true)
	require.NoError(t, err)
	require.Equal(t, uint64(0), remainingGas)
	require.Equal(t, []byte{1}, ret)
}

func TestVerklePrecompile_ThresholdNotMet(t *testing.T) {
	v := &verklePrecompile{}

	// Create valid input but threshold not met
	commitment := make([]byte, 32)
	proof := make([]byte, 32)
	thresholdMet := byte(0) // Threshold NOT met

	input := append(commitment, proof...)
	input = append(input, thresholdMet)

	ret, remainingGas, err := v.Run(nil, common.Address{}, v.Address(), input, VerkleVerifyGas, true)
	require.NoError(t, err)
	require.Equal(t, uint64(0), remainingGas)
	require.Equal(t, []byte{0}, ret) // Returns false
}

func TestVerklePrecompile_InvalidProof(t *testing.T) {
	v := &verklePrecompile{}

	// Create mismatched commitment and proof
	commitment := make([]byte, 32)
	for i := 0; i < 32; i++ {
		commitment[i] = byte(i)
	}
	proof := make([]byte, 32)
	for i := 0; i < 32; i++ {
		proof[i] = byte(255 - i) // Different from commitment
	}
	thresholdMet := byte(1)

	input := append(commitment, proof...)
	input = append(input, thresholdMet)

	ret, remainingGas, err := v.Run(nil, common.Address{}, v.Address(), input, VerkleVerifyGas, true)
	require.NoError(t, err)
	require.Equal(t, uint64(0), remainingGas)
	require.Equal(t, []byte{0}, ret) // Returns false due to mismatch
}

func TestVerklePrecompile_InputTooShort(t *testing.T) {
	v := &verklePrecompile{}

	// Input less than 65 bytes
	input := make([]byte, 64)

	ret, remainingGas, err := v.Run(nil, common.Address{}, v.Address(), input, VerkleVerifyGas, true)
	require.ErrorIs(t, err, ErrInvalidInput)
	require.Nil(t, ret)
	require.Equal(t, uint64(0), remainingGas)
}

func TestVerklePrecompile_OutOfGas(t *testing.T) {
	v := &verklePrecompile{}

	input := make([]byte, 65)

	ret, remainingGas, err := v.Run(nil, common.Address{}, v.Address(), input, VerkleVerifyGas-1, true)
	require.ErrorIs(t, err, vm.ErrOutOfGas)
	require.Nil(t, ret)
	require.Equal(t, uint64(0), remainingGas)
}

// =============================================================================
// BLS Precompile Tests
// =============================================================================

func TestBLSPrecompile_Address(t *testing.T) {
	b := &blsPrecompile{}
	expected := common.HexToAddress(BLSVerifyAddress)
	require.Equal(t, expected, b.Address())
}

func TestBLSPrecompile_RequiredGas(t *testing.T) {
	b := &blsPrecompile{}
	require.Equal(t, uint64(BLSVerifyGas), b.RequiredGas(nil))
	require.Equal(t, uint64(BLSVerifyGas), b.RequiredGas(make([]byte, 200)))
}

func TestBLSPrecompile_InputTooShort(t *testing.T) {
	b := &blsPrecompile{}

	// Input format: [pubkey(48)] [message(32)] [signature(96)] = 176 bytes
	tests := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"partial_pubkey", 30},
		{"pubkey_only", 48},
		{"pubkey_and_message", 80},
		{"one_byte_short", 175},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := make([]byte, tc.size)
			ret, remainingGas, err := b.Run(nil, common.Address{}, b.Address(), input, BLSVerifyGas, true)
			require.ErrorIs(t, err, ErrInvalidInput)
			require.Nil(t, ret)
			require.Equal(t, uint64(0), remainingGas)
		})
	}
}

func TestBLSPrecompile_InvalidPubKey(t *testing.T) {
	b := &blsPrecompile{}

	// Create invalid pubkey (all zeros is not a valid BLS pubkey)
	input := make([]byte, 176)

	ret, remainingGas, err := b.Run(nil, common.Address{}, b.Address(), input, BLSVerifyGas, true)
	require.NoError(t, err) // No error, just returns 0
	require.Equal(t, []byte{0}, ret)
	require.Equal(t, uint64(0), remainingGas)
}

func TestBLSPrecompile_OutOfGas(t *testing.T) {
	b := &blsPrecompile{}

	input := make([]byte, 176)

	ret, remainingGas, err := b.Run(nil, common.Address{}, b.Address(), input, BLSVerifyGas-1, true)
	require.ErrorIs(t, err, vm.ErrOutOfGas)
	require.Nil(t, ret)
	require.Equal(t, uint64(0), remainingGas)
}

// =============================================================================
// BLS Aggregate Precompile Tests
// =============================================================================

func TestBLSAggregatePrecompile_Address(t *testing.T) {
	b := &blsAggregatePrecompile{}
	expected := common.HexToAddress(BLSAggregateAddress)
	require.Equal(t, expected, b.Address())
}

func TestBLSAggregatePrecompile_RequiredGas(t *testing.T) {
	b := &blsAggregatePrecompile{}

	tests := []struct {
		name     string
		numSigs  int
		expected uint64
	}{
		{"empty", 0, 0},
		{"one_sig", 1, BLSAggregateGas},
		{"two_sigs", 2, 2 * BLSAggregateGas},
		{"ten_sigs", 10, 10 * BLSAggregateGas},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := make([]byte, tc.numSigs*96)
			gas := b.RequiredGas(input)
			require.Equal(t, tc.expected, gas)
		})
	}
}

func TestBLSAggregatePrecompile_InvalidInputLength(t *testing.T) {
	b := &blsAggregatePrecompile{}

	// Input must be multiple of 96 bytes
	tests := []struct {
		name string
		size int
	}{
		{"one_byte", 1},
		{"partial_sig", 50},
		{"one_and_half_sigs", 144},
		{"almost_two_sigs", 191},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := make([]byte, tc.size)
			gas := b.RequiredGas(input)
			ret, remainingGas, err := b.Run(nil, common.Address{}, b.Address(), input, gas+1000, true)
			require.ErrorIs(t, err, ErrInvalidInput)
			require.Nil(t, ret)
			require.Greater(t, remainingGas, uint64(0))
		})
	}
}

func TestBLSAggregatePrecompile_InvalidSignature(t *testing.T) {
	b := &blsAggregatePrecompile{}

	// Create invalid signature (all zeros is not valid)
	input := make([]byte, 96)

	gas := b.RequiredGas(input)
	ret, _, err := b.Run(nil, common.Address{}, b.Address(), input, gas, true)
	require.ErrorIs(t, err, ErrInvalidSignature)
	require.Nil(t, ret)
}

func TestBLSAggregatePrecompile_OutOfGas(t *testing.T) {
	b := &blsAggregatePrecompile{}

	input := make([]byte, 96*3) // 3 signatures
	requiredGas := b.RequiredGas(input)

	ret, remainingGas, err := b.Run(nil, common.Address{}, b.Address(), input, requiredGas-1, true)
	require.ErrorIs(t, err, vm.ErrOutOfGas)
	require.Nil(t, ret)
	require.Equal(t, uint64(0), remainingGas)
}

// =============================================================================
// Ringtail (ML-DSA) Precompile Tests
// =============================================================================

func TestRingtailPrecompile_Address(t *testing.T) {
	r := &ringtailPrecompile{}
	expected := common.HexToAddress(RingtailVerifyAddress)
	require.Equal(t, expected, r.Address())
}

func TestRingtailPrecompile_RequiredGas(t *testing.T) {
	r := &ringtailPrecompile{}
	require.Equal(t, uint64(RingtailVerifyGas), r.RequiredGas(nil))
	require.Equal(t, uint64(RingtailVerifyGas), r.RequiredGas(make([]byte, 5000)))
}

func TestRingtailPrecompile_InputTooShort(t *testing.T) {
	r := &ringtailPrecompile{}

	// Input format: [mode(1)] [pubkey_len(2)] [pubkey] [msg_len(2)] [msg] [sig]
	tests := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"mode_only", 1},
		{"mode_and_partial_len", 2},
		{"header_only", 5},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := make([]byte, tc.size)
			ret, _, err := r.Run(nil, common.Address{}, r.Address(), input, RingtailVerifyGas, true)
			require.ErrorIs(t, err, ErrInvalidInput)
			require.Nil(t, ret)
		})
	}
}

func TestRingtailPrecompile_TruncatedPubKey(t *testing.T) {
	r := &ringtailPrecompile{}

	// [mode(1)] [pubkey_len(2)] but pubkey is truncated
	input := make([]byte, 10)
	input[0] = 0x01            // mode
	input[1] = 0x00            // pubkey_len high byte
	input[2] = 0x20            // pubkey_len low byte = 32
	// Only 7 bytes of pubkey follow (input[3:10])

	ret, _, err := r.Run(nil, common.Address{}, r.Address(), input, RingtailVerifyGas, true)
	require.ErrorIs(t, err, ErrInvalidInput)
	require.Nil(t, ret)
}

func TestRingtailPrecompile_TruncatedMessage(t *testing.T) {
	r := &ringtailPrecompile{}

	// Build input with pubkey present but message truncated
	pubKeyLen := 32
	input := make([]byte, 3+pubKeyLen+2) // mode + pubkey_len + pubkey + msg_len (no msg body)
	input[0] = 0x01                       // mode
	input[1] = 0x00                       // pubkey_len high
	input[2] = byte(pubKeyLen)            // pubkey_len low
	// pubkey bytes: input[3:35]
	input[3+pubKeyLen] = 0x00   // msg_len high
	input[3+pubKeyLen+1] = 0x10 // msg_len low = 16
	// No message bytes follow

	ret, _, err := r.Run(nil, common.Address{}, r.Address(), input, RingtailVerifyGas, true)
	require.ErrorIs(t, err, ErrInvalidInput)
	require.Nil(t, ret)
}

func TestRingtailPrecompile_InvalidPubKey(t *testing.T) {
	r := &ringtailPrecompile{}

	// Build complete input with invalid pubkey (all zeros)
	pubKeyLen := 1952 // ML-DSA-65 pubkey size
	msgLen := 32
	sigLen := 3293 // ML-DSA-65 signature size

	input := make([]byte, 1+2+pubKeyLen+2+msgLen+sigLen)
	input[0] = 0x01                       // mode (MLDSA65 = 1)
	input[1] = byte(pubKeyLen >> 8)       // pubkey_len high
	input[2] = byte(pubKeyLen & 0xFF)     // pubkey_len low
	input[3+pubKeyLen] = byte(msgLen >> 8)
	input[3+pubKeyLen+1] = byte(msgLen & 0xFF)
	// Leave everything zeros - invalid pubkey

	ret, _, err := r.Run(nil, common.Address{}, r.Address(), input, RingtailVerifyGas, true)
	require.NoError(t, err) // No error, returns 0
	require.Equal(t, []byte{0}, ret)
}

func TestRingtailPrecompile_OutOfGas(t *testing.T) {
	r := &ringtailPrecompile{}

	input := make([]byte, 100)

	ret, remainingGas, err := r.Run(nil, common.Address{}, r.Address(), input, RingtailVerifyGas-1, true)
	require.ErrorIs(t, err, vm.ErrOutOfGas)
	require.Nil(t, ret)
	require.Equal(t, uint64(0), remainingGas)
}

// =============================================================================
// Hybrid Precompile Tests
// =============================================================================

func TestHybridPrecompile_Address(t *testing.T) {
	h := &hybridPrecompile{}
	expected := common.HexToAddress(HybridVerifyAddress)
	require.Equal(t, expected, h.Address())
}

func TestHybridPrecompile_RequiredGas(t *testing.T) {
	h := &hybridPrecompile{}
	require.Equal(t, uint64(HybridVerifyGas), h.RequiredGas(nil))
	require.Equal(t, uint64(HybridVerifyGas), h.RequiredGas(make([]byte, 1000)))
}

func TestHybridPrecompile_InputTooShort(t *testing.T) {
	h := &hybridPrecompile{}

	// Minimum: [bls_sig(96)] [ringtail_sig_len(2)] [ringtail_sig] [message(32)] [bls_pubkey(48)] [ringtail_pubkey]
	tests := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"partial_bls_sig", 50},
		{"bls_sig_only", 96},
		{"bls_sig_and_len", 98},
		{"one_byte_short", 177},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := make([]byte, tc.size)
			ret, _, err := h.Run(nil, common.Address{}, h.Address(), input, HybridVerifyGas, true)
			require.ErrorIs(t, err, ErrInvalidInput)
			require.Nil(t, ret)
		})
	}
}

func TestHybridPrecompile_TruncatedRingtailSig(t *testing.T) {
	h := &hybridPrecompile{}

	// Build input with ringtail_sig_len larger than actual data
	input := make([]byte, 200)
	// bls_sig: input[0:96]
	input[96] = 0x10 // ringtail_sig_len high = 4096 (way larger than remaining)
	input[97] = 0x00 // ringtail_sig_len low

	ret, _, err := h.Run(nil, common.Address{}, h.Address(), input, HybridVerifyGas, true)
	require.ErrorIs(t, err, ErrInvalidInput)
	require.Nil(t, ret)
}

func TestHybridPrecompile_InvalidBLSPubKey(t *testing.T) {
	h := &hybridPrecompile{}

	// Build complete but invalid input (all zeros)
	ringtailSigLen := 100
	// [bls_sig(96)] [ringtail_sig_len(2)] [ringtail_sig] [message(32)] [bls_pubkey(48)] [ringtail_pubkey]
	totalLen := 96 + 2 + ringtailSigLen + 32 + 48 + 100
	input := make([]byte, totalLen)
	input[96] = byte(ringtailSigLen >> 8)
	input[97] = byte(ringtailSigLen & 0xFF)
	// All zeros = invalid keys

	ret, _, err := h.Run(nil, common.Address{}, h.Address(), input, HybridVerifyGas, true)
	require.NoError(t, err)
	require.Equal(t, []byte{0}, ret) // Returns false
}

func TestHybridPrecompile_OutOfGas(t *testing.T) {
	h := &hybridPrecompile{}

	input := make([]byte, 300)
	input[96] = 0x00
	input[97] = 0x10 // ringtail_sig_len = 16

	ret, remainingGas, err := h.Run(nil, common.Address{}, h.Address(), input, HybridVerifyGas-1, true)
	require.ErrorIs(t, err, vm.ErrOutOfGas)
	require.Nil(t, ret)
	require.Equal(t, uint64(0), remainingGas)
}

// =============================================================================
// Compressed Precompile Tests
// =============================================================================

func TestCompressedPrecompile_Address(t *testing.T) {
	c := &compressedPrecompile{}
	expected := common.HexToAddress(CompressedAddress)
	require.Equal(t, expected, c.Address())
}

func TestCompressedPrecompile_RequiredGas(t *testing.T) {
	c := &compressedPrecompile{}
	require.Equal(t, uint64(CompressedVerifyGas), c.RequiredGas(nil))
	require.Equal(t, uint64(CompressedVerifyGas), c.RequiredGas(make([]byte, 100)))
}

func TestCompressedPrecompile_ThresholdMet(t *testing.T) {
	c := &compressedPrecompile{}

	// Input: [commitment(16)] [proof(16)] [metadata(8)] [validators(4)]
	input := make([]byte, 44)

	// Set validator bits: need 22+ of 32 validators
	// 0xFFFFFF00 = 24 validators set (bits 8-31)
	input[40] = 0x00
	input[41] = 0xFF
	input[42] = 0xFF
	input[43] = 0xFF

	ret, remainingGas, err := c.Run(nil, common.Address{}, c.Address(), input, CompressedVerifyGas, true)
	require.NoError(t, err)
	require.Equal(t, uint64(0), remainingGas)
	require.Equal(t, []byte{1}, ret) // Threshold met
}

func TestCompressedPrecompile_ThresholdNotMet(t *testing.T) {
	c := &compressedPrecompile{}

	// Input: [commitment(16)] [proof(16)] [metadata(8)] [validators(4)]
	input := make([]byte, 44)

	// Set validator bits: only 10 validators (need 22)
	// 0x000003FF = 10 validators set (bits 0-9)
	input[40] = 0xFF
	input[41] = 0x03
	input[42] = 0x00
	input[43] = 0x00

	ret, remainingGas, err := c.Run(nil, common.Address{}, c.Address(), input, CompressedVerifyGas, true)
	require.NoError(t, err)
	require.Equal(t, uint64(0), remainingGas)
	require.Equal(t, []byte{0}, ret) // Threshold not met
}

func TestCompressedPrecompile_ExactThreshold(t *testing.T) {
	c := &compressedPrecompile{}

	input := make([]byte, 44)

	// Set exactly 22 validators (threshold is >= 22)
	// 0x003FFFFF = 22 validators set (bits 0-21)
	input[40] = 0xFF
	input[41] = 0xFF
	input[42] = 0x3F
	input[43] = 0x00

	ret, remainingGas, err := c.Run(nil, common.Address{}, c.Address(), input, CompressedVerifyGas, true)
	require.NoError(t, err)
	require.Equal(t, uint64(0), remainingGas)
	require.Equal(t, []byte{1}, ret) // Exactly at threshold
}

func TestCompressedPrecompile_JustBelowThreshold(t *testing.T) {
	c := &compressedPrecompile{}

	input := make([]byte, 44)

	// Set 21 validators (one below threshold)
	// 0x001FFFFF = 21 validators set (bits 0-20)
	input[40] = 0xFF
	input[41] = 0xFF
	input[42] = 0x1F
	input[43] = 0x00

	ret, remainingGas, err := c.Run(nil, common.Address{}, c.Address(), input, CompressedVerifyGas, true)
	require.NoError(t, err)
	require.Equal(t, uint64(0), remainingGas)
	require.Equal(t, []byte{0}, ret) // Below threshold
}

func TestCompressedPrecompile_AllValidators(t *testing.T) {
	c := &compressedPrecompile{}

	input := make([]byte, 44)

	// All 32 validators
	input[40] = 0xFF
	input[41] = 0xFF
	input[42] = 0xFF
	input[43] = 0xFF

	ret, remainingGas, err := c.Run(nil, common.Address{}, c.Address(), input, CompressedVerifyGas, true)
	require.NoError(t, err)
	require.Equal(t, uint64(0), remainingGas)
	require.Equal(t, []byte{1}, ret)
}

func TestCompressedPrecompile_NoValidators(t *testing.T) {
	c := &compressedPrecompile{}

	input := make([]byte, 44) // All zeros

	ret, remainingGas, err := c.Run(nil, common.Address{}, c.Address(), input, CompressedVerifyGas, true)
	require.NoError(t, err)
	require.Equal(t, uint64(0), remainingGas)
	require.Equal(t, []byte{0}, ret)
}

func TestCompressedPrecompile_InputTooShort(t *testing.T) {
	c := &compressedPrecompile{}

	tests := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"commitment_only", 16},
		{"commitment_and_proof", 32},
		{"with_partial_metadata", 40},
		{"one_byte_short", 43},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := make([]byte, tc.size)
			ret, _, err := c.Run(nil, common.Address{}, c.Address(), input, CompressedVerifyGas, true)
			require.ErrorIs(t, err, ErrInvalidInput)
			require.Nil(t, ret)
		})
	}
}

func TestCompressedPrecompile_OutOfGas(t *testing.T) {
	c := &compressedPrecompile{}

	input := make([]byte, 44)

	ret, remainingGas, err := c.Run(nil, common.Address{}, c.Address(), input, CompressedVerifyGas-1, true)
	require.ErrorIs(t, err, vm.ErrOutOfGas)
	require.Nil(t, ret)
	require.Equal(t, uint64(0), remainingGas)
}

// =============================================================================
// verifyVerkleLight Helper Tests
// =============================================================================

func TestVerifyVerkleLight(t *testing.T) {
	tests := []struct {
		name       string
		commitment []byte
		proof      []byte
		expected   bool
	}{
		{
			name:       "identical",
			commitment: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
			proof:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
			expected:   true,
		},
		{
			name:       "first_half_match",
			commitment: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
			proof:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expected:   false, // Mismatch at index 16, but 16 <= 16 so returns false
		},
		{
			name:       "mismatch_at_17",
			commitment: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
			proof:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expected:   true, // Mismatch at index 17, 17 > 16 so returns true
		},
		{
			name:       "mismatch_at_start",
			commitment: []byte{1, 2, 3, 4},
			proof:      []byte{0, 2, 3, 4},
			expected:   false, // Mismatch at index 0, 0 <= 16 so returns false
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := verifyVerkleLight(tc.commitment, tc.proof)
			require.Equal(t, tc.expected, result)
		})
	}
}

// =============================================================================
// GetAllPrecompiles Tests
// =============================================================================

func TestGetAllPrecompiles(t *testing.T) {
	precompiles := GetAllPrecompiles()

	require.Len(t, precompiles, 6)

	expectedAddresses := []string{
		VerkleVerifyAddress,
		BLSVerifyAddress,
		BLSAggregateAddress,
		RingtailVerifyAddress,
		HybridVerifyAddress,
		CompressedAddress,
	}

	for _, addr := range expectedAddresses {
		_, exists := precompiles[common.HexToAddress(addr)]
		require.True(t, exists, "Missing precompile at address %s", addr)
	}
}

func TestPrecompileAddresses(t *testing.T) {
	// Verify all addresses are in the expected Lux precompile range
	addresses := []string{
		VerkleVerifyAddress,
		BLSVerifyAddress,
		BLSAggregateAddress,
		RingtailVerifyAddress,
		HybridVerifyAddress,
		CompressedAddress,
	}

	for _, addr := range addresses {
		address := common.HexToAddress(addr)
		// Should start with 0x03 (Lux consensus precompile range)
		require.Equal(t, byte(0x03), address[0], "Address %s not in consensus precompile range", addr)
	}
}

// =============================================================================
// Gas Consumption Tests
// =============================================================================

func TestGasConsumption_Verkle(t *testing.T) {
	v := &verklePrecompile{}
	input := make([]byte, 65)
	input[64] = 1 // threshold met

	suppliedGas := uint64(VerkleVerifyGas + 1000)
	_, remainingGas, err := v.Run(nil, common.Address{}, v.Address(), input, suppliedGas, true)
	require.NoError(t, err)
	require.Equal(t, uint64(1000), remainingGas)
}

func TestGasConsumption_BLS(t *testing.T) {
	b := &blsPrecompile{}
	input := make([]byte, 176)

	suppliedGas := uint64(BLSVerifyGas + 500)
	_, remainingGas, err := b.Run(nil, common.Address{}, b.Address(), input, suppliedGas, true)
	require.NoError(t, err)
	require.Equal(t, uint64(500), remainingGas)
}

func TestGasConsumption_Compressed(t *testing.T) {
	c := &compressedPrecompile{}
	input := make([]byte, 44)

	suppliedGas := uint64(CompressedVerifyGas + 200)
	_, remainingGas, err := c.Run(nil, common.Address{}, c.Address(), input, suppliedGas, true)
	require.NoError(t, err)
	require.Equal(t, uint64(200), remainingGas)
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkVerkleVerify(b *testing.B) {
	v := &verklePrecompile{}
	input := make([]byte, 65)
	for i := 0; i < 32; i++ {
		input[i] = byte(i)
		input[32+i] = byte(i)
	}
	input[64] = 1

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = v.Run(nil, common.Address{}, v.Address(), input, VerkleVerifyGas, true)
	}
}

func BenchmarkCompressedVerify(b *testing.B) {
	c := &compressedPrecompile{}
	input := make([]byte, 44)
	input[40] = 0xFF
	input[41] = 0xFF
	input[42] = 0xFF
	input[43] = 0xFF

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = c.Run(nil, common.Address{}, c.Address(), input, CompressedVerifyGas, true)
	}
}

func BenchmarkBLSAggregateGas(b *testing.B) {
	ba := &blsAggregatePrecompile{}

	for _, numSigs := range []int{1, 10, 100} {
		b.Run(string(rune('0'+numSigs)), func(b *testing.B) {
			input := make([]byte, numSigs*96)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = ba.RequiredGas(input)
			}
		})
	}
}
