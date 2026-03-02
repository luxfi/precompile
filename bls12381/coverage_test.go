// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls12381

import (
	"testing"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// --- Config tests ---

func TestConfig_Key(t *testing.T) {
	require.Equal(t, G1AddConfigKey, (&Config{}).Key())
}

func TestConfig_Timestamp_Nil(t *testing.T) {
	require.Nil(t, (&Config{}).Timestamp())
}

func TestConfig_Timestamp_Set(t *testing.T) {
	ts := uint64(999)
	c := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, c.Timestamp())
}

func TestConfig_IsDisabled(t *testing.T) {
	require.False(t, (&Config{}).IsDisabled())
	require.True(t, (&Config{Upgrade: precompileconfig.Upgrade{Disable: true}}).IsDisabled())
}

func TestConfig_Equal_Same(t *testing.T) {
	ts := uint64(100)
	c1 := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	c2 := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.True(t, c1.Equal(c2))
}

func TestConfig_Equal_Different(t *testing.T) {
	ts1, ts2 := uint64(100), uint64(200)
	c1 := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts1}}
	c2 := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts2}}
	require.False(t, c1.Equal(c2))
}

func TestConfig_Equal_WrongType(t *testing.T) {
	require.False(t, (&Config{}).Equal(nil))
}

func TestConfig_Verify(t *testing.T) {
	require.NoError(t, (&Config{}).Verify(nil))
}

func TestConfigurator_MakeConfig(t *testing.T) {
	cfg := (&configurator{}).MakeConfig()
	_, ok := cfg.(*Config)
	require.True(t, ok)
}

func TestConfigurator_Configure(t *testing.T) {
	require.NoError(t, (&configurator{}).Configure(nil, nil, nil, nil))
}

// --- msmGas discount table ---

func TestMsmGas_SinglePair(t *testing.T) {
	require.Equal(t, uint64(GasG1MSM), msmGas(1, GasG1MSM))
}

func TestMsmGas_ZeroPairs(t *testing.T) {
	require.Equal(t, uint64(GasG1MSM), msmGas(0, GasG1MSM))
}

func TestMsmGas_DiscountBrackets(t *testing.T) {
	tests := []struct {
		pairs    uint64
		discount uint64
	}{
		{2, 949},
		{4, 949},
		{5, 854},
		{8, 854},
		{9, 723},
		{16, 723},
		{17, 577},
		{32, 577},
		{33, 461},
		{64, 461},
		{65, 368},
		{128, 368},
		{129, 294},
		{256, 294},
	}
	for _, tt := range tests {
		expected := (GasG1MSM * tt.pairs * tt.discount) / 1000
		require.Equal(t, expected, msmGas(tt.pairs, GasG1MSM), "pairs=%d", tt.pairs)
	}
}

// --- Infinity point handling ---

func TestDecodeG1_InfinityPoint(t *testing.T) {
	// Infinity is all zeros
	input := make([]byte, G1PointLen)
	pt, err := decodeG1(input)
	require.NoError(t, err)
	require.True(t, pt.IsInfinity())
}

func TestDecodeG2_InfinityPoint(t *testing.T) {
	input := make([]byte, G2PointLen)
	pt, err := decodeG2(input)
	require.NoError(t, err)
	require.True(t, pt.IsInfinity())
}

// --- decodeG1 field element padding ---

func TestDecodeG1_NonZeroPadding_X(t *testing.T) {
	input := make([]byte, G1PointLen)
	input[0] = 0x01 // first padding byte non-zero
	_, err := decodeG1(input)
	require.ErrorIs(t, err, ErrInvalidFieldElem)
}

func TestDecodeG1_NonZeroPadding_Y(t *testing.T) {
	input := make([]byte, G1PointLen)
	input[64] = 0x01 // first Y padding byte non-zero
	_, err := decodeG1(input)
	require.ErrorIs(t, err, ErrInvalidFieldElem)
}

func TestDecodeG1_ShortInput(t *testing.T) {
	_, err := decodeG1(make([]byte, G1PointLen-1))
	require.ErrorIs(t, err, ErrInvalidInput)
}

// --- decodeG2 field element padding ---

func TestDecodeG2_NonZeroPadding(t *testing.T) {
	for _, offset := range []int{0, 64, 128, 192} {
		input := make([]byte, G2PointLen)
		input[offset] = 0x01
		_, err := decodeG2(input)
		require.ErrorIs(t, err, ErrInvalidFieldElem, "offset=%d", offset)
	}
}

func TestDecodeG2_ShortInput(t *testing.T) {
	_, err := decodeG2(make([]byte, G2PointLen-1))
	require.ErrorIs(t, err, ErrInvalidInput)
}

// --- decodeScalar ---

func TestDecodeScalar_Short(t *testing.T) {
	_, err := decodeScalar(make([]byte, ScalarLen-1))
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestDecodeScalar_Valid(t *testing.T) {
	input := make([]byte, ScalarLen)
	input[31] = 1
	s, err := decodeScalar(input)
	require.NoError(t, err)
	require.False(t, s.IsZero())
}

// --- G1 operations with generator point ---

func TestG1Add_Generator(t *testing.T) {
	_, _, g1Aff, _ := bls.Generators()
	enc := encodeG1(&g1Aff)

	input := make([]byte, 2*G1PointLen)
	copy(input[:G1PointLen], enc)
	copy(input[G1PointLen:], enc)

	result, _, err := blsOps.g1Add(input, 1_000_000)
	require.NoError(t, err)
	require.Equal(t, G1PointLen, len(result))
}

func TestG1Mul_Generator(t *testing.T) {
	_, _, g1Aff, _ := bls.Generators()
	enc := encodeG1(&g1Aff)

	input := make([]byte, G1PointLen+ScalarLen)
	copy(input[:G1PointLen], enc)
	input[G1PointLen+ScalarLen-1] = 2 // scalar = 2

	result, _, err := blsOps.g1Mul(input, 1_000_000)
	require.NoError(t, err)
	require.Equal(t, G1PointLen, len(result))
}

func TestG1MSM_EmptyInput(t *testing.T) {
	_, _, err := blsOps.g1MSM(nil, 1_000_000)
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestG1MSM_BadAlignment(t *testing.T) {
	_, _, err := blsOps.g1MSM(make([]byte, 1), 1_000_000)
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestG1MSM_Generator(t *testing.T) {
	_, _, g1Aff, _ := bls.Generators()
	enc := encodeG1(&g1Aff)

	input := make([]byte, G1PointLen+ScalarLen)
	copy(input[:G1PointLen], enc)
	input[G1PointLen+ScalarLen-1] = 3

	result, _, err := blsOps.g1MSM(input, 1_000_000)
	require.NoError(t, err)
	require.Equal(t, G1PointLen, len(result))
}

// --- G2 operations ---

func TestG2Add_Generator(t *testing.T) {
	_, _, _, g2Aff := bls.Generators()
	enc := encodeG2(&g2Aff)

	input := make([]byte, 2*G2PointLen)
	copy(input[:G2PointLen], enc)
	copy(input[G2PointLen:], enc)

	result, _, err := blsOps.g2Add(input, 1_000_000)
	require.NoError(t, err)
	require.Equal(t, G2PointLen, len(result))
}

func TestG2Mul_Generator(t *testing.T) {
	_, _, _, g2Aff := bls.Generators()
	enc := encodeG2(&g2Aff)

	input := make([]byte, G2PointLen+ScalarLen)
	copy(input[:G2PointLen], enc)
	input[G2PointLen+ScalarLen-1] = 2

	result, _, err := blsOps.g2Mul(input, 1_000_000)
	require.NoError(t, err)
	require.Equal(t, G2PointLen, len(result))
}

func TestG2MSM_EmptyInput(t *testing.T) {
	_, _, err := blsOps.g2MSM(nil, 1_000_000)
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestG2MSM_BadAlignment(t *testing.T) {
	_, _, err := blsOps.g2MSM(make([]byte, 1), 1_000_000)
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestG2MSM_Generator(t *testing.T) {
	_, _, _, g2Aff := bls.Generators()
	enc := encodeG2(&g2Aff)

	input := make([]byte, G2PointLen+ScalarLen)
	copy(input[:G2PointLen], enc)
	input[G2PointLen+ScalarLen-1] = 3

	result, _, err := blsOps.g2MSM(input, 1_000_000)
	require.NoError(t, err)
	require.Equal(t, G2PointLen, len(result))
}

// --- Pairing ---

func TestPairing_EmptyInputDirect(t *testing.T) {
	_, _, err := blsOps.pairing(nil, 1_000_000)
	require.ErrorIs(t, err, ErrInvalidPairingLen)
}

func TestPairing_BadAlignment(t *testing.T) {
	_, _, err := blsOps.pairing(make([]byte, 1), 1_000_000)
	require.ErrorIs(t, err, ErrInvalidPairingLen)
}

func TestPairing_InfinityPair(t *testing.T) {
	// Pair of infinity points
	input := make([]byte, PairingPair)
	result, _, err := blsOps.pairing(input, 1_000_000)
	require.NoError(t, err)
	require.Equal(t, byte(1), result[31], "pairing of identity points should be 1")
}

// --- PairingGas ---

func TestPairingGas_InvalidLen(t *testing.T) {
	require.Equal(t, uint64(0), PairingGas(0))
	require.Equal(t, uint64(0), PairingGas(1))
}

func TestPairingGas_OnePair(t *testing.T) {
	expected := uint64(GasPairingBase + GasPairingPerPair)
	require.Equal(t, expected, PairingGas(PairingPair))
}

func TestPairingGas_TwoPairs(t *testing.T) {
	expected := uint64(GasPairingBase + 2*GasPairingPerPair)
	require.Equal(t, expected, PairingGas(2*PairingPair))
}

// --- G1/G2 operation error paths ---

func TestG1Add_ShortInputCoverage(t *testing.T) {
	_, _, err := blsOps.g1Add(make([]byte, 2*G1PointLen-1), 1_000_000)
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestG1Mul_ShortInput(t *testing.T) {
	_, _, err := blsOps.g1Mul(make([]byte, G1PointLen+ScalarLen-1), 1_000_000)
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestG2Add_ShortInputCoverage(t *testing.T) {
	_, _, err := blsOps.g2Add(make([]byte, 2*G2PointLen-1), 1_000_000)
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestG2Mul_ShortInput(t *testing.T) {
	_, _, err := blsOps.g2Mul(make([]byte, G2PointLen+ScalarLen-1), 1_000_000)
	require.ErrorIs(t, err, ErrInvalidInput)
}

// --- Out of gas ---

func TestG1Add_OutOfGas(t *testing.T) {
	_, _, err := blsOps.g1Add(make([]byte, 2*G1PointLen), GasG1Add-1)
	require.Error(t, err)
}

func TestG1Mul_OutOfGas(t *testing.T) {
	_, _, err := blsOps.g1Mul(make([]byte, G1PointLen+ScalarLen), GasG1Mul-1)
	require.Error(t, err)
}

func TestG2Add_OutOfGas(t *testing.T) {
	_, _, err := blsOps.g2Add(make([]byte, 2*G2PointLen), GasG2Add-1)
	require.Error(t, err)
}

func TestG2Mul_OutOfGas(t *testing.T) {
	_, _, err := blsOps.g2Mul(make([]byte, G2PointLen+ScalarLen), GasG2Mul-1)
	require.Error(t, err)
}

func TestPairing_OutOfGas(t *testing.T) {
	_, _, err := blsOps.pairing(make([]byte, PairingPair), 1)
	require.Error(t, err)
}

// --- Point not on curve ---

func TestDecodeG1_NotOnCurve(t *testing.T) {
	input := make([]byte, G1PointLen)
	// Set x = 1, y = 1 (not on BLS12-381 G1)
	input[63] = 1
	input[127] = 1
	_, err := decodeG1(input)
	require.ErrorIs(t, err, ErrPointNotOnCurve)
}

func TestDecodeG2_NotOnCurve(t *testing.T) {
	input := make([]byte, G2PointLen)
	// Set some non-trivial point not on G2
	input[63] = 1
	input[127] = 1
	input[191] = 1
	input[255] = 1
	_, err := decodeG2(input)
	require.ErrorIs(t, err, ErrPointNotOnCurve)
}

// --- G1 Add with invalid second point ---

func TestG1Add_SecondPointInvalid(t *testing.T) {
	_, _, g1Aff, _ := bls.Generators()
	enc := encodeG1(&g1Aff)

	input := make([]byte, 2*G1PointLen)
	copy(input[:G1PointLen], enc) // valid first point

	// Invalid second point (1,1)
	input[G1PointLen+63] = 1
	input[G1PointLen+127] = 1

	_, _, err := blsOps.g1Add(input, 1_000_000)
	require.Error(t, err)
}

func TestG1Mul_InvalidPoint(t *testing.T) {
	input := make([]byte, G1PointLen+ScalarLen)
	input[63] = 1
	input[127] = 1
	input[G1PointLen+ScalarLen-1] = 1
	_, _, err := blsOps.g1Mul(input, 1_000_000)
	require.Error(t, err)
}

func TestG2Add_SecondPointInvalid(t *testing.T) {
	_, _, _, g2Aff := bls.Generators()
	enc := encodeG2(&g2Aff)

	input := make([]byte, 2*G2PointLen)
	copy(input[:G2PointLen], enc)
	input[G2PointLen+63] = 1
	input[G2PointLen+127] = 1
	input[G2PointLen+191] = 1
	input[G2PointLen+255] = 1

	_, _, err := blsOps.g2Add(input, 1_000_000)
	require.Error(t, err)
}
