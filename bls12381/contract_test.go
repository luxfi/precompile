// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls12381

import (
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/modules"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Module registration: all 7 addresses must be registered
// ===========================================================================

func TestAllModulesRegistered(t *testing.T) {
	tests := []struct {
		name    string
		addr    common.Address
		key     string
	}{
		{"G1Add", G1AddAddress, G1AddConfigKey},
		{"G1Mul", G1MulAddress, G1MulConfigKey},
		{"G1MSM", G1MSMAddress, G1MSMConfigKey},
		{"G2Add", G2AddAddress, G2AddConfigKey},
		{"G2Mul", G2MulAddress, G2MulConfigKey},
		{"G2MSM", G2MSMAddress, G2MSMConfigKey},
		{"Pairing", PairingAddress, PairingConfigKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, ok := modules.GetPrecompileModuleByAddress(tt.addr)
			require.True(t, ok, "module not registered at address %s", tt.addr.Hex())
			require.Equal(t, tt.key, m.ConfigKey)
		})
	}
}

func TestAddressValues(t *testing.T) {
	require.Equal(t, common.HexToAddress("0x0b"), G1AddAddress)
	require.Equal(t, common.HexToAddress("0x0c"), G1MulAddress)
	require.Equal(t, common.HexToAddress("0x0d"), G1MSMAddress)
	require.Equal(t, common.HexToAddress("0x0e"), G2AddAddress)
	require.Equal(t, common.HexToAddress("0x0f"), G2MulAddress)
	require.Equal(t, common.HexToAddress("0x10"), G2MSMAddress)
	require.Equal(t, common.HexToAddress("0x11"), PairingAddress)
}

// ===========================================================================
// Helpers
// ===========================================================================

func g1Generator() bls12381.G1Affine {
	_, _, g1, _ := bls12381.Generators()
	return g1
}

func g2Generator() bls12381.G2Affine {
	_, _, _, g2 := bls12381.Generators()
	return g2
}

func encodeG1Pair(a, b *bls12381.G1Affine) []byte {
	out := make([]byte, 2*G1PointLen)
	copy(out[:G1PointLen], encodeG1(a))
	copy(out[G1PointLen:], encodeG1(b))
	return out
}

func encodeG2Pair(a, b *bls12381.G2Affine) []byte {
	out := make([]byte, 2*G2PointLen)
	copy(out[:G2PointLen], encodeG2(a))
	copy(out[G2PointLen:], encodeG2(b))
	return out
}

func encodePointScalar(pt []byte, s *fr.Element) []byte {
	out := make([]byte, len(pt)+ScalarLen)
	copy(out, pt)
	sBytes := s.Bytes()
	copy(out[len(pt):], sBytes[:])
	return out
}

func infinityG1() []byte {
	return make([]byte, G1PointLen)
}

func infinityG2() []byte {
	return make([]byte, G2PointLen)
}

func runPrecompile(addr common.Address, input []byte, gas uint64) ([]byte, uint64, error) {
	m, ok := modules.GetPrecompileModuleByAddress(addr)
	if !ok {
		return nil, gas, ErrInvalidInput
	}
	return m.Contract.Run(nil, common.Address{}, addr, input, gas, false)
}

// ===========================================================================
// G1Add (0x0B)
// ===========================================================================

func TestG1Add_GeneratorPlusGenerator(t *testing.T) {
	g := g1Generator()
	input := encodeG1Pair(&g, &g)
	result, gas, err := runPrecompile(G1AddAddress, input, 10000)
	require.NoError(t, err)
	require.Equal(t, uint64(10000-GasG1Add), gas)
	require.Len(t, result, G1PointLen)

	// g + g = 2*g
	var expected bls12381.G1Affine
	expected.Add(&g, &g)
	require.Equal(t, encodeG1(&expected), result)
}

func TestG1Add_Identity(t *testing.T) {
	g := g1Generator()
	input := make([]byte, 2*G1PointLen)
	copy(input[:G1PointLen], infinityG1())
	copy(input[G1PointLen:], encodeG1(&g))

	result, _, err := runPrecompile(G1AddAddress, input, 10000)
	require.NoError(t, err)
	require.Equal(t, encodeG1(&g), result)
}

func TestG1Add_InsufficientGas(t *testing.T) {
	g := g1Generator()
	input := encodeG1Pair(&g, &g)
	_, _, err := runPrecompile(G1AddAddress, input, GasG1Add-1)
	require.Error(t, err)
}

func TestG1Add_ShortInput(t *testing.T) {
	_, _, err := runPrecompile(G1AddAddress, make([]byte, G1PointLen-1), 10000)
	require.Error(t, err)
}

// ===========================================================================
// G1Mul (0x0C)
// ===========================================================================

func TestG1Mul_ScalarOne(t *testing.T) {
	g := g1Generator()
	var one fr.Element
	one.SetOne()
	input := encodePointScalar(encodeG1(&g), &one)

	result, gas, err := runPrecompile(G1MulAddress, input, 100000)
	require.NoError(t, err)
	require.Equal(t, uint64(100000-GasG1Mul), gas)
	require.Equal(t, encodeG1(&g), result)
}

func TestG1Mul_ScalarTwo(t *testing.T) {
	g := g1Generator()
	var two fr.Element
	two.SetUint64(2)
	input := encodePointScalar(encodeG1(&g), &two)

	result, _, err := runPrecompile(G1MulAddress, input, 100000)
	require.NoError(t, err)

	var expected bls12381.G1Affine
	expected.ScalarMultiplication(&g, big.NewInt(2))
	require.Equal(t, encodeG1(&expected), result)
}

func TestG1Mul_ScalarZero(t *testing.T) {
	g := g1Generator()
	var zero fr.Element // zero-initialized
	input := encodePointScalar(encodeG1(&g), &zero)

	result, _, err := runPrecompile(G1MulAddress, input, 100000)
	require.NoError(t, err)
	// Scalar 0 * G = infinity
	var inf bls12381.G1Affine // zero = infinity
	require.Equal(t, encodeG1(&inf), result)
}

func TestG1Mul_InsufficientGas(t *testing.T) {
	g := g1Generator()
	var one fr.Element
	one.SetOne()
	input := encodePointScalar(encodeG1(&g), &one)
	_, _, err := runPrecompile(G1MulAddress, input, GasG1Mul-1)
	require.Error(t, err)
}

// ===========================================================================
// G1MSM (0x0D)
// ===========================================================================

func TestG1MSM_TwoPairs(t *testing.T) {
	g := g1Generator()
	var s1, s2 fr.Element
	s1.SetUint64(3)
	s2.SetUint64(5)

	input := make([]byte, 0, 2*(G1PointLen+ScalarLen))
	input = append(input, encodePointScalar(encodeG1(&g), &s1)...)
	input = append(input, encodePointScalar(encodeG1(&g), &s2)...)

	result, _, err := runPrecompile(G1MSMAddress, input, 1000000)
	require.NoError(t, err)

	// 3*G + 5*G = 8*G
	var expected bls12381.G1Affine
	expected.ScalarMultiplication(&g, big.NewInt(8))
	require.Equal(t, encodeG1(&expected), result)
}

func TestG1MSM_SinglePair(t *testing.T) {
	g := g1Generator()
	var s fr.Element
	s.SetUint64(7)
	input := encodePointScalar(encodeG1(&g), &s)

	result, gas, err := runPrecompile(G1MSMAddress, input, 100000)
	require.NoError(t, err)
	// Single pair: no discount, base gas
	require.Equal(t, uint64(100000-GasG1MSM), gas)

	var expected bls12381.G1Affine
	expected.ScalarMultiplication(&g, big.NewInt(7))
	require.Equal(t, encodeG1(&expected), result)
}

func TestG1MSM_GasDiscount(t *testing.T) {
	g := g1Generator()
	var s fr.Element
	s.SetUint64(1)

	// 4 pairs should get discount (949/1000)
	input := make([]byte, 0, 4*(G1PointLen+ScalarLen))
	for i := 0; i < 4; i++ {
		input = append(input, encodePointScalar(encodeG1(&g), &s)...)
	}

	expectedGas := msmGas(4, GasG1MSM)
	require.Less(t, expectedGas, uint64(4*GasG1MSM)) // discount applied

	_, gas, err := runPrecompile(G1MSMAddress, input, 1000000)
	require.NoError(t, err)
	require.Equal(t, uint64(1000000)-expectedGas, gas)
}

func TestG1MSM_InvalidLength(t *testing.T) {
	// Not a multiple of pairSize
	_, _, err := runPrecompile(G1MSMAddress, make([]byte, G1PointLen+ScalarLen+1), 1000000)
	require.Error(t, err)
}

func TestG1MSM_Empty(t *testing.T) {
	_, _, err := runPrecompile(G1MSMAddress, []byte{}, 1000000)
	require.Error(t, err)
}

// ===========================================================================
// G2Add (0x0E)
// ===========================================================================

func TestG2Add_GeneratorPlusGenerator(t *testing.T) {
	g := g2Generator()
	input := encodeG2Pair(&g, &g)
	result, gas, err := runPrecompile(G2AddAddress, input, 10000)
	require.NoError(t, err)
	require.Equal(t, uint64(10000-GasG2Add), gas)

	var expected bls12381.G2Affine
	expected.Add(&g, &g)
	require.Equal(t, encodeG2(&expected), result)
}

func TestG2Add_Identity(t *testing.T) {
	g := g2Generator()
	input := make([]byte, 2*G2PointLen)
	copy(input[:G2PointLen], infinityG2())
	copy(input[G2PointLen:], encodeG2(&g))

	result, _, err := runPrecompile(G2AddAddress, input, 10000)
	require.NoError(t, err)
	require.Equal(t, encodeG2(&g), result)
}

func TestG2Add_ShortInput(t *testing.T) {
	_, _, err := runPrecompile(G2AddAddress, make([]byte, G2PointLen-1), 10000)
	require.Error(t, err)
}

// ===========================================================================
// G2Mul (0x0F)
// ===========================================================================

func TestG2Mul_ScalarOne(t *testing.T) {
	g := g2Generator()
	var one fr.Element
	one.SetOne()
	input := encodePointScalar(encodeG2(&g), &one)

	result, gas, err := runPrecompile(G2MulAddress, input, 100000)
	require.NoError(t, err)
	require.Equal(t, uint64(100000-GasG2Mul), gas)
	require.Equal(t, encodeG2(&g), result)
}

func TestG2Mul_ScalarTwo(t *testing.T) {
	g := g2Generator()
	var two fr.Element
	two.SetUint64(2)
	input := encodePointScalar(encodeG2(&g), &two)

	result, _, err := runPrecompile(G2MulAddress, input, 100000)
	require.NoError(t, err)

	var expected bls12381.G2Affine
	expected.ScalarMultiplication(&g, big.NewInt(2))
	require.Equal(t, encodeG2(&expected), result)
}

func TestG2Mul_InsufficientGas(t *testing.T) {
	g := g2Generator()
	var one fr.Element
	one.SetOne()
	input := encodePointScalar(encodeG2(&g), &one)
	_, _, err := runPrecompile(G2MulAddress, input, GasG2Mul-1)
	require.Error(t, err)
}

// ===========================================================================
// G2MSM (0x10)
// ===========================================================================

func TestG2MSM_TwoPairs(t *testing.T) {
	g := g2Generator()
	var s1, s2 fr.Element
	s1.SetUint64(3)
	s2.SetUint64(5)

	input := make([]byte, 0, 2*(G2PointLen+ScalarLen))
	input = append(input, encodePointScalar(encodeG2(&g), &s1)...)
	input = append(input, encodePointScalar(encodeG2(&g), &s2)...)

	result, _, err := runPrecompile(G2MSMAddress, input, 1000000)
	require.NoError(t, err)

	var expected bls12381.G2Affine
	expected.ScalarMultiplication(&g, big.NewInt(8))
	require.Equal(t, encodeG2(&expected), result)
}

// ===========================================================================
// Pairing (0x11)
// ===========================================================================

func TestPairing_TrivialCheck(t *testing.T) {
	// e(G1, G2) * e(-G1, G2) = 1  (pairing check should return true)
	g1 := g1Generator()
	g2 := g2Generator()

	var negG1 bls12381.G1Affine
	negG1.Neg(&g1)

	input := make([]byte, 2*PairingPair)
	copy(input[0:G1PointLen], encodeG1(&g1))
	copy(input[G1PointLen:PairingPair], encodeG2(&g2))
	copy(input[PairingPair:PairingPair+G1PointLen], encodeG1(&negG1))
	copy(input[PairingPair+G1PointLen:2*PairingPair], encodeG2(&g2))

	result, gas, err := runPrecompile(PairingAddress, input, 1000000)
	require.NoError(t, err)

	// Gas: 65000 + 43000*2 = 151000
	expectedGas := uint64(GasPairingBase + 2*GasPairingPerPair)
	require.Equal(t, uint64(1000000)-expectedGas, gas)

	// Result should be 1 (pairing check passes)
	require.Len(t, result, 32)
	require.Equal(t, byte(1), result[31])
}

func TestPairing_SinglePairFails(t *testing.T) {
	// e(G1, G2) != 1 for non-trivial pair
	g1 := g1Generator()
	g2 := g2Generator()

	input := make([]byte, PairingPair)
	copy(input[0:G1PointLen], encodeG1(&g1))
	copy(input[G1PointLen:PairingPair], encodeG2(&g2))

	result, gas, err := runPrecompile(PairingAddress, input, 1000000)
	require.NoError(t, err)

	// Gas: 65000 + 43000*1 = 108000
	expectedGas := uint64(GasPairingBase + GasPairingPerPair)
	require.Equal(t, uint64(1000000)-expectedGas, gas)

	// Result should be 0 (pairing check fails: e(G1,G2) != 1)
	require.Equal(t, byte(0), result[31])
}

func TestPairing_EmptyInput(t *testing.T) {
	_, _, err := runPrecompile(PairingAddress, []byte{}, 1000000)
	require.ErrorIs(t, err, ErrInvalidPairingLen)
}

func TestPairing_InvalidLength(t *testing.T) {
	_, _, err := runPrecompile(PairingAddress, make([]byte, PairingPair+1), 1000000)
	require.ErrorIs(t, err, ErrInvalidPairingLen)
}

func TestPairing_InsufficientGas(t *testing.T) {
	g1 := g1Generator()
	g2 := g2Generator()
	input := make([]byte, PairingPair)
	copy(input[0:G1PointLen], encodeG1(&g1))
	copy(input[G1PointLen:PairingPair], encodeG2(&g2))

	// Need 108000, supply less
	_, _, err := runPrecompile(PairingAddress, input, 100000)
	require.Error(t, err)
}

func TestPairing_WithInfinity(t *testing.T) {
	// e(0, G2) = 1, so a single pair with infinity G1 should pass
	g2 := g2Generator()
	input := make([]byte, PairingPair)
	copy(input[:G1PointLen], infinityG1())
	copy(input[G1PointLen:], encodeG2(&g2))

	result, _, err := runPrecompile(PairingAddress, input, 1000000)
	require.NoError(t, err)
	require.Equal(t, byte(1), result[31])
}

// ===========================================================================
// Gas accounting
// ===========================================================================

func TestPairingGasFormula(t *testing.T) {
	// EIP-2537: 65000 + 43000*n
	require.Equal(t, uint64(0), PairingGas(0))
	require.Equal(t, uint64(108000), PairingGas(PairingPair))     // 65000 + 43000*1
	require.Equal(t, uint64(151000), PairingGas(2*PairingPair))   // 65000 + 43000*2
	require.Equal(t, uint64(194000), PairingGas(3*PairingPair))   // 65000 + 43000*3
	require.Equal(t, uint64(495000), PairingGas(10*PairingPair))  // 65000 + 43000*10
}

func TestMSMGasDiscount(t *testing.T) {
	// 1 pair: no discount
	require.Equal(t, uint64(12000), msmGas(1, GasG1MSM))
	// 2 pairs: 949/1000 discount
	require.Equal(t, uint64(12000*2*949/1000), msmGas(2, GasG1MSM))
	// 8 pairs: 854/1000 discount
	require.Equal(t, uint64(12000*8*854/1000), msmGas(8, GasG1MSM))
	// 128 pairs: 368/1000 discount
	require.Equal(t, uint64(12000*128*368/1000), msmGas(128, GasG1MSM))
}

func TestGasConstants(t *testing.T) {
	require.Equal(t, uint64(500), uint64(GasG1Add))
	require.Equal(t, uint64(12000), uint64(GasG1Mul))
	require.Equal(t, uint64(800), uint64(GasG2Add))
	require.Equal(t, uint64(45000), uint64(GasG2Mul))
	require.Equal(t, uint64(65000), uint64(GasPairingBase))
	require.Equal(t, uint64(43000), uint64(GasPairingPerPair))
}

// ===========================================================================
// Invalid inputs (not on curve, not in subgroup, bad padding)
// ===========================================================================

func TestG1Add_NotOnCurve(t *testing.T) {
	// Point with valid padding but not on curve
	input := make([]byte, 2*G1PointLen)
	// Set x=1, y=1 (not on BLS12-381 curve)
	input[63] = 1   // x = 1
	input[127] = 1  // y = 1

	_, _, err := runPrecompile(G1AddAddress, input, 10000)
	require.Error(t, err)
}

func TestG1Add_BadPadding(t *testing.T) {
	g := g1Generator()
	input := encodeG1Pair(&g, &g)
	// Corrupt the padding byte (first 16 bytes should be zero)
	input[0] = 0xFF

	_, _, err := runPrecompile(G1AddAddress, input, 10000)
	require.ErrorIs(t, err, ErrInvalidFieldElem)
}

func TestG2Add_BadPadding(t *testing.T) {
	g := g2Generator()
	input := encodeG2Pair(&g, &g)
	input[0] = 0xFF

	_, _, err := runPrecompile(G2AddAddress, input, 10000)
	require.ErrorIs(t, err, ErrInvalidFieldElem)
}

// ===========================================================================
// Encode/decode roundtrip
// ===========================================================================

func TestG1EncodeDecodeRoundtrip(t *testing.T) {
	g := g1Generator()
	encoded := encodeG1(&g)
	decoded, err := decodeG1(encoded)
	require.NoError(t, err)
	require.True(t, g.Equal(&decoded))
}

func TestG2EncodeDecodeRoundtrip(t *testing.T) {
	g := g2Generator()
	encoded := encodeG2(&g)
	decoded, err := decodeG2(encoded)
	require.NoError(t, err)
	require.True(t, g.Equal(&decoded))
}

func TestInfinityG1Roundtrip(t *testing.T) {
	inf := infinityG1()
	decoded, err := decodeG1(inf)
	require.NoError(t, err)
	require.True(t, decoded.IsInfinity())
}

func TestInfinityG2Roundtrip(t *testing.T) {
	inf := infinityG2()
	decoded, err := decodeG2(inf)
	require.NoError(t, err)
	require.True(t, decoded.IsInfinity())
}

// ===========================================================================
// Field element validation
// ===========================================================================

func TestDecodeG1_FieldElementTooLarge(t *testing.T) {
	// Create input where x coordinate exceeds the field modulus.
	// The BLS12-381 Fp modulus is:
	// 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
	// We put a value >= modulus in the x coordinate.
	input := make([]byte, G1PointLen)
	// Set x to be larger than modulus: 0xFF...FF in the valid region
	for i := 16; i < 64; i++ {
		input[i] = 0xFF
	}
	// y = 0 (valid padding)

	_, err := decodeG1(input)
	// gnark-crypto's SetBytes does modular reduction, so this won't fail at decode.
	// But the resulting point won't be on the curve.
	require.Error(t, err) // Either not on curve or not in subgroup
}

// ===========================================================================
// Cross-operation consistency
// ===========================================================================

func TestG1Mul_EqualsRepeatedAdd(t *testing.T) {
	// 3*G via mul should equal G+G+G via add
	g := g1Generator()
	var three fr.Element
	three.SetUint64(3)
	input := encodePointScalar(encodeG1(&g), &three)
	mulResult, _, err := runPrecompile(G1MulAddress, input, 100000)
	require.NoError(t, err)

	// G + G
	addInput := encodeG1Pair(&g, &g)
	twoG, _, err := runPrecompile(G1AddAddress, addInput, 10000)
	require.NoError(t, err)

	// 2G + G
	var twoGPt bls12381.G1Affine
	twoGPt, err = decodeG1(twoG)
	require.NoError(t, err)
	addInput2 := encodeG1Pair(&twoGPt, &g)
	addResult, _, err := runPrecompile(G1AddAddress, addInput2, 10000)
	require.NoError(t, err)

	require.Equal(t, mulResult, addResult)
}

func TestG2Mul_EqualsRepeatedAdd(t *testing.T) {
	g := g2Generator()
	var three fr.Element
	three.SetUint64(3)
	input := encodePointScalar(encodeG2(&g), &three)
	mulResult, _, err := runPrecompile(G2MulAddress, input, 100000)
	require.NoError(t, err)

	addInput := encodeG2Pair(&g, &g)
	twoG, _, err := runPrecompile(G2AddAddress, addInput, 10000)
	require.NoError(t, err)

	var twoGPt bls12381.G2Affine
	twoGPt, err = decodeG2(twoG)
	require.NoError(t, err)
	addInput2 := encodeG2Pair(&twoGPt, &g)
	addResult, _, err := runPrecompile(G2AddAddress, addInput2, 10000)
	require.NoError(t, err)

	require.Equal(t, mulResult, addResult)
}

// ===========================================================================
// Benchmarks
// ===========================================================================

func BenchmarkG1Add(b *testing.B) {
	g := g1Generator()
	input := encodeG1Pair(&g, &g)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runPrecompile(G1AddAddress, input, 10000)
	}
}

func BenchmarkG1Mul(b *testing.B) {
	g := g1Generator()
	var s fr.Element
	s.SetUint64(12345)
	input := encodePointScalar(encodeG1(&g), &s)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runPrecompile(G1MulAddress, input, 100000)
	}
}

func BenchmarkG2Mul(b *testing.B) {
	g := g2Generator()
	var s fr.Element
	s.SetUint64(12345)
	input := encodePointScalar(encodeG2(&g), &s)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runPrecompile(G2MulAddress, input, 100000)
	}
}

func BenchmarkPairing_1Pair(b *testing.B) {
	g1 := g1Generator()
	g2 := g2Generator()
	var negG1 bls12381.G1Affine
	negG1.Neg(&g1)
	input := make([]byte, 2*PairingPair)
	copy(input[0:G1PointLen], encodeG1(&g1))
	copy(input[G1PointLen:PairingPair], encodeG2(&g2))
	copy(input[PairingPair:PairingPair+G1PointLen], encodeG1(&negG1))
	copy(input[PairingPair+G1PointLen:], encodeG2(&g2))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runPrecompile(PairingAddress, input, 1000000)
	}
}

// Verify fp.Element padding constraint via a quick sanity check.
func TestFpModulusFits48Bytes(t *testing.T) {
	// BLS12-381 Fp modulus is 381 bits = 48 bytes.
	// The first 16 bytes of the 64-byte padded encoding must be zero.
	var one fp.Element
	one.SetOne()
	b := one.Bytes()
	require.Len(t, b, 48) // gnark-crypto returns exactly 48 bytes
}
