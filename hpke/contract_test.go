// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hpke

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// testSeed returns a deterministic seed for testing derived from the given label.
func testSeed(label string) [SeedSize]byte {
	return sha256.Sum256([]byte(label))
}

func TestHPKEPrecompile_Address(t *testing.T) {
	expectedAddr := common.HexToAddress("0x0000000000000000000000000000000000009200")
	require.Equal(t, expectedAddr, ContractAddress)
	require.Equal(t, expectedAddr, HPKEPrecompile.Address())
}

func TestHPKE_SingleShotSeal_X25519(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)

	kem, _, _ := suite.Params()
	pk, _, err := kem.Scheme().GenerateKeyPair()
	require.NoError(t, err)

	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	plaintext := []byte("Hello, HPKE!")
	info := []byte("test info")
	aad := []byte("additional data")

	seed := testSeed("x25519-seal-test")
	sealInput := buildSealInput(KEMX25519, 0x0001, 0x0001, pkBytes, seed, info, aad, plaintext)
	gas := HPKEPrecompile.RequiredGas(append([]byte{OpSingleShotSeal}, sealInput...))

	result, remainingGas, err := HPKEPrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		append([]byte{OpSingleShotSeal}, sealInput...),
		gas,
		false,
	)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, uint64(0), remainingGas)

	// Result should contain enc + ciphertext
	encLen := kem.Scheme().CiphertextSize()
	require.True(t, len(result) > encLen)
}

func TestHPKE_SingleShotSeal_P256(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)

	kem, _, _ := suite.Params()
	pk, _, err := kem.Scheme().GenerateKeyPair()
	require.NoError(t, err)

	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	plaintext := []byte("Hello, HPKE P-256!")
	info := []byte("p256 info")
	aad := []byte("p256 aad")

	seed := testSeed("p256-seal-test")
	sealInput := buildSealInput(KEMP256, 0x0001, 0x0002, pkBytes, seed, info, aad, plaintext)
	gas := HPKEPrecompile.RequiredGas(append([]byte{OpSingleShotSeal}, sealInput...))

	result, _, err := HPKEPrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		append([]byte{OpSingleShotSeal}, sealInput...),
		gas,
		false,
	)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestHPKE_SingleShotSeal_X25519Kyber768(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_X25519_KYBER768_DRAFT00, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)

	kem, _, _ := suite.Params()
	pk, _, err := kem.Scheme().GenerateKeyPair()
	require.NoError(t, err)

	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	plaintext := []byte("Hello, post-quantum HPKE!")
	info := []byte("kyber info")
	aad := []byte("kyber aad")

	seed := testSeed("kyber768-seal-test")
	sealInput := buildSealInput(KEMX25519Kyber768, 0x0001, 0x0001, pkBytes, seed, info, aad, plaintext)
	gas := HPKEPrecompile.RequiredGas(append([]byte{OpSingleShotSeal}, sealInput...))
	require.GreaterOrEqual(t, gas, uint64(GasKEMEncapsX25519Kyber768))

	result, remainingGas, err := HPKEPrecompile.Run(
		nil, common.Address{}, ContractAddress,
		append([]byte{OpSingleShotSeal}, sealInput...),
		gas, false,
	)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, uint64(0), remainingGas)
}

func TestHPKE_SingleShotSeal_XWing(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_XWING, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)

	kem, _, _ := suite.Params()
	pk, _, err := kem.Scheme().GenerateKeyPair()
	require.NoError(t, err)

	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	plaintext := []byte("Hello, X-Wing HPKE!")
	info := []byte("xwing info")
	aad := []byte("xwing aad")

	seed := testSeed("xwing-seal-test")
	sealInput := buildSealInput(KEMXWing, 0x0001, 0x0001, pkBytes, seed, info, aad, plaintext)
	gas := HPKEPrecompile.RequiredGas(append([]byte{OpSingleShotSeal}, sealInput...))
	require.GreaterOrEqual(t, gas, uint64(GasKEMEncapsXWing))

	result, _, err := HPKEPrecompile.Run(
		nil, common.Address{}, ContractAddress,
		append([]byte{OpSingleShotSeal}, sealInput...),
		gas, false,
	)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestHPKE_InvalidOperation(t *testing.T) {
	input := []byte{0xFF, 0x00, 0x20}
	gas := HPKEPrecompile.RequiredGas(input)
	require.Equal(t, uint64(0), gas)

	_, _, err := HPKEPrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		1000000,
		false,
	)
	require.Error(t, err)
}

func TestHPKE_InvalidCipherSuite(t *testing.T) {
	input := []byte{OpSingleShotSeal, 0xFF, 0xFF, 0x00, 0x01, 0x00, 0x01}
	gas := HPKEPrecompile.RequiredGas(input)

	_, _, err := HPKEPrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		gas+100000,
		false,
	)
	require.Error(t, err)
}

func TestHPKE_InputTooShort(t *testing.T) {
	input := []byte{OpSingleShotSeal}

	_, _, err := HPKEPrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		100000,
		false,
	)
	require.Error(t, err)
}

func TestHPKE_OutOfGas(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)

	kem, _, _ := suite.Params()
	pk, _, err := kem.Scheme().GenerateKeyPair()
	require.NoError(t, err)

	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	seed := testSeed("oog-test")
	sealInput := buildSealInput(KEMX25519, 0x0001, 0x0001, pkBytes, seed, nil, nil, []byte("test"))

	_, _, err = HPKEPrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		append([]byte{OpSingleShotSeal}, sealInput...),
		100, // Insufficient gas
		false,
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "out of gas")
}

func TestHPKE_EmptyInput(t *testing.T) {
	_, _, err := HPKEPrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		[]byte{},
		100000,
		false,
	)
	require.Error(t, err)
}

func TestHPKE_RequiredGas(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		minGas uint64
	}{
		{
			name:   "SingleShotSeal X25519",
			input:  append([]byte{OpSingleShotSeal, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01}, make([]byte, 100)...),
			minGas: GasKEMEncapsX25519,
		},
		{
			name:   "SingleShotSeal P256",
			input:  append([]byte{OpSingleShotSeal, 0x00, 0x10, 0x00, 0x01, 0x00, 0x01}, make([]byte, 100)...),
			minGas: GasKEMEncapsP256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gas := HPKEPrecompile.RequiredGas(tt.input)
			require.GreaterOrEqual(t, gas, tt.minGas)
		})
	}
}

func TestHPKE_RequiredGas_PostQuantum(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected uint64
	}{
		{
			name:     "SingleShotSeal X25519Kyber768",
			input:    append([]byte{OpSingleShotSeal, 0x00, 0x30, 0x00, 0x01, 0x00, 0x01}, make([]byte, 100)...),
			expected: GasKEMEncapsX25519Kyber768,
		},
		{
			name:     "SingleShotSeal XWing",
			input:    append([]byte{OpSingleShotSeal, 0x64, 0x7a, 0x00, 0x01, 0x00, 0x01}, make([]byte, 100)...),
			expected: GasKEMEncapsXWing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gas := HPKEPrecompile.RequiredGas(tt.input)
			require.GreaterOrEqual(t, gas, tt.expected)
		})
	}
}

func TestHPKE_IsKyberKEM(t *testing.T) {
	require.True(t, isKyberKEM(KEMX25519Kyber768))
	require.True(t, isKyberKEM(KEMXWing))
	require.False(t, isKyberKEM(KEMX25519))
	require.False(t, isKyberKEM(KEMP256))
	require.False(t, isKyberKEM(KEMP384))
	require.False(t, isKyberKEM(KEMP521))
}

func TestHPKE_OpenRejected(t *testing.T) {
	// Verify that the old OpSingleShotOpen (0x21) is rejected
	input := append([]byte{0x21, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01}, make([]byte, 100)...)
	gas := HPKEPrecompile.RequiredGas(input)
	require.Equal(t, uint64(0), gas) // Unknown op returns 0 gas

	_, _, err := HPKEPrecompile.Run(
		nil, common.Address{}, ContractAddress,
		input, 1000000, false,
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported operation")
}

// Helper functions

func buildSealInput(kemID, kdfID, aeadID uint16, pk []byte, seed [SeedSize]byte, info, aad, plaintext []byte) []byte {
	input := make([]byte, 0)

	// Cipher suite (6 bytes)
	input = append(input, byte(kemID>>8), byte(kemID))
	input = append(input, byte(kdfID>>8), byte(kdfID))
	input = append(input, byte(aeadID>>8), byte(aeadID))

	// Deterministic seed (32 bytes)
	input = append(input, seed[:]...)

	// Public key length + data
	pkLen := make([]byte, 2)
	binary.BigEndian.PutUint16(pkLen, uint16(len(pk)))
	input = append(input, pkLen...)
	input = append(input, pk...)

	// Info length + data
	infoLen := make([]byte, 2)
	binary.BigEndian.PutUint16(infoLen, uint16(len(info)))
	input = append(input, infoLen...)
	input = append(input, info...)

	// AAD length + data
	aadLen := make([]byte, 2)
	binary.BigEndian.PutUint16(aadLen, uint16(len(aad)))
	input = append(input, aadLen...)
	input = append(input, aad...)

	// Plaintext
	input = append(input, plaintext...)

	return input
}

// Consensus determinism regression tests

func TestConsensusDeterministicSeal_X25519(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	kem, _, _ := suite.Params()
	pk, _, err := kem.Scheme().GenerateKeyPair()
	require.NoError(t, err)
	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	seed := testSeed("consensus-x25519")
	plaintext := []byte("consensus test payload")
	info := []byte("consensus info")
	aad := []byte("consensus aad")

	sealInput := buildSealInput(KEMX25519, 0x0001, 0x0001, pkBytes, seed, info, aad, plaintext)
	input := append([]byte{OpSingleShotSeal}, sealInput...)
	gas := HPKEPrecompile.RequiredGas(input)

	result1, _, err := HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, input, gas, false)
	require.NoError(t, err)

	result2, _, err := HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, input, gas, false)
	require.NoError(t, err)

	require.Equal(t, result1, result2, "HPKE Seal must be deterministic for consensus")

	// Third call to rule out alternating patterns
	result3, _, err := HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, input, gas, false)
	require.NoError(t, err)
	require.Equal(t, result1, result3, "HPKE Seal must be deterministic across any number of calls")
}

func TestConsensusDeterministicSeal_P256(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
	kem, _, _ := suite.Params()
	pk, _, err := kem.Scheme().GenerateKeyPair()
	require.NoError(t, err)
	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	seed := testSeed("consensus-p256")
	sealInput := buildSealInput(KEMP256, 0x0001, 0x0002, pkBytes, seed, nil, nil, []byte("p256 consensus"))
	input := append([]byte{OpSingleShotSeal}, sealInput...)
	gas := HPKEPrecompile.RequiredGas(input)

	result1, _, err := HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, input, gas, false)
	require.NoError(t, err)

	result2, _, err := HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, input, gas, false)
	require.NoError(t, err)

	require.Equal(t, result1, result2, "HPKE P-256 Seal must be deterministic for consensus")
}

func TestConsensusDeterministicSeal_XWing(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_XWING, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	kem, _, _ := suite.Params()
	pk, _, err := kem.Scheme().GenerateKeyPair()
	require.NoError(t, err)
	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	seed := testSeed("consensus-xwing")
	sealInput := buildSealInput(KEMXWing, 0x0001, 0x0001, pkBytes, seed, nil, nil, []byte("xwing consensus"))
	input := append([]byte{OpSingleShotSeal}, sealInput...)
	gas := HPKEPrecompile.RequiredGas(input)

	result1, _, err := HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, input, gas, false)
	require.NoError(t, err)

	result2, _, err := HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, input, gas, false)
	require.NoError(t, err)

	require.Equal(t, result1, result2, "HPKE X-Wing Seal must be deterministic for consensus")
}

func TestConsensusDifferentSeedsDifferentOutput(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	kem, _, _ := suite.Params()
	pk, _, err := kem.Scheme().GenerateKeyPair()
	require.NoError(t, err)
	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	plaintext := []byte("same plaintext")

	seed1 := testSeed("seed-alpha")
	seed2 := testSeed("seed-beta")

	input1 := append([]byte{OpSingleShotSeal}, buildSealInput(KEMX25519, 0x0001, 0x0001, pkBytes, seed1, nil, nil, plaintext)...)
	input2 := append([]byte{OpSingleShotSeal}, buildSealInput(KEMX25519, 0x0001, 0x0001, pkBytes, seed2, nil, nil, plaintext)...)

	gas1 := HPKEPrecompile.RequiredGas(input1)
	gas2 := HPKEPrecompile.RequiredGas(input2)

	result1, _, err := HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, input1, gas1, false)
	require.NoError(t, err)

	result2, _, err := HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, input2, gas2, false)
	require.NoError(t, err)

	require.NotEqual(t, result1, result2, "different seeds must produce different ciphertexts")
}

// Benchmarks

func BenchmarkHPKE_Seal_X25519(b *testing.B) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	kem, _, _ := suite.Params()
	pk, _, _ := kem.Scheme().GenerateKeyPair()
	pkBytes, _ := pk.MarshalBinary()

	plaintext := []byte("benchmark message")
	seed := testSeed("bench-x25519")
	sealInput := buildSealInput(KEMX25519, 0x0001, 0x0001, pkBytes, seed, nil, nil, plaintext)
	input := append([]byte{OpSingleShotSeal}, sealInput...)
	gas := HPKEPrecompile.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, input, gas, false)
	}
}
