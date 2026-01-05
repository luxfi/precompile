// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hpke

import (
	"encoding/binary"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

func TestHPKEPrecompile_Address(t *testing.T) {
	// HPKE in Privacy/Encryption range: 0x0700...0001
	expectedAddr := common.HexToAddress("0x0000000000000000000000000000000000009200")
	require.Equal(t, expectedAddr, ContractAddress)
	require.Equal(t, expectedAddr, HPKEPrecompile.Address())
}

func TestHPKE_SingleShotSealOpen_X25519(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)

	// Generate recipient key pair
	kem, _, _ := suite.Params()
	pk, sk, err := kem.Scheme().GenerateKeyPair()
	require.NoError(t, err)

	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	skBytes, err := sk.MarshalBinary()
	require.NoError(t, err)

	plaintext := []byte("Hello, HPKE!")
	info := []byte("test info")
	aad := []byte("additional data")

	// Build seal input
	sealInput := buildSealInput(KEMX25519, 0x0001, 0x0001, pkBytes, info, aad, plaintext)

	gas := HPKEPrecompile.RequiredGas(append([]byte{OpSingleShotSeal}, sealInput...))

	// Seal
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

	// Extract enc and ciphertext
	encLen := kem.Scheme().CiphertextSize()
	require.True(t, len(result) > encLen)

	enc := result[:encLen]
	ciphertext := result[encLen:]

	// Build open input
	openInput := buildOpenInput(KEMX25519, 0x0001, 0x0001, enc, skBytes, info, aad, ciphertext)

	gas = HPKEPrecompile.RequiredGas(append([]byte{OpSingleShotOpen}, openInput...))

	// Open
	decrypted, remainingGas, err := HPKEPrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		append([]byte{OpSingleShotOpen}, openInput...),
		gas,
		false,
	)

	require.NoError(t, err)
	require.NotNil(t, decrypted)
	require.Equal(t, uint64(0), remainingGas)
	require.Equal(t, plaintext, decrypted)
}

func TestHPKE_SingleShotSealOpen_P256(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)

	kem, _, _ := suite.Params()
	pk, sk, err := kem.Scheme().GenerateKeyPair()
	require.NoError(t, err)

	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	skBytes, err := sk.MarshalBinary()
	require.NoError(t, err)

	plaintext := []byte("Hello, HPKE P-256!")
	info := []byte("p256 info")
	aad := []byte("p256 aad")

	// Seal
	sealInput := buildSealInput(KEMP256, 0x0001, 0x0002, pkBytes, info, aad, plaintext)
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

	encLen := kem.Scheme().CiphertextSize()
	enc := result[:encLen]
	ciphertext := result[encLen:]

	// Open
	openInput := buildOpenInput(KEMP256, 0x0001, 0x0002, enc, skBytes, info, aad, ciphertext)
	gas = HPKEPrecompile.RequiredGas(append([]byte{OpSingleShotOpen}, openInput...))

	decrypted, _, err := HPKEPrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		append([]byte{OpSingleShotOpen}, openInput...),
		gas,
		false,
	)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestHPKE_SingleShotOpen_InvalidCiphertext(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)

	kem, _, _ := suite.Params()
	pk, sk, err := kem.Scheme().GenerateKeyPair()
	require.NoError(t, err)

	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	skBytes, err := sk.MarshalBinary()
	require.NoError(t, err)

	plaintext := []byte("Test message")

	// Seal first
	sealInput := buildSealInput(KEMX25519, 0x0001, 0x0001, pkBytes, nil, nil, plaintext)
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

	encLen := kem.Scheme().CiphertextSize()
	enc := result[:encLen]
	ciphertext := result[encLen:]

	// Corrupt ciphertext
	ciphertext[0] ^= 0xFF

	// Try to open
	openInput := buildOpenInput(KEMX25519, 0x0001, 0x0001, enc, skBytes, nil, nil, ciphertext)
	gas = HPKEPrecompile.RequiredGas(append([]byte{OpSingleShotOpen}, openInput...))

	_, _, err = HPKEPrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		append([]byte{OpSingleShotOpen}, openInput...),
		gas,
		false,
	)
	require.Error(t, err)
}

func TestHPKE_InvalidOperation(t *testing.T) {
	input := []byte{0xFF, 0x00, 0x20} // Invalid op

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
	input := []byte{OpSingleShotSeal, 0xFF, 0xFF, 0x00, 0x01, 0x00, 0x01} // Invalid KEM

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

	sealInput := buildSealInput(KEMX25519, 0x0001, 0x0001, pkBytes, nil, nil, []byte("test"))

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
		{
			name:   "SingleShotOpen",
			input:  append([]byte{OpSingleShotOpen, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01}, make([]byte, 100)...),
			minGas: GasKEMEncapsX25519,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gas := HPKEPrecompile.RequiredGas(tt.input)
			require.GreaterOrEqual(t, gas, tt.minGas)
		})
	}
}

func TestHPKE_LargeMessage(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)

	kem, _, _ := suite.Params()
	pk, sk, err := kem.Scheme().GenerateKeyPair()
	require.NoError(t, err)

	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	skBytes, err := sk.MarshalBinary()
	require.NoError(t, err)

	// 10KB message
	plaintext := make([]byte, 10240)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	sealInput := buildSealInput(KEMX25519, 0x0001, 0x0001, pkBytes, nil, nil, plaintext)
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

	encLen := kem.Scheme().CiphertextSize()
	enc := result[:encLen]
	ciphertext := result[encLen:]

	openInput := buildOpenInput(KEMX25519, 0x0001, 0x0001, enc, skBytes, nil, nil, ciphertext)
	gas = HPKEPrecompile.RequiredGas(append([]byte{OpSingleShotOpen}, openInput...))

	decrypted, _, err := HPKEPrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		append([]byte{OpSingleShotOpen}, openInput...),
		gas,
		false,
	)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

// Helper functions

func buildSealInput(kemID, kdfID, aeadID uint16, pk, info, aad, plaintext []byte) []byte {
	input := make([]byte, 0)

	// Cipher suite (6 bytes)
	input = append(input, byte(kemID>>8), byte(kemID))
	input = append(input, byte(kdfID>>8), byte(kdfID))
	input = append(input, byte(aeadID>>8), byte(aeadID))

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

func buildOpenInput(kemID, kdfID, aeadID uint16, enc, sk, info, aad, ciphertext []byte) []byte {
	input := make([]byte, 0)

	// Cipher suite (6 bytes)
	input = append(input, byte(kemID>>8), byte(kemID))
	input = append(input, byte(kdfID>>8), byte(kdfID))
	input = append(input, byte(aeadID>>8), byte(aeadID))

	// Enc length + data
	encLen := make([]byte, 2)
	binary.BigEndian.PutUint16(encLen, uint16(len(enc)))
	input = append(input, encLen...)
	input = append(input, enc...)

	// SK length + data
	skLen := make([]byte, 2)
	binary.BigEndian.PutUint16(skLen, uint16(len(sk)))
	input = append(input, skLen...)
	input = append(input, sk...)

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

	// Ciphertext
	input = append(input, ciphertext...)

	return input
}

// Benchmarks

func BenchmarkHPKE_Seal_X25519(b *testing.B) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	kem, _, _ := suite.Params()
	pk, _, _ := kem.Scheme().GenerateKeyPair()
	pkBytes, _ := pk.MarshalBinary()

	plaintext := []byte("benchmark message")
	sealInput := buildSealInput(KEMX25519, 0x0001, 0x0001, pkBytes, nil, nil, plaintext)
	input := append([]byte{OpSingleShotSeal}, sealInput...)
	gas := HPKEPrecompile.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, input, gas, false)
	}
}

func BenchmarkHPKE_Open_X25519(b *testing.B) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	kem, _, _ := suite.Params()
	pk, sk, _ := kem.Scheme().GenerateKeyPair()
	pkBytes, _ := pk.MarshalBinary()
	skBytes, _ := sk.MarshalBinary()

	plaintext := []byte("benchmark message")
	sealInput := buildSealInput(KEMX25519, 0x0001, 0x0001, pkBytes, nil, nil, plaintext)
	result, _, _ := HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, append([]byte{OpSingleShotSeal}, sealInput...), 1000000, false)

	encLen := kem.Scheme().CiphertextSize()
	enc := result[:encLen]
	ciphertext := result[encLen:]

	openInput := buildOpenInput(KEMX25519, 0x0001, 0x0001, enc, skBytes, nil, nil, ciphertext)
	input := append([]byte{OpSingleShotOpen}, openInput...)
	gas := HPKEPrecompile.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, input, gas, false)
	}
}
