// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ring

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

func TestRingSignaturePrecompile_Address(t *testing.T) {
	// Ring Signatures in Threshold Signatures range: 0x0800...0001
	expectedAddr := common.HexToAddress("0x0000000000000000000000000000000000009202")
	require.Equal(t, expectedAddr, ContractAddress)
	require.Equal(t, expectedAddr, RingSignaturePrecompile.Address())
}

func TestRing_SignVerify_Size2(t *testing.T) {
	curve := secp256k1.S256()

	// Generate ring of 2 keys
	ring := make([][]byte, 2)
	privKeys := make([]*ecdsa.PrivateKey, 2)

	for i := 0; i < 2; i++ {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		privKeys[i] = priv
		ring[i] = secp256k1.CompressPubkey(priv.PublicKey.X, priv.PublicKey.Y)
	}

	message := []byte("Ring signature test message")
	signerIdx := 0

	// Get signer's private key
	signerSk := privKeys[signerIdx].D.Bytes()
	if len(signerSk) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(signerSk):], signerSk)
		signerSk = padded
	}

	// Build sign input
	signInput := buildSignInput(SchemeLSAGSecp256k1, ring, signerSk, byte(signerIdx), message)

	gas := RingSignaturePrecompile.RequiredGas(signInput)

	// Sign
	signature, remainingGas, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		signInput,
		gas,
		false,
	)

	require.NoError(t, err)
	require.NotNil(t, signature)
	require.Equal(t, uint64(0), remainingGas)

	// Build verify input
	verifyInput := buildVerifyInput(SchemeLSAGSecp256k1, ring, signature, message)

	gas = RingSignaturePrecompile.RequiredGas(verifyInput)

	// Verify
	result, remainingGas, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		verifyInput,
		gas,
		false,
	)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, uint64(0), remainingGas)
	require.Equal(t, []byte{0x01}, result) // Valid signature
}

func TestRing_SignVerify_Size5(t *testing.T) {
	curve := secp256k1.S256()

	// Generate ring of 5 keys
	ringSize := 5
	ring := make([][]byte, ringSize)
	privKeys := make([]*ecdsa.PrivateKey, ringSize)

	for i := 0; i < ringSize; i++ {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		privKeys[i] = priv
		ring[i] = secp256k1.CompressPubkey(priv.PublicKey.X, priv.PublicKey.Y)
	}

	message := []byte("Ring signature with 5 members")
	signerIdx := 3 // Sign with middle key

	signerSk := privKeys[signerIdx].D.Bytes()
	if len(signerSk) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(signerSk):], signerSk)
		signerSk = padded
	}

	signInput := buildSignInput(SchemeLSAGSecp256k1, ring, signerSk, byte(signerIdx), message)
	gas := RingSignaturePrecompile.RequiredGas(signInput)

	signature, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		signInput,
		gas,
		false,
	)
	require.NoError(t, err)

	verifyInput := buildVerifyInput(SchemeLSAGSecp256k1, ring, signature, message)
	gas = RingSignaturePrecompile.RequiredGas(verifyInput)

	result, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		verifyInput,
		gas,
		false,
	)
	require.NoError(t, err)
	require.Equal(t, []byte{0x01}, result)
}

func TestRing_Verify_InvalidSignature(t *testing.T) {
	curve := secp256k1.S256()

	ring := make([][]byte, 2)
	privKeys := make([]*ecdsa.PrivateKey, 2)

	for i := 0; i < 2; i++ {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		privKeys[i] = priv
		ring[i] = secp256k1.CompressPubkey(priv.PublicKey.X, priv.PublicKey.Y)
	}

	message := []byte("Test message")
	signerIdx := 0

	signerSk := privKeys[signerIdx].D.Bytes()
	if len(signerSk) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(signerSk):], signerSk)
		signerSk = padded
	}

	signInput := buildSignInput(SchemeLSAGSecp256k1, ring, signerSk, byte(signerIdx), message)
	gas := RingSignaturePrecompile.RequiredGas(signInput)

	signature, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		signInput,
		gas,
		false,
	)
	require.NoError(t, err)

	// Corrupt signature
	signature[10] ^= 0xFF

	verifyInput := buildVerifyInput(SchemeLSAGSecp256k1, ring, signature, message)
	gas = RingSignaturePrecompile.RequiredGas(verifyInput)

	result, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		verifyInput,
		gas,
		false,
	)
	require.NoError(t, err)
	require.Equal(t, []byte{0x00}, result) // Invalid signature
}

func TestRing_Verify_WrongMessage(t *testing.T) {
	curve := secp256k1.S256()

	ring := make([][]byte, 2)
	privKeys := make([]*ecdsa.PrivateKey, 2)

	for i := 0; i < 2; i++ {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		privKeys[i] = priv
		ring[i] = secp256k1.CompressPubkey(priv.PublicKey.X, priv.PublicKey.Y)
	}

	message1 := []byte("Original message")
	message2 := []byte("Different message")

	signerSk := privKeys[0].D.Bytes()
	if len(signerSk) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(signerSk):], signerSk)
		signerSk = padded
	}

	signInput := buildSignInput(SchemeLSAGSecp256k1, ring, signerSk, 0, message1)
	gas := RingSignaturePrecompile.RequiredGas(signInput)

	signature, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		signInput,
		gas,
		false,
	)
	require.NoError(t, err)

	// Verify with wrong message
	verifyInput := buildVerifyInput(SchemeLSAGSecp256k1, ring, signature, message2)
	gas = RingSignaturePrecompile.RequiredGas(verifyInput)

	result, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		verifyInput,
		gas,
		false,
	)
	require.NoError(t, err)
	require.Equal(t, []byte{0x00}, result) // Invalid
}

func TestRing_ComputeKeyImage(t *testing.T) {
	curve := secp256k1.S256()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	privKey := priv.D.Bytes()
	if len(privKey) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(privKey):], privKey)
		privKey = padded
	}

	input := buildKeyImageInput(SchemeLSAGSecp256k1, privKey)
	gas := RingSignaturePrecompile.RequiredGas(input)

	keyImage, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		gas,
		false,
	)

	require.NoError(t, err)
	require.NotNil(t, keyImage)
	require.Equal(t, CompressedPubKeySize, len(keyImage)) // 33 bytes compressed

	// Same private key should produce same key image
	keyImage2, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		gas,
		false,
	)
	require.NoError(t, err)
	require.Equal(t, keyImage, keyImage2)
}

func TestRing_KeyImage_ConsistentWithSignature(t *testing.T) {
	curve := secp256k1.S256()

	ring := make([][]byte, 3)
	privKeys := make([]*ecdsa.PrivateKey, 3)

	for i := 0; i < 3; i++ {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		privKeys[i] = priv
		ring[i] = secp256k1.CompressPubkey(priv.PublicKey.X, priv.PublicKey.Y)
	}

	signerIdx := 1
	signerSk := privKeys[signerIdx].D.Bytes()
	if len(signerSk) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(signerSk):], signerSk)
		signerSk = padded
	}

	// Compute key image directly
	kiInput := buildKeyImageInput(SchemeLSAGSecp256k1, signerSk)
	gas := RingSignaturePrecompile.RequiredGas(kiInput)

	keyImage, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		kiInput,
		gas,
		false,
	)
	require.NoError(t, err)

	// Sign and extract key image from signature
	signInput := buildSignInput(SchemeLSAGSecp256k1, ring, signerSk, byte(signerIdx), []byte("test"))
	gas = RingSignaturePrecompile.RequiredGas(signInput)

	signature, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		signInput,
		gas,
		false,
	)
	require.NoError(t, err)

	// Key image is first 33 bytes of signature
	signatureKeyImage := signature[:CompressedPubKeySize]

	require.Equal(t, keyImage, signatureKeyImage)
}

func TestRing_InvalidScheme(t *testing.T) {
	input := []byte{OpSign, 0xFF, 2} // Invalid scheme

	gas := RingSignaturePrecompile.RequiredGas(input)
	require.Equal(t, uint64(0), gas)
}

func TestRing_RingSizeTooSmall(t *testing.T) {
	curve := secp256k1.S256()
	priv, _ := ecdsa.GenerateKey(curve, rand.Reader)

	ring := [][]byte{secp256k1.CompressPubkey(priv.PublicKey.X, priv.PublicKey.Y)}

	signerSk := priv.D.Bytes()
	if len(signerSk) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(signerSk):], signerSk)
		signerSk = padded
	}

	signInput := buildSignInput(SchemeLSAGSecp256k1, ring, signerSk, 0, []byte("test"))
	gas := RingSignaturePrecompile.RequiredGas(signInput)

	_, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		signInput,
		gas+100000,
		false,
	)
	require.Error(t, err)
	require.Equal(t, ErrInvalidRingSize, err)
}

func TestRing_SignerIndexOutOfBounds(t *testing.T) {
	curve := secp256k1.S256()

	ring := make([][]byte, 2)
	for i := 0; i < 2; i++ {
		priv, _ := ecdsa.GenerateKey(curve, rand.Reader)
		ring[i] = secp256k1.CompressPubkey(priv.PublicKey.X, priv.PublicKey.Y)
	}

	priv, _ := ecdsa.GenerateKey(curve, rand.Reader)
	signerSk := priv.D.Bytes()
	if len(signerSk) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(signerSk):], signerSk)
		signerSk = padded
	}

	// Signer index 5 is out of bounds for ring size 2
	signInput := buildSignInput(SchemeLSAGSecp256k1, ring, signerSk, 5, []byte("test"))
	gas := RingSignaturePrecompile.RequiredGas(signInput)

	_, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		signInput,
		gas+100000,
		false,
	)
	require.Error(t, err)
	require.Equal(t, ErrInvalidSignerIdx, err)
}

func TestRing_OutOfGas(t *testing.T) {
	curve := secp256k1.S256()

	ring := make([][]byte, 2)
	privKeys := make([]*ecdsa.PrivateKey, 2)

	for i := 0; i < 2; i++ {
		priv, _ := ecdsa.GenerateKey(curve, rand.Reader)
		privKeys[i] = priv
		ring[i] = secp256k1.CompressPubkey(priv.PublicKey.X, priv.PublicKey.Y)
	}

	signerSk := privKeys[0].D.Bytes()
	if len(signerSk) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(signerSk):], signerSk)
		signerSk = padded
	}

	signInput := buildSignInput(SchemeLSAGSecp256k1, ring, signerSk, 0, []byte("test"))

	_, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		signInput,
		100, // Insufficient gas
		false,
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "out of gas")
}

func TestRing_InputTooShort(t *testing.T) {
	input := []byte{OpSign, SchemeLSAGSecp256k1}

	_, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		100000,
		false,
	)
	require.Error(t, err)
}

func TestRing_RequiredGas(t *testing.T) {
	tests := []struct {
		name     string
		ringSize int
		minGas   uint64
	}{
		{"Sign size 2", 2, GasSignBase + 2*GasSignPerMember},
		{"Sign size 5", 5, GasSignBase + 5*GasSignPerMember},
		{"Sign size 10", 10, GasSignBase + 10*GasSignPerMember},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ring := make([][]byte, tt.ringSize)
			for i := 0; i < tt.ringSize; i++ {
				ring[i] = make([]byte, CompressedPubKeySize)
			}

			input := buildSignInput(SchemeLSAGSecp256k1, ring, make([]byte, 32), 0, []byte("test"))
			gas := RingSignaturePrecompile.RequiredGas(input)
			require.GreaterOrEqual(t, gas, tt.minGas)
		})
	}
}

// Helper functions

func buildSignInput(scheme byte, ring [][]byte, signerSk []byte, signerIdx byte, message []byte) []byte {
	input := make([]byte, 0)
	input = append(input, OpSign, scheme)
	input = append(input, byte(len(ring)))

	for _, pk := range ring {
		input = append(input, pk...)
	}

	input = append(input, signerSk...)
	input = append(input, signerIdx)
	input = append(input, message...)

	return input
}

func buildVerifyInput(scheme byte, ring [][]byte, signature, message []byte) []byte {
	input := make([]byte, 0)
	input = append(input, OpVerify, scheme)
	input = append(input, byte(len(ring)))

	for _, pk := range ring {
		input = append(input, pk...)
	}

	input = append(input, signature...)
	input = append(input, message...)

	return input
}

func buildKeyImageInput(scheme byte, privKey []byte) []byte {
	input := make([]byte, 0)
	input = append(input, OpComputeKeyImage, scheme)
	input = append(input, privKey...)

	return input
}

// Benchmarks

func BenchmarkRing_Sign_Size3(b *testing.B) {
	curve := secp256k1.S256()
	ringSize := 3

	ring := make([][]byte, ringSize)
	privKeys := make([]*ecdsa.PrivateKey, ringSize)

	for i := 0; i < ringSize; i++ {
		priv, _ := ecdsa.GenerateKey(curve, rand.Reader)
		privKeys[i] = priv
		ring[i] = secp256k1.CompressPubkey(priv.PublicKey.X, priv.PublicKey.Y)
	}

	signerSk := privKeys[0].D.Bytes()
	if len(signerSk) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(signerSk):], signerSk)
		signerSk = padded
	}

	signInput := buildSignInput(SchemeLSAGSecp256k1, ring, signerSk, 0, []byte("benchmark"))
	gas := RingSignaturePrecompile.RequiredGas(signInput)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = RingSignaturePrecompile.Run(nil, common.Address{}, ContractAddress, signInput, gas, false)
	}
}

func BenchmarkRing_Verify_Size3(b *testing.B) {
	curve := secp256k1.S256()
	ringSize := 3

	ring := make([][]byte, ringSize)
	privKeys := make([]*ecdsa.PrivateKey, ringSize)

	for i := 0; i < ringSize; i++ {
		priv, _ := ecdsa.GenerateKey(curve, rand.Reader)
		privKeys[i] = priv
		ring[i] = secp256k1.CompressPubkey(priv.PublicKey.X, priv.PublicKey.Y)
	}

	signerSk := privKeys[0].D.Bytes()
	if len(signerSk) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(signerSk):], signerSk)
		signerSk = padded
	}

	message := []byte("benchmark")
	signInput := buildSignInput(SchemeLSAGSecp256k1, ring, signerSk, 0, message)
	signature, _, _ := RingSignaturePrecompile.Run(nil, common.Address{}, ContractAddress, signInput, 1000000, false)

	verifyInput := buildVerifyInput(SchemeLSAGSecp256k1, ring, signature, message)
	gas := RingSignaturePrecompile.RequiredGas(verifyInput)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = RingSignaturePrecompile.Run(nil, common.Address{}, ContractAddress, verifyInput, gas, false)
	}
}

func BenchmarkRing_ComputeKeyImage(b *testing.B) {
	curve := secp256k1.S256()
	priv, _ := ecdsa.GenerateKey(curve, rand.Reader)

	privKey := priv.D.Bytes()
	if len(privKey) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(privKey):], privKey)
		privKey = padded
	}

	input := buildKeyImageInput(SchemeLSAGSecp256k1, privKey)
	gas := RingSignaturePrecompile.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = RingSignaturePrecompile.Run(nil, common.Address{}, ContractAddress, input, gas, false)
	}
}
