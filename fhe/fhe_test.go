// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"math/big"
	"testing"

	"github.com/luxfi/fhe"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// TestTFHEInitialization tests that the TFHE components initialize correctly
func TestTFHEInitialization(t *testing.T) {
	err := initTFHE()
	require.NoError(t, err, "TFHE initialization should succeed")
	require.NotNil(t, evaluator, "evaluator should be initialized")
	require.NotNil(t, encryptor, "encryptor should be initialized")
	require.NotNil(t, decryptor, "decryptor should be initialized")
	require.NotNil(t, secretKey, "secretKey should be initialized")
	require.NotNil(t, publicKey, "publicKey should be initialized")
}

// TestFheTypeMapping tests FHE type constant to TFHE type mapping
func TestFheTypeMapping(t *testing.T) {
	tests := []struct {
		name     string
		fheType  uint8
		expected fhe.FheUintType
	}{
		{"bool", TypeEbool, fhe.FheBool},
		{"uint8", TypeEuint8, fhe.FheUint8},
		{"uint16", TypeEuint16, fhe.FheUint16},
		{"uint32", TypeEuint32, fhe.FheUint32},
		{"uint64", TypeEuint64, fhe.FheUint64},
		{"uint128", TypeEuint128, fhe.FheUint128},
		{"uint256", TypeEuint256, fhe.FheUint256},
		{"address", TypeEaddress, fhe.FheUint160},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fheTypeToTFHEType(tt.fheType)
			require.Equal(t, tt.expected, result)
		})
	}
}

// TestTrivialEncryptDecrypt tests encrypt-decrypt roundtrip
func TestTrivialEncryptDecrypt(t *testing.T) {
	err := initTFHE()
	require.NoError(t, err)

	tests := []struct {
		name    string
		value   uint64
		fheType uint8
	}{
		{"zero_uint8", 0, TypeEuint8},
		{"one_uint8", 1, TypeEuint8},
		{"max_uint8", 255, TypeEuint8},
		{"uint32_42", 42, TypeEuint32},
		{"uint64_large", 12345678, TypeEuint64},
		{"bool_true", 1, TypeEbool},
		{"bool_false", 0, TypeEbool},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			ct := tfheTrivialEncrypt(big.NewInt(int64(tt.value)), tt.fheType)
			require.NotNil(t, ct, "encryption should succeed")
			require.Greater(t, len(ct), 0, "ciphertext should not be empty")

			// Decrypt
			decrypted := tfheDecrypt(ct, tt.fheType)
			require.NotNil(t, decrypted)
			require.Equal(t, tt.value, decrypted.Uint64(), "decrypted value should match")
		})
	}
}

// TestBitCiphertextSerialization tests BitCiphertext serialization roundtrip
func TestBitCiphertextSerialization(t *testing.T) {
	err := initTFHE()
	require.NoError(t, err)

	// Encrypt a value
	value := uint64(42)
	ct := tfheTrivialEncrypt(big.NewInt(int64(value)), TypeEuint8)
	require.NotNil(t, ct)

	// Deserialize to BitCiphertext and back
	bc := deserializeBitCiphertext(ct)
	require.NotNil(t, bc)

	serialized := serializeBitCiphertext(bc)
	require.NotNil(t, serialized)

	// Deserialize again and verify
	bc2 := deserializeBitCiphertext(serialized)
	require.NotNil(t, bc2)
	require.Equal(t, bc.NumBits(), bc2.NumBits())
}

// TestFHEAdd tests homomorphic addition
func TestFHEAdd(t *testing.T) {
	err := initTFHE()
	require.NoError(t, err)

	tests := []struct {
		name     string
		a, b     uint64
		fheType  uint8
		expected uint64
	}{
		{"zero_plus_zero", 0, 0, TypeEuint8, 0},
		{"one_plus_one", 1, 1, TypeEuint8, 2},
		{"3_plus_5", 3, 5, TypeEuint8, 8},
		{"overflow_uint8", 200, 100, TypeEuint8, 44}, // 300 mod 256 = 44
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctA := tfheTrivialEncrypt(big.NewInt(int64(tt.a)), tt.fheType)
			ctB := tfheTrivialEncrypt(big.NewInt(int64(tt.b)), tt.fheType)
			require.NotNil(t, ctA)
			require.NotNil(t, ctB)

			result := tfheAdd(ctA, ctB, tt.fheType)
			require.NotNil(t, result, "addition should succeed")

			decrypted := tfheDecrypt(result, tt.fheType)
			require.Equal(t, tt.expected, decrypted.Uint64())
		})
	}
}

// TestFHESub tests homomorphic subtraction
func TestFHESub(t *testing.T) {
	err := initTFHE()
	require.NoError(t, err)

	tests := []struct {
		name     string
		a, b     uint64
		fheType  uint8
		expected uint64
	}{
		{"5_minus_3", 5, 3, TypeEuint8, 2},
		{"10_minus_0", 10, 0, TypeEuint8, 10},
		{"underflow", 3, 5, TypeEuint8, 254}, // Two's complement wrap
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctA := tfheTrivialEncrypt(big.NewInt(int64(tt.a)), tt.fheType)
			ctB := tfheTrivialEncrypt(big.NewInt(int64(tt.b)), tt.fheType)
			require.NotNil(t, ctA)
			require.NotNil(t, ctB)

			result := tfheSub(ctA, ctB, tt.fheType)
			require.NotNil(t, result, "subtraction should succeed")

			decrypted := tfheDecrypt(result, tt.fheType)
			require.Equal(t, tt.expected, decrypted.Uint64())
		})
	}
}

// TestFHEMul tests homomorphic multiplication
func TestFHEMul(t *testing.T) {
	err := initTFHE()
	require.NoError(t, err)

	tests := []struct {
		name     string
		a, b     uint64
		fheType  uint8
		expected uint64
	}{
		{"zero_times_anything", 0, 42, TypeEuint8, 0},
		{"one_times_anything", 1, 42, TypeEuint8, 42},
		{"3_times_4", 3, 4, TypeEuint8, 12},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctA := tfheTrivialEncrypt(big.NewInt(int64(tt.a)), tt.fheType)
			ctB := tfheTrivialEncrypt(big.NewInt(int64(tt.b)), tt.fheType)
			require.NotNil(t, ctA)
			require.NotNil(t, ctB)

			result := tfheMul(ctA, ctB, tt.fheType)
			require.NotNil(t, result, "multiplication should succeed")

			decrypted := tfheDecrypt(result, tt.fheType)
			require.Equal(t, tt.expected, decrypted.Uint64())
		})
	}
}

// TestFHEComparisons tests comparison operations
func TestFHEComparisons(t *testing.T) {
	err := initTFHE()
	require.NoError(t, err)

	tests := []struct {
		name     string
		op       string
		a, b     uint64
		expected bool
	}{
		{"lt_true", "lt", 3, 5, true},
		{"lt_false", "lt", 5, 3, false},
		{"lt_equal", "lt", 3, 3, false},
		{"le_true", "le", 3, 5, true},
		{"le_equal", "le", 3, 3, true},
		{"le_false", "le", 5, 3, false},
		{"gt_true", "gt", 5, 3, true},
		{"gt_false", "gt", 3, 5, false},
		{"gt_equal", "gt", 3, 3, false},
		{"ge_true", "ge", 5, 3, true},
		{"ge_equal", "ge", 3, 3, true},
		{"ge_false", "ge", 3, 5, false},
		{"eq_true", "eq", 5, 5, true},
		{"eq_false", "eq", 3, 5, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctA := tfheTrivialEncrypt(big.NewInt(int64(tt.a)), TypeEuint8)
			ctB := tfheTrivialEncrypt(big.NewInt(int64(tt.b)), TypeEuint8)
			require.NotNil(t, ctA)
			require.NotNil(t, ctB)

			var result []byte
			switch tt.op {
			case "lt":
				result = tfheLt(ctA, ctB, TypeEuint8)
			case "le":
				result = tfheLe(ctA, ctB, TypeEuint8)
			case "gt":
				result = tfheGt(ctA, ctB, TypeEuint8)
			case "ge":
				result = tfheGe(ctA, ctB, TypeEuint8)
			case "eq":
				result = tfheEq(ctA, ctB, TypeEuint8)
			}
			require.NotNil(t, result, "%s should succeed", tt.op)

			// Comparison returns encrypted bool
			decrypted := tfheDecrypt(result, TypeEbool)
			expectedVal := uint64(0)
			if tt.expected {
				expectedVal = 1
			}
			require.Equal(t, expectedVal, decrypted.Uint64())
		})
	}
}

// TestFHEBitwise tests bitwise operations
func TestFHEBitwise(t *testing.T) {
	err := initTFHE()
	require.NoError(t, err)

	tests := []struct {
		name     string
		op       string
		a, b     uint64
		expected uint64
	}{
		{"and_0x0F_0xF0", "and", 0x0F, 0xF0, 0x00},
		{"and_0xFF_0x0F", "and", 0xFF, 0x0F, 0x0F},
		{"or_0x0F_0xF0", "or", 0x0F, 0xF0, 0xFF},
		{"or_0x00_0x00", "or", 0x00, 0x00, 0x00},
		{"xor_0xFF_0xFF", "xor", 0xFF, 0xFF, 0x00},
		{"xor_0x0F_0xF0", "xor", 0x0F, 0xF0, 0xFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctA := tfheTrivialEncrypt(big.NewInt(int64(tt.a)), TypeEuint8)
			ctB := tfheTrivialEncrypt(big.NewInt(int64(tt.b)), TypeEuint8)
			require.NotNil(t, ctA)
			require.NotNil(t, ctB)

			var result []byte
			switch tt.op {
			case "and":
				result = tfheAnd(ctA, ctB, TypeEuint8)
			case "or":
				result = tfheOr(ctA, ctB, TypeEuint8)
			case "xor":
				result = tfheXor(ctA, ctB, TypeEuint8)
			}
			require.NotNil(t, result, "%s should succeed", tt.op)

			decrypted := tfheDecrypt(result, TypeEuint8)
			require.Equal(t, tt.expected, decrypted.Uint64())
		})
	}
}

// TestFHENot tests bitwise NOT
func TestFHENot(t *testing.T) {
	err := initTFHE()
	require.NoError(t, err)

	tests := []struct {
		name     string
		value    uint64
		expected uint64
	}{
		{"not_0x00", 0x00, 0xFF},
		{"not_0xFF", 0xFF, 0x00},
		{"not_0x0F", 0x0F, 0xF0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := tfheTrivialEncrypt(big.NewInt(int64(tt.value)), TypeEuint8)
			require.NotNil(t, ct)

			result := tfheNot(ct, TypeEuint8)
			require.NotNil(t, result)

			decrypted := tfheDecrypt(result, TypeEuint8)
			require.Equal(t, tt.expected, decrypted.Uint64())
		})
	}
}

// TestFHEShift tests shift operations
func TestFHEShift(t *testing.T) {
	err := initTFHE()
	require.NoError(t, err)

	tests := []struct {
		name     string
		op       string
		value    uint64
		shift    int
		expected uint64
	}{
		{"shl_1_by_1", "shl", 1, 1, 2},
		{"shl_1_by_3", "shl", 1, 3, 8},
		{"shl_overflow", "shl", 128, 1, 0}, // 128 << 1 = 256, but uint8 wraps to 0
		{"shr_8_by_1", "shr", 8, 1, 4},
		{"shr_255_by_4", "shr", 255, 4, 15},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := tfheTrivialEncrypt(big.NewInt(int64(tt.value)), TypeEuint8)
			require.NotNil(t, ct)

			var result []byte
			switch tt.op {
			case "shl":
				result = tfheShl(ct, tt.shift, TypeEuint8)
			case "shr":
				result = tfheShr(ct, tt.shift, TypeEuint8)
			}
			require.NotNil(t, result, "%s should succeed", tt.op)

			decrypted := tfheDecrypt(result, TypeEuint8)
			require.Equal(t, tt.expected, decrypted.Uint64())
		})
	}
}

// TestFHEMinMax tests min/max operations
// Note: These operations are computationally expensive (involve comparison + selection)
// so we only test a single case of each
func TestFHEMinMax(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow FHE min/max tests in short mode")
	}

	err := initTFHE()
	require.NoError(t, err)

	// Test min: min(5, 3) = 3
	t.Run("min", func(t *testing.T) {
		ctA := tfheTrivialEncrypt(big.NewInt(5), TypeEuint8)
		ctB := tfheTrivialEncrypt(big.NewInt(3), TypeEuint8)
		require.NotNil(t, ctA)
		require.NotNil(t, ctB)

		result := tfheMin(ctA, ctB, TypeEuint8)
		require.NotNil(t, result, "min should succeed")

		decrypted := tfheDecrypt(result, TypeEuint8)
		require.Equal(t, uint64(3), decrypted.Uint64())
	})

	// Test max: max(3, 5) = 5
	t.Run("max", func(t *testing.T) {
		ctA := tfheTrivialEncrypt(big.NewInt(3), TypeEuint8)
		ctB := tfheTrivialEncrypt(big.NewInt(5), TypeEuint8)
		require.NotNil(t, ctA)
		require.NotNil(t, ctB)

		result := tfheMax(ctA, ctB, TypeEuint8)
		require.NotNil(t, result, "max should succeed")

		decrypted := tfheDecrypt(result, TypeEuint8)
		require.Equal(t, uint64(5), decrypted.Uint64())
	})
}

// TestFHEScalarAdd tests scalar addition
func TestFHEScalarAdd(t *testing.T) {
	err := initTFHE()
	require.NoError(t, err)

	tests := []struct {
		name     string
		value    uint64
		scalar   uint64
		expected uint64
	}{
		{"add_0", 5, 0, 5},
		{"add_1", 5, 1, 6},
		{"add_10", 5, 10, 15},
		{"overflow", 250, 10, 4}, // 260 mod 256 = 4
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := tfheTrivialEncrypt(big.NewInt(int64(tt.value)), TypeEuint8)
			require.NotNil(t, ct)

			result := tfheScalarAdd(ct, tt.scalar, TypeEuint8)
			require.NotNil(t, result)

			decrypted := tfheDecrypt(result, TypeEuint8)
			require.Equal(t, tt.expected, decrypted.Uint64())
		})
	}
}

// TestFHEScalarMul tests scalar multiplication
func TestFHEScalarMul(t *testing.T) {
	err := initTFHE()
	require.NoError(t, err)

	tests := []struct {
		name     string
		value    uint64
		scalar   uint64
		expected uint64
	}{
		{"mul_0", 5, 0, 0},
		{"mul_1", 5, 1, 5},
		{"mul_2", 5, 2, 10},
		{"mul_10", 5, 10, 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := tfheTrivialEncrypt(big.NewInt(int64(tt.value)), TypeEuint8)
			require.NotNil(t, ct)

			result := tfheScalarMul(ct, tt.scalar, TypeEuint8)
			require.NotNil(t, result)

			decrypted := tfheDecrypt(result, TypeEuint8)
			require.Equal(t, tt.expected, decrypted.Uint64())
		})
	}
}

// TestFHECast tests type casting
func TestFHECast(t *testing.T) {
	err := initTFHE()
	require.NoError(t, err)

	// Cast uint8 to uint16
	ct8 := tfheTrivialEncrypt(big.NewInt(42), TypeEuint8)
	require.NotNil(t, ct8)

	ct16 := tfheCast(ct8, TypeEuint8, TypeEuint16)
	require.NotNil(t, ct16)

	decrypted := tfheDecrypt(ct16, TypeEuint16)
	require.Equal(t, uint64(42), decrypted.Uint64())
}

// TestFHERandom tests random number generation
func TestFHERandom(t *testing.T) {
	err := initTFHE()
	require.NoError(t, err)

	// Generate encrypted random
	result := tfheRandom(TypeEuint8, 12345)
	require.NotNil(t, result)

	// Decrypt to verify it produces a value
	decrypted := tfheDecrypt(result, TypeEuint8)
	require.NotNil(t, decrypted)
	// Value should be in range [0, 255] for uint8
	require.True(t, decrypted.Uint64() <= 255)
}

// TestGetNetworkPublicKey tests public key retrieval
func TestGetNetworkPublicKey(t *testing.T) {
	err := initTFHE()
	require.NoError(t, err)

	pk := tfheGetNetworkPublicKey()
	require.NotNil(t, pk)
	require.Greater(t, len(pk), 0)
}

// TestCiphertextStore tests the ciphertext storage mechanism
func TestCiphertextStore(t *testing.T) {
	err := initTFHE()
	require.NoError(t, err)

	// Create ciphertext
	ct := tfheTrivialEncrypt(big.NewInt(42), TypeEuint8)
	require.NotNil(t, ct)

	// Store it
	handle := storeCiphertext(ct, TypeEuint8)
	require.NotEqual(t, common.Hash{}, handle)

	// Retrieve it
	retrieved, ctType, ok := getCiphertext(handle)
	require.True(t, ok)
	require.Equal(t, TypeEuint8, ctType)
	require.Equal(t, ct, retrieved)
}

// TestPerformFHEOperation tests the high-level operation dispatcher
func TestPerformFHEOperation(t *testing.T) {
	err := initTFHE()
	require.NoError(t, err)

	caller := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Store two ciphertexts
	ct1 := tfheTrivialEncrypt(big.NewInt(10), TypeEuint8)
	ct2 := tfheTrivialEncrypt(big.NewInt(3), TypeEuint8)

	handle1 := storeCiphertext(ct1, TypeEuint8)
	handle2 := storeCiphertext(ct2, TypeEuint8)

	// Test add operation
	resultHandle := performFHEOperation("add", handle1, handle2, caller)
	require.NotEqual(t, common.Hash{}, resultHandle)

	resultCt, _, ok := getCiphertext(resultHandle)
	require.True(t, ok)

	decrypted := tfheDecrypt(resultCt, TypeEuint8)
	require.Equal(t, uint64(13), decrypted.Uint64())
}

// TestEncryptValue tests the encryptValue helper
func TestEncryptValue(t *testing.T) {
	err := initTFHE()
	require.NoError(t, err)

	caller := common.HexToAddress("0x1234567890123456789012345678901234567890")

	handle := encryptValue(42, TypeEuint8, caller)
	require.NotEqual(t, common.Hash{}, handle)

	ct, ctType, ok := getCiphertext(handle)
	require.True(t, ok)
	require.Equal(t, TypeEuint8, ctType)

	decrypted := tfheDecrypt(ct, ctType)
	require.Equal(t, uint64(42), decrypted.Uint64())
}

// TestEncryptAddress tests address encryption
func TestEncryptAddress(t *testing.T) {
	err := initTFHE()
	require.NoError(t, err)

	caller := common.HexToAddress("0x1234567890123456789012345678901234567890")
	// Use a small address that fits in uint64 for testing
	// Full 160-bit addresses require proper radix integer encryption
	addr := common.HexToAddress("0x0000000000000000000000000000000012345678")

	handle := encryptAddress(addr, caller)
	require.NotEqual(t, common.Hash{}, handle)

	ct, ctType, ok := getCiphertext(handle)
	require.True(t, ok)
	require.Equal(t, TypeEaddress, ctType)

	// Decrypt and verify the lower 64 bits
	decrypted := tfheDecrypt(ct, ctType)
	require.NotNil(t, decrypted)
	// Verify the address value is preserved (lower 64 bits)
	require.Equal(t, uint64(0x12345678), decrypted.Uint64())
}

// TestFHEVerify tests ciphertext verification
func TestFHEVerify(t *testing.T) {
	err := initTFHE()
	require.NoError(t, err)

	// Create valid ciphertext
	ct := tfheTrivialEncrypt(big.NewInt(42), TypeEuint8)
	require.NotNil(t, ct)

	// Verify should succeed for valid ciphertext
	valid := tfheVerify(ct, TypeEuint8)
	require.True(t, valid)

	// Verify should fail for garbage data
	garbage := []byte{0x00, 0x01, 0x02, 0x03}
	invalid := tfheVerify(garbage, TypeEuint8)
	require.False(t, invalid)
}
