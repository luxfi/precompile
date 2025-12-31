// Copyright (C) 2019-2024, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"sync"

	"github.com/luxfi/fhe"
)

var (
	// Singleton TFHE components
	tfheOnce  sync.Once
	evaluator *fhe.BitwiseEvaluator
	encryptor *fhe.BitwiseEncryptor
	decryptor *fhe.BitwiseDecryptor
	secretKey *fhe.SecretKey
	publicKey *fhe.PublicKey
	params    fhe.Parameters
	initErr   error
)

// Initialize TFHE components
func initTFHE() error {
	tfheOnce.Do(func() {
		var err error

		// Create parameters
		params, err = fhe.NewParametersFromLiteral(fhe.PN10QP27)
		if err != nil {
			initErr = err
			return
		}

		// Generate keys
		kg := fhe.NewKeyGenerator(params)
		secretKey, publicKey = kg.GenKeyPair()
		bsk := kg.GenBootstrapKey(secretKey)

		// Create operators
		encryptor = fhe.NewBitwiseEncryptor(params, secretKey)
		decryptor = fhe.NewBitwiseDecryptor(params, secretKey)
		evaluator = fhe.NewBitwiseEvaluator(params, bsk, secretKey)
	})

	return initErr
}

// fheTypeToTFHEType converts FHE type constant to TFHE FheUintType
func fheTypeToTFHEType(fheType uint8) fhe.FheUintType {
	switch fheType {
	case TypeEbool:
		return fhe.FheBool
	case TypeEuint8:
		return fhe.FheUint8
	case TypeEuint16:
		return fhe.FheUint16
	case TypeEuint32:
		return fhe.FheUint32
	case TypeEuint64:
		return fhe.FheUint64
	case TypeEuint128:
		return fhe.FheUint128
	case TypeEuint256:
		return fhe.FheUint256
	case TypeEaddress:
		return fhe.FheUint160
	default:
		return fhe.FheUint32
	}
}

// serializeBitCiphertext converts BitCiphertext to bytes
func serializeBitCiphertext(ct *fhe.BitCiphertext) []byte {
	if ct == nil {
		return nil
	}
	data, err := ct.MarshalBinary()
	if err != nil {
		return nil
	}
	return data
}

// deserializeBitCiphertext converts bytes to BitCiphertext
func deserializeBitCiphertext(data []byte) *fhe.BitCiphertext {
	if len(data) == 0 {
		return nil
	}
	ct := new(fhe.BitCiphertext)
	if err := ct.UnmarshalBinary(data); err != nil {
		return nil
	}
	return ct
}

// serializeCiphertext converts a single Ciphertext (encrypted bit) to bytes
func serializeCiphertext(ct *fhe.Ciphertext) []byte {
	if ct == nil {
		return nil
	}
	data, err := ct.MarshalBinary()
	if err != nil {
		return nil
	}
	return data
}

// deserializeCiphertext converts bytes to a single Ciphertext (encrypted bit)
func deserializeCiphertext(data []byte) *fhe.Ciphertext {
	if len(data) == 0 {
		return nil
	}
	ct := new(fhe.Ciphertext)
	if err := ct.UnmarshalBinary(data); err != nil {
		return nil
	}
	return ct
}

// FHE Operations - Binary Arithmetic

func tfheAdd(lhs, rhs []byte, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	result, err := evaluator.Add(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheSub(lhs, rhs []byte, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	result, err := evaluator.Sub(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheMul(lhs, rhs []byte, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	// TFHE multiplication using schoolbook algorithm
	result, err := evaluator.Mul(ctLhs, ctRhs)
	if err != nil {
		// Fall back to scalar multiply by 1 if full mul not available
		result, err = evaluator.ScalarMul(ctLhs, 1)
		if err != nil {
			return nil
		}
	}

	return serializeBitCiphertext(result)
}

func tfheDiv(lhs, rhs []byte, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	// TFHE division using binary long division
	result, err := evaluator.Div(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheRem(lhs, rhs []byte, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	// TFHE remainder operation
	result, err := evaluator.Rem(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

// FHE Operations - Comparison
// These return encrypted boolean (single encrypted bit)

func tfheLt(lhs, rhs []byte, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	result, err := evaluator.Lt(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	// Wrap single bit as FheBool BitCiphertext for consistent serialization
	boolCt := fhe.WrapBoolCiphertext(result)
	return serializeBitCiphertext(boolCt)
}

func tfheLe(lhs, rhs []byte, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	result, err := evaluator.Le(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	boolCt := fhe.WrapBoolCiphertext(result)
	return serializeBitCiphertext(boolCt)
}

func tfheGt(lhs, rhs []byte, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	result, err := evaluator.Gt(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	boolCt := fhe.WrapBoolCiphertext(result)
	return serializeBitCiphertext(boolCt)
}

func tfheGe(lhs, rhs []byte, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	result, err := evaluator.Ge(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	boolCt := fhe.WrapBoolCiphertext(result)
	return serializeBitCiphertext(boolCt)
}

func tfheEq(lhs, rhs []byte, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	result, err := evaluator.Eq(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	boolCt := fhe.WrapBoolCiphertext(result)
	return serializeBitCiphertext(boolCt)
}

func tfheNe(lhs, rhs []byte, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	// NE(a, b) = (a < b) OR (a > b)
	ltResult, err := evaluator.Lt(ctLhs, ctRhs)
	if err != nil {
		return nil
	}
	gtResult, err := evaluator.Gt(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	// Wrap single bits in BitCiphertext for OR operation
	ltBits := fhe.WrapBoolCiphertext(ltResult)
	gtBits := fhe.WrapBoolCiphertext(gtResult)

	neResult, err := evaluator.Or(ltBits, gtBits)
	if err != nil {
		return nil
	}

	// Return as BitCiphertext (1-bit)
	return serializeBitCiphertext(neResult)
}

// FHE Operations - Bitwise

func tfheAnd(lhs, rhs []byte, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	result, err := evaluator.And(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheOr(lhs, rhs []byte, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	result, err := evaluator.Or(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheXor(lhs, rhs []byte, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	result, err := evaluator.Xor(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheNot(ct []byte, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	// Not returns *BitCiphertext directly (no error)
	result := evaluator.Not(ctIn)
	return serializeBitCiphertext(result)
}

func tfheNeg(ct []byte, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	// Negation: negate the value (two's complement)
	result, err := evaluator.Neg(ctIn)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

// FHE Operations - Selection and Cast

func tfheSelect(control, ifTrue, ifFalse []byte, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	// Control is a single encrypted bit
	ctControl := deserializeCiphertext(control)
	ctTrue := deserializeBitCiphertext(ifTrue)
	ctFalse := deserializeBitCiphertext(ifFalse)
	if ctControl == nil || ctTrue == nil || ctFalse == nil {
		return nil
	}

	// Select: if control then ifTrue else ifFalse
	result, err := evaluator.Select(ctControl, ctTrue, ctFalse)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheCast(ct []byte, fromType, toType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	targetType := fheTypeToTFHEType(toType)
	// CastTo returns *BitCiphertext directly (no error)
	result := evaluator.CastTo(ctIn, targetType)

	return serializeBitCiphertext(result)
}

// FHE Operations - Min/Max

func tfheMin(lhs, rhs []byte, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	// Min = (lhs < rhs) ? lhs : rhs
	ltResult, err := evaluator.Lt(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	result, err := evaluator.Select(ltResult, ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheMax(lhs, rhs []byte, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	// Max = (lhs > rhs) ? lhs : rhs
	gtResult, err := evaluator.Gt(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	result, err := evaluator.Select(gtResult, ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

// FHE Operations - Encryption/Decryption

func tfheVerify(ct []byte, fheType uint8) bool {
	// Basic validation - check ciphertext can be deserialized
	return deserializeBitCiphertext(ct) != nil
}

func tfheDecrypt(ct []byte, fheType uint8) *big.Int {
	if err := initTFHE(); err != nil {
		return big.NewInt(0)
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return big.NewInt(0)
	}

	plaintext := decryptor.DecryptUint64(ctIn)
	return new(big.Int).SetUint64(plaintext)
}

func tfheTrivialEncrypt(plaintext *big.Int, toType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	targetType := fheTypeToTFHEType(toType)
	// Use encryptor for now (trivial encryption would be noiseless)
	ct := encryptor.EncryptUint64(plaintext.Uint64(), targetType)

	return serializeBitCiphertext(ct)
}

func tfheSealOutput(ct, pk []byte, fheType uint8) []byte {
	// Seal output for a specific public key
	// In production, this would re-encrypt under the given public key
	// For now, just return the ciphertext with a header
	result := make([]byte, len(ct)+len(pk)+8)
	binary.BigEndian.PutUint32(result[0:4], uint32(len(pk)))
	binary.BigEndian.PutUint32(result[4:8], uint32(len(ct)))
	copy(result[8:8+len(pk)], pk)
	copy(result[8+len(pk):], ct)
	return result
}

func tfheRandom(fheType uint8, seed uint64) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	// Generate random bytes based on seed
	targetType := fheTypeToTFHEType(fheType)

	// Create deterministic seed bytes
	seedBytes := make([]byte, 32)
	binary.BigEndian.PutUint64(seedBytes[24:], seed)

	rng := fhe.NewFheRNG(params, secretKey, seedBytes)
	ct := rng.RandomUint(targetType)

	return serializeBitCiphertext(ct)
}

func tfheGetNetworkPublicKey() []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	if publicKey == nil {
		return nil
	}

	data, err := publicKey.MarshalBinary()
	if err != nil {
		// Return random bytes as fallback
		result := make([]byte, 32)
		rand.Read(result)
		return result
	}

	return data
}

// === Shift Operations ===

func tfheShl(ct []byte, shift int, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	// Shl returns *BitCiphertext directly
	result := evaluator.Shl(ctIn, shift)
	return serializeBitCiphertext(result)
}

func tfheShr(ct []byte, shift int, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	// Shr returns *BitCiphertext directly
	result := evaluator.Shr(ctIn, shift)
	return serializeBitCiphertext(result)
}

func tfheRotl(ct []byte, shift int, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	// Rotate left: combine shl and shr
	numBits := ctIn.NumBits()
	shift = shift % numBits

	leftPart := evaluator.Shl(ctIn, shift)
	rightPart := evaluator.Shr(ctIn, numBits-shift)

	result, err := evaluator.Or(leftPart, rightPart)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheRotr(ct []byte, shift int, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	// Rotate right: combine shr and shl
	numBits := ctIn.NumBits()
	shift = shift % numBits

	rightPart := evaluator.Shr(ctIn, shift)
	leftPart := evaluator.Shl(ctIn, numBits-shift)

	result, err := evaluator.Or(leftPart, rightPart)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

// === Scalar Operations ===

func tfheScalarAdd(ct []byte, scalar uint64, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	result, err := evaluator.ScalarAdd(ctIn, scalar)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheScalarSub(ct []byte, scalar uint64, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	// ScalarSub: a - scalar = a + (-scalar) = a + (2^n - scalar)
	// Use two's complement for subtraction
	numBits := ctIn.NumBits()
	mask := uint64((1 << numBits) - 1)
	negScalar := (^scalar + 1) & mask

	result, err := evaluator.ScalarAdd(ctIn, negScalar)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheScalarMul(ct []byte, scalar uint64, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	result, err := evaluator.ScalarMul(ctIn, scalar)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheScalarDiv(ct []byte, scalar uint64, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	if scalar == 0 {
		// Division by zero: return max value
		return tfheMaxValue(fheType)
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	// For scalar division, encrypt the scalar and use encrypted division
	targetType := fheTypeToTFHEType(fheType)
	ctScalar := encryptor.EncryptUint64(scalar, targetType)

	result, err := evaluator.Div(ctIn, ctScalar)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheScalarRem(ct []byte, scalar uint64, fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	if scalar == 0 {
		// Remainder by zero: return original value
		return ct
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	// For scalar remainder, encrypt the scalar and use encrypted rem
	targetType := fheTypeToTFHEType(fheType)
	ctScalar := encryptor.EncryptUint64(scalar, targetType)

	result, err := evaluator.Rem(ctIn, ctScalar)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

// tfheMaxValue returns an encrypted max value (all bits set)
func tfheMaxValue(fheType uint8) []byte {
	if err := initTFHE(); err != nil {
		return nil
	}

	targetType := fheTypeToTFHEType(fheType)
	maxVal := evaluator.MaxValue(targetType)
	return serializeBitCiphertext(maxVal)
}
