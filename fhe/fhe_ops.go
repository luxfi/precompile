// Copyright (C) 2019-2024, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// FHE operations for the EVM gateway precompile, backed by github.com/luxfi/fhe.
//
// Confidentiality model (LP-134, threshold FHE):
//
//	The precompile holds ONLY PUBLIC key material — the network encryption
//	public key and the bootstrap/evaluation key — both published by the
//	F-Chain (ThresholdVM) DKG. The FHE secret key is Shamir-shared across the
//	F-Chain validator set and is NEVER reconstructed by any single party, so
//	the precompile CANNOT (and MUST NOT) decrypt locally. Decryption is a
//	threshold ceremony on the F-Chain; see contract.go handleDecrypt.
//
//	This file therefore contains NO secret key, NO decryptor, and NO in-source
//	keygen seed. Key material is installed via SetNetworkKeys (from the F-Chain
//	DKG output, loaded by Configure) and is identical on every validator. Until
//	keys are installed, every key-dependent op fails closed (returns nil) rather
//	than fabricating a key — there is no insecure default.
package fhe

import (
	"encoding/binary"
	"math/big"
	"sync"

	"github.com/luxfi/fhe"
	"github.com/luxfi/precompile/contract"
)

var (
	// params is the public FHE parameter set. Deterministic and key-independent,
	// so it is safe to derive in-process; it must match the params the F-Chain
	// DKG used to generate the installed keys.
	params     fhe.Parameters
	paramsOnce sync.Once
	paramsErr  error

	// Network PUBLIC key material, installed via SetNetworkKeys from the F-Chain
	// DKG. There is deliberately NO secret key and NO decryptor here.
	keysMu       sync.RWMutex
	publicKey    *fhe.PublicKey
	bootstrapKey *fhe.BootstrapKey
	encryptor    *fhe.BitwisePublicEncryptor // public-key encryption only
	evaluator    *fhe.BitwiseEvaluator       // homomorphic compute (bootstrap key only)
)

// ensureParams initializes the public FHE parameter set exactly once.
func ensureParams() (fhe.Parameters, error) {
	paramsOnce.Do(func() {
		params, paramsErr = fhe.NewParametersFromLiteral(fhe.PN10QP27)
	})
	return params, paramsErr
}

// SetNetworkKeys installs the F-Chain DKG-published PUBLIC key material:
// the encryption public key (pk) and the bootstrap/evaluation key (bsk).
//
// The corresponding FHE secret key is threshold-shared on the F-Chain and is
// NEVER held by the precompile, so installing these keys grants the ability to
// encrypt and to homomorphically compute, but NOT to decrypt. Decryption stays
// a threshold ceremony.
//
// Determinism: every validator installs the identical published bundle, so the
// derived encryptor/evaluator behave identically across the network. Passing a
// nil key clears the corresponding capability (fail closed).
func SetNetworkKeys(pk *fhe.PublicKey, bsk *fhe.BootstrapKey) error {
	p, err := ensureParams()
	if err != nil {
		return err
	}

	keysMu.Lock()
	defer keysMu.Unlock()

	publicKey = pk
	bootstrapKey = bsk

	if pk != nil {
		encryptor = fhe.NewBitwisePublicEncryptor(p, pk)
	} else {
		encryptor = nil
	}
	if bsk != nil {
		// The evaluator needs only the bootstrap key; its sk parameter is
		// deprecated and ignored by luxfi/fhe. Pass nil — the precompile has
		// no secret key to give.
		evaluator = fhe.NewBitwiseEvaluator(p, bsk, nil)
	} else {
		evaluator = nil
	}
	return nil
}

// HasNetworkKeys reports whether public key material is installed. Used by the
// VM/operator to detect an inert (fail-closed) FHE precompile.
func HasNetworkKeys() bool {
	keysMu.RLock()
	defer keysMu.RUnlock()
	return encryptor != nil && evaluator != nil
}

func getEvaluator() *fhe.BitwiseEvaluator {
	keysMu.RLock()
	defer keysMu.RUnlock()
	return evaluator
}

func getEncryptor() *fhe.BitwisePublicEncryptor {
	keysMu.RLock()
	defer keysMu.RUnlock()
	return encryptor
}

func getPublicKey() *fhe.PublicKey {
	keysMu.RLock()
	defer keysMu.RUnlock()
	return publicKey
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

// MaxCiphertextBits is the widest supported ciphertext. euint256 is the largest FHE type
// this precompile offers, so nothing legitimate carries more bits than this.
const MaxCiphertextBits = 256

// wellFramed reports whether data is a complete, self-consistent BitCiphertext encoding:
//
//	[4]numBits | [1]fheType | numBits x ( [4]bitLen | bitLen bytes )
//
// It must run before the bytes reach UnmarshalBinary, which reads each declared length and
// allocates for it BEFORE checking that the input actually contains that many bytes:
// `make([]*Ciphertext, numBits)` then `make([]byte, bitLen)`. Both counts are little-endian
// uint32 read straight off the wire, so five bytes of calldata ask for a 34 GB slice and
// nine ask for 4 GB — a remote memory-exhaustion primitive behind a flat 50,000 gas fee.
// Every declared length is checked against the bytes actually present, in int arithmetic,
// before any of them is used to allocate.
func wellFramed(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	numBits := int(binary.LittleEndian.Uint32(data[:4]))
	if numBits < 0 || numBits > MaxCiphertextBits {
		return false
	}
	off := 5 // numBits + fheType
	for range numBits {
		if off+4 > len(data) {
			return false
		}
		bitLen := int(binary.LittleEndian.Uint32(data[off : off+4]))
		off += 4
		if bitLen < 0 || off+bitLen > len(data) {
			return false
		}
		off += bitLen
	}
	return true
}

// boolBit extracts the single encrypted bit out of a serialized boolean BitCiphertext.
//
// Every TypeEbool value this precompile stores is a BitCiphertext of width one, but the
// evaluator's Select takes a bare *Ciphertext, and the pinned luxfi/fhe exposes no accessor
// for the bit inside (the field is unexported). The wire format does expose it: after the
// 4-byte width and the 1-byte type, a one-bit value carries exactly one length-prefixed
// blob, and that blob IS the inner Ciphertext's own encoding. Returns nil for anything that
// is not a well-framed single-bit value.
func boolBit(data []byte) []byte {
	if !wellFramed(data) || binary.LittleEndian.Uint32(data[:4]) != 1 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(data[5:9]))
	return data[9 : 9+n]
}

func deserializeBitCiphertext(data []byte) *fhe.BitCiphertext {
	if !wellFramed(data) {
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
//
// Every compute op runs under the PUBLIC bootstrap key only; no secret key is
// involved and no plaintext is ever exposed. When no bootstrap key is installed
// the op fails closed (returns nil).

func tfheAdd(lhs, rhs []byte, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	result, err := ev.Add(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheSub(lhs, rhs []byte, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	result, err := ev.Sub(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheMul(lhs, rhs []byte, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	// TFHE multiplication using schoolbook algorithm.
	// This is O(n^2) in bootstrapping operations for n-bit integers.
	result, err := ev.Mul(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheDiv(lhs, rhs []byte, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	// TFHE division using binary long division
	result, err := ev.Div(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheRem(lhs, rhs []byte, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	// TFHE remainder operation
	result, err := ev.Rem(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

// FHE Operations - Comparison
// These return encrypted boolean (single encrypted bit)

func tfheLt(lhs, rhs []byte, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	result, err := ev.Lt(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	// Wrap single bit as FheBool BitCiphertext for consistent serialization
	boolCt := fhe.WrapBoolCiphertext(result)
	return serializeBitCiphertext(boolCt)
}

func tfheLe(lhs, rhs []byte, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	result, err := ev.Le(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	boolCt := fhe.WrapBoolCiphertext(result)
	return serializeBitCiphertext(boolCt)
}

func tfheGt(lhs, rhs []byte, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	result, err := ev.Gt(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	boolCt := fhe.WrapBoolCiphertext(result)
	return serializeBitCiphertext(boolCt)
}

func tfheGe(lhs, rhs []byte, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	result, err := ev.Ge(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	boolCt := fhe.WrapBoolCiphertext(result)
	return serializeBitCiphertext(boolCt)
}

func tfheEq(lhs, rhs []byte, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	result, err := ev.Eq(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	boolCt := fhe.WrapBoolCiphertext(result)
	return serializeBitCiphertext(boolCt)
}

func tfheNe(lhs, rhs []byte, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	// NE(a, b) = (a < b) OR (a > b)
	ltResult, err := ev.Lt(ctLhs, ctRhs)
	if err != nil {
		return nil
	}
	gtResult, err := ev.Gt(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	// Wrap single bits in BitCiphertext for OR operation
	ltBits := fhe.WrapBoolCiphertext(ltResult)
	gtBits := fhe.WrapBoolCiphertext(gtResult)

	neResult, err := ev.Or(ltBits, gtBits)
	if err != nil {
		return nil
	}

	// Return as BitCiphertext (1-bit)
	return serializeBitCiphertext(neResult)
}

// FHE Operations - Bitwise

func tfheAnd(lhs, rhs []byte, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	result, err := ev.And(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheOr(lhs, rhs []byte, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	result, err := ev.Or(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheXor(lhs, rhs []byte, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	result, err := ev.Xor(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheNot(ct []byte, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	// Not returns *BitCiphertext directly (no error)
	result := ev.Not(ctIn)
	return serializeBitCiphertext(result)
}

func tfheNeg(ct []byte, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	// Negation: negate the value (two's complement)
	result, err := ev.Neg(ctIn)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

// FHE Operations - Selection and Cast

func tfheSelect(control, ifTrue, ifFalse []byte, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	// The control is a boolean HANDLE, and every TypeEbool value this precompile stores is
	// a BitCiphertext: comparisons wrap their single-bit result with WrapBoolCiphertext
	// before serializing, and asEbool encrypts through the same path. Decoding the control
	// as a bare Ciphertext therefore matched nothing the precompile is able to produce, so
	// select failed for every input it was ever given — silently, because a failed
	// operation used to be returned as the zero handle with a nil error.
	ctControl := deserializeCiphertext(boolBit(control))
	ctTrue := deserializeBitCiphertext(ifTrue)
	ctFalse := deserializeBitCiphertext(ifFalse)
	if ctControl == nil || ctTrue == nil || ctFalse == nil {
		return nil
	}

	// Select: if control then ifTrue else ifFalse
	result, err := ev.Select(ctControl, ctTrue, ctFalse)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheCast(ct []byte, fromType, toType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	targetType := fheTypeToTFHEType(toType)
	// CastTo returns *BitCiphertext directly (no error)
	result := ev.CastTo(ctIn, targetType)

	return serializeBitCiphertext(result)
}

// FHE Operations - Min/Max

func tfheMin(lhs, rhs []byte, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	// Min = (lhs < rhs) ? lhs : rhs
	ltResult, err := ev.Lt(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	result, err := ev.Select(ltResult, ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheMax(lhs, rhs []byte, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctLhs := deserializeBitCiphertext(lhs)
	ctRhs := deserializeBitCiphertext(rhs)
	if ctLhs == nil || ctRhs == nil {
		return nil
	}

	// Max = (lhs > rhs) ? lhs : rhs
	gtResult, err := ev.Gt(ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	result, err := ev.Select(gtResult, ctLhs, ctRhs)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

// FHE Operations - Encryption / Input handling
//
// Note: there is intentionally NO local decrypt and NO local seal here. Both
// require the secret key, which the precompile does not hold; they are handled
// as ACL-gated, fail-closed threshold requests in contract.go.

func tfheVerify(ct []byte, fheType uint8) bool {
	// Basic validation - check ciphertext can be deserialized. No key needed:
	// input ciphertexts are encrypted off-chain under the network public key.
	return deserializeBitCiphertext(ct) != nil
}

// tfheTrivialEncrypt encrypts a PUBLIC plaintext (an on-chain calldata value)
// under the network PUBLIC key. The plaintext is already public on-chain, so no
// confidentiality is created or lost here — this only lifts a known value into
// the ciphertext domain so it can be combined with confidential ciphertexts.
// Fails closed (nil) when no public key is installed.
//
// A plaintext past 64 bits is refused rather than truncated, because the only
// loader the encryptor exposes is EncryptUint64 and its bit loop reads
// `value >> i` off a uint64 — for i above 63 that is zero, in Go, always. The
// container is genuinely wider (a euint256 really is 256 bits, and tfheRandom
// fills every one of them), so the missing bits are not rounded away, they are
// encrypted AS ZERO and are indistinguishable afterwards from a value that was
// zero to begin with. Measured before this refusal existed:
//
//	asEuint256(2^200) decrypted to 0, in a 256-bit container.
//	asEaddress on two addresses sharing their last 8 bytes produced the SAME
//	plaintext, so a homomorphic equality on encrypted addresses answered true
//	for two different accounts.
//
// Casting to a NARROWER type still truncates, exactly as Solidity's uintN(x)
// does and exactly as the asEuint4/8/16/32 handlers already do by masking; the
// callers below 64 bits mask before they arrive here, so this refuses nothing
// they send. What it refuses is the case where the declared width is WIDER than
// the loader, which is not a cast at all — it is a value the encryptor cannot
// carry. Widening it needs an EncryptBig on BitwisePublicEncryptor upstream;
// BitCiphertext's fields are unexported and it has no constructor from bits, so
// there is nothing to compose here in the meantime.
func tfheTrivialEncrypt(plaintext *big.Int, toType uint8) []byte {
	enc := getEncryptor()
	if enc == nil {
		return nil
	}
	value, err := contract.Unsigned(plaintext, 64)
	if err != nil {
		return nil
	}

	targetType := fheTypeToTFHEType(toType)
	ct, err := enc.EncryptUint64(value, targetType)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(ct)
}

func tfheRandom(fheType uint8, seed uint64) []byte {
	pk := getPublicKey()
	if pk == nil {
		return nil
	}

	p, err := ensureParams()
	if err != nil {
		return nil
	}

	targetType := fheTypeToTFHEType(fheType)

	// Deterministic seed bytes → public-key RNG. No secret key involved.
	seedBytes := make([]byte, 32)
	binary.BigEndian.PutUint64(seedBytes[24:], seed)

	rng := fhe.NewFheRNGPublic(p, pk, seedBytes)
	ct, err := rng.RandomUint(targetType)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(ct)
}

func tfheGetNetworkPublicKey() []byte {
	pk := getPublicKey()
	if pk == nil {
		return nil
	}

	data, err := pk.MarshalBinary()
	if err != nil {
		// Returning random bytes here would be a consensus violation:
		// each node would return different data for the same call.
		return nil
	}

	return data
}

// === Shift Operations ===

func tfheShl(ct []byte, shift int, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	// Shl returns *BitCiphertext directly
	result := ev.Shl(ctIn, shift)
	return serializeBitCiphertext(result)
}

func tfheShr(ct []byte, shift int, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	// Shr returns *BitCiphertext directly
	result := ev.Shr(ctIn, shift)
	return serializeBitCiphertext(result)
}

func tfheRotl(ct []byte, shift int, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	// Rotate left: combine shl and shr
	numBits := ctIn.NumBits()
	shift = shift % numBits

	leftPart := ev.Shl(ctIn, shift)
	rightPart := ev.Shr(ctIn, numBits-shift)

	result, err := ev.Or(leftPart, rightPart)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheRotr(ct []byte, shift int, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	// Rotate right: combine shr and shl
	numBits := ctIn.NumBits()
	shift = shift % numBits

	rightPart := ev.Shr(ctIn, shift)
	leftPart := ev.Shl(ctIn, numBits-shift)

	result, err := ev.Or(leftPart, rightPart)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

// === Scalar Operations ===

func tfheScalarAdd(ct []byte, scalar uint64, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	result, err := ev.ScalarAdd(ctIn, scalar)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheScalarSub(ct []byte, scalar uint64, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
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

	result, err := ev.ScalarAdd(ctIn, negScalar)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheScalarMul(ct []byte, scalar uint64, fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	ctIn := deserializeBitCiphertext(ct)
	if ctIn == nil {
		return nil
	}

	result, err := ev.ScalarMul(ctIn, scalar)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheScalarDiv(ct []byte, scalar uint64, fheType uint8) []byte {
	ev := getEvaluator()
	enc := getEncryptor()
	if ev == nil || enc == nil {
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

	// For scalar division, encrypt the scalar (a public value) under the
	// network public key and use encrypted division.
	targetType := fheTypeToTFHEType(fheType)
	ctScalar, err := enc.EncryptUint64(scalar, targetType)
	if err != nil {
		return nil
	}

	result, err := ev.Div(ctIn, ctScalar)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

func tfheScalarRem(ct []byte, scalar uint64, fheType uint8) []byte {
	ev := getEvaluator()
	enc := getEncryptor()
	if ev == nil || enc == nil {
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

	// For scalar remainder, encrypt the scalar (a public value) under the
	// network public key and use encrypted rem.
	targetType := fheTypeToTFHEType(fheType)
	ctScalar, err := enc.EncryptUint64(scalar, targetType)
	if err != nil {
		return nil
	}

	result, err := ev.Rem(ctIn, ctScalar)
	if err != nil {
		return nil
	}

	return serializeBitCiphertext(result)
}

// tfheMaxValue returns an encrypted max value (all bits set)
func tfheMaxValue(fheType uint8) []byte {
	ev := getEvaluator()
	if ev == nil {
		return nil
	}

	targetType := fheTypeToTFHEType(fheType)
	maxVal := ev.MaxValue(targetType)
	return serializeBitCiphertext(maxVal)
}

// GetBackend returns the current FHE backend being used
func GetBackend() string {
	return "CPU (pure Go)"
}
