// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import (
	"errors"
	"fmt"
	"math"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	// ContractMLDSAVerifyAddress is the address of the ML-DSA verify precompile
	// (LP-3500/LP-4200 unified PQCrypto block: 0x012202).
	// 0x0200... is FHE-precompile space; PQ verify lives in 0x012200-0x0122FF.
	ContractMLDSAVerifyAddress = common.HexToAddress("0x0000000000000000000000000000000000012202")

	// Singleton instance
	MLDSAVerifyPrecompile = &mldsaVerifyPrecompile{}

	_ contract.StatefulPrecompiledContract = &mldsaVerifyPrecompile{}

	ErrInvalidInputLength = contract.ErrInvalidInput
	ErrInvalidMode        = errors.New("invalid ML-DSA mode")
	ErrUnsupportedMode    = errors.New("unsupported ML-DSA mode")

	// precompileCtx is the domain-separation context for EVM precompile signature
	// verification. FIPS 204 Section 5.3: prevents cross-protocol replay between
	// EVM precompile verify and other ML-DSA uses (UTXO, Warp, MPC).
	precompileCtx = []byte("lux-evm-precompile-mldsa-v1")
)

// ML-DSA modes supported by this precompile
const (
	ModeMLDSA44 uint8 = 0x44 // ML-DSA-44 (128-bit security, NIST Level 2)
	ModeMLDSA65 uint8 = 0x65 // ML-DSA-65 (192-bit security, NIST Level 3)
	ModeMLDSA87 uint8 = 0x87 // ML-DSA-87 (256-bit security, NIST Level 5)
)

// Size constants for each mode
const (
	// ML-DSA-44
	MLDSA44PublicKeySize = 1312
	MLDSA44SignatureSize = 2420

	// ML-DSA-65
	MLDSA65PublicKeySize = 1952
	MLDSA65SignatureSize = 3309

	// ML-DSA-87
	MLDSA87PublicKeySize = 2592
	MLDSA87SignatureSize = 4627

	// Common
	ModeByte       = 1  // Mode indicator byte
	MessageLenSize = 32 // Size of message length field (uint256)
)

// Operation selectors (first byte of calldata)
const (
	OpVerify      uint8 = 0x00 // Single verify (default)
	OpBatchVerify uint8 = 0x10 // Batch verify N signatures
)

// Gas costs - adjusted per mode based on computational complexity
const (
	// Base gas costs per mode (single verify)
	MLDSA44VerifyBaseGas uint64 = 75_000  // Smaller keys, faster
	MLDSA65VerifyBaseGas uint64 = 100_000 // Medium (original)
	MLDSA87VerifyBaseGas uint64 = 150_000 // Larger keys, slower

	// Per-byte gas for message
	MLDSAVerifyPerByteGas uint64 = 10

	// Batch verify gas costs (cheaper than N * single)
	BatchVerifyBaseGas   uint64 = 50_000 // Fixed overhead
	BatchVerifyPerSigGas uint64 = 40_000 // Per signature (vs 75k-150k single)
)

// CountSize is the byte width of the batch count field (uint16, big-endian)
const CountSize = 2

type mldsaVerifyPrecompile struct{}

// Address returns the address of the ML-DSA verify precompile
func (p *mldsaVerifyPrecompile) Address() common.Address {
	return ContractMLDSAVerifyAddress
}

// getModeParams returns the parameters for a given ML-DSA mode
func getModeParams(mode uint8) (pubKeySize, sigSize int, baseGas uint64, mldsaMode mldsa.Mode, err error) {
	switch mode {
	case ModeMLDSA44:
		return MLDSA44PublicKeySize, MLDSA44SignatureSize, MLDSA44VerifyBaseGas, mldsa.MLDSA44, nil
	case ModeMLDSA65:
		return MLDSA65PublicKeySize, MLDSA65SignatureSize, MLDSA65VerifyBaseGas, mldsa.MLDSA65, nil
	case ModeMLDSA87:
		return MLDSA87PublicKeySize, MLDSA87SignatureSize, MLDSA87VerifyBaseGas, mldsa.MLDSA87, nil
	default:
		return 0, 0, 0, 0, ErrUnsupportedMode
	}
}

// RequiredGas calculates the gas required for ML-DSA verification
func (p *mldsaVerifyPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < ModeByte {
		return MLDSA65VerifyBaseGas // Default to ML-DSA-65 gas for invalid input
	}

	// Check for batch verify op
	if input[0] == OpBatchVerify {
		return p.requiredGasBatch(input)
	}

	mode := input[0]
	pubKeySize, _, baseGas, _, err := getModeParams(mode)
	if err != nil {
		return MLDSA65VerifyBaseGas // Default for invalid mode
	}

	// Check if we have enough bytes to read message length
	msgLenOffset := ModeByte + pubKeySize
	if len(input) < msgLenOffset+MessageLenSize {
		return baseGas
	}

	// Extract message length from input
	msgLenBytes := input[msgLenOffset : msgLenOffset+MessageLenSize]
	msgLen := readUint256(msgLenBytes)

	// Overflow check: cap at max gas if msgLen would overflow
	if msgLen > (math.MaxUint64-baseGas)/MLDSAVerifyPerByteGas {
		return math.MaxUint64
	}

	// Base cost + per-byte cost for message
	return baseGas + (msgLen * MLDSAVerifyPerByteGas)
}

// requiredGasBatch calculates gas for batch verification
func (p *mldsaVerifyPrecompile) requiredGasBatch(input []byte) uint64 {
	// Minimum: op(1) + mode(1) + count(2)
	if len(input) < 1+ModeByte+CountSize {
		return BatchVerifyBaseGas
	}
	count := uint64(input[2])<<8 | uint64(input[3])
	return BatchVerifyBaseGas + count*BatchVerifyPerSigGas
}

// Run implements the ML-DSA signature verification precompile
// Input format (NEW - supports all modes):
//
//	[0]              = mode byte (0x44, 0x65, or 0x87) -- OR op byte 0x10 for batch
//	[1:pubKeyEnd]    = public key (size depends on mode)
//	[pubKeyEnd:+32]  = message length as uint256 (32 bytes)
//	[+32:+sigEnd]    = signature (size depends on mode)
//	[sigEnd:...]     = message (variable length)
//
// Output: 32-byte word (1 = valid, 0 = invalid)
func (p *mldsaVerifyPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	// Calculate required gas
	gasCost := p.RequiredGas(input)
	remainingGas, err := contract.DeductGas(suppliedGas, gasCost)
	if err != nil {
		return nil, 0, err
	}

	// Minimum: mode byte
	if len(input) < ModeByte {
		return nil, remainingGas, fmt.Errorf("%w: need at least mode byte", ErrInvalidInputLength)
	}

	// Dispatch batch verify
	if input[0] == OpBatchVerify {
		return p.runBatchVerify(input, suppliedGas, gasCost)
	}

	// Parse mode
	mode := input[0]
	pubKeySize, sigSize, _, mldsaMode, err := getModeParams(mode)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("%w: 0x%02x", ErrUnsupportedMode, mode)
	}

	// Calculate offsets
	pubKeyStart := ModeByte
	pubKeyEnd := pubKeyStart + pubKeySize
	msgLenStart := pubKeyEnd
	msgLenEnd := msgLenStart + MessageLenSize
	sigStart := msgLenEnd
	sigEnd := sigStart + sigSize

	// Minimum input size for this mode
	minInputSize := sigEnd
	if len(input) < minInputSize {
		return nil, remainingGas, fmt.Errorf("%w: expected at least %d bytes for mode 0x%02x, got %d",
			ErrInvalidInputLength, minInputSize, mode, len(input))
	}

	// Parse input
	publicKey := input[pubKeyStart:pubKeyEnd]
	messageLenBytes := input[msgLenStart:msgLenEnd]
	signature := input[sigStart:sigEnd]

	// Read message length
	messageLen := readUint256(messageLenBytes)

	// Validate total input size
	expectedSize := uint64(sigEnd) + messageLen
	if uint64(len(input)) != expectedSize {
		return nil, remainingGas, fmt.Errorf("%w: expected %d bytes total, got %d",
			ErrInvalidInputLength, expectedSize, len(input))
	}

	// Extract message
	message := input[sigEnd:expectedSize]

	// CPU is the single source of truth. This precompile binds a non-empty
	// FIPS-204 context string (precompileCtx) into mu = CRH(tr || 0x00 ||
	// ctxlen || ctx || M). The luxfi/accel ML-DSA kernel verifies with an
	// EMPTY context (ctxlen 0x00) and cannot absorb precompileCtx, so its
	// verdict differs from this one on every signature -- a CPU/GPU consensus
	// split. Re-introducing accel requires a ctx-aware verify kernel
	// (crypto_sign_verify_ctx) proven byte-identical to VerifySignatureCtx.
	pub, err := mldsa.PublicKeyFromBytes(publicKey, mldsaMode)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("invalid public key: %w", err)
	}
	valid := pub.VerifySignatureCtx(message, signature, precompileCtx)

	// Return result as 32-byte word (1 = valid, 0 = invalid)
	result := make([]byte, 32)
	if valid {
		result[31] = 1
	}

	return result, remainingGas, nil
}

// runBatchVerify verifies N ML-DSA signatures in a single precompile call.
//
// Input format:
//
//	[0]       = 0x10 (OpBatchVerify)
//	[1]       = mode byte (0x44, 0x65, or 0x87)
//	[2:4]     = count as uint16 big-endian
//	[4:...]   = count * entry, each entry:
//	              [pubKey]   (pubKeySize bytes)
//	              [msgLen]   (32 bytes, uint256 big-endian)
//	              [signature](sigSize bytes)
//	              [message]  (msgLen bytes)
//
// Output: count bytes, each 0x00 (invalid) or 0x01 (valid), left-padded to 32-byte alignment
func (p *mldsaVerifyPrecompile) runBatchVerify(input []byte, suppliedGas, gasCost uint64) ([]byte, uint64, error) {
	remainingGas, err := contract.DeductGas(suppliedGas, gasCost)
	if err != nil {
		return nil, 0, err
	}

	// Minimum header: op(1) + mode(1) + count(2) = 4
	if len(input) < 4 {
		return nil, remainingGas, fmt.Errorf("%w: batch header too short", ErrInvalidInputLength)
	}

	mode := input[1]
	count := int(input[2])<<8 | int(input[3])

	// Empty batch is valid -- return empty padded result
	if count == 0 {
		return make([]byte, 32), remainingGas, nil
	}

	pubKeySize, sigSize, _, mldsaMode, err := getModeParams(mode)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("%w: 0x%02x", ErrUnsupportedMode, mode)
	}

	// Parse all entries
	messages := make([][]byte, count)
	signatures := make([][]byte, count)
	publicKeys := make([][]byte, count)

	offset := 4 // past header
	for i := range count {
		// pubkey
		if offset+pubKeySize > len(input) {
			return nil, remainingGas, fmt.Errorf("%w: entry %d truncated at pubkey", ErrInvalidInputLength, i)
		}
		publicKeys[i] = input[offset : offset+pubKeySize]
		offset += pubKeySize

		// message length
		if offset+MessageLenSize > len(input) {
			return nil, remainingGas, fmt.Errorf("%w: entry %d truncated at msglen", ErrInvalidInputLength, i)
		}
		msgLen := int(readUint256(input[offset : offset+MessageLenSize]))
		offset += MessageLenSize

		// signature
		if offset+sigSize > len(input) {
			return nil, remainingGas, fmt.Errorf("%w: entry %d truncated at signature", ErrInvalidInputLength, i)
		}
		signatures[i] = input[offset : offset+sigSize]
		offset += sigSize

		// message
		if offset+msgLen > len(input) {
			return nil, remainingGas, fmt.Errorf("%w: entry %d truncated at message", ErrInvalidInputLength, i)
		}
		messages[i] = input[offset : offset+msgLen]
		offset += msgLen
	}

	if offset != len(input) {
		return nil, remainingGas, fmt.Errorf("%w: %d trailing bytes", ErrInvalidInputLength, len(input)-offset)
	}

	// CPU is the single source of truth (same ctx-binding reason as the
	// single-verify path: the accel ML-DSA kernel verifies with empty context
	// and cannot reproduce the precompileCtx-bound verdict). Sequential
	// per-element verify under the FIPS-204 context.
	results := make([]bool, count)
	for i := range count {
		pub, parseErr := mldsa.PublicKeyFromBytes(publicKeys[i], mldsaMode)
		if parseErr != nil {
			results[i] = false
			continue
		}
		results[i] = pub.VerifySignatureCtx(messages[i], signatures[i], precompileCtx)
	}

	// Pack results: pad to 32-byte word, results right-aligned
	padded := 32
	if count > padded {
		// Round up to next 32-byte boundary
		padded = ((count + 31) / 32) * 32
	}
	out := make([]byte, padded)
	for i := range count {
		if results[i] {
			out[padded-count+i] = 1
		}
	}

	return out, remainingGas, nil
}

// readUint256 reads a big-endian uint256 as uint64
func readUint256(b []byte) uint64 {
	if len(b) != 32 {
		return 0
	}
	// Only read last 8 bytes (assume high bytes are 0 for reasonable message lengths)
	return uint64(b[24])<<56 | uint64(b[25])<<48 | uint64(b[26])<<40 | uint64(b[27])<<32 |
		uint64(b[28])<<24 | uint64(b[29])<<16 | uint64(b[30])<<8 | uint64(b[31])
}

// Legacy format (isLegacyFormat + RunLegacy) removed: the heuristic
// "first byte isn't 0x44/0x65/0x87 so it's legacy" was never wired into
// production dispatch and created an ambiguous format-detection path
// flagged by red review (2026-04-12). All ML-DSA input must now carry
// an explicit mode byte.
