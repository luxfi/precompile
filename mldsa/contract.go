// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import (
	"errors"
	"fmt"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	// ContractMLDSAVerifyAddress is the address of the ML-DSA verify precompile
	ContractMLDSAVerifyAddress = common.HexToAddress("0x0200000000000000000000000000000000000006")

	// Singleton instance
	MLDSAVerifyPrecompile = &mldsaVerifyPrecompile{}

	_ contract.StatefulPrecompiledContract = &mldsaVerifyPrecompile{}

	ErrInvalidInputLength = errors.New("invalid input length")
	ErrInvalidMode        = errors.New("invalid ML-DSA mode")
	ErrUnsupportedMode    = errors.New("unsupported ML-DSA mode")
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

// Gas costs - adjusted per mode based on computational complexity
const (
	// Base gas costs per mode
	MLDSA44VerifyBaseGas uint64 = 75_000  // Smaller keys, faster
	MLDSA65VerifyBaseGas uint64 = 100_000 // Medium (original)
	MLDSA87VerifyBaseGas uint64 = 150_000 // Larger keys, slower

	// Per-byte gas for message
	MLDSAVerifyPerByteGas uint64 = 10
)

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

	// Base cost + per-byte cost for message
	return baseGas + (msgLen * MLDSAVerifyPerByteGas)
}

// Run implements the ML-DSA signature verification precompile
// Input format (NEW - supports all modes):
//
//	[0]              = mode byte (0x44, 0x65, or 0x87)
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
	if suppliedGas < gasCost {
		return nil, 0, errors.New("out of gas")
	}

	// Minimum: mode byte
	if len(input) < ModeByte {
		return nil, suppliedGas - gasCost, fmt.Errorf("%w: need at least mode byte", ErrInvalidInputLength)
	}

	// Parse mode
	mode := input[0]
	pubKeySize, sigSize, _, mldsaMode, err := getModeParams(mode)
	if err != nil {
		return nil, suppliedGas - gasCost, fmt.Errorf("%w: 0x%02x", ErrUnsupportedMode, mode)
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
		return nil, suppliedGas - gasCost, fmt.Errorf("%w: expected at least %d bytes for mode 0x%02x, got %d",
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
		return nil, suppliedGas - gasCost, fmt.Errorf("%w: expected %d bytes total, got %d",
			ErrInvalidInputLength, expectedSize, len(input))
	}

	// Extract message
	message := input[sigEnd:expectedSize]

	// Parse public key from bytes
	pub, err := mldsa.PublicKeyFromBytes(publicKey, mldsaMode)
	if err != nil {
		return nil, suppliedGas - gasCost, fmt.Errorf("invalid public key: %w", err)
	}

	// Verify signature using public key method
	valid := pub.Verify(message, signature, nil)

	// Return result as 32-byte word (1 = valid, 0 = invalid)
	result := make([]byte, 32)
	if valid {
		result[31] = 1
	}

	return result, suppliedGas - gasCost, nil
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

// Legacy input format support (for backwards compatibility with ML-DSA-65 only)
// Detects if input uses legacy format (no mode byte) and handles accordingly
func (p *mldsaVerifyPrecompile) isLegacyFormat(input []byte) bool {
	// Legacy format starts directly with public key
	// New format starts with mode byte (0x44, 0x65, or 0x87)
	// ML-DSA public keys never start with these bytes
	if len(input) < 1 {
		return false
	}
	mode := input[0]
	return mode != ModeMLDSA44 && mode != ModeMLDSA65 && mode != ModeMLDSA87
}

// RunLegacy handles the legacy ML-DSA-65 only format for backwards compatibility
func (p *mldsaVerifyPrecompile) RunLegacy(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	// Legacy constants (ML-DSA-65 only)
	const (
		legacyPubKeySize = 1952
		legacyMsgLenSize = 32
		legacySigSize    = 3309
		legacyMinInput   = legacyPubKeySize + legacyMsgLenSize + legacySigSize
		legacyBaseGas    = 100_000
	)

	// Calculate gas
	gasCost := uint64(legacyBaseGas)
	if len(input) >= legacyPubKeySize+legacyMsgLenSize {
		msgLenBytes := input[legacyPubKeySize : legacyPubKeySize+legacyMsgLenSize]
		msgLen := readUint256(msgLenBytes)
		gasCost += msgLen * MLDSAVerifyPerByteGas
	}

	if suppliedGas < gasCost {
		return nil, 0, errors.New("out of gas")
	}

	if len(input) < legacyMinInput {
		return nil, suppliedGas - gasCost, fmt.Errorf("%w: expected at least %d bytes, got %d",
			ErrInvalidInputLength, legacyMinInput, len(input))
	}

	// Parse legacy format
	publicKey := input[0:legacyPubKeySize]
	messageLenBytes := input[legacyPubKeySize : legacyPubKeySize+legacyMsgLenSize]
	signature := input[legacyPubKeySize+legacyMsgLenSize : legacyPubKeySize+legacyMsgLenSize+legacySigSize]

	messageLen := readUint256(messageLenBytes)
	expectedSize := uint64(legacyMinInput) + messageLen
	if uint64(len(input)) != expectedSize {
		return nil, suppliedGas - gasCost, fmt.Errorf("%w: expected %d bytes total, got %d",
			ErrInvalidInputLength, expectedSize, len(input))
	}

	message := input[legacyMinInput:expectedSize]

	pub, err := mldsa.PublicKeyFromBytes(publicKey, mldsa.MLDSA65)
	if err != nil {
		return nil, suppliedGas - gasCost, fmt.Errorf("invalid public key: %w", err)
	}

	valid := pub.Verify(message, signature, nil)

	result := make([]byte, 32)
	if valid {
		result[31] = 1
	}

	return result, suppliedGas - gasCost, nil
}
