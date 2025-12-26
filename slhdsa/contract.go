// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package slhdsa

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/luxfi/crypto/slhdsa"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompiles/contract"
)

var (
	// ContractSLHDSAVerifyAddress is the address of the SLH-DSA verify precompile
	ContractSLHDSAVerifyAddress = common.HexToAddress("0x0200000000000000000000000000000000000009")

	// Singleton instance
	SLHDSAVerifyPrecompile = &slhdsaVerifyPrecompile{}

	_ contract.StatefulPrecompiledContract = &slhdsaVerifyPrecompile{}

	ErrInvalidInputLength = errors.New("invalid input length")
	ErrInvalidMode        = errors.New("invalid SLH-DSA mode")
	ErrUnsupportedMode    = errors.New("unsupported SLH-DSA mode")
)

// SLH-DSA modes supported by this precompile (12 parameter sets)
// Mode byte encoding: high nibble = hash (0=SHA2, 1=SHAKE), low nibble = size/variant
const (
	// SHA2 modes
	ModeSHA2_128s uint8 = 0x00 // SHA2, 128-bit security, small signatures
	ModeSHA2_128f uint8 = 0x01 // SHA2, 128-bit security, fast signing
	ModeSHA2_192s uint8 = 0x02 // SHA2, 192-bit security, small signatures
	ModeSHA2_192f uint8 = 0x03 // SHA2, 192-bit security, fast signing
	ModeSHA2_256s uint8 = 0x04 // SHA2, 256-bit security, small signatures
	ModeSHA2_256f uint8 = 0x05 // SHA2, 256-bit security, fast signing

	// SHAKE modes
	ModeSHAKE_128s uint8 = 0x10 // SHAKE, 128-bit security, small signatures
	ModeSHAKE_128f uint8 = 0x11 // SHAKE, 128-bit security, fast signing
	ModeSHAKE_192s uint8 = 0x12 // SHAKE, 192-bit security, small signatures
	ModeSHAKE_192f uint8 = 0x13 // SHAKE, 192-bit security, fast signing
	ModeSHAKE_256s uint8 = 0x14 // SHAKE, 256-bit security, small signatures
	ModeSHAKE_256f uint8 = 0x15 // SHAKE, 256-bit security, fast signing
)

// Size constants for each mode
const (
	// Public key sizes (2*n where n is security level parameter)
	SLH128PublicKeySize = 32  // 128-bit security
	SLH192PublicKeySize = 48  // 192-bit security
	SLH256PublicKeySize = 64  // 256-bit security

	// Signature sizes vary significantly by mode
	SLHSHA2_128sSignatureSize  = 7856
	SLHSHA2_128fSignatureSize  = 17088
	SLHSHA2_192sSignatureSize  = 16224
	SLHSHA2_192fSignatureSize  = 35664
	SLHSHA2_256sSignatureSize  = 29792
	SLHSHA2_256fSignatureSize  = 49856
	SLHSHAKE_128sSignatureSize = 7856
	SLHSHAKE_128fSignatureSize = 17088
	SLHSHAKE_192sSignatureSize = 16224
	SLHSHAKE_192fSignatureSize = 35664
	SLHSHAKE_256sSignatureSize = 29792
	SLHSHAKE_256fSignatureSize = 49856

	// Input format fields
	ModeByte       = 1  // Mode indicator byte
	PubKeyLenSize  = 2  // Size of public key length field (uint16)
	MessageLenSize = 2  // Size of message length field (uint16)
)

// Gas costs - adjusted per mode based on computational complexity
// Larger signatures require more verification work
const (
	// Base gas costs per parameter set
	SLH128sVerifyBaseGas uint64 = 50_000  // Small, fastest
	SLH128fVerifyBaseGas uint64 = 75_000  // Larger signature
	SLH192sVerifyBaseGas uint64 = 100_000 // Medium
	SLH192fVerifyBaseGas uint64 = 150_000 // Larger
	SLH256sVerifyBaseGas uint64 = 175_000 // Large
	SLH256fVerifyBaseGas uint64 = 250_000 // Largest signature

	// Per-byte gas for message
	SLHDSAVerifyPerByteGas uint64 = 10

	// Default gas for invalid input
	SLHDSADefaultGas uint64 = 100_000
)

type slhdsaVerifyPrecompile struct{}

// Address returns the address of the SLH-DSA verify precompile
func (p *slhdsaVerifyPrecompile) Address() common.Address {
	return ContractSLHDSAVerifyAddress
}

// getModeParams returns the parameters for a given SLH-DSA mode
func getModeParams(mode uint8) (pubKeySize, sigSize int, baseGas uint64, slhdsaMode slhdsa.Mode, err error) {
	switch mode {
	case ModeSHA2_128s:
		return SLH128PublicKeySize, SLHSHA2_128sSignatureSize, SLH128sVerifyBaseGas, slhdsa.SHA2_128s, nil
	case ModeSHA2_128f:
		return SLH128PublicKeySize, SLHSHA2_128fSignatureSize, SLH128fVerifyBaseGas, slhdsa.SHA2_128f, nil
	case ModeSHA2_192s:
		return SLH192PublicKeySize, SLHSHA2_192sSignatureSize, SLH192sVerifyBaseGas, slhdsa.SHA2_192s, nil
	case ModeSHA2_192f:
		return SLH192PublicKeySize, SLHSHA2_192fSignatureSize, SLH192fVerifyBaseGas, slhdsa.SHA2_192f, nil
	case ModeSHA2_256s:
		return SLH256PublicKeySize, SLHSHA2_256sSignatureSize, SLH256sVerifyBaseGas, slhdsa.SHA2_256s, nil
	case ModeSHA2_256f:
		return SLH256PublicKeySize, SLHSHA2_256fSignatureSize, SLH256fVerifyBaseGas, slhdsa.SHA2_256f, nil
	case ModeSHAKE_128s:
		return SLH128PublicKeySize, SLHSHAKE_128sSignatureSize, SLH128sVerifyBaseGas, slhdsa.SHAKE_128s, nil
	case ModeSHAKE_128f:
		return SLH128PublicKeySize, SLHSHAKE_128fSignatureSize, SLH128fVerifyBaseGas, slhdsa.SHAKE_128f, nil
	case ModeSHAKE_192s:
		return SLH192PublicKeySize, SLHSHAKE_192sSignatureSize, SLH192sVerifyBaseGas, slhdsa.SHAKE_192s, nil
	case ModeSHAKE_192f:
		return SLH192PublicKeySize, SLHSHAKE_192fSignatureSize, SLH192fVerifyBaseGas, slhdsa.SHAKE_192f, nil
	case ModeSHAKE_256s:
		return SLH256PublicKeySize, SLHSHAKE_256sSignatureSize, SLH256sVerifyBaseGas, slhdsa.SHAKE_256s, nil
	case ModeSHAKE_256f:
		return SLH256PublicKeySize, SLHSHAKE_256fSignatureSize, SLH256fVerifyBaseGas, slhdsa.SHAKE_256f, nil
	default:
		return 0, 0, 0, 0, ErrUnsupportedMode
	}
}

// RequiredGas calculates the gas required for SLH-DSA verification
func (p *slhdsaVerifyPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < ModeByte {
		return SLHDSADefaultGas
	}

	mode := input[0]
	pubKeySize, _, baseGas, _, err := getModeParams(mode)
	if err != nil {
		return SLHDSADefaultGas
	}

	// Check if we have enough bytes to read message length
	// Format: [mode(1)][pubKeyLen(2)][pubKey][msgLen(2)][message][signature]
	headerSize := ModeByte + PubKeyLenSize
	if len(input) < headerSize {
		return baseGas
	}

	pubKeyLen := int(binary.BigEndian.Uint16(input[ModeByte : ModeByte+PubKeyLenSize]))
	if pubKeyLen != pubKeySize {
		return baseGas // Invalid pubkey size for mode
	}

	msgLenOffset := headerSize + pubKeyLen
	if len(input) < msgLenOffset+MessageLenSize {
		return baseGas
	}

	msgLen := binary.BigEndian.Uint16(input[msgLenOffset : msgLenOffset+MessageLenSize])

	// Base cost + per-byte cost for message
	return baseGas + (uint64(msgLen) * SLHDSAVerifyPerByteGas)
}

// Run implements the SLH-DSA signature verification precompile
// Input format:
//
//	[0]              = mode byte (defines parameter set)
//	[1:3]            = public key length as uint16
//	[3:pubKeyEnd]    = public key
//	[pubKeyEnd:+2]   = message length as uint16
//	[+2:msgEnd]      = message
//	[msgEnd:...]     = signature
//
// Output: 32-byte word (1 = valid, 0 = invalid)
func (p *slhdsaVerifyPrecompile) Run(
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

	// Minimum: mode byte + pubkey length
	minHeader := ModeByte + PubKeyLenSize
	if len(input) < minHeader {
		return nil, suppliedGas - gasCost, fmt.Errorf("%w: need at least %d bytes", ErrInvalidInputLength, minHeader)
	}

	// Parse mode
	mode := input[0]
	pubKeySize, sigSize, _, slhdsaMode, err := getModeParams(mode)
	if err != nil {
		return nil, suppliedGas - gasCost, fmt.Errorf("%w: 0x%02x", ErrUnsupportedMode, mode)
	}

	// Parse public key length
	pubKeyLen := int(binary.BigEndian.Uint16(input[ModeByte : ModeByte+PubKeyLenSize]))
	if pubKeyLen != pubKeySize {
		return nil, suppliedGas - gasCost, fmt.Errorf("%w: expected pubkey size %d for mode 0x%02x, got %d",
			ErrInvalidInputLength, pubKeySize, mode, pubKeyLen)
	}

	// Calculate offsets
	pubKeyStart := ModeByte + PubKeyLenSize
	pubKeyEnd := pubKeyStart + pubKeyLen
	msgLenStart := pubKeyEnd
	msgLenEnd := msgLenStart + MessageLenSize

	// Check we have enough input
	if len(input) < msgLenEnd {
		return nil, suppliedGas - gasCost, fmt.Errorf("%w: input too short for message length", ErrInvalidInputLength)
	}

	// Parse message length
	msgLen := int(binary.BigEndian.Uint16(input[msgLenStart:msgLenEnd]))
	msgStart := msgLenEnd
	msgEnd := msgStart + msgLen
	sigStart := msgEnd
	sigEnd := sigStart + sigSize

	// Validate total input size
	if len(input) < sigEnd {
		return nil, suppliedGas - gasCost, fmt.Errorf("%w: expected at least %d bytes, got %d",
			ErrInvalidInputLength, sigEnd, len(input))
	}

	// Extract components
	publicKey := input[pubKeyStart:pubKeyEnd]
	message := input[msgStart:msgEnd]
	signature := input[sigStart:sigEnd]

	// Parse public key from bytes
	pub, err := slhdsa.PublicKeyFromBytes(publicKey, slhdsaMode)
	if err != nil {
		return nil, suppliedGas - gasCost, fmt.Errorf("invalid public key: %w", err)
	}

	// Verify signature
	valid := pub.Verify(message, signature, nil)

	// Return result as 32-byte word (1 = valid, 0 = invalid)
	result := make([]byte, 32)
	if valid {
		result[31] = 1
	}

	return result, suppliedGas - gasCost, nil
}

// ModeName returns a human-readable name for the mode
func ModeName(mode uint8) string {
	switch mode {
	case ModeSHA2_128s:
		return "SLH-DSA-SHA2-128s"
	case ModeSHA2_128f:
		return "SLH-DSA-SHA2-128f"
	case ModeSHA2_192s:
		return "SLH-DSA-SHA2-192s"
	case ModeSHA2_192f:
		return "SLH-DSA-SHA2-192f"
	case ModeSHA2_256s:
		return "SLH-DSA-SHA2-256s"
	case ModeSHA2_256f:
		return "SLH-DSA-SHA2-256f"
	case ModeSHAKE_128s:
		return "SLH-DSA-SHAKE-128s"
	case ModeSHAKE_128f:
		return "SLH-DSA-SHAKE-128f"
	case ModeSHAKE_192s:
		return "SLH-DSA-SHAKE-192s"
	case ModeSHAKE_192f:
		return "SLH-DSA-SHAKE-192f"
	case ModeSHAKE_256s:
		return "SLH-DSA-SHAKE-256s"
	case ModeSHAKE_256f:
		return "SLH-DSA-SHAKE-256f"
	default:
		return "unknown"
	}
}
