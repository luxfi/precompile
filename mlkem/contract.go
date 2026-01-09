// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package mlkem implements the ML-KEM (FIPS 203) key encapsulation precompile.
// Address: 0x0200000000000000000000000000000000000007
//
// See LP-4318 for full specification.
package mlkem

import (
	"errors"
	"fmt"

	"github.com/luxfi/crypto/mlkem"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	// ContractAddress is the address of the ML-KEM precompile
	ContractAddress = common.HexToAddress("0x0200000000000000000000000000000000000007")

	// Singleton instance
	MLKEMPrecompile = &mlkemPrecompile{}

	_ contract.StatefulPrecompiledContract = &mlkemPrecompile{}

	ErrInvalidInputLength   = errors.New("invalid input length")
	ErrInvalidMode          = errors.New("invalid ML-KEM mode")
	ErrUnsupportedMode      = errors.New("unsupported ML-KEM mode")
	ErrUnsupportedOperation = errors.New("unsupported operation")
	ErrEncapsulationFailed  = errors.New("encapsulation failed")
	ErrDecapsulationFailed  = errors.New("decapsulation failed")
)

// Operation selectors
const (
	OpEncapsulate = 0x01 // Generate shared secret + ciphertext from public key
	OpDecapsulate = 0x02 // Recover shared secret from ciphertext using private key
)

// ML-KEM modes (FIPS 203)
const (
	ModeMLKEM512  uint8 = 0x00 // ML-KEM-512 (128-bit security, NIST Level 1)
	ModeMLKEM768  uint8 = 0x01 // ML-KEM-768 (192-bit security, NIST Level 3)
	ModeMLKEM1024 uint8 = 0x02 // ML-KEM-1024 (256-bit security, NIST Level 5)
)

// Size constants for ML-KEM-512 (NIST Level 1)
const (
	MLKEM512PublicKeySize  = 800
	MLKEM512PrivateKeySize = 1632
	MLKEM512CiphertextSize = 768
	MLKEM512SharedKeySize  = 32
)

// Size constants for ML-KEM-768 (NIST Level 3)
const (
	MLKEM768PublicKeySize  = 1184
	MLKEM768PrivateKeySize = 2400
	MLKEM768CiphertextSize = 1088
	MLKEM768SharedKeySize  = 32
)

// Size constants for ML-KEM-1024 (NIST Level 5)
const (
	MLKEM1024PublicKeySize  = 1568
	MLKEM1024PrivateKeySize = 3168
	MLKEM1024CiphertextSize = 1568
	MLKEM1024SharedKeySize  = 32
)

// Gas costs - based on computational complexity
const (
	// Encapsulation gas costs per mode
	MLKEM512EncapsulateGas  uint64 = 50_000  // Smaller, faster
	MLKEM768EncapsulateGas  uint64 = 75_000  // Medium
	MLKEM1024EncapsulateGas uint64 = 100_000 // Larger, slower

	// Decapsulation gas costs per mode
	MLKEM512DecapsulateGas  uint64 = 60_000 // Slightly more than encaps
	MLKEM768DecapsulateGas  uint64 = 90_000
	MLKEM1024DecapsulateGas uint64 = 120_000
)

type mlkemPrecompile struct{}

// Address returns the address of the ML-KEM precompile
func (p *mlkemPrecompile) Address() common.Address {
	return ContractAddress
}

// getModeParams returns the parameters for a given ML-KEM mode
func getModeParams(mode uint8) (pubKeySize, privKeySize, ctSize, sharedSize int, encapsGas, decapsGas uint64, mlkemMode mlkem.Mode, err error) {
	switch mode {
	case ModeMLKEM512:
		return MLKEM512PublicKeySize, MLKEM512PrivateKeySize, MLKEM512CiphertextSize, MLKEM512SharedKeySize,
			MLKEM512EncapsulateGas, MLKEM512DecapsulateGas, mlkem.MLKEM512, nil
	case ModeMLKEM768:
		return MLKEM768PublicKeySize, MLKEM768PrivateKeySize, MLKEM768CiphertextSize, MLKEM768SharedKeySize,
			MLKEM768EncapsulateGas, MLKEM768DecapsulateGas, mlkem.MLKEM768, nil
	case ModeMLKEM1024:
		return MLKEM1024PublicKeySize, MLKEM1024PrivateKeySize, MLKEM1024CiphertextSize, MLKEM1024SharedKeySize,
			MLKEM1024EncapsulateGas, MLKEM1024DecapsulateGas, mlkem.MLKEM1024, nil
	default:
		return 0, 0, 0, 0, 0, 0, 0, ErrUnsupportedMode
	}
}

// RequiredGas calculates the gas required for ML-KEM operations
func (p *mlkemPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 2 {
		return MLKEM768EncapsulateGas // Default for invalid input
	}

	op := input[0]
	mode := input[1]

	_, _, _, _, encapsGas, decapsGas, _, err := getModeParams(mode)
	if err != nil {
		return MLKEM768EncapsulateGas // Default for invalid mode
	}

	switch op {
	case OpEncapsulate:
		return encapsGas
	case OpDecapsulate:
		return decapsGas
	default:
		return MLKEM768EncapsulateGas
	}
}

// Run implements the ML-KEM precompile
// Input format:
//
//	[0]     = operation byte (0x01 = encapsulate, 0x02 = decapsulate)
//	[1]     = mode byte (0x00 = 512, 0x01 = 768, 0x02 = 1024)
//	[2:...] = operation-specific data
//
// Encapsulate input:
//
//	[2:2+pubKeySize] = public key
//
// Encapsulate output:
//
//	[0:ctSize]       = ciphertext
//	[ctSize:ctSize+32] = shared secret (32 bytes)
//
// Decapsulate input:
//
//	[2:2+privKeySize] = private key
//	[2+privKeySize:2+privKeySize+ctSize] = ciphertext
//
// Decapsulate output:
//
//	[0:32] = shared secret (32 bytes)
func (p *mlkemPrecompile) Run(
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

	// Minimum: op byte + mode byte
	if len(input) < 2 {
		return nil, suppliedGas - gasCost, ErrInvalidInputLength
	}

	op := input[0]
	mode := input[1]

	var result []byte
	var err error

	switch op {
	case OpEncapsulate:
		result, err = p.encapsulate(mode, input[2:])
	case OpDecapsulate:
		result, err = p.decapsulate(mode, input[2:])
	default:
		err = fmt.Errorf("%w: 0x%02x", ErrUnsupportedOperation, op)
	}

	if err != nil {
		return nil, suppliedGas - gasCost, err
	}

	return result, suppliedGas - gasCost, nil
}

// encapsulate generates a shared secret and ciphertext from a public key
func (p *mlkemPrecompile) encapsulate(mode uint8, input []byte) ([]byte, error) {
	pubKeySize, _, ctSize, sharedSize, _, _, mlkemMode, err := getModeParams(mode)
	if err != nil {
		return nil, err
	}

	// Validate input length
	if len(input) != pubKeySize {
		return nil, fmt.Errorf("%w: expected %d bytes for public key, got %d",
			ErrInvalidInputLength, pubKeySize, len(input))
	}

	// Parse public key
	pk, err := mlkem.PublicKeyFromBytes(input, mlkemMode)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	// Encapsulate - generates ciphertext and shared secret
	ciphertext, sharedSecret, err := pk.Encapsulate()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncapsulationFailed, err)
	}

	// Return ciphertext || sharedSecret
	result := make([]byte, ctSize+sharedSize)
	copy(result[:ctSize], ciphertext)
	copy(result[ctSize:], sharedSecret)

	return result, nil
}

// decapsulate recovers the shared secret from a ciphertext using a private key
func (p *mlkemPrecompile) decapsulate(mode uint8, input []byte) ([]byte, error) {
	_, privKeySize, ctSize, _, _, _, mlkemMode, err := getModeParams(mode)
	if err != nil {
		return nil, err
	}

	// Validate input length
	expectedLen := privKeySize + ctSize
	if len(input) != expectedLen {
		return nil, fmt.Errorf("%w: expected %d bytes (privKey=%d + ct=%d), got %d",
			ErrInvalidInputLength, expectedLen, privKeySize, ctSize, len(input))
	}

	// Parse private key
	privKeyBytes := input[:privKeySize]
	ciphertext := input[privKeySize:]

	sk, err := mlkem.PrivateKeyFromBytes(privKeyBytes, mlkemMode)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	// Decapsulate - recovers shared secret
	sharedSecret, err := sk.Decapsulate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecapsulationFailed, err)
	}

	return sharedSecret, nil
}
