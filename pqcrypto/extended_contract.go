// Copyright (C) 2025, Lux Industries Inc All rights reserved.
// Extended Post-Quantum Cryptography Precompile Implementation

package pqcrypto

import (
	"errors"
	"fmt"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/crypto/mlkem"
	"github.com/luxfi/crypto/slhdsa"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

const (
	// Additional gas costs for signing operations
	MLDSASignGas    = 12000
	SLHDSASignGas   = 20000
	MLDSAGenKeyGas  = 15000
	MLKEMGenKeyGas  = 12000
	SLHDSAGenKeyGas = 25000

	// Additional function selectors
	MLDSASignSelector    = "mldsa_sign"
	SLHDSASignSelector   = "slhdsa_sign"
	MLDSAGenKeySelector  = "mldsa_genkey"
	MLKEMGenKeySelector  = "mlkem_genkey"
	SLHDSAGenKeySelector = "slhdsa_genkey"
)

// Extended methods for signing operations

// mldsaSign creates an ML-DSA signature with deterministic randomness.
// Input format: [mode(1)] [seed(32)] [privkey_len(2)] [privkey] [message]
//
// The 32-byte seed ensures consensus safety: identical output across validators.
func (p *pqCryptoPrecompile) mldsaSign(input []byte) ([]byte, uint64, error) {
	if len(input) < 1+seedSize+2 {
		return nil, 0, fmt.Errorf("%w: sign requires mode(1) + seed(%d) + privkey_len(2) + privkey + message", errInvalidInput, seedSize)
	}

	mode := mldsa.Mode(input[0])

	var seed [32]byte
	copy(seed[:], input[1:1+seedSize])

	privKeyLen := int(input[1+seedSize])<<8 | int(input[1+seedSize+1])

	if len(input) < 1+seedSize+2+privKeyLen {
		return nil, 0, errInvalidInput
	}

	privKeyBytes := input[1+seedSize+2 : 1+seedSize+2+privKeyLen]
	message := input[1+seedSize+2+privKeyLen:]

	privKey, err := mldsa.PrivateKeyFromBytes(mode, privKeyBytes)
	if err != nil {
		return nil, 0, err
	}

	reader := newDeterministicReader(seed)
	signature, err := privKey.Sign(reader, message, nil)
	if err != nil {
		return nil, 0, err
	}

	return signature, 0, nil
}

// slhdsaSign creates an SLH-DSA signature with deterministic randomness.
// Input format: [mode(1)] [seed(32)] [privkey_len(2)] [privkey] [message]
//
// The 32-byte seed ensures consensus safety: identical output across validators.
func (p *pqCryptoPrecompile) slhdsaSign(input []byte) ([]byte, uint64, error) {
	if len(input) < 1+seedSize+2 {
		return nil, 0, fmt.Errorf("%w: sign requires mode(1) + seed(%d) + privkey_len(2) + privkey + message", errInvalidInput, seedSize)
	}

	mode := slhdsa.Mode(input[0])

	var seed [32]byte
	copy(seed[:], input[1:1+seedSize])

	privKeyLen := int(input[1+seedSize])<<8 | int(input[1+seedSize+1])

	if len(input) < 1+seedSize+2+privKeyLen {
		return nil, 0, errInvalidInput
	}

	privKeyBytes := input[1+seedSize+2 : 1+seedSize+2+privKeyLen]
	message := input[1+seedSize+2+privKeyLen:]

	privKey, err := slhdsa.PrivateKeyFromBytes(mode, privKeyBytes)
	if err != nil {
		return nil, 0, err
	}

	reader := newDeterministicReader(seed)
	signature, err := privKey.Sign(reader, message, nil)
	if err != nil {
		return nil, 0, err
	}

	return signature, 0, nil
}

// mldsaGenKey generates an ML-DSA key pair with deterministic randomness.
// Input format: [mode(1)] [seed(32)]
//
// The 32-byte seed ensures consensus safety: identical keys across validators.
func (p *pqCryptoPrecompile) mldsaGenKey(input []byte) ([]byte, uint64, error) {
	if len(input) < 1+seedSize {
		return nil, 0, fmt.Errorf("%w: genkey requires mode(1) + seed(%d)", errInvalidInput, seedSize)
	}

	mode := mldsa.Mode(input[0])

	var seed [32]byte
	copy(seed[:], input[1:1+seedSize])

	reader := newDeterministicReader(seed)
	privKey, err := mldsa.GenerateKey(reader, mode)
	if err != nil {
		return nil, 0, err
	}

	privBytes := privKey.Bytes()
	pubBytes := privKey.PublicKey.Bytes()

	output := make([]byte, 2+len(privBytes)+len(pubBytes))
	output[0] = byte(len(privBytes) >> 8)
	output[1] = byte(len(privBytes))
	copy(output[2:2+len(privBytes)], privBytes)
	copy(output[2+len(privBytes):], pubBytes)

	return output, 0, nil
}

// mlkemGenKey generates an ML-KEM key pair with deterministic randomness.
// Input format: [mode(1)] [seed(32)]
//
// The 32-byte seed ensures consensus safety: identical keys across validators.
func (p *pqCryptoPrecompile) mlkemGenKey(input []byte) ([]byte, uint64, error) {
	if len(input) < 1+seedSize {
		return nil, 0, fmt.Errorf("%w: genkey requires mode(1) + seed(%d)", errInvalidInput, seedSize)
	}

	mode := mlkem.Mode(input[0])

	var seed [32]byte
	copy(seed[:], input[1:1+seedSize])

	reader := newDeterministicReader(seed)
	pubKey, privKey, err := mlkem.GenerateKeyPair(reader, mode)
	if err != nil {
		return nil, 0, err
	}

	privBytes := privKey.Bytes()
	pubBytes := pubKey.Bytes()

	output := make([]byte, 2+len(privBytes)+len(pubBytes))
	output[0] = byte(len(privBytes) >> 8)
	output[1] = byte(len(privBytes))
	copy(output[2:2+len(privBytes)], privBytes)
	copy(output[2+len(privBytes):], pubBytes)

	return output, 0, nil
}

// slhdsaGenKey generates an SLH-DSA key pair with deterministic randomness.
// Input format: [mode(1)] [seed(32)]
//
// The 32-byte seed ensures consensus safety: identical keys across validators.
func (p *pqCryptoPrecompile) slhdsaGenKey(input []byte) ([]byte, uint64, error) {
	if len(input) < 1+seedSize {
		return nil, 0, fmt.Errorf("%w: genkey requires mode(1) + seed(%d)", errInvalidInput, seedSize)
	}

	mode := slhdsa.Mode(input[0])

	var seed [32]byte
	copy(seed[:], input[1:1+seedSize])

	reader := newDeterministicReader(seed)
	privKey, err := slhdsa.GenerateKey(reader, mode)
	if err != nil {
		return nil, 0, err
	}

	privBytes := privKey.Bytes()
	pubBytes := privKey.PublicKey.Bytes()

	output := make([]byte, 2+len(privBytes)+len(pubBytes))
	output[0] = byte(len(privBytes) >> 8)
	output[1] = byte(len(privBytes))
	copy(output[2:2+len(privBytes)], privBytes)
	copy(output[2+len(privBytes):], pubBytes)

	return output, 0, nil
}

// ExtendedRequiredGas calculates gas for extended operations
func (p *pqCryptoPrecompile) ExtendedRequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return 0
	}

	// Parse function selector (first 4 bytes)
	selector := string(input[:4])

	switch selector {
	case MLDSASignSelector[:4]:
		return MLDSASignGas
	case SLHDSASignSelector[:4]:
		return SLHDSASignGas
	case MLDSAGenKeySelector[:4]:
		return MLDSAGenKeyGas
	case MLKEMGenKeySelector[:4]:
		return MLKEMGenKeyGas
	case SLHDSAGenKeySelector[:4]:
		return SLHDSAGenKeyGas
	default:
		return p.RequiredGas(input) // Fall back to original
	}
}

// ExtendedRun executes extended precompile operations
func (p *pqCryptoPrecompile) ExtendedRun(accessibleState contract.AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if len(input) < 4 {
		return nil, suppliedGas, errInvalidInput
	}

	// Calculate required gas
	requiredGas := p.ExtendedRequiredGas(input)
	if requiredGas == 0 {
		// Try original run
		return p.Run(accessibleState, caller, addr, input, suppliedGas, readOnly)
	}

	if suppliedGas < requiredGas {
		return nil, 0, contract.ErrOutOfGas
	}
	remainingGas = suppliedGas - requiredGas

	// Parse function selector
	selector := string(input[:4])
	data := input[4:]

	switch selector {
	case MLDSASignSelector[:4]:
		if readOnly {
			return nil, remainingGas, errors.New("cannot sign in read-only mode")
		}
		return p.mldsaSign(data)
	case SLHDSASignSelector[:4]:
		if readOnly {
			return nil, remainingGas, errors.New("cannot sign in read-only mode")
		}
		return p.slhdsaSign(data)
	case MLDSAGenKeySelector[:4]:
		if readOnly {
			return nil, remainingGas, errors.New("cannot generate keys in read-only mode")
		}
		return p.mldsaGenKey(data)
	case MLKEMGenKeySelector[:4]:
		if readOnly {
			return nil, remainingGas, errors.New("cannot generate keys in read-only mode")
		}
		return p.mlkemGenKey(data)
	case SLHDSAGenKeySelector[:4]:
		if readOnly {
			return nil, remainingGas, errors.New("cannot generate keys in read-only mode")
		}
		return p.slhdsaGenKey(data)
	default:
		return nil, remainingGas, fmt.Errorf("unknown function selector: %x", selector)
	}
}
