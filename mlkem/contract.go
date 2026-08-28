// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package mlkem implements the ML-KEM (FIPS 203) key encapsulation precompile.
// Address: 0x0000000000000000000000000000000000012201 (LP-4200 unified PQCrypto block)
//
// Operations:
//   - 0x01: Encapsulate -- generate shared secret + ciphertext from public key
//
// Decapsulate is intentionally excluded: it requires the private key in
// calldata, which is public on-chain. Decapsulation MUST be performed off-chain.
//
// See LP-4318 for full specification.
package mlkem

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/luxfi/crypto/mlkem"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// SeedSize is the required length of the caller-provided deterministic seed.
// Callers MUST supply a 32-byte seed as the first bytes of encapsulate input.
// Using crypto/rand on-chain produces different ciphertexts per validator,
// causing state divergence. Identical seed + pubkey + caller = identical
// ciphertext on every node.
const SeedSize = 32

// deterministicReader wraps a 32-byte seed with iterated SHA-256 so ML-KEM
// consumes a deterministic pseudorandom stream instead of crypto/rand.
type deterministicReader struct {
	state [SeedSize]byte
	pos   int
}

func newDeterministicReader(seed [SeedSize]byte) *deterministicReader {
	return &deterministicReader{state: seed}
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		if r.pos >= len(r.state) {
			r.state = sha256.Sum256(r.state[:])
			r.pos = 0
		}
		p[i] = r.state[r.pos]
		r.pos++
	}
	return len(p), nil
}

// deriveSeed domain-separates the caller-provided seed by caller address
// and a package-specific label, preventing cross-caller collision even if
// two contracts pick the same raw seed for the same recipient.
func deriveSeed(caller common.Address, raw [SeedSize]byte) [SeedSize]byte {
	h := sha256.New()
	h.Write([]byte("MLKEM_ENCAP_v1"))
	h.Write(caller.Bytes())
	h.Write(raw[:])
	var out [SeedSize]byte
	copy(out[:], h.Sum(nil))
	return out
}

var (
	// ContractAddress is the address of the ML-KEM precompile
	ContractAddress = common.HexToAddress("0x0000000000000000000000000000000000012201")

	// Singleton instance
	MLKEMPrecompile = &mlkemPrecompile{}

	_ contract.StatefulPrecompiledContract = &mlkemPrecompile{}

	ErrInvalidInputLength   = contract.ErrInvalidInput
	ErrInvalidMode          = errors.New("invalid ML-KEM mode")
	ErrUnsupportedMode      = errors.New("unsupported ML-KEM mode")
	ErrUnsupportedOperation = errors.New("unsupported operation")
	ErrEncapsulationFailed  = errors.New("encapsulation failed")
)

// Operation selectors -- encapsulate only, decapsulate is excluded for key safety
const (
	OpEncapsulate = 0x01
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
	MLKEM512CiphertextSize = 768
	MLKEM512SharedKeySize  = 32
)

// Size constants for ML-KEM-768 (NIST Level 3)
const (
	MLKEM768PublicKeySize  = 1184
	MLKEM768CiphertextSize = 1088
	MLKEM768SharedKeySize  = 32
)

// Size constants for ML-KEM-1024 (NIST Level 5)
const (
	MLKEM1024PublicKeySize  = 1568
	MLKEM1024CiphertextSize = 1568
	MLKEM1024SharedKeySize  = 32
)

// Gas costs - based on computational complexity
const (
	MLKEM512EncapsulateGas  uint64 = 50_000
	MLKEM768EncapsulateGas  uint64 = 75_000
	MLKEM1024EncapsulateGas uint64 = 100_000
)

type mlkemPrecompile struct{}

// Address returns the address of the ML-KEM precompile
func (p *mlkemPrecompile) Address() common.Address {
	return ContractAddress
}

// getModeParams returns the parameters for a given ML-KEM mode
func getModeParams(mode uint8) (pubKeySize, ctSize, sharedSize int, encapsGas uint64, mlkemMode mlkem.Mode, err error) {
	switch mode {
	case ModeMLKEM512:
		return MLKEM512PublicKeySize, MLKEM512CiphertextSize, MLKEM512SharedKeySize,
			MLKEM512EncapsulateGas, mlkem.MLKEM512, nil
	case ModeMLKEM768:
		return MLKEM768PublicKeySize, MLKEM768CiphertextSize, MLKEM768SharedKeySize,
			MLKEM768EncapsulateGas, mlkem.MLKEM768, nil
	case ModeMLKEM1024:
		return MLKEM1024PublicKeySize, MLKEM1024CiphertextSize, MLKEM1024SharedKeySize,
			MLKEM1024EncapsulateGas, mlkem.MLKEM1024, nil
	default:
		return 0, 0, 0, 0, 0, ErrUnsupportedMode
	}
}

// RequiredGas calculates the gas required for ML-KEM operations
func (p *mlkemPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 2 {
		return MLKEM768EncapsulateGas
	}

	op := input[0]
	mode := input[1]

	if op != OpEncapsulate {
		return MLKEM768EncapsulateGas
	}

	_, _, _, encapsGas, _, err := getModeParams(mode)
	if err != nil {
		return MLKEM768EncapsulateGas
	}

	return encapsGas
}

// Run implements the ML-KEM precompile
// Input format:
//
//	[0]     = operation byte (0x01 = encapsulate)
//	[1]     = mode byte (0x00 = 512, 0x01 = 768, 0x02 = 1024)
//	[2:...] = public key
//
// Encapsulate output:
//
//	[0:ctSize]       = ciphertext
//	[ctSize:ctSize+32] = shared secret (32 bytes)
func (p *mlkemPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	gasCost := p.RequiredGas(input)
	remainingGas, err := contract.DeductGas(suppliedGas, gasCost)
	if err != nil {
		return nil, 0, err
	}

	if len(input) < 2 {
		return nil, remainingGas, ErrInvalidInputLength
	}

	op := input[0]
	mode := input[1]

	var result []byte

	switch op {
	case OpEncapsulate:
		result, err = p.encapsulate(caller, mode, input[2:])
	default:
		err = fmt.Errorf("%w: 0x%02x", ErrUnsupportedOperation, op)
	}

	if err != nil {
		return nil, remainingGas, err
	}

	return result, remainingGas, nil
}

// encapsulate generates a shared secret and ciphertext from a public key.
// Input layout: [seed(32)][publicKey(pubKeySize)]. Seed + caller are
// combined via deriveSeed into a deterministic pseudorandom stream —
// identical inputs on every validator produce identical output, which
// is required for consensus. crypto/rand MUST NOT be used here.
func (p *mlkemPrecompile) encapsulate(caller common.Address, mode uint8, input []byte) ([]byte, error) {
	pubKeySize, ctSize, sharedSize, _, mlkemMode, err := getModeParams(mode)
	if err != nil {
		return nil, err
	}

	if len(input) != SeedSize+pubKeySize {
		return nil, fmt.Errorf("%w: expected %d bytes (seed %d + pubkey %d), got %d",
			ErrInvalidInputLength, SeedSize+pubKeySize, SeedSize, pubKeySize, len(input))
	}

	var rawSeed [SeedSize]byte
	copy(rawSeed[:], input[:SeedSize])
	seed := deriveSeed(caller, rawSeed)
	pubKey := input[SeedSize:]

	// CPU deterministic path (GPU removed: accel's mlkem does not expose
	// a seeded API, so it would default to crypto/rand → chain split).
	pk, err := mlkem.PublicKeyFromBytes(pubKey, mlkemMode)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	ciphertext, sharedSecret, err := pk.Encapsulate(newDeterministicReader(seed))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncapsulationFailed, err)
	}

	result := make([]byte, ctSize+sharedSize)
	copy(result[:ctSize], ciphertext)
	copy(result[ctSize:], sharedSecret)

	return result, nil
}
