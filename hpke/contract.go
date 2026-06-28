// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package hpke implements RFC 9180 HPKE (Hybrid Public Key Encryption) precompile
// for the Lux EVM. Address: 0x9200 (Lux Crypto Privacy range)
//
// See LP-3662 for full specification.
//
// Operations:
//   - 0x20: SingleShotSeal -- encrypt with recipient public key
//
// SingleShotOpen (decryption) is intentionally excluded: it requires the
// recipient's secret key in calldata, which is public on-chain. Decryption
// MUST be performed off-chain.
//
// The full HPKE seal (KEM encap -> HKDF key schedule -> AEAD) runs on the CPU
// via circl and is the single, deterministic source of truth across the
// validator set. A prior GPU "fast path" computed a Kyber encapsulation and
// then discarded it, so it was pure vestigial work and a divergence surface;
// it has been removed.
package hpke

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/hpke"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	// ContractAddress is the address of the HPKE precompile (Lux Crypto Privacy range 0x9200)
	ContractAddress = common.HexToAddress("0x9200")

	// Singleton instance
	HPKEPrecompile = &hpkePrecompile{}

	_ contract.StatefulPrecompiledContract = &hpkePrecompile{}

	ErrInvalidInput       = contract.ErrInvalidInput
	ErrInvalidCipherSuite = errors.New("invalid cipher suite")
)

// Operation selectors -- seal only, open is excluded for key safety
const (
	OpSingleShotSeal = 0x20
)

// KEM IDs
const (
	KEMP256   = 0x0010
	KEMP384   = 0x0011
	KEMP521   = 0x0012
	KEMX25519 = 0x0020

	// Post-quantum hybrid KEMs (contain Kyber/ML-KEM component)
	KEMX25519Kyber768 = 0x0030 // X25519 + Kyber768 (draft-westerbaan-cfrg-hpke-xyber768d00)
	KEMXWing          = 0x647a // X-Wing: X25519 + ML-KEM-768
)

// SeedSize is the required length of the caller-provided deterministic seed.
// Callers MUST provide a unique 32-byte seed per seal operation to ensure
// consensus safety. Using crypto/rand on-chain produces different ciphertexts
// per validator, causing state divergence.
const SeedSize = 32

// Gas costs
const (
	GasKEMEncapsP256   = 6000
	GasKEMEncapsP384   = 9000
	GasKEMEncapsP521   = 15000
	GasKEMEncapsX25519 = 3000

	// Post-quantum hybrid KEMs: ECDH + Kyber lattice ops
	GasKEMEncapsX25519Kyber768 = 50000 // X25519 + Kyber768
	GasKEMEncapsXWing          = 50000 // X-Wing hybrid

	GasKDFExtract     = 200
	GasAEADBase       = 400
	GasAEADPer64Bytes = 8
)

type hpkePrecompile struct{}

// deterministicReader is an io.Reader that produces deterministic bytes from
// a 32-byte seed using iterated SHA-256. Each time the 32-byte block is
// exhausted, the state is hashed to produce the next block.
//
// This replaces crypto/rand inside circl's sender.Setup() to guarantee that
// all validators produce identical ciphertexts for the same input, which is
// required for EVM consensus.
type deterministicReader struct {
	state [32]byte
	pos   int
}

func newDeterministicReader(seed [32]byte) *deterministicReader {
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

// Compile-time check that deterministicReader implements io.Reader.
var _ io.Reader = (*deterministicReader)(nil)

// Address returns the address of the HPKE precompile
func (p *hpkePrecompile) Address() common.Address {
	return ContractAddress
}

func kemGas(kemID uint16) uint64 {
	switch kemID {
	case KEMP256:
		return GasKEMEncapsP256
	case KEMP384:
		return GasKEMEncapsP384
	case KEMP521:
		return GasKEMEncapsP521
	case KEMX25519:
		return GasKEMEncapsX25519
	case KEMX25519Kyber768:
		return GasKEMEncapsX25519Kyber768
	case KEMXWing:
		return GasKEMEncapsXWing
	default:
		return GasKEMEncapsX25519
	}
}

// isKyberKEM returns true if the KEM ID includes a Kyber/ML-KEM lattice component.
func isKyberKEM(kemID uint16) bool {
	return kemID == KEMX25519Kyber768 || kemID == KEMXWing
}

// RequiredGas calculates gas for HPKE operations
func (p *hpkePrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return 0
	}

	op := input[0]

	switch op {
	case OpSingleShotSeal:
		// Minimum: op(1) + suite(6) + seed(32) = 39
		if len(input) < 1+6+SeedSize {
			return GasKEMEncapsX25519 + GasKDFExtract + GasAEADBase
		}
		kemID := uint16(input[1])<<8 | uint16(input[2])
		// Overhead: op(1) + suite(6) + seed(32) + pkLen(2) + infoLen(2) + aadLen(2) = 45
		// plus variable pk/info/aad lengths; estimate conservatively
		dataLen := max(len(input)-(1+6+SeedSize+2+2+2), 0)
		return kemGas(kemID) + GasKDFExtract + GasAEADBase + uint64(dataLen/64)*GasAEADPer64Bytes

	default:
		return 0
	}
}

// Run executes the HPKE precompile
func (p *hpkePrecompile) Run(
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

	if len(input) < 1 {
		return nil, remainingGas, ErrInvalidInput
	}

	op := input[0]

	var result []byte

	switch op {
	case OpSingleShotSeal:
		result, err = p.singleShotSeal(caller, input[1:])
	default:
		err = fmt.Errorf("unsupported operation: 0x%02x", op)
	}

	if err != nil {
		return nil, remainingGas, err
	}

	return result, remainingGas, nil
}

func (p *hpkePrecompile) parseSuite(input []byte) (hpke.Suite, error) {
	if len(input) < 6 {
		return hpke.Suite{}, ErrInvalidInput
	}

	kemID := uint16(input[0])<<8 | uint16(input[1])
	kdfID := uint16(input[2])<<8 | uint16(input[3])
	aeadID := uint16(input[4])<<8 | uint16(input[5])

	var kem hpke.KEM
	switch kemID {
	case KEMP256:
		kem = hpke.KEM_P256_HKDF_SHA256
	case KEMP384:
		kem = hpke.KEM_P384_HKDF_SHA384
	case KEMP521:
		kem = hpke.KEM_P521_HKDF_SHA512
	case KEMX25519:
		kem = hpke.KEM_X25519_HKDF_SHA256
	case KEMX25519Kyber768:
		kem = hpke.KEM_X25519_KYBER768_DRAFT00
	case KEMXWing:
		kem = hpke.KEM_XWING
	default:
		return hpke.Suite{}, ErrInvalidCipherSuite
	}

	var kdf hpke.KDF
	switch kdfID {
	case 0x0001:
		kdf = hpke.KDF_HKDF_SHA256
	case 0x0002:
		kdf = hpke.KDF_HKDF_SHA384
	case 0x0003:
		kdf = hpke.KDF_HKDF_SHA512
	default:
		return hpke.Suite{}, ErrInvalidCipherSuite
	}

	var aead hpke.AEAD
	switch aeadID {
	case 0x0001:
		aead = hpke.AEAD_AES128GCM
	case 0x0002:
		aead = hpke.AEAD_AES256GCM
	case 0x0003:
		aead = hpke.AEAD_ChaCha20Poly1305
	default:
		return hpke.Suite{}, ErrInvalidCipherSuite
	}

	return hpke.NewSuite(kem, kdf, aead), nil
}

// sealParams holds parsed parameters for a single-shot seal operation.
type sealParams struct {
	kemID     uint16
	suite     hpke.Suite
	seed      [SeedSize]byte // caller-provided deterministic seed
	recipient []byte
	info      []byte
	aad       []byte
	plaintext []byte
}

func (p *hpkePrecompile) parseSealParams(input []byte) (*sealParams, error) {
	// Minimum: 6 (suite) + 32 (seed) + 2 (pkLen) = 40
	if len(input) < 6+SeedSize+2 {
		return nil, ErrInvalidInput
	}

	kemID := uint16(input[0])<<8 | uint16(input[1])

	suite, err := p.parseSuite(input)
	if err != nil {
		return nil, err
	}

	offset := 6

	// Parse 32-byte deterministic seed (mandatory for consensus safety)
	var seed [SeedSize]byte
	copy(seed[:], input[offset:offset+SeedSize])
	offset += SeedSize

	// Parse recipient public key length
	if len(input) < offset+2 {
		return nil, ErrInvalidInput
	}
	pkLen := int(input[offset])<<8 | int(input[offset+1])
	offset += 2

	if len(input) < offset+pkLen {
		return nil, ErrInvalidInput
	}
	recipientPk := input[offset : offset+pkLen]
	offset += pkLen

	// Parse info length
	if len(input) < offset+2 {
		return nil, ErrInvalidInput
	}
	infoLen := int(input[offset])<<8 | int(input[offset+1])
	offset += 2

	var info []byte
	if infoLen > 0 {
		if len(input) < offset+infoLen {
			return nil, ErrInvalidInput
		}
		info = input[offset : offset+infoLen]
		offset += infoLen
	}

	// Parse AAD length
	if len(input) < offset+2 {
		return nil, ErrInvalidInput
	}
	aadLen := int(input[offset])<<8 | int(input[offset+1])
	offset += 2

	var aad []byte
	if aadLen > 0 {
		if len(input) < offset+aadLen {
			return nil, ErrInvalidInput
		}
		aad = input[offset : offset+aadLen]
		offset += aadLen
	}

	return &sealParams{
		kemID:     kemID,
		suite:     suite,
		seed:      seed,
		recipient: recipientPk,
		info:      info,
		aad:       aad,
		plaintext: input[offset:],
	}, nil
}

func (p *hpkePrecompile) singleShotSeal(caller common.Address, input []byte) ([]byte, error) {
	params, err := p.parseSealParams(input)
	if err != nil {
		return nil, err
	}

	// Domain-separate the caller-provided seed by the caller address. Two
	// different contracts using the same raw seed + same recipient pubkey
	// must NOT produce the same ciphertext (that would leak plaintext
	// equality across independent callers). SHA-256 of
	// "HPKE_SEAL_v1" || caller || raw_seed is the effective seed fed to
	// the deterministic reader. Same caller + same raw seed + same
	// recipient still deterministically reproduces the same ciphertext,
	// preserving consensus.
	params.seed = deriveEffectiveSeed(caller, params.seed)

	// CPU is the single source of truth. The previous GPU "fast path" ran a
	// Kyber KEM encapsulation on the accelerator and then THREW THE RESULT
	// AWAY, returning singleShotSealCPU(params) regardless -- pure vestigial
	// work whose only effect was an extra, non-deterministic divergence
	// surface. The full HPKE seal (KEM encap -> HKDF key schedule -> AEAD)
	// runs on circl, deterministically, for every validator.
	return p.singleShotSealCPU(params)
}

// deriveEffectiveSeed domain-separates the caller-provided HPKE seed by
// the calling contract's address. Prevents cross-caller seed reuse from
// leaking plaintext equality when two contracts happen to choose the
// same raw seed for the same recipient.
func deriveEffectiveSeed(caller common.Address, raw [SeedSize]byte) [SeedSize]byte {
	h := sha256.New()
	h.Write([]byte("HPKE_SEAL_v1"))
	h.Write(caller.Bytes())
	h.Write(raw[:])
	var out [SeedSize]byte
	copy(out[:], h.Sum(nil))
	return out
}

func (p *hpkePrecompile) singleShotSealCPU(params *sealParams) ([]byte, error) {
	kem, _, _ := params.suite.Params()
	pk, err := kem.Scheme().UnmarshalBinaryPublicKey(params.recipient)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	sender, err := params.suite.NewSender(pk, params.info)
	if err != nil {
		return nil, err
	}

	// Use deterministic RNG derived from caller-provided seed.
	// circl internally calls EncapsulateDeterministically(pk, seed) where
	// seed bytes come from this reader. Identical seeds produce identical
	// enc + shared secret across all validators -- consensus safe.
	rng := newDeterministicReader(params.seed)

	enc, sealer, err := sender.Setup(rng)
	if err != nil {
		return nil, err
	}

	ciphertext, err := sealer.Seal(params.plaintext, params.aad)
	if err != nil {
		return nil, err
	}

	result := make([]byte, len(enc)+len(ciphertext))
	copy(result, enc)
	copy(result[len(enc):], ciphertext)
	return result, nil
}

