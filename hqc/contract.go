// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package hqc is the EVM precompile for HQC (Hamming Quasi-Cyclic), the
// NIST PQC4-round selected backup KEM. Code-based, family-disjoint
// from Module-LWE ML-KEM: a structural break in lattice cryptography
// would not compromise HQC, and vice-versa.
//
// Address: 0x0000000000000000000000000000000000012208 (LP-4200 unified
// PQCrypto block, slot following Comet 0x012207).
//
// Operations:
//
//	0x01  Encapsulate — generate ciphertext + shared secret from
//	                    public key. Deterministic from a caller-
//	                    provided 32-byte seed (the same discipline
//	                    as the ML-KEM precompile: on-chain
//	                    determinism via seed, never crypto/rand).
//
// Decapsulate is intentionally excluded: it requires the private key
// in calldata, which is public on-chain. Decapsulation MUST be
// performed off-chain.
//
// LP-0120 §4 (family-disjoint KEM) pins this slot.
package hqc

import (
	"crypto/sha256"
	"errors"

	"github.com/luxfi/crypto/hqc"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// ContractAddress is the canonical LP-4200 slot for HQC.
var ContractAddress = common.HexToAddress("0x0000000000000000000000000000000000012208")

// HQCPrecompile is the singleton instance.
var HQCPrecompile = &hqcPrecompile{}

var _ contract.StatefulPrecompiledContract = &hqcPrecompile{}

// SeedSize fixed at 32 bytes — same on-chain-determinism contract as
// the ML-KEM precompile.
const SeedSize = 32

// Gas schedule. HQC encapsulation is dominated by polynomial multiplication
// in F_2[X]/(X^n - 1) with n ≈ 17-58 K bits depending on mode. Charge a
// flat base plus a per-byte cost.
const (
	BaseEncapsulateGas uint64 = 25_000
	PerByteGas         uint64 = 10
)

// Error sentinels.
var (
	ErrInvalidInputLength = errors.New("hqc: invalid input length")
	ErrInvalidMode        = errors.New("hqc: invalid mode byte")
	ErrInvalidOperation   = errors.New("hqc: invalid operation byte")
	ErrBackendNotWired    = errors.New("hqc: backend not wired (see luxfi/crypto/hqc; build with hqc_pqclean or hqc_circl)")
)

// deterministicReader — same construction as mlkem's. SHA-256 over
// the caller-supplied 32-byte seed, output stream consumed by the
// underlying HQC encapsulation. Ensures every validator produces
// bit-identical ciphertext (no state divergence).
type deterministicReader struct {
	state [SeedSize]byte
	pos   int
}

func newDeterministicReader(seed []byte) *deterministicReader {
	r := &deterministicReader{}
	copy(r.state[:], seed)
	return r
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	for n := 0; n < len(p); {
		if r.pos == 0 || r.pos >= 32 {
			h := sha256.Sum256(r.state[:])
			r.state = h
			r.pos = 0
		}
		c := copy(p[n:], r.state[r.pos:])
		r.pos += c
		n += c
	}
	return len(p), nil
}

type hqcPrecompile struct{}

// RequiredGas — base + per-byte over the entire input. The
// per-byte term covers seed (32 B), op byte (1 B), mode byte (1 B),
// and the public key (2,249 / 4,522 / 7,245 B by mode).
func (*hqcPrecompile) RequiredGas(input []byte) uint64 {
	return BaseEncapsulateGas + uint64(len(input))*PerByteGas
}

// Wire format
//
//	[1 byte  op]      0x01 = Encapsulate
//	[1 byte  mode]    0x00 = HQC-128, 0x01 = HQC-192, 0x02 = HQC-256
//	[32 bytes seed]   deterministic-rng seed
//	[N bytes  pk]     HQC public key, N = params.PublicKeySize for mode
//
// Returns the ciphertext concatenated with the 64-byte shared secret
// (CT || SS). The 64-byte shared secret is FIPS-style; truncate caller-
// side if a shorter symmetric key is needed.
func (p *hqcPrecompile) Run(
	_ contract.AccessibleState,
	_ common.Address,
	_ common.Address,
	input []byte,
	suppliedGas uint64,
	_ bool,
) ([]byte, uint64, error) {
	gas := p.RequiredGas(input)
	if suppliedGas < gas {
		return nil, 0, contract.ErrOutOfGas
	}
	remaining := suppliedGas - gas

	const minLen = 1 + 1 + SeedSize
	if len(input) < minLen {
		return nil, remaining, ErrInvalidInputLength
	}

	op := input[0]
	modeByte := input[1]
	seed := input[2 : 2+SeedSize]
	pkBytes := input[2+SeedSize:]

	if op != 0x01 {
		return nil, remaining, ErrInvalidOperation
	}

	var mode hqc.Mode
	switch modeByte {
	case 0x00:
		mode = hqc.HQC128
	case 0x01:
		mode = hqc.HQC192
	case 0x02:
		mode = hqc.HQC256
	default:
		return nil, remaining, ErrInvalidMode
	}

	params := hqc.MustParamsFor(mode)
	if len(pkBytes) != params.PublicKeySize {
		return nil, remaining, ErrInvalidInputLength
	}

	pk := &hqc.PublicKey{Mode: mode, Bytes: pkBytes}
	rng := newDeterministicReader(seed)
	ct, ss, err := hqc.Encapsulate(pk, rng)
	if err != nil {
		// Includes the ErrBackendNotWired stub-path failure on hosts
		// without an HQC backend compiled in.
		return nil, remaining, err
	}

	out := make([]byte, 0, len(ct.Bytes)+len(ss))
	out = append(out, ct.Bytes...)
	out = append(out, ss...)
	return out, remaining, nil
}
