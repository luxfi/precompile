// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package pulsar implements the EVM precompile entry for Pulsar
// threshold ML-DSA signature verification, the Module-LWE
// FIPS 204-compatible threshold scheme (github.com/luxfi/pulsar,
// formerly github.com/luxfi/pulsar-m).
//
// The cryptographic verification operation is **literally identical**
// to FIPS 204 ML-DSA.Verify -- that's the Class N1 manifesto. Any
// signature produced by a Pulsar threshold ceremony (DKG + Round1 +
// Round2 + Combine) is byte-equal to a single-party FIPS 204
// signature on the same message and group public key. Therefore this
// precompile dispatches to the underlying ML-DSA verifier in
// github.com/luxfi/crypto/mldsa under the hood.
//
// Why have a separate precompile address at all (vs. directing all
// callers to the existing ML-DSA precompile at 0x012202)?
//
//  1. **Gas-tier separation** -- contracts that consume threshold
//     signatures may want different accounting / metering policies
//     than single-party signature verifications.
//  2. **Telemetry** -- on-chain accounting can attribute Pulsar
//     verifies separately from generic ML-DSA verifies for analytics
//     and validator-set lifecycle dashboards.
//  3. **Forward-compatibility** -- if a future Pulsar version adds a
//     non-FIPS-204 verification path (e.g. an identifiable-abort
//     hint, an aggregated-cert envelope), the address slot is
//     reserved.
//
// At present (Pulsar v0.1.x), the precompile is a thin pass-through
// to the ML-DSA verifier with the same wire format. Gas cost matches
// the ML-DSA-65 base tier (Pulsar's production target).
package pulsar

import (
	"errors"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// Pulsar threshold-ML-DSA precompile address. The canonical LP-4200
// unified PQCrypto block reserves this slot for Pulsar.
//
//	0x012201 = ML-KEM
//	0x012202 = ML-DSA (single-party FIPS 204)
//	0x012203 = SLH-DSA
//	0x012204 = Pulsar  ← this precompile (threshold FIPS 204)
var ContractPulsarVerifyAddress = common.HexToAddress("0x0000000000000000000000000000000000012204")

// PulsarVerifyPrecompile is the singleton instance.
var PulsarVerifyPrecompile = &pulsarVerifyPrecompile{}

var (
	_ contract.StatefulPrecompiledContract = &pulsarVerifyPrecompile{}
)

// Errors returned by the precompile.
var (
	ErrInvalidInputLength = contract.ErrInvalidInput
	ErrInvalidMode        = errors.New("invalid Pulsar mode (must be 0x44, 0x65, or 0x87)")
	ErrUnsupportedMode    = errors.New("unsupported Pulsar mode")
	ErrInvalidSignature   = errors.New("Pulsar signature verification failed")
)

// Pulsar parameter sets mirror FIPS 204 ML-DSA's three security
// levels. Wire-format and size constants are identical to ML-DSA.
const (
	ModePulsar44 uint8 = 0x44 // NIST PQ Category 2
	ModePulsar65 uint8 = 0x65 // NIST PQ Category 3 (Lux production target)
	ModePulsar87 uint8 = 0x87 // NIST PQ Category 5
)

const (
	// Pulsar-44 sizes (same as ML-DSA-44 per FIPS 204).
	Pulsar44PublicKeySize = 1312
	Pulsar44SignatureSize = 2420

	// Pulsar-65 sizes.
	Pulsar65PublicKeySize = 1952
	Pulsar65SignatureSize = 3309

	// Pulsar-87 sizes.
	Pulsar87PublicKeySize = 2592
	Pulsar87SignatureSize = 4627

	ModeByte = 1
)

// Gas costs per Pulsar mode. Matches the ML-DSA precompile's
// per-mode costs (same work; same cost).
const (
	Pulsar44VerifyBaseGas uint64 = 75_000
	Pulsar65VerifyBaseGas uint64 = 100_000
	Pulsar87VerifyBaseGas uint64 = 150_000

	PulsarVerifyPerByteGas uint64 = 10
)

// precompileCtx is the domain-separation context for the Pulsar
// threshold precompile. Different from the single-party ML-DSA
// precompile context to keep on-chain transcripts unambiguous about
// which scheme produced the signature.
var precompileCtx = []byte("lux-evm-precompile-pulsar-v1")

type pulsarVerifyPrecompile struct{}

// RequiredGas returns the gas cost for verifying a Pulsar signature.
// Layout matches the ML-DSA precompile: first byte is the mode, then
// pubkey, then message, then signature.
func (p *pulsarVerifyPrecompile) RequiredGas(input []byte) uint64 {
	mode, err := contract.Read(input).Byte()
	if err != nil {
		return Pulsar65VerifyBaseGas // default to mid mode for malformed input
	}
	switch mode {
	case ModePulsar44:
		return Pulsar44VerifyBaseGas + uint64(len(input))*PulsarVerifyPerByteGas
	case ModePulsar65:
		return Pulsar65VerifyBaseGas + uint64(len(input))*PulsarVerifyPerByteGas
	case ModePulsar87:
		return Pulsar87VerifyBaseGas + uint64(len(input))*PulsarVerifyPerByteGas
	default:
		return Pulsar65VerifyBaseGas
	}
}

// Run verifies a Pulsar threshold signature.
//
// Input layout:
//
//	[mode][pubkey][message_len_uint256][message][signature]
//
// The verification operation is `mldsa.VerifyCtx(mode, pubkey, msg,
// precompileCtx, sig)`. By construction this also accepts any
// single-party ML-DSA signature -- Pulsar's wire format is FIPS 204
// byte-equal.
//
// Returns:
//   - empty bytes and nil error on successful verification.
//   - empty bytes and a typed error on any failure.
func (p *pulsarVerifyPrecompile) Run(
	_ contract.AccessibleState,
	_ common.Address,
	_ common.Address,
	input []byte,
	suppliedGas uint64,
	_ bool,
) ([]byte, uint64, error) {
	// Meter once, up front, and report what is left from every exit
	// below. Charging only on the paths that reach the verifier would
	// hand back the caller's full gas for a malformed input -- work
	// done, nothing billed.
	remainingGas, err := contract.DeductGas(suppliedGas, p.RequiredGas(input))
	if err != nil {
		return nil, 0, err
	}
	// input is a window into EVM memory, not a buffer of its own: len is
	// what the caller declared and paid for, cap is the rest of that
	// memory, which the same caller filled with MSTORE. A slice expression
	// reaching past len therefore does not panic, it returns bytes the
	// caller chose, and the verifier answers over material nobody
	// declared. Every field below is taken through the cursor, which
	// bounds each read against the declared length, and every refusal is
	// mapped back to this package's own sentinel so errors.Is answers
	// exactly what it answered before.
	in := contract.Read(input)

	mode, err := in.Byte()
	if err != nil {
		return nil, remainingGas, ErrInvalidInputLength
	}

	var pubSize, sigSize int
	var mldsaMode mldsa.Mode
	switch mode {
	case ModePulsar44:
		pubSize = Pulsar44PublicKeySize
		sigSize = Pulsar44SignatureSize
		mldsaMode = mldsa.MLDSA44
	case ModePulsar65:
		pubSize = Pulsar65PublicKeySize
		sigSize = Pulsar65SignatureSize
		mldsaMode = mldsa.MLDSA65
	case ModePulsar87:
		pubSize = Pulsar87PublicKeySize
		sigSize = Pulsar87SignatureSize
		mldsaMode = mldsa.MLDSA87
	default:
		return nil, remainingGas, ErrInvalidMode
	}

	pubkey, err := in.Bytes(uint64(pubSize))
	if err != nil {
		return nil, remainingGas, ErrInvalidInputLength
	}

	// Message length is a big-endian uint256 of which the low 8 bytes are
	// the length; the high 24 are read and discarded, exactly as before.
	if _, err := in.Bytes(24); err != nil {
		return nil, remainingGas, ErrInvalidInputLength
	}
	mlen, err := in.Uint64()
	if err != nil {
		return nil, remainingGas, ErrInvalidInputLength
	}

	// mlen is attacker-chosen, so msg and sig must both be proved to fit
	// without ever computing mlen+sigSize, which wraps uint64. Taking them
	// as two consecutive reads does that structurally: each is bounded by
	// subtraction on what the cursor still holds, so there is no sum to
	// wrap and nothing left to hand-check.
	msg, err := in.Bytes(mlen)
	if err != nil {
		return nil, remainingGas, ErrInvalidInputLength
	}
	sig, err := in.Bytes(uint64(sigSize))
	if err != nil {
		return nil, remainingGas, ErrInvalidInputLength
	}

	// Bytes past the signature are accepted; that is this format's
	// documented behaviour, which is why in.End() is not called here.

	pk, err := mldsa.PublicKeyFromBytes(pubkey, mldsaMode)
	if err != nil {
		return nil, remainingGas, ErrInvalidSignature
	}
	if !pk.VerifySignatureCtx(msg, sig, precompileCtx) {
		return nil, remainingGas, ErrInvalidSignature
	}
	return nil, remainingGas, nil
}
