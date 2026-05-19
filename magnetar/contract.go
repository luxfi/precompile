// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package magnetar implements the EVM precompile entry for Magnetar,
// public-DKG MPC threshold SLH-DSA. The construction (Pedersen-VSS DKG +
// MPC evaluation over the WOTS+/FORS/Merkle signing tree of FIPS 205)
// produces a signature byte-equal to a single-party FIPS 205 SLH-DSA
// signature on the same message and group public key. Verification IS
// the standard FIPS 205 verifier.
//
// LP-4200 unified PQCrypto block:
//
//	0x012201 = ML-KEM     (Module-LWE KEM, FIPS 203)
//	0x012202 = ML-DSA     (Module-LWE single-party signature, FIPS 204)
//	0x012203 = SLH-DSA    (hash-based single-party signature, FIPS 205)
//	0x012204 = Pulsar     (Module-LWE threshold FIPS 204, byte-equal)
//	0x012205 = P3Q        (strict-PQ STARK)
//	0x012206 = Corona     (Ring-LWE threshold signatures)
//	0x012207 = Magnetar   ← this precompile (hash-based threshold FIPS 205)
//	0x012208 = HQC        (code-based KEM, family-disjoint backup)
//
// Why a distinct slot if the verifier is interchangeable with SLH-DSA's?
//
//  1. Gas-tier separation — contracts that consume threshold-SLH-DSA
//     signatures may want different accounting / metering policies
//     than single-party SLH-DSA verifies.
//  2. Telemetry — on-chain accounting can attribute Magnetar verifies
//     separately from generic SLH-DSA verifies for analytics and
//     validator-set lifecycle dashboards.
//  3. Forward-compatibility — if a future Magnetar version adds a
//     non-FIPS-205 verification path (identifiable-abort hint, an
//     aggregated-cert envelope), the address slot is reserved.
//
// Wire format mirrors the SLH-DSA precompile:
//
//	[1 byte  mode]              FIPS 205 parameter set (see Mode* below)
//	[2 bytes pubkey_len]        big-endian uint16
//	[pubkey_len bytes pubkey]   SLH-DSA public key
//	[2 bytes msg_len]           big-endian uint16
//	[msg_len bytes message]     message bytes
//	[N bytes signature]         SLH-DSA signature, size determined by mode
//
// Returns a 32-byte word (right-padded): 1 if valid, 0 otherwise.
package magnetar

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/luxfi/crypto/slhdsa"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// ContractMagnetarVerifyAddress is the canonical LP-4200 slot for Magnetar.
var ContractMagnetarVerifyAddress = common.HexToAddress("0x0000000000000000000000000000000000012207")

// MagnetarVerifyPrecompile is the singleton instance.
var MagnetarVerifyPrecompile = &magnetarVerifyPrecompile{}

var _ contract.StatefulPrecompiledContract = &magnetarVerifyPrecompile{}

// Errors returned by the precompile.
var (
	ErrInvalidInputLength = contract.ErrInvalidInput
	ErrInvalidMode        = errors.New("magnetar: invalid SLH-DSA mode")
	ErrUnsupportedMode    = errors.New("magnetar: unsupported SLH-DSA mode")
)

// Mode bytes match the SLH-DSA precompile (LP-4200 §SLH-DSA). High
// nibble = hash family (0=SHA2, 1=SHAKE); low nibble = size/variant.
// Magnetar accepts every FIPS 205 parameter set; the MPC ceremony off
// the chain is what differs, the wire output is FIPS 205 byte-equal.
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

// FIPS 205 fixed sizes.
const (
	// Public key sizes (2*n where n is the security parameter).
	SLH128PublicKeySize = 32 // 128-bit security
	SLH192PublicKeySize = 48 // 192-bit security
	SLH256PublicKeySize = 64 // 256-bit security

	// Signature sizes (parameter-set dependent).
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

	// Wire-format header fields.
	ModeByte       = 1 // Mode indicator
	PubKeyLenSize  = 2 // Public key length (uint16)
	MessageLenSize = 2 // Message length (uint16)
)

// Gas costs — match the SLH-DSA precompile's per-mode tiering. The
// underlying verification cost IS standard FIPS 205 verify, so the
// gas should be identical. Telemetry separation (per the doc-comment
// above) is the only operational reason for the dedicated slot.
const (
	SLH128sVerifyBaseGas uint64 = 50_000  // Small, fastest
	SLH128fVerifyBaseGas uint64 = 75_000  // Larger signature
	SLH192sVerifyBaseGas uint64 = 100_000 // Medium
	SLH192fVerifyBaseGas uint64 = 150_000 // Larger
	SLH256sVerifyBaseGas uint64 = 175_000 // Large
	SLH256fVerifyBaseGas uint64 = 250_000 // Largest signature

	// Per-byte gas for message body.
	MagnetarVerifyPerByteGas uint64 = 10

	// Default gas for invalid input (matches slhdsa precompile).
	MagnetarDefaultGas uint64 = 100_000
)

// precompileCtx is the domain-separation context for the Magnetar
// threshold precompile. Different from the single-party SLH-DSA
// precompile context to keep on-chain transcripts unambiguous about
// which ceremony produced the signature. Both contexts verify under
// the standard FIPS 205 verifier; the precompile binds the slot.
var precompileCtx = []byte("lux-evm-precompile-magnetar-v1")

type magnetarVerifyPrecompile struct{}

// Address returns the precompile address.
func (p *magnetarVerifyPrecompile) Address() common.Address {
	return ContractMagnetarVerifyAddress
}

// getModeParams returns the parameters for a given mode byte.
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

// RequiredGas calculates the gas required for Magnetar verification.
// Identical schedule to the SLH-DSA precompile: per-mode base plus a
// per-byte cost over the message body.
func (p *magnetarVerifyPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < ModeByte {
		return MagnetarDefaultGas
	}

	mode := input[0]
	pubKeySize, _, baseGas, _, err := getModeParams(mode)
	if err != nil {
		return MagnetarDefaultGas
	}

	// Need enough bytes to read the pubkey-length header.
	headerSize := ModeByte + PubKeyLenSize
	if len(input) < headerSize {
		return baseGas
	}

	pubKeyLen := int(binary.BigEndian.Uint16(input[ModeByte : ModeByte+PubKeyLenSize]))
	if pubKeyLen != pubKeySize {
		return baseGas // invalid pubkey size for mode
	}

	msgLenOffset := headerSize + pubKeyLen
	if len(input) < msgLenOffset+MessageLenSize {
		return baseGas
	}

	msgLen := binary.BigEndian.Uint16(input[msgLenOffset : msgLenOffset+MessageLenSize])

	return baseGas + (uint64(msgLen) * MagnetarVerifyPerByteGas)
}

// Run verifies a Magnetar threshold-SLH-DSA signature.
//
// Input format:
//
//	[0]              = mode byte (defines parameter set)
//	[1:3]            = public key length as uint16
//	[3:pubKeyEnd]    = public key
//	[pubKeyEnd:+2]   = message length as uint16
//	[+2:msgEnd]      = message
//	[msgEnd:...]     = signature
//
// Output: 32-byte word (1 = valid, 0 = invalid).
//
// Under the hood this dispatches to luxfi/crypto/slhdsa.VerifySignatureCtx
// — Magnetar's MPC ceremony guarantees byte-equal output with single-
// party FIPS 205, so the verifier is interchangeable. The dedicated
// slot is what binds the verification to "this signature came from a
// threshold ceremony" for on-chain code that cares about the binding.
func (p *magnetarVerifyPrecompile) Run(
	_ contract.AccessibleState,
	_ common.Address,
	_ common.Address,
	input []byte,
	suppliedGas uint64,
	_ bool,
) ([]byte, uint64, error) {
	gasCost := p.RequiredGas(input)
	remainingGas, err := contract.DeductGas(suppliedGas, gasCost)
	if err != nil {
		return nil, 0, err
	}

	// Minimum: mode byte + pubkey length header.
	minHeader := ModeByte + PubKeyLenSize
	if len(input) < minHeader {
		return nil, remainingGas, fmt.Errorf("%w: need at least %d bytes", ErrInvalidInputLength, minHeader)
	}

	mode := input[0]
	pubKeySize, sigSize, _, slhdsaMode, err := getModeParams(mode)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("%w: 0x%02x", ErrUnsupportedMode, mode)
	}

	pubKeyLen := int(binary.BigEndian.Uint16(input[ModeByte : ModeByte+PubKeyLenSize]))
	if pubKeyLen != pubKeySize {
		return nil, remainingGas, fmt.Errorf("%w: expected pubkey size %d for mode 0x%02x, got %d",
			ErrInvalidInputLength, pubKeySize, mode, pubKeyLen)
	}

	pubKeyStart := ModeByte + PubKeyLenSize
	pubKeyEnd := pubKeyStart + pubKeyLen
	msgLenStart := pubKeyEnd
	msgLenEnd := msgLenStart + MessageLenSize

	if len(input) < msgLenEnd {
		return nil, remainingGas, fmt.Errorf("%w: input too short for message length", ErrInvalidInputLength)
	}

	msgLen := int(binary.BigEndian.Uint16(input[msgLenStart:msgLenEnd]))
	msgStart := msgLenEnd
	msgEnd := msgStart + msgLen
	sigStart := msgEnd
	sigEnd := sigStart + sigSize

	if len(input) < sigEnd {
		return nil, remainingGas, fmt.Errorf("%w: expected at least %d bytes, got %d",
			ErrInvalidInputLength, sigEnd, len(input))
	}

	publicKey := input[pubKeyStart:pubKeyEnd]
	message := input[msgStart:msgEnd]
	signature := input[sigStart:sigEnd]

	pub, err := slhdsa.PublicKeyFromBytes(publicKey, slhdsaMode)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("invalid public key: %w", err)
	}
	valid := pub.VerifySignatureCtx(message, signature, precompileCtx)

	result := make([]byte, 32)
	if valid {
		result[31] = 1
	}
	return result, remainingGas, nil
}

// ModeName returns a human-readable name for the mode byte.
func ModeName(mode uint8) string {
	switch mode {
	case ModeSHA2_128s:
		return "Magnetar-SHA2-128s"
	case ModeSHA2_128f:
		return "Magnetar-SHA2-128f"
	case ModeSHA2_192s:
		return "Magnetar-SHA2-192s"
	case ModeSHA2_192f:
		return "Magnetar-SHA2-192f"
	case ModeSHA2_256s:
		return "Magnetar-SHA2-256s"
	case ModeSHA2_256f:
		return "Magnetar-SHA2-256f"
	case ModeSHAKE_128s:
		return "Magnetar-SHAKE-128s"
	case ModeSHAKE_128f:
		return "Magnetar-SHAKE-128f"
	case ModeSHAKE_192s:
		return "Magnetar-SHAKE-192s"
	case ModeSHAKE_192f:
		return "Magnetar-SHAKE-192f"
	case ModeSHAKE_256s:
		return "Magnetar-SHAKE-256s"
	case ModeSHAKE_256f:
		return "Magnetar-SHAKE-256f"
	default:
		return "unknown"
	}
}
