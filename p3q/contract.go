// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package p3q implements the EVM precompile at slot 0x012205 for P3Q
// — "Post-Quantum Pulsar Proof" — the on-chain Pulsar / FIPS 204
// ML-DSA threshold-signature verifier.
//
// Canonical reference: HANZO-CRYPTO-SUITE §5.2 + LP-218 + ROADMAP
// §B.11. P3Q is the Solidity-callable verifier shim for the rollup-
// commit pattern of LP-218: a Tier-3 rollup sequencer Pulsar-threshold-
// signs the tuple (prev_root, new_root, batch_hash), packs the
// signature into a RollupBatchTx, and the parent L1 verifies the
// signature via this precompile inside normal block validation.
//
// Cryptographically, Pulsar's headline Class N1 claim is that a
// threshold-ceremony signature is byte-equal to a single-party
// FIPS 204 ML-DSA signature on the same message and group public key.
// Therefore this precompile's verifier core IS the FIPS 204 ML-DSA
// verifier — there is no Pulsar-specific verification logic. The
// dispatch goes through luxfi/crypto/mldsa.VerifySignatureCtx, which
// is a thin alias over cloudflare/circl mldsa{44,65,87} (the FIPS 204
// §6.3 verifier). One verifier, two import seams, byte-equal output.
//
// LP-4200 unified PQCrypto block:
//
//	0x012201 = ML-KEM            (Module-LWE KEM, FIPS 203)
//	0x012202 = ML-DSA            (Module-LWE single-party signature, FIPS 204)
//	0x012203 = SLH-DSA           (hash-based signature, FIPS 205)
//	0x012204 = Pulsar            (Module-LWE threshold, FIPS 204 byte-equal)
//	0x012205 = P3Q               ← this precompile (LP-218 rollup-commit verifier)
//	0x012206 = Corona            (Ring-LWE threshold)
//	0x012207 = Magnetar          (SLH-DSA threshold, FIPS 205 byte-equal)
//	0x012208 = HQC               (code-based KEM, family-disjoint backup)
//
// Relationship to the Pulsar precompile at 0x012204:
//
//   - 0x012204 (Pulsar) is the generic Pulsar / threshold-FIPS-204
//     verifier. Wire: [mode][pubkey][msg_len][msg][sig]. Accepts
//     arbitrary-length messages. Use for: any Pulsar-signed payload
//     that needs Solidity-callable verification.
//   - 0x012205 (P3Q) is the rollup-commit-specialised verifier of
//     LP-218. Wire: [mode][pulsarSigLen][pulsarSig][groupPubKeyLen]
//     [groupPubKey][messageHash:32]. The message is a fixed 32-byte
//     hash. Use for: the LP-218 rollup pattern (rollup sequencer
//     Pulsar-signs (prev_root || new_root || batch_hash)).
//
// The two precompiles share a common verifier core but serve distinct
// consumers — orthogonal slots, orthogonal wire formats, one and one
// way to do each (HANZO-CRYPTO-SUITE §5.2: "P3Q is a new primitive at
// its own slot, not bolted onto existing ZK or Pulsar").
//
// Wire format (single-call interface, no function selector):
//
//	[ 1 byte  ] kind (0x01 Pulsar / 0x02 Corona / 0x03 Magnetar)
//	[ 1 byte  ] mode (primitive-specific level — for Pulsar:
//	                  0x44 / 0x65 / 0x87 ML-DSA parameter set)
//	[ 4 bytes ] pulsarSig length (big-endian uint32)
//	[ N bytes ] pulsarSig                    (length = previous field)
//	[ 4 bytes ] groupPubKey length (big-endian uint32)
//	[ M bytes ] groupPubKey                  (length = previous field)
//	[ 32 bytes ] messageHash                  (32-byte digest)
//
// Output: 32-byte EVM-ABI-encoded bool. Last byte is 0x01 on
// successful verification, 0x00 on any verification failure (including
// malformed input, mode mismatch, length mismatch, signature size
// mismatch, public-key size mismatch, FIPS 204 verifier reject).
//
// Returns `(out, gasLeft, nil)` on every well-gas-supplied call: the
// boolean result is conveyed via the output word, never via the Go
// error. This matches the LP-218 §"Failure modes" semantics — the
// precompile reports verification outcome without reverting, so the
// caller (Solidity contract) decides whether `false` is fatal.
//
// Gas cost: BaseVerifyGas + PerByteGas * len(input). The 50_000 base
// is the LP-218 calibration (10x BLS verify ≈ 5_000 gas; 17x ecrecover
// ≈ 3_000 gas) reflecting the inherent cost of ML-DSA lattice
// verification (NTT inverse + matrix-vector multiplication mod q).
// The per-byte adder covers serialization / hashing overhead. At a
// canonical ML-DSA-65 payload (1952-byte pk + 3309-byte sig + 32-byte
// hash + 9-byte framing = 5302 bytes) the total gas is
// 50_000 + 5302 * 10 = 103_020 gas — well under the 12M C-Chain block
// gas limit (per contract.FeeConfigReporter audit at 117 verifies per
// block).
//
// Domain separation: every P3Q verify binds the FIPS 204 context
// string `lux-evm-precompile-p3q-v1`. Mismatched context between
// signer and verifier causes the FIPS 204 verifier to reject — this
// prevents cross-precompile replay where a Pulsar signature minted
// for the generic 0x012204 path is re-submitted to the rollup-commit
// 0x012205 path. The signer SHOULD set ctx = "lux-evm-precompile-p3q-v1"
// when producing rollup-commit signatures destined for on-chain P3Q
// verification.
//
// Constant-time properties: P3Q operates on PUBLIC calldata — both
// the signature and the public key are observable on-chain. The CT
// concern is therefore not confidentiality but soundness: no timing
// channel may distinguish an accepting verify from a rejecting verify
// in a way that an adversary could turn into a consensus-relevant
// oracle. The FIPS 204 verifier is constant-time per FIPS 204 §6.3 and
// cloudflare/circl's documented CT contract; we forward that property
// without introducing data-dependent branches at the precompile layer.
// The only branches in Run are on PUBLIC mode/length fields, which is
// allowed under the CT contract.
package p3q

import (
	"encoding/binary"
	"errors"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// ContractP3QVerifyAddress is the canonical LP-4200 slot for P3Q per
// HANZO-CRYPTO-SUITE §5.2 and LP-218.
var ContractP3QVerifyAddress = common.HexToAddress("0x0000000000000000000000000000000000012205")

// P3QVerifyPrecompile is the singleton instance bound to slot
// 0x012205 by package init() in module.go.
var P3QVerifyPrecompile = &p3qVerifyPrecompile{}

var _ contract.StatefulPrecompiledContract = &p3qVerifyPrecompile{}

// Wire format size constants.
const (
	// KindByte is the single-byte P3Q family discriminator at offset 0
	// of the calldata per LP-218 §"Precompile wire format" (decomplected
	// 2026-06-03 — slot 0x012205 hosts the unified P3Q verifier family;
	// dispatch on the kind byte selects which lattice/hash primitive
	// performs the verify).
	KindByte = 1

	// ModeByte is the primitive-specific parameter-set identifier at
	// offset 1 of the calldata (post-kind). For KindPulsar / KindCorona,
	// this names the FIPS 204 ML-DSA parameter set (44/65/87). For
	// KindMagnetar, this names the FIPS 205 SLH-DSA parameter set.
	ModeByte = 1

	// LengthFieldSize is the byte width of each big-endian uint32
	// length field embedded in the wire format.
	LengthFieldSize = 4

	// MessageHashSize is the byte width of the fixed messageHash field
	// per LP-218 (the precompile binds a 32-byte digest, not a
	// variable-length message — that is the distinguishing feature of
	// P3Q vs the generic Pulsar precompile at 0x012204).
	MessageHashSize = 32

	// MinInputLength is the smallest structurally valid input:
	// 1 kind + 1 mode + 4 sig_len + 0 sig + 4 pk_len + 0 pk + 32 hash.
	// A zero-length signature or zero-length public key cannot
	// possibly verify (FIPS 204 requires both to be non-empty), but
	// the structural check is constant-time over PUBLIC lengths and
	// the FIPS 204 verifier surfaces the actual rejection.
	MinInputLength = KindByte + ModeByte + LengthFieldSize + LengthFieldSize + MessageHashSize
)

// P3Q family kinds per LP-218 / LP-220. Slot 0x012205 hosts a unified
// verifier; the kind byte at offset 0 of the wire format selects
// which primitive performs the verify. Decomplection of 2026-06-03
// collapsed the prior sibling-slots model (LP-220 §"Architectural
// decision — single slot, kind-byte dispatch") into one slot.
//
// Today this precompile fully implements KindPulsar (FIPS 204 ML-DSA
// byte-equal output via Pulsar threshold ceremony). KindCorona and
// KindMagnetar reserve their slot in the dispatch table but return
// abiFalse via the NotImplemented path until their lattice-threshold
// libraries land (see LP-220 §"Per-kind specs").
const (
	KindPulsar   uint8 = 0x01 // FIPS 204 ML-DSA (Module-LWE threshold, byte-equal)
	KindCorona   uint8 = 0x02 // Ring-LWE threshold (Corona eprint 2024/1113)
	KindMagnetar uint8 = 0x03 // FIPS 205 SLH-DSA (hash-based threshold)
)

// ML-DSA parameter-set identifiers. Wire bytes match the canonical
// FIPS 204 mode numbering used across the Lux precompile family
// (0x012202 ML-DSA, 0x012204 Pulsar). Aligning with sibling precompiles
// keeps client tooling uniform.
const (
	ModeMLDSA44 uint8 = 0x44 // NIST PQ Category 2
	ModeMLDSA65 uint8 = 0x65 // NIST PQ Category 3 (Lux production target)
	ModeMLDSA87 uint8 = 0x87 // NIST PQ Category 5
)

// FIPS 204 byte-size constants per parameter set (FIPS 204 Table 2).
// Mirrored from the Pulsar precompile at 0x012204 — same lattice,
// same byte layout, same sizes.
const (
	MLDSA44PublicKeySize = 1312
	MLDSA44SignatureSize = 2420

	MLDSA65PublicKeySize = 1952
	MLDSA65SignatureSize = 3309

	MLDSA87PublicKeySize = 2592
	MLDSA87SignatureSize = 4627
)

// Gas schedule per LP-218 §"Honest cost comparison":
//
//	P3Q (Pulsar / ML-DSA-65) | 50,000 gas | ~50 μs Blackwell | ~80 μs CPU
//	BLS pairing verify       |  5,000 gas | ~10 μs Blackwell | ~6 ms CPU
//	ecrecover (secp256k1)    |  3,000 gas |  ~3 μs Blackwell | ~10 μs CPU
//
// The 10× factor over BLS reflects lattice verification's inherent
// cost (NTT inverse + matrix-vector mul mod q). The per-byte adder
// covers serialization / wire-format parsing. Calibrated against the
// parity audit (luxfi/threshold parity_test): Pulsar verify
// measures ~0.13-0.17 ms across all N on M1 Max and DGX Spark; at
// 12k gas/ms (geth's published gas-per-millisecond yardstick), that
// is ~1.6-2.0k gas of CPU time, dwarfed by the conservative 50k base.
const (
	BaseVerifyGas uint64 = 50_000
	PerByteGas    uint64 = 10
)

// PrecompileCtx is the FIPS 204 context string bound to every P3Q
// verify call. Distinct from the generic 0x012204 Pulsar precompile's
// context ("lux-evm-precompile-pulsar-v1") so a signature minted for
// one slot cannot be replayed against the other.
//
// The context is a public, constant byte string — exposing it does not
// weaken the verifier; rather, it forces an attacker to obtain a fresh
// signature under the P3Q context for any on-chain replay attempt.
var PrecompileCtx = []byte("lux-evm-precompile-p3q-v1")

// Error sentinels. Returned only on out-of-gas: any verification
// failure (malformed input, wrong kind, wrong mode, length mismatch,
// FIPS 204 reject) is surfaced as `(out=[0x00…00], nil error)` — the
// Solidity caller observes `false` and decides whether that is fatal.
// This matches LP-218 §"Failure modes": "No revert on cryptographic
// failure — caller decides whether false is fatal."
var (
	ErrInvalidInputLength = errors.New("p3q: invalid input length")
	ErrUnsupportedKind    = errors.New("p3q: unsupported family kind (must be 0x01 Pulsar / 0x02 Corona / 0x03 Magnetar)")
	ErrUnsupportedMode    = errors.New("p3q: unsupported ML-DSA mode (must be 0x44, 0x65, or 0x87)")
	ErrKindNotImplemented = errors.New("p3q: kind reserved but verifier not yet wired (LP-220 follow-up)")
)

type p3qVerifyPrecompile struct{}

// RequiredGas returns BaseVerifyGas + PerByteGas * len(input).
//
// The cost function is monotonic in input length and uniform across
// success / failure paths (per the LP-218 gas-billing contract:
// "audited gas charge"). A short malformed input pays the base; a
// well-formed N-byte input pays base + N * PerByteGas. No reduced
// price for early rejection — uniform billing prevents a gas-side
// channel from leaking which validation stage rejected the input.
func (p *p3qVerifyPrecompile) RequiredGas(input []byte) uint64 {
	return BaseVerifyGas + uint64(len(input))*PerByteGas
}

// modeParams resolves the wire-byte mode to (mldsa.Mode, pkSize,
// sigSize). Returns ErrUnsupportedMode on an unrecognised byte.
func modeParams(mode uint8) (m mldsa.Mode, pkSize, sigSize int, err error) {
	switch mode {
	case ModeMLDSA44:
		return mldsa.MLDSA44, MLDSA44PublicKeySize, MLDSA44SignatureSize, nil
	case ModeMLDSA65:
		return mldsa.MLDSA65, MLDSA65PublicKeySize, MLDSA65SignatureSize, nil
	case ModeMLDSA87:
		return mldsa.MLDSA87, MLDSA87PublicKeySize, MLDSA87SignatureSize, nil
	default:
		return 0, 0, 0, ErrUnsupportedMode
	}
}

// abiFalse returns a fresh 32-byte zero slice — the EVM-ABI encoding
// of `bool false`. Callers may mutate the return value.
func abiFalse() []byte { return make([]byte, 32) }

// abiTrueClone returns a fresh 32-byte slice with the last byte set
// to 0x01 — the EVM-ABI encoding of `bool true`. Callers may mutate
// the return value.
func abiTrueClone() []byte { b := make([]byte, 32); b[31] = 1; return b }

// Run verifies a P3Q-family signature per LP-218 / LP-220. Today only
// KindPulsar (FIPS 204 ML-DSA byte-equal output) is wired; KindCorona
// and KindMagnetar are reserved and return abiFalse until their
// verifiers land.
//
// Wire format (single-call interface, no function selector):
//
//	[ 1 byte  ] kind (0x01 Pulsar / 0x02 Corona / 0x03 Magnetar)
//	[ 1 byte  ] mode (0x44 / 0x65 / 0x87 — primitive-specific)
//	[ 4 bytes ] pulsarSig length  (BE32)
//	[ N bytes ] pulsarSig
//	[ 4 bytes ] groupPubKey length (BE32)
//	[ M bytes ] groupPubKey
//	[ 32 bytes ] messageHash
//
// Output: 32-byte EVM-ABI bool (last byte 0x01 on success, 0x00 on
// any verification failure).
//
// Error returns:
//   - contract.ErrOutOfGas when suppliedGas < RequiredGas(input).
//
// Verification failures (malformed input, mode mismatch, length
// mismatch, FIPS 204 reject) return `(abiFalse, gasLeft, nil)` — the
// LP-218 contract: no revert on cryptographic failure.
func (p *p3qVerifyPrecompile) Run(
	_ contract.AccessibleState,
	_ common.Address,
	_ common.Address,
	input []byte,
	suppliedGas uint64,
	_ bool,
) ([]byte, uint64, error) {
	gas := p.RequiredGas(input)
	remaining, err := contract.DeductGas(suppliedGas, gas)
	if err != nil {
		return nil, 0, err
	}

	// Structural validation — all on PUBLIC fields (kind byte + mode
	// byte + length fields + total length). No data-dependent branches
	// on signature or public-key contents.
	if len(input) < MinInputLength {
		return abiFalse(), remaining, nil
	}

	// Family-kind dispatch per LP-218 / LP-220 §"Single slot, kind-byte
	// dispatch". Today only KindPulsar is wired; KindCorona / KindMagnetar
	// reserve their slot and fall through to abiFalse. Adding their
	// verifier paths is a follow-up that does not change the precompile
	// surface — only the dispatch table grows.
	kind := input[0]
	switch kind {
	case KindPulsar:
		// fall through to the existing FIPS 204 ML-DSA verify path
	case KindCorona, KindMagnetar:
		// Reserved kinds — verifier not yet wired. Return abiFalse
		// (the LP-218 "no revert on cryptographic failure" contract)
		// so callers still see a consistent surface; once the lattice/
		// hash threshold libraries land, this branch routes to its
		// own verifier.
		return abiFalse(), remaining, nil
	default:
		// Unknown kind — abiFalse, same as any malformed input.
		return abiFalse(), remaining, nil
	}

	mode := input[KindByte]
	m, pkSize, sigSize, mErr := modeParams(mode)
	if mErr != nil {
		return abiFalse(), remaining, nil
	}

	// Parse pulsarSig: [4 bytes len][N bytes sig].
	off := KindByte + ModeByte
	if len(input)-off < LengthFieldSize {
		return abiFalse(), remaining, nil
	}
	sigLen := binary.BigEndian.Uint32(input[off : off+LengthFieldSize])
	off += LengthFieldSize
	if uint64(len(input)-off) < uint64(sigLen) {
		return abiFalse(), remaining, nil
	}
	if int(sigLen) != sigSize {
		// Length mismatch against the mode's expected FIPS 204
		// signature size. The FIPS 204 verifier would reject anyway;
		// short-circuit here so we don't risk feeding a wrong-length
		// slice to the underlying primitive.
		return abiFalse(), remaining, nil
	}
	pulsarSig := input[off : off+int(sigLen)]
	off += int(sigLen)

	// Parse groupPubKey: [4 bytes len][M bytes pk].
	if len(input)-off < LengthFieldSize {
		return abiFalse(), remaining, nil
	}
	pkLen := binary.BigEndian.Uint32(input[off : off+LengthFieldSize])
	off += LengthFieldSize
	if uint64(len(input)-off) < uint64(pkLen) {
		return abiFalse(), remaining, nil
	}
	if int(pkLen) != pkSize {
		return abiFalse(), remaining, nil
	}
	groupPubKey := input[off : off+int(pkLen)]
	off += int(pkLen)

	// Parse messageHash: exactly 32 bytes at the tail. The wire layout
	// places the hash AFTER the variable-length blobs so the offset is
	// content-independent (parseable by reading only the length fields,
	// no scanning).
	if len(input)-off < MessageHashSize {
		return abiFalse(), remaining, nil
	}
	messageHash := input[off : off+MessageHashSize]

	// Trailing bytes (off + MessageHashSize < len(input)) are accepted
	// to match the convention used by the sibling STARK-FRI precompile
	// (precompile/starkfri/contract.go::TestStarkFRI_Fuzz_PaddedInput).
	// Padding does not affect verification.

	// Construct typed ML-DSA PublicKey. The mldsa package parses the
	// FIPS 204 packed-pk byte layout into the runtime struct used by
	// the verifier.
	pk, perr := mldsa.PublicKeyFromBytes(groupPubKey, m)
	if perr != nil {
		return abiFalse(), remaining, nil
	}

	// FIPS 204 ML-DSA.Verify under the P3Q domain-separation context.
	if !pk.VerifySignatureCtx(messageHash, pulsarSig, PrecompileCtx) {
		return abiFalse(), remaining, nil
	}
	return abiTrueClone(), remaining, nil
}

// Verify is the in-process Pulsar verification entry-point for callers
// outside the EVM precompile path (chains/zkvm dispatch, off-chain
// pre-checks, tests). Bypasses gas accounting and AccessibleState
// (those concerns belong to the precompile wrapper).
//
// Returns nil on a verifying signature; a typed error otherwise. Uses
// the same FIPS 204 context as the precompile path so off-chain
// pre-checks are byte-identical to on-chain verification.
//
// Pre-conditions:
//   - mode is one of {ModeMLDSA44, ModeMLDSA65, ModeMLDSA87}
//   - len(groupPubKey) matches the mode's pk size
//   - len(pulsarSig) matches the mode's sig size
//   - len(messageHash) is MessageHashSize (32)
//
// Violations of these pre-conditions return a typed error rather than
// a panic.
func Verify(mode uint8, groupPubKey, pulsarSig, messageHash []byte) error {
	m, pkSize, sigSize, err := modeParams(mode)
	if err != nil {
		return err
	}
	if len(groupPubKey) != pkSize {
		return errors.New("p3q: groupPubKey size mismatch")
	}
	if len(pulsarSig) != sigSize {
		return errors.New("p3q: pulsarSig size mismatch")
	}
	if len(messageHash) != MessageHashSize {
		return errors.New("p3q: messageHash must be 32 bytes")
	}
	pk, perr := mldsa.PublicKeyFromBytes(groupPubKey, m)
	if perr != nil {
		return perr
	}
	if !pk.VerifySignatureCtx(messageHash, pulsarSig, PrecompileCtx) {
		return errors.New("p3q: FIPS 204 ML-DSA verify rejected")
	}
	return nil
}

// EncodeInput is a helper for callers (tests, Solidity adapters,
// off-chain pre-flight checks) to serialize (mode, sig, pk, hash) into
// the wire format the precompile expects. The encoder is also the
// canonical reference for the wire layout — any deviation between
// EncodeInput and Run is a bug in one or the other.
//
// EncodeInput targets KindPulsar (the only kind with a wired verifier
// today). For explicit kind selection use EncodeInputKind.
func EncodeInput(mode uint8, pulsarSig, groupPubKey, messageHash []byte) []byte {
	return EncodeInputKind(KindPulsar, mode, pulsarSig, groupPubKey, messageHash)
}

// EncodeInputKind serializes (kind, mode, sig, pk, hash) into the
// canonical LP-218 P3Q wire format with the kind byte at offset 0
// per LP-220 §"Architectural decision — single slot, kind-byte
// dispatch".
func EncodeInputKind(kind, mode uint8, pulsarSig, groupPubKey, messageHash []byte) []byte {
	out := make([]byte, 0, KindByte+ModeByte+LengthFieldSize+len(pulsarSig)+LengthFieldSize+len(groupPubKey)+MessageHashSize)
	out = append(out, kind)
	out = append(out, mode)
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], uint32(len(pulsarSig)))
	out = append(out, b4[:]...)
	out = append(out, pulsarSig...)
	binary.BigEndian.PutUint32(b4[:], uint32(len(groupPubKey)))
	out = append(out, b4[:]...)
	out = append(out, groupPubKey...)
	// messageHash MUST be exactly 32 bytes. If the caller passes a
	// different length, the wire format is malformed; the precompile
	// will reject. Surface that to the caller by writing whatever was
	// passed (no silent padding / truncation).
	out = append(out, messageHash...)
	return out
}
