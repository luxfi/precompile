// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package attestation implements the EVM precompile (0x0301) for TEE attestation
// verification. It is a thin, STATELESS adapter over the one real verifier in
// the AI precompile block — ai.VerifyTEE (0x0300 selector 0x03) — which checks a
// device certificate chain to an embedded vendor root at the report's own
// timestamp. There is exactly one way to verify a TEE quote across the block.
//
// Design (decomplected from the prior fake duplicate):
//   - Verification is real: a quote either chains to an embedded vendor root or
//     it is rejected. Zero-byte / forged evidence fails closed. There is no
//     "verified-by-default" path.
//   - Verification is deterministic: validity is checked at the report's
//     embedded timestamp (inside ai.verifyAttestation), never the wall clock.
//     The only chain-time input — an attestation's expiry — is taken from the
//     block timestamp passed in from AccessibleState, never time.Now().
//   - Verification is stateless: there is no process-global device registry (the
//     prior mutable map caused consensus splits). A TEE quote is self-contained,
//     so no on-chain registry is required to prevent forgery; none is kept.
//
// Precompile selectors (first 4 bytes of input):
//   - 0x01: VerifyNVTrust   (GPU TEE quote)
//   - 0x02: VerifyTPM       (CPU TEE quote: SGX / SEV-SNP / TDX)
//   - 0x03: VerifyCompute   (AI compute-result TEE quote)
//   - 0x04: CreateAttestation (verify a quote, issue a deterministic record)
//   - 0x05: GetDeviceStatus (no on-chain registry → always not-found)
package attestation

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"math/big"

	evmmath "github.com/luxfi/geth/common/math"

	"github.com/zeebo/blake3"

	"github.com/luxfi/precompile/ai"
	"github.com/luxfi/precompile/contract"
)

// Precompile addresses (0x0301-0x030F reserved for attestation)
const (
	AddressNVTrust      = "0x0301"
	AddressTPM          = "0x0302"
	AddressCompute      = "0x0303"
	AddressCreate       = "0x0304"
	AddressDeviceStatus = "0x0305"
)

// Gas costs
const (
	GasVerifyNVTrust   uint64 = 50000 // GPU attestation verification
	GasVerifyTPM       uint64 = 25000 // TPM attestation verification
	GasVerifyCompute   uint64 = 35000 // Compute attestation verification
	GasCreateAttest    uint64 = 75000 // Create new attestation
	GasGetDeviceStatus uint64 = 5000  // Query device status

	// GasPerByte prices the caller-supplied payload every selector decodes and,
	// for the verifying selectors, parses as a certificate chain. Matches the
	// rate the other size-dependent precompiles here charge.
	GasPerByte uint64 = 10
)

// Deterministic trust scores returned for a verified quote, by TEE flavor. A
// quote that does not verify scores 0.
const (
	trustScoreGPU = 90 // hardware-rooted GPU TEE (NVTrust)
	trustScoreCPU = 85 // CPU TEE (SGX / SEV-SNP / TDX)

	// attestationTTL is how long, in seconds, an issued attestation record is
	// considered valid past the block in which it was created.
	attestationTTL = 3600
)

// Errors
var (
	ErrInvalidInput        = contract.ErrInvalidInput
	ErrInvalidGPUEvidence  = errors.New("invalid GPU attestation evidence")
	ErrInvalidTPMQuote     = errors.New("invalid TPM attestation quote")
	ErrInvalidComputeProof = errors.New("invalid compute attestation proof")
	ErrDeviceNotAttested   = errors.New("device not attested")
	ErrTrustScoreTooLow    = errors.New("trust score below minimum threshold")
	ErrAttestationExpired  = errors.New("attestation has expired")
)

// QuoteInput is the TEE attestation envelope every verifying selector consumes.
// It is the same envelope the canonical verifier (ai.VerifyTEE) checks:
//
//	Receipt   = report(48) || certChainDER   (report = deviceID|timestamp|nonce)
//	Signature = device leaf-cert signature over the 48-byte report
type QuoteInput struct {
	Receipt   []byte `json:"receipt"`
	Signature []byte `json:"signature"`
}

// verifyQuote decodes a QuoteInput and verifies it with the real cert-chain
// verifier. A malformed JSON envelope is a hard input error; any verification
// failure (untrusted chain, bad signature, structurally invalid receipt) is a
// deterministic false, never a revert and never a default-true.
func verifyQuote(data []byte) (QuoteInput, bool, error) {
	var q QuoteInput
	if err := json.Unmarshal(data, &q); err != nil {
		return q, false, ErrInvalidInput
	}
	ok, err := ai.VerifyTEE(q.Receipt, q.Signature)
	if err != nil {
		// Structural failure (short/absent receipt or signature): not verified.
		return q, false, nil
	}
	return q, ok, nil
}

// VerifyNVTrustOutput represents output from GPU attestation verification
type VerifyNVTrustOutput struct {
	Verified    bool  `json:"verified"`
	TrustScore  uint8 `json:"trust_score"`
	HardwareCC  bool  `json:"hardware_cc"`
	RIMVerified bool  `json:"rim_verified"`
	Mode        uint8 `json:"mode"` // 0=Local
}

// VerifyNVTrust verifies a GPU TEE quote via the real cert-chain verifier.
// Gas: 50,000
func VerifyNVTrust(input []byte) ([]byte, error) {
	_, verified, err := verifyQuote(input)
	if err != nil {
		return nil, err
	}
	out := &VerifyNVTrustOutput{Verified: verified}
	if verified {
		out.TrustScore = trustScoreGPU
		out.HardwareCC = true
		out.RIMVerified = true
	}
	return encodeOutput(out)
}

// VerifyTPMOutput represents output from CPU TEE attestation verification
type VerifyTPMOutput struct {
	Verified   bool  `json:"verified"`
	TrustScore uint8 `json:"trust_score"`
}

// VerifyTPM verifies a CPU TEE quote (SGX / SEV-SNP / TDX) via the real
// cert-chain verifier.
// Gas: 25,000
func VerifyTPM(input []byte) ([]byte, error) {
	_, verified, err := verifyQuote(input)
	if err != nil {
		return nil, err
	}
	out := &VerifyTPMOutput{Verified: verified}
	if verified {
		out.TrustScore = trustScoreCPU
	}
	return encodeOutput(out)
}

// VerifyComputeOutput represents output from compute attestation verification
type VerifyComputeOutput struct {
	Verified    bool  `json:"verified"`
	TrustScore  uint8 `json:"trust_score"`
	ResultValid bool  `json:"result_valid"`
}

// VerifyCompute verifies an AI compute-result TEE quote via the real cert-chain
// verifier. The quote is the proof the computation ran inside a genuine TEE.
// Gas: 35,000
func VerifyCompute(input []byte) ([]byte, error) {
	_, verified, err := verifyQuote(input)
	if err != nil {
		return nil, err
	}
	out := &VerifyComputeOutput{Verified: verified, ResultValid: verified}
	if verified {
		out.TrustScore = trustScoreGPU
	}
	return encodeOutput(out)
}

// CreateAttestationOutput represents output from attestation creation
type CreateAttestationOutput struct {
	Success       bool     `json:"success"`
	AttestationID [32]byte `json:"attestation_id"`
	TrustScore    uint8    `json:"trust_score"`
	ExpiresAt     uint64   `json:"expires_at"` // block-time + TTL, deterministic
}

// CreateAttestation verifies a TEE quote and, on success, issues a deterministic
// attestation record. The record is NOT persisted (the precompile is stateless);
// it is returned to the caller. Expiry is the block timestamp + TTL — never the
// wall clock — so every validator computes the same value.
// Gas: 75,000
func CreateAttestation(input []byte, blockTS uint64) ([]byte, error) {
	q, verified, err := verifyQuote(input)
	if err != nil {
		return nil, err
	}
	out := &CreateAttestationOutput{
		Success:       verified,
		AttestationID: attestationID(q.Receipt),
		ExpiresAt:     blockTS + attestationTTL,
	}
	if verified {
		out.TrustScore = trustScoreGPU
	}
	return encodeOutput(out)
}

// GetDeviceStatusInput represents input for querying device status
type GetDeviceStatusInput struct {
	DeviceID [32]byte `json:"device_id"`
}

// GetDeviceStatusOutput represents output from a device status query
type GetDeviceStatusOutput struct {
	Found bool `json:"found"`
}

// GetDeviceStatus reports a device's attestation status. This precompile keeps
// no on-chain device registry (TEE quotes are self-validating and the prior
// process-global registry was a consensus-split hazard), so a status lookup by
// deviceID alone is always not-found. Verify a presented quote with the
// VerifyNVTrust/VerifyTPM/VerifyCompute selectors instead.
// Gas: 5,000
func GetDeviceStatus(input []byte) ([]byte, error) {
	var di GetDeviceStatusInput
	if err := json.Unmarshal(input, &di); err != nil {
		return nil, ErrInvalidInput
	}
	return encodeOutput(&GetDeviceStatusOutput{Found: false})
}

// attestationID derives a deterministic id from the verified quote receipt.
func attestationID(receipt []byte) [32]byte {
	return blake3.Sum256(receipt)
}

// IsHardwareCCCapable reports whether a GPU model supports hardware confidential
// computing. Pure, static lookup — no external dependency.
func IsHardwareCCCapable(model string) bool {
	for _, m := range SupportedGPUModels() {
		if m == model {
			return true
		}
	}
	return false
}

// SupportedGPUModels returns the CC-capable GPU models.
func SupportedGPUModels() []string {
	return []string{
		"H100",
		"H200",
		"B100",
		"B200",
		"GB200",
		"RTX PRO 6000",
	}
}

// RequiredGas returns the gas cost for an attestation call over [input], where
// input carries the 4-byte selector followed by the operation's payload.
//
// The cost has a per-byte term because the work does. Every verifying selector
// JSON-decodes the whole payload and then hands the receipt to ai.VerifyTEE,
// which parses the X.509 chain embedded in it and verifies that chain to a
// vendor root — work that grows with the payload and, for a chain of many
// certificates, faster than linearly. A flat fee over a caller-chosen blob
// prices a megabyte the same as a hundred bytes.
//
// The base fees and the per-byte rate follow the same shape the other
// size-dependent precompiles in this repo use (see mldsa, slhdsa, starkfri).
func RequiredGas(input []byte) uint64 {
	base := GasVerifyNVTrust
	if len(input) >= 4 {
		switch [4]byte(input[:4]) {
		case [4]byte{0x01, 0x00, 0x00, 0x00}: // verifyNVTrust
			base = GasVerifyNVTrust
		case [4]byte{0x02, 0x00, 0x00, 0x00}: // verifyTPM
			base = GasVerifyTPM
		case [4]byte{0x03, 0x00, 0x00, 0x00}: // verifyCompute
			base = GasVerifyCompute
		case [4]byte{0x04, 0x00, 0x00, 0x00}: // createAttestation
			base = GasCreateAttest
		case [4]byte{0x05, 0x00, 0x00, 0x00}: // getDeviceStatus
			base = GasGetDeviceStatus
		}
	}

	n := uint64(len(input))
	if n > (math.MaxUint64-base)/GasPerByte {
		return math.MaxUint64
	}
	return base + n*GasPerByte
}

// Run executes the attestation precompile. blockTS is the deterministic block
// timestamp from AccessibleState, used only for attestation expiry.
func Run(input []byte, blockTS uint64) ([]byte, error) {
	if len(input) < 4 {
		return nil, ErrInvalidInput
	}

	var selector [4]byte
	copy(selector[:], input[:4])
	data := input[4:]

	switch selector {
	case [4]byte{0x01, 0x00, 0x00, 0x00}:
		return VerifyNVTrust(data)
	case [4]byte{0x02, 0x00, 0x00, 0x00}:
		return VerifyTPM(data)
	case [4]byte{0x03, 0x00, 0x00, 0x00}:
		return VerifyCompute(data)
	case [4]byte{0x04, 0x00, 0x00, 0x00}:
		return CreateAttestation(data, blockTS)
	case [4]byte{0x05, 0x00, 0x00, 0x00}:
		return GetDeviceStatus(data)
	default:
		return nil, ErrInvalidInput
	}
}

func encodeOutput(v any) ([]byte, error) {
	return json.Marshal(v)
}

// ABIEncode encodes values for EVM ABI format.
func ABIEncode(values ...any) []byte {
	var result []byte
	for _, v := range values {
		switch val := v.(type) {
		case bool:
			if val {
				result = append(result, make([]byte, 31)...)
				result = append(result, 1)
			} else {
				result = append(result, make([]byte, 32)...)
			}
		case uint8:
			result = append(result, make([]byte, 31)...)
			result = append(result, val)
		case uint32:
			buf := make([]byte, 32)
			binary.BigEndian.PutUint32(buf[28:], val)
			result = append(result, buf...)
		case uint64:
			buf := make([]byte, 32)
			binary.BigEndian.PutUint64(buf[24:], val)
			result = append(result, buf...)
		case [32]byte:
			result = append(result, val[:]...)
		case *big.Int:
			if val == nil {
				result = append(result, make([]byte, 32)...)
			} else {
				// One EVM word, two's complement, for the whole int256/uint256
				// range. Bytes() alone drops the sign — encoding -1 as 1 — and
				// panics on a value wider than 32 bytes, because the padding
				// length goes negative.
				result = append(result, evmmath.U256Bytes(new(big.Int).Set(val))...)
			}
		}
	}
	return result
}
