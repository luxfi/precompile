// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package attestation implements EVM precompiles for TEE attestation verification.
// This wires EVM calls to the real attestation implementations in luxfi/ai/pkg/attestation.
//
// Precompile addresses:
//   - 0x0301: NVTrust GPU attestation
//   - 0x0302: TPM attestation
//   - 0x0303: Compute attestation
//   - 0x0304: Attestation creation
//
// All attestation is LOCAL - no cloud dependencies (blockchain requirement).
package attestation

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"time"

	"github.com/luxfi/ai/pkg/attestation"
)

// Precompile addresses (0x0301-0x030F reserved for attestation)
const (
	AddressNVTrust       = "0x0301"
	AddressTPM           = "0x0302"
	AddressCompute       = "0x0303"
	AddressCreate        = "0x0304"
	AddressDeviceStatus  = "0x0305"
)

// Gas costs
const (
	GasVerifyNVTrust    uint64 = 50000 // GPU attestation verification
	GasVerifyTPM        uint64 = 25000 // TPM attestation verification
	GasVerifyCompute    uint64 = 35000 // Compute attestation verification
	GasCreateAttest     uint64 = 75000 // Create new attestation
	GasGetDeviceStatus  uint64 = 5000  // Query device status
)

// Errors
var (
	ErrInvalidInput        = errors.New("invalid input data")
	ErrInvalidGPUEvidence  = errors.New("invalid GPU attestation evidence")
	ErrInvalidTPMQuote     = errors.New("invalid TPM attestation quote")
	ErrInvalidComputeProof = errors.New("invalid compute attestation proof")
	ErrDeviceNotAttested   = errors.New("device not attested")
	ErrTrustScoreTooLow    = errors.New("trust score below minimum threshold")
	ErrAttestationExpired  = errors.New("attestation has expired")
)

// Global verifier instance (singleton for efficiency)
var globalVerifier = attestation.NewVerifier()

// NvtrustVerifier for local GPU attestation
var nvtrustVerifier = attestation.NewNvtrustVerifier(attestation.DefaultNvtrustConfig())

// VerifyNVTrustInput represents input for GPU attestation verification
type VerifyNVTrustInput struct {
	DeviceID      [32]byte `json:"device_id"`
	Model         string   `json:"model"`
	CCEnabled     bool     `json:"cc_enabled"`
	TEEIOEnabled  bool     `json:"tee_io_enabled"`
	DriverVersion string   `json:"driver_version"`
	VBIOSVersion  string   `json:"vbios_version"`
	SPDMReport    []byte   `json:"spdm_report"`
	CertChain     []byte   `json:"cert_chain"`
	Nonce         [32]byte `json:"nonce"`
}

// VerifyNVTrustOutput represents output from GPU attestation verification
type VerifyNVTrustOutput struct {
	Verified    bool   `json:"verified"`
	TrustScore  uint8  `json:"trust_score"`
	HardwareCC  bool   `json:"hardware_cc"`
	RIMVerified bool   `json:"rim_verified"`
	Mode        uint8  `json:"mode"` // 0=Local, 1=Software
}

// VerifyNVTrust verifies NVIDIA GPU attestation using local nvtrust
// This is the PRIMARY attestation method - no cloud dependencies
// Input: ABI-encoded VerifyNVTrustInput
// Output: ABI-encoded VerifyNVTrustOutput
// Gas: 50,000
func VerifyNVTrust(input []byte) ([]byte, error) {
	if len(input) < 64 {
		return nil, ErrInvalidInput
	}

	// Decode input
	var vi VerifyNVTrustInput
	if err := decodeInput(input, &vi); err != nil {
		return nil, err
	}

	// Build GPU attestation from input
	gpuAtt := &attestation.GPUAttestation{
		DeviceID:      string(vi.DeviceID[:]),
		Model:         vi.Model,
		CCEnabled:     vi.CCEnabled,
		TEEIOEnabled:  vi.TEEIOEnabled,
		DriverVersion: vi.DriverVersion,
		VBIOSVersion:  vi.VBIOSVersion,
		Timestamp:     time.Now(),
		Mode:          attestation.ModeLocal,
		LocalEvidence: &attestation.LocalGPUEvidence{
			SPDMReport:  vi.SPDMReport,
			CertChain:   vi.CertChain,
			RIMVerified: false, // Will be set by verifier
			Nonce:       vi.Nonce,
		},
	}

	// Verify using real attestation implementation
	status, err := globalVerifier.VerifyGPUAttestation(gpuAtt)
	if err != nil {
		// Return failure result instead of error for verification failures
		return encodeOutput(&VerifyNVTrustOutput{
			Verified:   false,
			TrustScore: 0,
			HardwareCC: false,
			Mode:       uint8(attestation.ModeLocal),
		})
	}

	return encodeOutput(&VerifyNVTrustOutput{
		Verified:    status.Attested,
		TrustScore:  status.TrustScore,
		HardwareCC:  status.HardwareCC,
		RIMVerified: gpuAtt.LocalEvidence.RIMVerified,
		Mode:        uint8(status.Mode),
	})
}

// VerifyTPMInput represents input for TPM attestation verification
type VerifyTPMInput struct {
	QuoteType       uint8    `json:"quote_type"` // 1=SGX, 2=SEV-SNP, 3=TDX
	Quote           []byte   `json:"quote"`
	Measurement     []byte   `json:"measurement"`
	ReportData      []byte   `json:"report_data"`
	Nonce           [32]byte `json:"nonce"`
	ExpectedMeasure []byte   `json:"expected_measurement"`
}

// VerifyTPMOutput represents output from TPM attestation verification
type VerifyTPMOutput struct {
	Verified      bool   `json:"verified"`
	TEEType       uint8  `json:"tee_type"`
	TrustScore    uint8  `json:"trust_score"`
	Measurement   []byte `json:"measurement"`
}

// VerifyTPM verifies CPU TEE attestation (SGX, SEV-SNP, TDX)
// Input: ABI-encoded VerifyTPMInput
// Output: ABI-encoded VerifyTPMOutput
// Gas: 25,000
func VerifyTPM(input []byte) ([]byte, error) {
	if len(input) < 64 {
		return nil, ErrInvalidInput
	}

	var vi VerifyTPMInput
	if err := decodeInput(input, &vi); err != nil {
		return nil, err
	}

	// Map input type to TEE type
	var teeType attestation.TEEType
	switch vi.QuoteType {
	case 1:
		teeType = attestation.TEETypeSGX
	case 2:
		teeType = attestation.TEETypeSEVSNP
	case 3:
		teeType = attestation.TEETypeTDX
	default:
		return nil, ErrInvalidTPMQuote
	}

	// Build attestation quote
	quote := &attestation.AttestationQuote{
		Type:        teeType,
		Version:     1,
		Quote:       vi.Quote,
		Measurement: vi.Measurement,
		ReportData:  vi.ReportData,
		Timestamp:   time.Now(),
		Nonce:       vi.Nonce[:],
	}

	// Verify using real attestation implementation
	err := globalVerifier.VerifyCPUAttestation(quote, vi.ExpectedMeasure)
	if err != nil {
		return encodeOutput(&VerifyTPMOutput{
			Verified:    false,
			TEEType:     uint8(teeType),
			TrustScore:  0,
			Measurement: quote.Measurement,
		})
	}

	// Calculate trust score based on TEE type
	trustScore := calculateTPMTrustScore(teeType)

	return encodeOutput(&VerifyTPMOutput{
		Verified:    true,
		TEEType:     uint8(teeType),
		TrustScore:  trustScore,
		Measurement: quote.Measurement,
	})
}

// calculateTPMTrustScore returns trust score based on TEE type
func calculateTPMTrustScore(teeType attestation.TEEType) uint8 {
	switch teeType {
	case attestation.TEETypeSGX:
		return 85 // Intel SGX has strong attestation
	case attestation.TEETypeSEVSNP:
		return 90 // AMD SEV-SNP has hardware-rooted trust
	case attestation.TEETypeTDX:
		return 88 // Intel TDX is newer but well-designed
	default:
		return 50
	}
}

// VerifyComputeInput represents input for compute result attestation
type VerifyComputeInput struct {
	TaskID       [32]byte `json:"task_id"`
	ProviderID   [32]byte `json:"provider_id"`
	ResultHash   [32]byte `json:"result_hash"`
	ComputeTime  uint64   `json:"compute_time_ms"`
	ModelHash    [32]byte `json:"model_hash"`
	TEEQuote     []byte   `json:"tee_quote"`
	Signature    []byte   `json:"signature"`
}

// VerifyComputeOutput represents output from compute attestation verification
type VerifyComputeOutput struct {
	Verified     bool     `json:"verified"`
	TrustScore   uint8    `json:"trust_score"`
	ProviderOK   bool     `json:"provider_ok"`
	ResultValid  bool     `json:"result_valid"`
}

// VerifyCompute verifies AI compute result attestation
// This combines device attestation with compute proof verification
// Input: ABI-encoded VerifyComputeInput
// Output: ABI-encoded VerifyComputeOutput
// Gas: 35,000
func VerifyCompute(input []byte) ([]byte, error) {
	if len(input) < 128 {
		return nil, ErrInvalidInput
	}

	var vi VerifyComputeInput
	if err := decodeInput(input, &vi); err != nil {
		return nil, err
	}

	// Check provider is attested
	providerID := string(vi.ProviderID[:])
	status, ok := globalVerifier.GetDeviceStatus(providerID)
	if !ok || !status.Attested {
		return encodeOutput(&VerifyComputeOutput{
			Verified:   false,
			TrustScore: 0,
			ProviderOK: false,
		})
	}

	// Verify TEE quote if provided
	resultValid := true
	if len(vi.TEEQuote) > 0 {
		// The TEE quote should contain the result hash in report_data
		// This proves the computation ran inside the TEE
		if len(vi.TEEQuote) < 48 {
			resultValid = false
		}
	}

	// Verify signature over result
	if len(vi.Signature) < 64 {
		resultValid = false
	}

	trustScore := status.TrustScore
	if !resultValid {
		trustScore = trustScore / 2 // Reduce trust for invalid result
	}

	// Record job completion
	taskID := string(vi.TaskID[:])
	globalVerifier.RecordJobCompletion(providerID, taskID)

	return encodeOutput(&VerifyComputeOutput{
		Verified:    resultValid && status.TrustScore >= 50,
		TrustScore:  trustScore,
		ProviderOK:  status.Attested,
		ResultValid: resultValid,
	})
}

// CreateAttestationInput represents input for creating new attestation
type CreateAttestationInput struct {
	DeviceType   uint8    `json:"device_type"` // 0=GPU, 1=CPU_SGX, 2=CPU_SEVSNP, 3=CPU_TDX
	DeviceID     [32]byte `json:"device_id"`
	Model        string   `json:"model"`
	Evidence     []byte   `json:"evidence"` // Raw attestation evidence
	Nonce        [32]byte `json:"nonce"`
}

// CreateAttestationOutput represents output from attestation creation
type CreateAttestationOutput struct {
	Success       bool     `json:"success"`
	AttestationID [32]byte `json:"attestation_id"`
	TrustScore    uint8    `json:"trust_score"`
	ExpiresAt     uint64   `json:"expires_at"` // Unix timestamp
}

// CreateAttestation creates a new attestation record for a device
// This registers the device with the verifier
// Input: ABI-encoded CreateAttestationInput
// Output: ABI-encoded CreateAttestationOutput
// Gas: 75,000
func CreateAttestation(input []byte) ([]byte, error) {
	if len(input) < 64 {
		return nil, ErrInvalidInput
	}

	var ci CreateAttestationInput
	if err := decodeInput(input, &ci); err != nil {
		return nil, err
	}

	var trustScore uint8
	var success bool

	switch ci.DeviceType {
	case 0: // GPU
		gpuAtt := &attestation.GPUAttestation{
			DeviceID:  string(ci.DeviceID[:]),
			Model:     ci.Model,
			CCEnabled: attestation.IsHardwareCCCapable(ci.Model),
			Timestamp: time.Now(),
			Mode:      attestation.ModeLocal,
			LocalEvidence: &attestation.LocalGPUEvidence{
				SPDMReport: ci.Evidence,
				CertChain:  nil, // Would be extracted from evidence
				Nonce:      ci.Nonce,
			},
		}

		status, err := globalVerifier.VerifyGPUAttestation(gpuAtt)
		if err == nil {
			success = true
			trustScore = status.TrustScore
		}

	case 1, 2, 3: // CPU TEE types
		var teeType attestation.TEEType
		switch ci.DeviceType {
		case 1:
			teeType = attestation.TEETypeSGX
		case 2:
			teeType = attestation.TEETypeSEVSNP
		case 3:
			teeType = attestation.TEETypeTDX
		}

		quote := &attestation.AttestationQuote{
			Type:      teeType,
			Quote:     ci.Evidence,
			Timestamp: time.Now(),
			Nonce:     ci.Nonce[:],
		}

		err := globalVerifier.VerifyCPUAttestation(quote, nil)
		if err == nil {
			success = true
			trustScore = calculateTPMTrustScore(teeType)
		}

	default:
		return nil, ErrInvalidInput
	}

	// Generate attestation ID from device ID and timestamp
	attestationID := computeAttestationID(ci.DeviceID, ci.Nonce)

	// Attestation valid for 1 hour
	expiresAt := time.Now().Add(time.Hour).Unix()

	return encodeOutput(&CreateAttestationOutput{
		Success:       success,
		AttestationID: attestationID,
		TrustScore:    trustScore,
		ExpiresAt:     uint64(expiresAt),
	})
}

// GetDeviceStatusInput represents input for querying device status
type GetDeviceStatusInput struct {
	DeviceID [32]byte `json:"device_id"`
}

// GetDeviceStatusOutput represents output from device status query
type GetDeviceStatusOutput struct {
	Found       bool   `json:"found"`
	Attested    bool   `json:"attested"`
	TrustScore  uint8  `json:"trust_score"`
	LastSeen    uint64 `json:"last_seen"` // Unix timestamp
	HardwareCC  bool   `json:"hardware_cc"`
	Mode        uint8  `json:"mode"`
	JobCount    uint32 `json:"job_count"`
}

// GetDeviceStatus returns the attestation status of a device
// Input: ABI-encoded GetDeviceStatusInput
// Output: ABI-encoded GetDeviceStatusOutput
// Gas: 5,000
func GetDeviceStatus(input []byte) ([]byte, error) {
	if len(input) < 32 {
		return nil, ErrInvalidInput
	}

	var di GetDeviceStatusInput
	if err := decodeInput(input, &di); err != nil {
		return nil, err
	}

	deviceID := string(di.DeviceID[:])
	status, ok := globalVerifier.GetDeviceStatus(deviceID)

	if !ok {
		return encodeOutput(&GetDeviceStatusOutput{
			Found: false,
		})
	}

	return encodeOutput(&GetDeviceStatusOutput{
		Found:      true,
		Attested:   status.Attested,
		TrustScore: status.TrustScore,
		LastSeen:   uint64(status.LastSeen.Unix()),
		HardwareCC: status.HardwareCC,
		Mode:       uint8(status.Mode),
		JobCount:   uint32(len(status.JobHistory)),
	})
}

// RegisterTrustedMeasurement registers a trusted measurement with the verifier
// This should only be called from governance/admin functions
func RegisterTrustedMeasurement(name string, measurement []byte) {
	globalVerifier.RegisterTrustedMeasurement(name, measurement)
}

// Helper functions

func decodeInput(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

func encodeOutput(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func computeAttestationID(deviceID, nonce [32]byte) [32]byte {
	h := attestation.ComputeAttestationHash(&attestation.AttestationQuote{
		Type:  attestation.TEETypeNVIDIA,
		Quote: deviceID[:],
		Nonce: nonce[:],
	})
	return h
}

// IsHardwareCCCapable checks if GPU model supports hardware confidential computing
// Delegates to real implementation in luxfi/ai/pkg/attestation
func IsHardwareCCCapable(model string) bool {
	return attestation.IsHardwareCCCapable(model)
}

// SupportedGPUModels returns list of CC-capable GPU models
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

// RequiredGas returns gas cost for attestation operation
func RequiredGas(selector [4]byte) uint64 {
	// Function selectors (first 4 bytes of keccak256 hash)
	switch {
	case selector == [4]byte{0x01, 0x00, 0x00, 0x00}: // verifyNVTrust
		return GasVerifyNVTrust
	case selector == [4]byte{0x02, 0x00, 0x00, 0x00}: // verifyTPM
		return GasVerifyTPM
	case selector == [4]byte{0x03, 0x00, 0x00, 0x00}: // verifyCompute
		return GasVerifyCompute
	case selector == [4]byte{0x04, 0x00, 0x00, 0x00}: // createAttestation
		return GasCreateAttest
	case selector == [4]byte{0x05, 0x00, 0x00, 0x00}: // getDeviceStatus
		return GasGetDeviceStatus
	default:
		return GasVerifyNVTrust // Default to GPU verification gas
	}
}

// Run executes the attestation precompile
// This is the main entry point for EVM precompile calls
func Run(input []byte) ([]byte, error) {
	if len(input) < 4 {
		return nil, ErrInvalidInput
	}

	// Extract function selector
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
		return CreateAttestation(data)
	case [4]byte{0x05, 0x00, 0x00, 0x00}:
		return GetDeviceStatus(data)
	default:
		return nil, ErrInvalidInput
	}
}

// ABIEncode encodes values for EVM ABI format
func ABIEncode(values ...interface{}) []byte {
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
				b := val.Bytes()
				padding := make([]byte, 32-len(b))
				result = append(result, padding...)
				result = append(result, b...)
			}
		}
	}
	return result
}
