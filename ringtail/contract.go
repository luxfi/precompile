// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ringtailthreshold

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/lattice/v6/ring"
	"github.com/luxfi/lattice/v6/utils/structs"
	"github.com/luxfi/precompiles/contract"
	"github.com/luxfi/ringtail/sign"
	"github.com/luxfi/ringtail/threshold"
)

var (
	// ContractRingtailThresholdAddress is the address of the Ringtail threshold signature precompile
	ContractRingtailThresholdAddress = common.HexToAddress("0x020000000000000000000000000000000000000B")

	// Singleton instance
	RingtailThresholdPrecompile = &ringtailThresholdPrecompile{}

	_ contract.StatefulPrecompiledContract = &ringtailThresholdPrecompile{}

	ErrInvalidInputLength    = errors.New("invalid input length")
	ErrInvalidThreshold      = errors.New("invalid threshold: t must be > 0 and <= n")
	ErrInvalidSignature      = errors.New("signature verification failed")
	ErrInsufficientParties   = errors.New("insufficient parties for threshold")
	ErrDeserializationFailed = errors.New("failed to deserialize signature components")
)

const (
	// Gas costs for Ringtail threshold signature verification
	// Based on lattice operations being more expensive than elliptic curve
	RingtailThresholdBaseGas     uint64 = 150_000 // Base cost for threshold verification
	RingtailThresholdPerPartyGas uint64 = 10_000  // Cost per party in threshold

	// Input format constants
	ThresholdSize    = 4  // uint32 threshold t
	TotalPartiesSize = 4  // uint32 total parties n
	MessageHashSize  = 32 // 32-byte message hash

	// Minimum input size: threshold + total parties + message hash + minimal signature
	MinInputSize = ThresholdSize + TotalPartiesSize + MessageHashSize

	// Ringtail signature component sizes (based on sign.go constants)
	// These are serialized sizes for the signature components
	PolySize        = 256 // Approximate size per polynomial coefficient
	VectorM         = 8   // M parameter from config
	VectorN         = 7   // N parameter from config
	DeltaVectorSize = VectorM * PolySize
	ZVectorSize     = VectorN * PolySize
	CPolySize       = PolySize

	// Expected signature size: c + z + Delta
	ExpectedSignatureSize = CPolySize + ZVectorSize + DeltaVectorSize
)

type ringtailThresholdPrecompile struct{}

// Address returns the address of the Ringtail threshold signature precompile
func (p *ringtailThresholdPrecompile) Address() common.Address {
	return ContractRingtailThresholdAddress
}

// RequiredGas calculates the gas required for Ringtail threshold verification
func (p *ringtailThresholdPrecompile) RequiredGas(input []byte) uint64 {
	return RingtailThresholdGasCost(input)
}

// RingtailThresholdGasCost calculates the gas cost for threshold verification
func RingtailThresholdGasCost(input []byte) uint64 {
	if len(input) < MinInputSize {
		return RingtailThresholdBaseGas
	}

	// Extract number of parties from input
	totalParties := binary.BigEndian.Uint32(input[ThresholdSize : ThresholdSize+TotalPartiesSize])

	// Base cost + per-party cost
	return RingtailThresholdBaseGas + (uint64(totalParties) * RingtailThresholdPerPartyGas)
}

// Run implements the Ringtail threshold signature verification precompile
func (p *ringtailThresholdPrecompile) Run(
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

	// Input format:
	// [0:4]       = threshold t (uint32)
	// [4:8]       = total parties n (uint32)
	// [8:40]      = message hash (32 bytes)
	// [40:...]    = threshold signature (variable, ~4KB for default params)

	if len(input) < MinInputSize {
		return nil, suppliedGas - gasCost, fmt.Errorf("%w: expected at least %d bytes, got %d",
			ErrInvalidInputLength, MinInputSize, len(input))
	}

	// Parse threshold parameters
	thresholdVal := binary.BigEndian.Uint32(input[0:ThresholdSize])
	totalParties := binary.BigEndian.Uint32(input[ThresholdSize : ThresholdSize+TotalPartiesSize])
	messageHash := input[ThresholdSize+TotalPartiesSize : ThresholdSize+TotalPartiesSize+MessageHashSize]

	// Validate threshold
	if thresholdVal == 0 || thresholdVal > totalParties {
		return nil, suppliedGas - gasCost, fmt.Errorf("%w: t=%d, n=%d",
			ErrInvalidThreshold, thresholdVal, totalParties)
	}

	// Extract signature bytes
	signatureBytes := input[MinInputSize:]
	if len(signatureBytes) < ExpectedSignatureSize {
		return nil, suppliedGas - gasCost, fmt.Errorf("%w: expected at least %d bytes, got %d",
			ErrInvalidInputLength, ExpectedSignatureSize, len(signatureBytes))
	}

	// Verify the threshold signature
	valid, err := verifyThresholdSignature(thresholdVal, totalParties, messageHash, signatureBytes)
	if err != nil {
		return nil, suppliedGas - gasCost, fmt.Errorf("verification error: %w", err)
	}

	// Return result as 32-byte word (1 = valid, 0 = invalid)
	result := make([]byte, 32)
	if valid {
		result[31] = 1
	}

	return result, suppliedGas - gasCost, nil
}

// verifyThresholdSignature verifies a Ringtail threshold signature
func verifyThresholdSignature(thresholdVal, totalParties uint32, messageHash, signatureBytes []byte) (bool, error) {
	// Initialize ring parameters using threshold package
	params, err := threshold.NewParams()
	if err != nil {
		return false, fmt.Errorf("failed to create params: %w", err)
	}

	// Deserialize signature components from bytes
	sig, groupKey, err := deserializeSignature(params, signatureBytes)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrDeserializationFailed, err)
	}

	// Convert message hash to string for verification (matching sign.Verify interface)
	mu := fmt.Sprintf("%x", messageHash)

	// Verify using the threshold package's Verify function
	valid := threshold.Verify(groupKey, mu, sig)

	return valid, nil
}

// deserializeSignature deserializes threshold signature components from bytes
func deserializeSignature(params *threshold.Params, data []byte) (
	*threshold.Signature,
	*threshold.GroupKey,
	error,
) {
	r := params.R
	r_xi := params.RXi
	r_nu := params.RNu

	buf := bytes.NewReader(data)

	// Deserialize c (challenge polynomial)
	c := r.NewPoly()
	if err := deserializePoly(buf, r, c); err != nil {
		return nil, nil, fmt.Errorf("deserialize c: %w", err)
	}
	// c must be in NTT form for VectorPolyMul
	r.NTT(c, c)
	r.MForm(c, c)

	// Deserialize z vector (N polynomials)
	z := initializeVector(r, sign.N)
	for i := 0; i < sign.N; i++ {
		if err := deserializePoly(buf, r, z[i]); err != nil {
			return nil, nil, fmt.Errorf("deserialize z[%d]: %w", i, err)
		}
		// z must be in NTT form for MatrixVectorMul
		r.NTT(z[i], z[i])
		r.MForm(z[i], z[i])
	}

	// Deserialize Delta vector (M polynomials in r_nu ring)
	// Delta stays in coefficient form (used after rounding)
	Delta := initializeVector(r_nu, sign.M)
	for i := 0; i < sign.M; i++ {
		if err := deserializePoly(buf, r_nu, Delta[i]); err != nil {
			return nil, nil, fmt.Errorf("deserialize Delta[%d]: %w", i, err)
		}
	}

	// Deserialize A matrix (M x N)
	A := initializeMatrix(r, sign.M, sign.N)
	for i := 0; i < sign.M; i++ {
		for j := 0; j < sign.N; j++ {
			if err := deserializePoly(buf, r, A[i][j]); err != nil {
				return nil, nil, fmt.Errorf("deserialize A[%d][%d]: %w", i, j, err)
			}
			// A must be in NTT form for MatrixVectorMul
			r.NTT(A[i][j], A[i][j])
			r.MForm(A[i][j], A[i][j])
		}
	}

	// Deserialize bTilde vector (M polynomials in r_xi ring)
	// bTilde stays in coefficient form (used after rounding)
	bTilde := initializeVector(r_xi, sign.M)
	for i := 0; i < sign.M; i++ {
		if err := deserializePoly(buf, r_xi, bTilde[i]); err != nil {
			return nil, nil, fmt.Errorf("deserialize bTilde[%d]: %w", i, err)
		}
	}

	sig := &threshold.Signature{
		C:     c,
		Z:     z,
		Delta: Delta,
	}

	groupKey := &threshold.GroupKey{
		A:      A,
		BTilde: bTilde,
		Params: params,
	}

	return sig, groupKey, nil
}

// deserializePoly deserializes a polynomial from binary data
func deserializePoly(buf *bytes.Reader, r *ring.Ring, poly ring.Poly) error {
	coeffs := make([]*big.Int, r.N())
	for i := 0; i < r.N(); i++ {
		coeffBytes := make([]byte, 8) // 64-bit coefficients
		if _, err := buf.Read(coeffBytes); err != nil {
			return fmt.Errorf("failed to read coefficient %d: %w", i, err)
		}
		coeffs[i] = new(big.Int).SetBytes(coeffBytes)
	}

	// Convert big.Int coefficients to ring polynomial
	r.SetCoefficientsBigint(coeffs, poly)
	return nil
}

// initializeVector creates a vector of polynomials
func initializeVector(r *ring.Ring, size int) structs.Vector[ring.Poly] {
	vec := make(structs.Vector[ring.Poly], size)
	for i := range vec {
		vec[i] = r.NewPoly()
	}
	return vec
}

// initializeMatrix creates a matrix of polynomials
func initializeMatrix(r *ring.Ring, rows, cols int) structs.Matrix[ring.Poly] {
	mat := make(structs.Matrix[ring.Poly], rows)
	for i := range mat {
		mat[i] = make([]ring.Poly, cols)
		for j := range mat[i] {
			mat[i][j] = r.NewPoly()
		}
	}
	return mat
}

// EstimateGas estimates gas for a given number of parties
func EstimateGas(parties uint32) uint64 {
	return RingtailThresholdBaseGas + (uint64(parties) * RingtailThresholdPerPartyGas)
}
