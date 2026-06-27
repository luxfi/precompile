// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package coronathreshold

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/corona/sign"
	"github.com/luxfi/corona/threshold"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
	"github.com/luxfi/precompile/contract"
)

var (
	// ContractCoronaThresholdAddress is the address of the Corona Module-LWE threshold signature precompile.
	// LP-4200 unified PQCrypto block (Module-LWE threshold, Ringtail/Raccoon): 0x012206.
	// Was 0x020000...000B which collides with FHE precompile space (0x0200...0080+).
	ContractCoronaThresholdAddress = common.HexToAddress("0x0000000000000000000000000000000000012206")

	// Singleton instance
	CoronaThresholdPrecompile = &coronaThresholdPrecompile{}

	_ contract.StatefulPrecompiledContract = &coronaThresholdPrecompile{}

	ErrInvalidInputLength    = contract.ErrInvalidInput
	ErrInvalidThreshold      = errors.New("invalid threshold: t must be > 0 and <= n")
	ErrInvalidSignature      = errors.New("signature verification failed")
	ErrInsufficientParties   = errors.New("insufficient parties for threshold")
	ErrDeserializationFailed = errors.New("failed to deserialize signature components")
)

const (
	// Gas costs for Corona threshold signature verification
	// Based on lattice operations being more expensive than elliptic curve
	CoronaThresholdBaseGas     uint64 = 150_000 // Base cost for threshold verification
	CoronaThresholdPerPartyGas uint64 = 10_000  // Cost per party in threshold

	// Input format constants
	ThresholdSize    = 4  // uint32 threshold t
	TotalPartiesSize = 4  // uint32 total parties n
	MessageHashSize  = 32 // 32-byte message hash

	// Minimum input size: threshold + total parties + message hash + minimal signature
	MinInputSize = ThresholdSize + TotalPartiesSize + MessageHashSize

	// Corona signature component sizes (based on sign.go constants)
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

type coronaThresholdPrecompile struct{}

// Address returns the address of the Corona Module-LWE threshold signature precompile
func (p *coronaThresholdPrecompile) Address() common.Address {
	return ContractCoronaThresholdAddress
}

// RequiredGas calculates the gas required for Corona threshold verification
func (p *coronaThresholdPrecompile) RequiredGas(input []byte) uint64 {
	return CoronaThresholdGasCost(input)
}

// CoronaThresholdGasCost calculates the gas cost for threshold verification
func CoronaThresholdGasCost(input []byte) uint64 {
	if len(input) < MinInputSize {
		return CoronaThresholdBaseGas
	}

	// Extract number of parties from input
	totalParties := binary.BigEndian.Uint32(input[ThresholdSize : ThresholdSize+TotalPartiesSize])

	// Base cost + per-party cost
	return CoronaThresholdBaseGas + (uint64(totalParties) * CoronaThresholdPerPartyGas)
}

// Run implements the Corona threshold signature verification precompile
func (p *coronaThresholdPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	// Calculate required gas
	gasCost := p.RequiredGas(input)
	remainingGas, err := contract.DeductGas(suppliedGas, gasCost)
	if err != nil {
		return nil, 0, err
	}

	// Input format:
	// [0:4]       = threshold t (uint32)
	// [4:8]       = total parties n (uint32)
	// [8:40]      = message hash (32 bytes)
	// [40:...]    = threshold signature (variable, ~4KB for default params)

	if len(input) < MinInputSize {
		return nil, remainingGas, fmt.Errorf("%w: expected at least %d bytes, got %d",
			ErrInvalidInputLength, MinInputSize, len(input))
	}

	// Parse threshold parameters
	thresholdVal := binary.BigEndian.Uint32(input[0:ThresholdSize])
	totalParties := binary.BigEndian.Uint32(input[ThresholdSize : ThresholdSize+TotalPartiesSize])
	messageHash := input[ThresholdSize+TotalPartiesSize : ThresholdSize+TotalPartiesSize+MessageHashSize]

	// Validate threshold
	if thresholdVal == 0 || thresholdVal > totalParties {
		return nil, remainingGas, fmt.Errorf("%w: t=%d, n=%d",
			ErrInvalidThreshold, thresholdVal, totalParties)
	}

	// Extract signature bytes
	signatureBytes := input[MinInputSize:]
	if len(signatureBytes) < ExpectedSignatureSize {
		return nil, remainingGas, fmt.Errorf("%w: expected at least %d bytes, got %d",
			ErrInvalidInputLength, ExpectedSignatureSize, len(signatureBytes))
	}

	// Verify the threshold signature
	valid, err := verifyThresholdSignature(thresholdVal, totalParties, messageHash, signatureBytes)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("verification error: %w", err)
	}

	// Return result as 32-byte word (1 = valid, 0 = invalid)
	result := make([]byte, 32)
	if valid {
		result[31] = 1
	}

	return result, remainingGas, nil
}

// verifyThresholdSignature verifies a Corona threshold signature
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

	// Domain-separate the precompile-level verification context so an
	// off-chain Corona signature produced by consensus/protocol/quasar
	// for a per-block sid cannot be replayed as an on-chain precompile
	// call when the bare message hashes happen to collide. Mirrors the
	// Pulsar precompile's precompileCtx = "lux-evm-precompile-pulsar-v1".
	const precompileCtx = "lux-evm-precompile-corona-v1"
	mu := fmt.Sprintf("%s|%x", precompileCtx, messageHash)

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
	for i := range sign.N {
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
	for i := range sign.M {
		if err := deserializePoly(buf, r_nu, Delta[i]); err != nil {
			return nil, nil, fmt.Errorf("deserialize Delta[%d]: %w", i, err)
		}
	}

	// Deserialize A matrix (M x N)
	A := initializeMatrix(r, sign.M, sign.N)
	for i := range sign.M {
		for j := range sign.N {
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
	for i := range sign.M {
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

// deserializePoly deserializes a polynomial from binary data.
//
// The verifier later calls r.NTT(poly, poly) to convert the coefficient-form
// polynomial into evaluation form, which is where the actual hot-path NTT
// happens. That NTT is performed by the lattice library on coefficients
// stored inside ring.Poly's internal representation.
//
// A prior version of this function called accellattice.NTTForward on a
// separate []uint64 coefficient array, discarded the result, and then did
// r.SetCoefficientsBigint anyway — burning GPU dispatch latency without
// ever consuming the GPU output. There is no byte-format bridge between
// the accel NTT and ring.Poly's internal coefficient layout, so the GPU
// path was unused even on success. Removed; GPU dispatch will be wired
// in once accel publishes a kernel that produces ring.Poly-compatible
// coefficient bytes (or once ring.Poly exposes a SetCoefficientsUint64
// fast-path).
func deserializePoly(buf *bytes.Reader, r *ring.Ring, poly ring.Poly) error {
	coeffs := make([]*big.Int, r.N())
	for i := 0; i < r.N(); i++ {
		coeffBytes := make([]byte, 8) // 64-bit coefficients
		if _, err := buf.Read(coeffBytes); err != nil {
			return fmt.Errorf("failed to read coefficient %d: %w", i, err)
		}
		coeffs[i] = new(big.Int).SetBytes(coeffBytes)
	}
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
	return CoronaThresholdBaseGas + (uint64(parties) * CoronaThresholdPerPartyGas)
}
