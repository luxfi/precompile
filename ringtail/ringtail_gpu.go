// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

// Package ringtailthreshold provides GPU-accelerated Ringtail threshold signature
// verification precompile with Metal/CUDA acceleration via luxcpp/lattice.
package ringtailthreshold

/*
#cgo CFLAGS: -I${SRCDIR}/../../cpp/lattice/include
#cgo LDFLAGS: -L${SRCDIR}/../../cpp/lattice/build-local -lluxlattice -lstdc++
#cgo darwin LDFLAGS: -framework Foundation -framework Metal -framework MetalPerformanceShaders

// Map lux_lattice_ functions (in header) to lattice_ functions (in library)
#define lux_lattice_gpu_available      lattice_gpu_available
#define lux_lattice_get_backend        lattice_get_backend
#define lux_lattice_clear_cache        lattice_clear_cache
#define lux_lattice_ntt_create         lattice_ntt_create
#define lux_lattice_ntt_destroy        lattice_ntt_destroy
#define lux_lattice_ntt_get_params     lattice_ntt_get_params
#define lux_lattice_ntt_forward        lattice_ntt_forward
#define lux_lattice_ntt_inverse        lattice_ntt_inverse
#define lux_lattice_ntt_batch_forward  lattice_ntt_batch_forward
#define lux_lattice_ntt_batch_inverse  lattice_ntt_batch_inverse
#define lux_lattice_poly_mul_ntt       lattice_poly_mul_ntt
#define lux_lattice_poly_mul           lattice_poly_mul
#define lux_lattice_poly_add           lattice_poly_add
#define lux_lattice_poly_sub           lattice_poly_sub
#define lux_lattice_poly_scalar_mul    lattice_poly_scalar_mul
#define lux_lattice_sample_gaussian    lattice_sample_gaussian
#define lux_lattice_sample_uniform     lattice_sample_uniform
#define lux_lattice_sample_ternary     lattice_sample_ternary
#define lux_lattice_find_primitive_root lattice_find_primitive_root
#define lux_lattice_mod_inverse        lattice_mod_inverse
#define lux_lattice_is_ntt_prime       lattice_is_ntt_prime

#include <lux/lattice/lattice.h>
#include <stdlib.h>
#include <string.h>

// Short aliases for Go code readability (hides lux_lattice_ prefix)
// Types
#define NTTContext                 LuxLatticeNTTContext

// Library functions

// NTT context management

// Polynomial operations

// Sampling

// Utility

// Error codes
#define LATTICE_SUCCESS            LUX_LATTICE_SUCCESS
#define LATTICE_ERROR_INVALID_N    LUX_LATTICE_ERROR_INVALID_N
#define LATTICE_ERROR_INVALID_Q    LUX_LATTICE_ERROR_INVALID_Q
#define LATTICE_ERROR_NULL_PTR     LUX_LATTICE_ERROR_NULL_PTR
#define LATTICE_ERROR_GPU          LUX_LATTICE_ERROR_GPU
#define LATTICE_ERROR_MEMORY       LUX_LATTICE_ERROR_MEMORY

// Helper to copy coefficients to C array
static void copy_coeffs_to_c(uint64_t* dest, uint64_t* src, uint32_t n) {
    memcpy(dest, src, n * sizeof(uint64_t));
}

// Helper to copy coefficients from C array
static void copy_coeffs_from_c(uint64_t* dest, uint64_t* src, uint32_t n) {
    memcpy(dest, src, n * sizeof(uint64_t));
}
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"unsafe"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/ringtail/sign"
	"github.com/luxfi/ringtail/threshold"
)

var (
	// GPU-accelerated singleton
	RingtailThresholdPrecompileGPU = &ringtailThresholdPrecompileGPU{}

	_ contract.StatefulPrecompiledContract = &ringtailThresholdPrecompileGPU{}

	// GPU initialization
	gpuOnce      sync.Once
	gpuAvailable bool
	gpuBackend   string

	// NTT context cache (keyed by N and Q)
	nttContexts   = make(map[string]*C.NTTContext)
	nttContextsMu sync.RWMutex

	// Default Ringtail parameters for NTT context
	// These should match the sign.go constants
	DefaultN uint32 = 1024       // Ring dimension
	DefaultQ uint64 = 0x7ffe0001 // NTT-friendly prime
)

// initGPU initializes GPU support for lattice operations
func initGPU() {
	gpuOnce.Do(func() {
		gpuAvailable = bool(C.lattice_gpu_available())
		if gpuAvailable {
			gpuBackend = C.GoString(C.lattice_get_backend())
		} else {
			gpuBackend = "CPU"
		}
	})
}

// GetBackend returns the active backend name ("Metal", "CUDA", or "CPU")
func GetBackend() string {
	initGPU()
	if gpuAvailable {
		return "GPU (" + gpuBackend + ")"
	}
	return "CPU (pure Go)"
}

// IsGPUAvailable returns true if GPU acceleration is available
func IsGPUAvailable() bool {
	initGPU()
	return gpuAvailable
}

// getNTTContext gets or creates an NTT context for the given parameters
func getNTTContext(N uint32, Q uint64) *C.NTTContext {
	key := fmt.Sprintf("%d_%d", N, Q)

	nttContextsMu.RLock()
	ctx, ok := nttContexts[key]
	nttContextsMu.RUnlock()

	if ok {
		return ctx
	}

	// Create new context
	nttContextsMu.Lock()
	defer nttContextsMu.Unlock()

	// Double-check after acquiring write lock
	if ctx, ok := nttContexts[key]; ok {
		return ctx
	}

	ctx = C.lattice_ntt_create(C.uint32_t(N), C.uint64_t(Q))
	if ctx != nil {
		nttContexts[key] = ctx
	}
	return ctx
}

// gpuNTT performs forward NTT using GPU acceleration
func gpuNTT(coeffs []uint64, N uint32, Q uint64) ([]uint64, error) {
	ctx := getNTTContext(N, Q)
	if ctx == nil {
		return nil, errors.New("failed to create NTT context")
	}

	// Allocate C array
	cCoeffs := C.malloc(C.size_t(N) * C.sizeof_uint64_t)
	if cCoeffs == nil {
		return nil, errors.New("failed to allocate memory")
	}
	defer C.free(cCoeffs)

	// Copy coefficients to C array
	cPtr := (*C.uint64_t)(cCoeffs)
	for i := uint32(0); i < N; i++ {
		*(*C.uint64_t)(unsafe.Pointer(uintptr(cCoeffs) + uintptr(i)*8)) = C.uint64_t(coeffs[i])
	}

	// Perform NTT
	ret := C.lattice_ntt_forward(ctx, cPtr, 1)
	if ret != 0 {
		return nil, fmt.Errorf("NTT forward failed with code %d", ret)
	}

	// Copy result back
	result := make([]uint64, N)
	for i := uint32(0); i < N; i++ {
		result[i] = uint64(*(*C.uint64_t)(unsafe.Pointer(uintptr(cCoeffs) + uintptr(i)*8)))
	}

	return result, nil
}

// gpuInverseNTT performs inverse NTT using GPU acceleration
func gpuInverseNTT(coeffs []uint64, N uint32, Q uint64) ([]uint64, error) {
	ctx := getNTTContext(N, Q)
	if ctx == nil {
		return nil, errors.New("failed to create NTT context")
	}

	// Allocate C array
	cCoeffs := C.malloc(C.size_t(N) * C.sizeof_uint64_t)
	if cCoeffs == nil {
		return nil, errors.New("failed to allocate memory")
	}
	defer C.free(cCoeffs)

	// Copy coefficients to C array
	for i := uint32(0); i < N; i++ {
		*(*C.uint64_t)(unsafe.Pointer(uintptr(cCoeffs) + uintptr(i)*8)) = C.uint64_t(coeffs[i])
	}

	// Perform inverse NTT
	cPtr := (*C.uint64_t)(cCoeffs)
	ret := C.lattice_ntt_inverse(ctx, cPtr, 1)
	if ret != 0 {
		return nil, fmt.Errorf("NTT inverse failed with code %d", ret)
	}

	// Copy result back
	result := make([]uint64, N)
	for i := uint32(0); i < N; i++ {
		result[i] = uint64(*(*C.uint64_t)(unsafe.Pointer(uintptr(cCoeffs) + uintptr(i)*8)))
	}

	return result, nil
}

// gpuBatchNTT performs batch forward NTT using GPU acceleration
func gpuBatchNTT(polys [][]uint64, N uint32, Q uint64) ([][]uint64, error) {
	if len(polys) == 0 {
		return nil, nil
	}

	ctx := getNTTContext(N, Q)
	if ctx == nil {
		return nil, errors.New("failed to create NTT context")
	}

	count := len(polys)

	// Allocate C arrays for pointers
	polyPtrs := make([]*C.uint64_t, count)
	cArrays := make([]unsafe.Pointer, count)

	for i, poly := range polys {
		cCoeffs := C.malloc(C.size_t(N) * C.sizeof_uint64_t)
		if cCoeffs == nil {
			// Free previously allocated
			for j := 0; j < i; j++ {
				C.free(cArrays[j])
			}
			return nil, errors.New("failed to allocate memory")
		}
		cArrays[i] = cCoeffs

		// Copy coefficients
		for k := uint32(0); k < N; k++ {
			*(*C.uint64_t)(unsafe.Pointer(uintptr(cCoeffs) + uintptr(k)*8)) = C.uint64_t(poly[k])
		}
		polyPtrs[i] = (*C.uint64_t)(cCoeffs)
	}

	// Cleanup function
	defer func() {
		for _, ptr := range cArrays {
			C.free(ptr)
		}
	}()

	// Perform batch NTT
	ret := C.lattice_ntt_batch_forward(ctx, &polyPtrs[0], C.uint32_t(count))
	if ret != 0 {
		return nil, fmt.Errorf("batch NTT forward failed with code %d", ret)
	}

	// Copy results back
	results := make([][]uint64, count)
	for i := 0; i < count; i++ {
		results[i] = make([]uint64, N)
		for k := uint32(0); k < N; k++ {
			results[i][k] = uint64(*(*C.uint64_t)(unsafe.Pointer(uintptr(cArrays[i]) + uintptr(k)*8)))
		}
	}

	return results, nil
}

// gpuPolyMulNTT performs polynomial multiplication in NTT domain using GPU
func gpuPolyMulNTT(a, b []uint64, N uint32, Q uint64) ([]uint64, error) {
	ctx := getNTTContext(N, Q)
	if ctx == nil {
		return nil, errors.New("failed to create NTT context")
	}

	// Allocate C arrays
	size := C.size_t(N) * C.sizeof_uint64_t
	cA := C.malloc(size)
	cB := C.malloc(size)
	cResult := C.malloc(size)
	if cA == nil || cB == nil || cResult == nil {
		if cA != nil {
			C.free(cA)
		}
		if cB != nil {
			C.free(cB)
		}
		if cResult != nil {
			C.free(cResult)
		}
		return nil, errors.New("failed to allocate memory")
	}
	defer C.free(cA)
	defer C.free(cB)
	defer C.free(cResult)

	// Copy input coefficients
	for i := uint32(0); i < N; i++ {
		*(*C.uint64_t)(unsafe.Pointer(uintptr(cA) + uintptr(i)*8)) = C.uint64_t(a[i])
		*(*C.uint64_t)(unsafe.Pointer(uintptr(cB) + uintptr(i)*8)) = C.uint64_t(b[i])
	}

	// Perform multiplication
	ret := C.lattice_poly_mul_ntt(ctx,
		(*C.uint64_t)(cResult),
		(*C.uint64_t)(cA),
		(*C.uint64_t)(cB))
	if ret != 0 {
		return nil, fmt.Errorf("polynomial multiplication failed with code %d", ret)
	}

	// Copy result back
	result := make([]uint64, N)
	for i := uint32(0); i < N; i++ {
		result[i] = uint64(*(*C.uint64_t)(unsafe.Pointer(uintptr(cResult) + uintptr(i)*8)))
	}

	return result, nil
}

type ringtailThresholdPrecompileGPU struct{}

// Address returns the address of the GPU-accelerated Ringtail precompile
func (p *ringtailThresholdPrecompileGPU) Address() common.Address {
	return ContractRingtailThresholdAddress
}

// RequiredGas calculates the gas required for GPU-accelerated verification
// GPU version has reduced gas cost due to faster execution
func (p *ringtailThresholdPrecompileGPU) RequiredGas(input []byte) uint64 {
	initGPU()
	baseCost := RingtailThresholdGasCost(input)

	// GPU acceleration reduces gas by 40% when available
	if gpuAvailable {
		return baseCost * 60 / 100
	}
	return baseCost
}

// Run implements GPU-accelerated Ringtail threshold signature verification
func (p *ringtailThresholdPrecompileGPU) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	initGPU()

	// Calculate required gas
	gasCost := p.RequiredGas(input)
	if suppliedGas < gasCost {
		return nil, 0, errors.New("out of gas")
	}

	// Input validation
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

	// Verify using GPU-accelerated path if available
	var valid bool
	var err error
	if gpuAvailable {
		valid, err = verifyThresholdSignatureGPU(thresholdVal, totalParties, messageHash, signatureBytes)
	} else {
		// Fall back to CPU implementation
		valid, err = verifyThresholdSignature(thresholdVal, totalParties, messageHash, signatureBytes)
	}

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

// verifyThresholdSignatureGPU verifies a Ringtail threshold signature using GPU acceleration
func verifyThresholdSignatureGPU(thresholdVal, totalParties uint32, messageHash, signatureBytes []byte) (bool, error) {
	// Initialize ring parameters using threshold package
	params, err := threshold.NewParams()
	if err != nil {
		return false, fmt.Errorf("failed to create params: %w", err)
	}

	// Get ring parameters for GPU
	N := uint32(params.R.N())
	Q := params.R.Modulus().Uint64()

	// Deserialize signature components with GPU-accelerated NTT
	sig, groupKey, err := deserializeSignatureGPU(params, signatureBytes, N, Q)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrDeserializationFailed, err)
	}

	// Convert message hash to string for verification
	mu := fmt.Sprintf("%x", messageHash)

	// Verify using the threshold package's Verify function
	// The internal operations will use the ring which may have GPU acceleration
	valid := threshold.Verify(groupKey, mu, sig)

	return valid, nil
}

// deserializeSignatureGPU deserializes threshold signature components with GPU-accelerated NTT
func deserializeSignatureGPU(params *threshold.Params, data []byte, N uint32, Q uint64) (
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

	// GPU-accelerated NTT for c
	cCoeffs := polyToUint64(c, r)
	cNTT, err := gpuNTT(cCoeffs, N, Q)
	if err == nil {
		// Use GPU result
		uint64ToPoly(cNTT, c, r)
	} else {
		// Fall back to CPU
		r.NTT(c, c)
	}
	r.MForm(c, c)

	// Deserialize z vector (N polynomials) with batch GPU NTT
	z := initializeVector(r, sign.N)
	zCoeffs := make([][]uint64, sign.N)
	for i := 0; i < sign.N; i++ {
		if err := deserializePoly(buf, r, z[i]); err != nil {
			return nil, nil, fmt.Errorf("deserialize z[%d]: %w", i, err)
		}
		zCoeffs[i] = polyToUint64(z[i], r)
	}

	// Batch NTT for z vector
	zNTTs, err := gpuBatchNTT(zCoeffs, N, Q)
	if err == nil {
		// Use GPU results
		for i := 0; i < sign.N; i++ {
			uint64ToPoly(zNTTs[i], z[i], r)
		}
	} else {
		// Fall back to CPU
		for i := 0; i < sign.N; i++ {
			r.NTT(z[i], z[i])
		}
	}
	for i := 0; i < sign.N; i++ {
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

	// Deserialize A matrix (M x N) with batch GPU NTT
	A := initializeMatrix(r, sign.M, sign.N)
	aCoeffs := make([][]uint64, sign.M*sign.N)
	idx := 0
	for i := 0; i < sign.M; i++ {
		for j := 0; j < sign.N; j++ {
			if err := deserializePoly(buf, r, A[i][j]); err != nil {
				return nil, nil, fmt.Errorf("deserialize A[%d][%d]: %w", i, j, err)
			}
			aCoeffs[idx] = polyToUint64(A[i][j], r)
			idx++
		}
	}

	// Batch NTT for A matrix
	aNTTs, err := gpuBatchNTT(aCoeffs, N, Q)
	if err == nil {
		idx = 0
		for i := 0; i < sign.M; i++ {
			for j := 0; j < sign.N; j++ {
				uint64ToPoly(aNTTs[idx], A[i][j], r)
				idx++
			}
		}
	} else {
		// Fall back to CPU
		for i := 0; i < sign.M; i++ {
			for j := 0; j < sign.N; j++ {
				r.NTT(A[i][j], A[i][j])
			}
		}
	}
	for i := 0; i < sign.M; i++ {
		for j := 0; j < sign.N; j++ {
			r.MForm(A[i][j], A[i][j])
		}
	}

	// Deserialize bTilde vector (M polynomials in r_xi ring)
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

// polyToUint64 converts a ring polynomial to uint64 slice
func polyToUint64(p ring.Poly, r *ring.Ring) []uint64 {
	n := r.N()
	result := make([]uint64, n)
	// Access coefficients directly from level 0
	for i := 0; i < n; i++ {
		result[i] = p.Coeffs[0][i]
	}
	return result
}

// uint64ToPoly converts uint64 slice to ring polynomial
func uint64ToPoly(coeffs []uint64, p ring.Poly, r *ring.Ring) {
	bigCoeffs := make([]*big.Int, len(coeffs))
	for i, c := range coeffs {
		bigCoeffs[i] = new(big.Int).SetUint64(c)
	}
	r.SetCoefficientsBigint(bigCoeffs, p)
}

// BatchVerifyRingtail verifies multiple Ringtail signatures in parallel using GPU
func BatchVerifyRingtail(signatures, publicKeys [][]byte, messages [][]byte) ([]bool, error) {
	initGPU()

	if len(signatures) != len(publicKeys) || len(signatures) != len(messages) {
		return nil, errors.New("mismatched input lengths")
	}

	results := make([]bool, len(signatures))

	// If GPU is not available, verify sequentially on CPU
	if !gpuAvailable {
		for i := range signatures {
			params, err := threshold.NewParams()
			if err != nil {
				results[i] = false
				continue
			}
			sig, groupKey, err := deserializeSignature(params, signatures[i])
			if err != nil {
				results[i] = false
				continue
			}
			mu := fmt.Sprintf("%x", messages[i])
			results[i] = threshold.Verify(groupKey, mu, sig)
		}
		return results, nil
	}

	// GPU batch verification
	// For GPU path, we can parallelize the NTT operations across all signatures
	params, err := threshold.NewParams()
	if err != nil {
		return nil, fmt.Errorf("failed to create params: %w", err)
	}

	N := uint32(params.R.N())
	Q := params.R.Modulus().Uint64()

	for i := range signatures {
		sig, groupKey, err := deserializeSignatureGPU(params, signatures[i], N, Q)
		if err != nil {
			results[i] = false
			continue
		}
		mu := fmt.Sprintf("%x", messages[i])
		results[i] = threshold.Verify(groupKey, mu, sig)
	}

	return results, nil
}

// MatrixVectorMulGPU performs matrix-vector multiplication using GPU
func MatrixVectorMulGPU(matrix [][]uint64, vector []uint64, N uint32, Q uint64) ([]uint64, error) {
	if !gpuAvailable {
		return nil, errors.New("GPU not available")
	}

	rows := len(matrix)
	cols := len(matrix[0])
	if cols != len(vector) {
		return nil, errors.New("dimension mismatch")
	}

	result := make([]uint64, rows)

	// Perform row-by-row dot products using GPU polynomial multiplication
	for i := 0; i < rows; i++ {
		rowSum := make([]uint64, N)
		for j := 0; j < cols; j++ {
			// Multiply matrix[i][j] by vector[j]
			// This is element-wise multiplication in NTT domain
			prod, err := gpuPolyMulNTT(matrix[i], vector, N, Q)
			if err != nil {
				return nil, err
			}
			// Accumulate
			for k := range rowSum {
				sum := rowSum[k] + prod[k]
				if sum >= Q {
					sum -= Q
				}
				rowSum[k] = sum
			}
		}
		// Store first coefficient as result (for simple representation)
		result[i] = rowSum[0]
	}

	return result, nil
}

// ClearGPUCache clears GPU context caches
func ClearGPUCache() {
	nttContextsMu.Lock()
	defer nttContextsMu.Unlock()

	for _, ctx := range nttContexts {
		C.lattice_ntt_destroy(ctx)
	}
	nttContexts = make(map[string]*C.NTTContext)

	C.lattice_clear_cache()
}
