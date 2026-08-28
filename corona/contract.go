// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package coronathreshold

import (
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

	// RingDegree is the number of coefficients in a polynomial of the
	// Corona ring, i.e. threshold.NewParams().R.N(). Pinned against
	// the library in TestExpectedSizeMatchesTheWire.
	RingDegree = 256

	// CoefficientSize is the wire width of one coefficient.
	// deserializePoly reads coefficients as fixed 64-bit big-endian
	// words, so this is 8 and not a function of the modulus.
	CoefficientSize = 8

	// PolyWireSize is one serialized polynomial.
	PolyWireSize = RingDegree * CoefficientSize

	// SignaturePolyCount is the number of polynomials deserializeSignature
	// reads, in wire order: the challenge c, the response vector z
	// (sign.N), the rounding vector Delta (sign.M), the public matrix A
	// (sign.M x sign.N) and the commitment vector bTilde (sign.M).
	//
	// The last two belong to the group key rather than the signature.
	// They travel in the same blob because the precompile is handed no
	// key by any other route -- there is no on-chain registry of Corona
	// group keys, so the caller supplies the key it wants checked
	// against. Soundness therefore rests on the caller's own binding of
	// that key to a validator set, not on this precompile.
	SignaturePolyCount = 1 + sign.N + sign.M + sign.M*sign.N + sign.M

	// ExpectedSignatureSize is the exact byte length of the blob that
	// follows the header. It is exact, not a lower bound: every
	// component is fixed-size, so the signature body has one length and
	// no other.
	ExpectedSignatureSize = SignaturePolyCount * PolyWireSize

	// MaxBilledParties clamps the party count read from calldata before
	// it is multiplied into the fee. `n` is attacker-chosen and the
	// verifier does not consult it (see verifyThresholdSignature: the
	// signature body is a fixed ExpectedSignatureSize and the work is
	// the same for every declared n), so an unclamped multiplier lets a
	// caller quote an arbitrary fee for constant work. Matches the
	// clamp the sibling threshold precompiles apply.
	MaxBilledParties uint32 = 1000
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

// CoronaThresholdGasCost calculates the gas cost for threshold verification.
//
// It reads the declared party count through a cursor, like every other read of
// this calldata. RequiredGas cannot return an error, so a short input bills the
// base — which is what it billed before, and the number is unchanged.
func CoronaThresholdGasCost(input []byte) uint64 {
	in := contract.Read(input)
	if _, err := in.Bytes(ThresholdSize); err != nil {
		return CoronaThresholdBaseGas
	}
	parties, err := in.Uint32()
	if err != nil {
		return CoronaThresholdBaseGas
	}
	// Anything shorter than a full header billed the base before and bills
	// it now; the count is only consulted once the header is whole. Written
	// as a remaining-length test rather than an up-front one so that each
	// refusal above is reachable — a guard that dominates the reads under it
	// makes their branches dead, and a dead branch is a branch no test can
	// hold to anything.
	if in.Len() < MessageHashSize {
		return CoronaThresholdBaseGas
	}
	return EstimateGas(parties)
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
	//
	// Read through a cursor: every bound is the cursor's, none is written
	// here, and an over-read is refused rather than served out of the
	// calldata's spare capacity. See contract/cursor.go.
	in := contract.Read(input)
	thresholdVal, err := in.Uint32()
	if err != nil {
		return nil, remainingGas, fmt.Errorf("%w: threshold: %v", ErrInvalidInputLength, err)
	}
	totalParties, err := in.Uint32()
	if err != nil {
		return nil, remainingGas, fmt.Errorf("%w: party count: %v", ErrInvalidInputLength, err)
	}
	messageHash, err := in.Bytes(MessageHashSize)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("%w: message hash: %v", ErrInvalidInputLength, err)
	}

	// Validate threshold
	if thresholdVal == 0 || thresholdVal > totalParties {
		return nil, remainingGas, fmt.Errorf("%w: t=%d, n=%d",
			ErrInvalidThreshold, thresholdVal, totalParties)
	}

	// The body is a fixed ExpectedSignatureSize. Anything after it is
	// padding this format has always accepted (TestAcceptsTrailingPadding),
	// so take exactly the body and leave the rest — widening or narrowing
	// that is a consensus-visible decision, not a parser's.
	signatureBytes, err := in.Bytes(ExpectedSignatureSize)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("%w: expected at least %d signature bytes, got %d",
			ErrInvalidInputLength, ExpectedSignatureSize, in.Len())
	}

	// Verify the threshold signature
	valid, err := verifyThresholdSignature(messageHash, signatureBytes)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("verification error: %w", err)
	}

	return contract.Checked(valid).Word(), remainingGas, nil
}

// verifyThresholdSignature verifies a Corona threshold signature.
//
// It takes no (t, n): the declared threshold and party count do not
// enter the verification equation. Soundness comes from the aggregated
// signature verifying against the group key that travels with it,
// which a forger cannot produce without t real shares. The header's
// (t, n) are caller metadata, checked only for internal consistency in
// Run, and passing them here would suggest an influence they do not
// have.
func verifyThresholdSignature(messageHash, signatureBytes []byte) (bool, error) {
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

	buf := contract.Read(data)

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
// Coefficients are read through a contract.Cursor, whose Bytes is
// all-or-error by construction.
//
// This function used to read a *bytes.Reader with Read, which reports a
// PARTIAL read as (n < len, nil) and only signals io.EOF once nothing at all
// remains. A truncated blob therefore left the tail of coeffBytes at its
// allocated zero and yielded a coefficient the caller never sent: fabricated
// data accepted as signed material instead of a refusal. io.ReadFull fixed
// that by turning a short read into io.ErrUnexpectedEOF, but it fixed it by
// discipline — the bug was reachable again the moment somebody wrote Read.
// A Cursor cannot short-read: there is no call that returns fewer bytes than
// it was asked for, so the parser is total for the same reason the bounds are
// total, and it is one type rather than two conventions.
func deserializePoly(buf *contract.Cursor, r *ring.Ring, poly ring.Poly) error {
	coeffs := make([]*big.Int, r.N())
	for i := 0; i < r.N(); i++ {
		coeffBytes, err := buf.Bytes(CoefficientSize)
		if err != nil {
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

// EstimateGas is the cost function for a declared party count, and the
// only one: CoronaThresholdGasCost reads `n` off the wire and calls
// through to here, so the quote an off-chain caller gets is by
// construction the fee the EVM deducts. Declared counts above
// MaxBilledParties bill as MaxBilledParties.
func EstimateGas(parties uint32) uint64 {
	return CoronaThresholdBaseGas + uint64(min(parties, MaxBilledParties))*CoronaThresholdPerPartyGas
}
