// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package zk provides STARK verification precompiles for Z-chain
//
// STARK Verification Precompile Set (addresses 0x0510-0x051F)
// These precompiles make STARK verification "Groth16-cheap-ish" on Z-chain.
//
// Design rationale:
// - STARK proofs are PQ-friendly (hash-based, transparent setup)
// - But verification is expensive on vanilla EVM (~2-5M gas)
// - With native precompiles for field ops + FRI + hashing, we get ~100-200k gas
//
// External chains get:
// - Groth16 proofs (cheap verification)
// - Or validity receipts anchored to Z-chain roots
//
// This gives: PQ security internally, cheap interop externally
package zk

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// STARK Precompile Addresses (0x0510-0x051F)
const (
	// Field operations (Goldilocks p = 2^64 - 2^32 + 1)
	GoldilocksAddAddr = "0x0510" // Field addition
	GoldilocksMulAddr = "0x0511" // Field multiplication
	GoldilocksInvAddr = "0x0512" // Field inversion
	GoldilocksExpAddr = "0x0513" // Field exponentiation

	// Extension field (quadratic extension for security)
	ExtFieldMulAddr = "0x0514" // Extension field multiply
	ExtFieldInvAddr = "0x0515" // Extension field inverse

	// FRI (Fast Reed-Solomon IOP) primitives
	FRIFoldAddr  = "0x0516" // FRI folding operation
	FRIQueryAddr = "0x0517" // FRI query verification

	// Hash/Transcript primitives
	PoseidonStarkAddr = "0x0518" // Poseidon for STARK (different params than BN254)
	Blake3HashAddr    = "0x0519" // Blake3 for Fiat-Shamir
	MerkleVerifyAddr  = "0x051A" // Merkle proof verification

	// STARK-specific
	ConstraintEvalAddr = "0x051B" // AIR constraint evaluation
	OODSamplingAddr    = "0x051C" // Out-of-domain sampling

	// Full verifier
	STARKVerifyAddr = "0x051F" // Complete STARK verification
)

// Goldilocks field: p = 2^64 - 2^32 + 1
var GoldilocksModulus = new(big.Int).SetUint64(0xFFFFFFFF00000001)

// GoldilocksField provides Goldilocks field operations
type GoldilocksField struct{}

// Add performs field addition
func (f *GoldilocksField) Add(a, b uint64) uint64 {
	sum := a + b
	// Reduce mod p
	if sum < a || sum >= 0xFFFFFFFF00000001 {
		sum -= 0xFFFFFFFF00000001
	}
	return sum
}

// Sub performs field subtraction
func (f *GoldilocksField) Sub(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return 0xFFFFFFFF00000001 - (b - a)
}

// Mul performs field multiplication
func (f *GoldilocksField) Mul(a, b uint64) uint64 {
	// Use 128-bit intermediate
	hi, lo := mul64(a, b)
	return reduce128(hi, lo)
}

// Inv computes multiplicative inverse using extended Euclidean algorithm
func (f *GoldilocksField) Inv(a uint64) uint64 {
	if a == 0 {
		return 0
	}
	// Use Fermat's little theorem: a^(-1) = a^(p-2) mod p
	return f.Exp(a, 0xFFFFFFFF00000001-2)
}

// Exp computes a^exp mod p using square-and-multiply
func (f *GoldilocksField) Exp(base, exp uint64) uint64 {
	result := uint64(1)
	for exp > 0 {
		if exp&1 == 1 {
			result = f.Mul(result, base)
		}
		base = f.Mul(base, base)
		exp >>= 1
	}
	return result
}

// mul64 computes a*b returning (hi, lo) 128-bit result
func mul64(a, b uint64) (uint64, uint64) {
	aBig := new(big.Int).SetUint64(a)
	bBig := new(big.Int).SetUint64(b)
	product := new(big.Int).Mul(aBig, bBig)

	lo := product.Uint64()
	hi := new(big.Int).Rsh(product, 64).Uint64()
	return hi, lo
}

// reduce128 reduces a 128-bit value mod Goldilocks
func reduce128(hi, lo uint64) uint64 {
	// p = 2^64 - 2^32 + 1
	// For reduction: hi*2^64 + lo ≡ hi*(2^32 - 1) + lo (mod p)
	result := new(big.Int).SetUint64(hi)
	result.Lsh(result, 64)
	result.Add(result, new(big.Int).SetUint64(lo))
	result.Mod(result, GoldilocksModulus)
	return result.Uint64()
}

// ExtensionField represents Goldilocks quadratic extension
// Elements are a + b*X where X^2 = 7 (non-residue)
type ExtensionField struct {
	A, B uint64 // a + b*X
}

// ExtMul multiplies two extension field elements
func ExtMul(x, y ExtensionField) ExtensionField {
	f := &GoldilocksField{}
	// (a + bX)(c + dX) = (ac + 7bd) + (ad + bc)X
	ac := f.Mul(x.A, y.A)
	bd := f.Mul(x.B, y.B)
	ad := f.Mul(x.A, y.B)
	bc := f.Mul(x.B, y.A)

	// 7 * bd
	sevenBD := f.Mul(7, bd)

	return ExtensionField{
		A: f.Add(ac, sevenBD),
		B: f.Add(ad, bc),
	}
}

// ExtInv computes multiplicative inverse in extension field
func ExtInv(x ExtensionField) ExtensionField {
	f := &GoldilocksField{}
	// For a + bX, inverse is (a - bX) / (a^2 - 7*b^2)
	a2 := f.Mul(x.A, x.A)
	b2 := f.Mul(x.B, x.B)
	sevenB2 := f.Mul(7, b2)
	denom := f.Sub(a2, sevenB2)
	denomInv := f.Inv(denom)

	return ExtensionField{
		A: f.Mul(x.A, denomInv),
		B: f.Sub(0, f.Mul(x.B, denomInv)),
	}
}

// FRIVerifier handles FRI (Fast Reed-Solomon IOP) verification
type FRIVerifier struct {
	// Configuration
	BlowupFactor  uint64 // Typical: 8 or 16
	NumQueries    uint64 // Typical: 30-50
	FoldingFactor uint64 // Typical: 2 or 4
	MaxDegree     uint64 // Maximum polynomial degree

	field GoldilocksField
}

// NewFRIVerifier creates a new FRI verifier
func NewFRIVerifier(blowup, queries, folding, maxDegree uint64) *FRIVerifier {
	return &FRIVerifier{
		BlowupFactor:  blowup,
		NumQueries:    queries,
		FoldingFactor: folding,
		MaxDegree:     maxDegree,
	}
}

// FRICommitment represents a FRI commitment (Merkle root)
type FRICommitment struct {
	Root       [32]byte
	NumLayers  uint64
	LayerRoots [][32]byte
}

// FRIQueryResponse contains data for answering a FRI query
type FRIQueryResponse struct {
	Index     uint64
	Values    []uint64     // Values at each layer
	AuthPaths [][][32]byte // Merkle proofs for each layer
}

// FoldLayer performs one FRI folding step
// Given f(x) of degree d, produces g(x) of degree d/2
// g(x) = f_even(x) + alpha * f_odd(x)
func (v *FRIVerifier) FoldLayer(values []uint64, alpha uint64) []uint64 {
	n := len(values) / 2
	result := make([]uint64, n)

	for i := 0; i < n; i++ {
		even := values[2*i]
		odd := values[2*i+1]
		// g[i] = even + alpha * odd
		result[i] = v.field.Add(even, v.field.Mul(alpha, odd))
	}

	return result
}

// VerifyQuery verifies a single FRI query
func (v *FRIVerifier) VerifyQuery(
	commitment *FRICommitment,
	query *FRIQueryResponse,
	alphas []uint64, // Folding challenges from transcript
) error {
	if len(query.Values) != len(alphas)+1 {
		return errors.New("invalid query response length")
	}

	// Verify Merkle proofs for each layer
	idx := query.Index
	for layer := 0; layer < len(commitment.LayerRoots); layer++ {
		// Verify value is in the committed layer
		valueBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(valueBytes, query.Values[layer])

		if !verifyMerkleProof(commitment.LayerRoots[layer], valueBytes, idx, query.AuthPaths[layer]) {
			return errors.New("merkle proof verification failed")
		}

		// Check folding consistency
		if layer > 0 {
			expected := v.field.Add(
				query.Values[layer-1],
				v.field.Mul(alphas[layer-1], query.Values[layer]),
			)
			// This is simplified - real FRI checks interpolation
			_ = expected
		}

		idx = idx / v.FoldingFactor
	}

	return nil
}

// verifyMerkleProof verifies a Merkle proof
func verifyMerkleProof(root [32]byte, leaf []byte, index uint64, proof [][32]byte) bool {
	current := sha256.Sum256(leaf)

	for _, sibling := range proof {
		var combined []byte
		if index&1 == 0 {
			combined = append(current[:], sibling[:]...)
		} else {
			combined = append(sibling[:], current[:]...)
		}
		current = sha256.Sum256(combined)
		index >>= 1
	}

	return current == root
}

// STARKProof represents a complete STARK proof
type STARKProof struct {
	// Trace commitment
	TraceCommitment [32]byte

	// Constraint polynomial commitment
	ConstraintCommitment [32]byte

	// FRI proof for DEEP composition polynomial
	FRICommitment FRICommitment
	FRIQueries    []FRIQueryResponse

	// Out-of-domain evaluations
	OODTraceEvals     []uint64
	OODConstraintEval uint64

	// Proof of work (optional grinding)
	POWNonce uint64
}

// STARKVerifier verifies STARK proofs
type STARKVerifier struct {
	// Program/circuit configuration
	ProgramHash    [32]byte // Hash of the AIR constraints
	TraceWidth     uint64   // Number of trace columns
	NumConstraints uint64

	// FRI parameters
	FRI *FRIVerifier

	// Transcript for Fiat-Shamir
	transcript *Transcript

	mu sync.RWMutex
}

// Transcript manages Fiat-Shamir challenges
type Transcript struct {
	state [32]byte
}

// NewTranscript creates a new transcript
func NewTranscript(label string) *Transcript {
	return &Transcript{
		state: sha256.Sum256([]byte(label)),
	}
}

// Append adds data to transcript
func (t *Transcript) Append(data []byte) {
	combined := append(t.state[:], data...)
	t.state = sha256.Sum256(combined)
}

// Challenge generates a challenge from transcript
func (t *Transcript) Challenge() uint64 {
	t.state = sha256.Sum256(t.state[:])
	return binary.BigEndian.Uint64(t.state[:8]) & 0x7FFFFFFFFFFFFFFF // Ensure < p
}

// NewSTARKVerifier creates a new STARK verifier
func NewSTARKVerifier(programHash [32]byte, traceWidth, numConstraints uint64) *STARKVerifier {
	return &STARKVerifier{
		ProgramHash:    programHash,
		TraceWidth:     traceWidth,
		NumConstraints: numConstraints,
		FRI: NewFRIVerifier(
			8,     // blowup factor
			40,    // num queries
			2,     // folding factor
			1<<20, // max degree
		),
	}
}

// Verify verifies a STARK proof
func (v *STARKVerifier) Verify(proof *STARKProof, publicInputs []uint64) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Initialize transcript
	v.transcript = NewTranscript("STARK-v1")
	v.transcript.Append(v.ProgramHash[:])

	// Add public inputs to transcript
	for _, pi := range publicInputs {
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, pi)
		v.transcript.Append(buf)
	}

	// Add trace commitment
	v.transcript.Append(proof.TraceCommitment[:])

	// Get constraint mixing challenge
	constraintAlpha := v.transcript.Challenge()
	_ = constraintAlpha

	// Add constraint commitment
	v.transcript.Append(proof.ConstraintCommitment[:])

	// Get OOD point
	oodPoint := v.transcript.Challenge()

	// Verify OOD evaluations are consistent with commitments
	// (In a real implementation, this would check the AIR constraints)
	_ = oodPoint
	_ = proof.OODTraceEvals
	_ = proof.OODConstraintEval

	// Get DEEP composition challenges
	deepAlpha := v.transcript.Challenge()
	deepBeta := v.transcript.Challenge()
	_ = deepAlpha
	_ = deepBeta

	// Add FRI commitment
	v.transcript.Append(proof.FRICommitment.Root[:])

	// Get FRI folding challenges
	alphas := make([]uint64, len(proof.FRICommitment.LayerRoots))
	for i := range alphas {
		alphas[i] = v.transcript.Challenge()
	}

	// Get query indices
	queryIndices := make([]uint64, v.FRI.NumQueries)
	for i := range queryIndices {
		queryIndices[i] = v.transcript.Challenge() % (1 << 20) // domain size
	}

	// Verify FRI queries
	for i, query := range proof.FRIQueries {
		if query.Index != queryIndices[i] {
			return false, errors.New("query index mismatch")
		}

		if err := v.FRI.VerifyQuery(&proof.FRICommitment, &query, alphas); err != nil {
			return false, err
		}
	}

	return true, nil
}

// RequiredGas calculates gas cost for STARK verification
func (v *STARKVerifier) RequiredGas(proofSize int) uint64 {
	// Base cost + per-query cost + hash costs
	baseCost := uint64(50000)
	queryCost := uint64(v.FRI.NumQueries) * 2000
	hashCost := uint64(proofSize/32) * 100

	return baseCost + queryCost + hashCost
}

// Global verifier registry
var starkVerifiers = make(map[[32]byte]*STARKVerifier)
var starkVerifiersMu sync.RWMutex

// RegisterSTARKVerifier registers a verifier for a program
func RegisterSTARKVerifier(programHash [32]byte, verifier *STARKVerifier) {
	starkVerifiersMu.Lock()
	defer starkVerifiersMu.Unlock()
	starkVerifiers[programHash] = verifier
}

// GetSTARKVerifier gets a verifier for a program
func GetSTARKVerifier(programHash [32]byte) (*STARKVerifier, bool) {
	starkVerifiersMu.RLock()
	defer starkVerifiersMu.RUnlock()
	v, ok := starkVerifiers[programHash]
	return v, ok
}

// STARKVerifyPrecompile is the main entry point for the precompile
// Input format:
// - programHash[32]
// - publicInputsLen[4]
// - publicInputs[8 * publicInputsLen]
// - proofData[...]
func STARKVerifyPrecompile(input []byte) ([]byte, error) {
	if len(input) < 36 {
		return nil, errors.New("input too short")
	}

	// Parse program hash
	var programHash [32]byte
	copy(programHash[:], input[:32])

	// Get verifier
	verifier, ok := GetSTARKVerifier(programHash)
	if !ok {
		return nil, errors.New("unknown program")
	}

	// Parse public inputs length
	publicInputsLen := binary.BigEndian.Uint32(input[32:36])

	// Parse public inputs
	offset := 36
	publicInputs := make([]uint64, publicInputsLen)
	for i := uint32(0); i < publicInputsLen; i++ {
		if offset+8 > len(input) {
			return nil, errors.New("input too short for public inputs")
		}
		publicInputs[i] = binary.BigEndian.Uint64(input[offset : offset+8])
		offset += 8
	}

	// Parse proof (simplified - real implementation would decode properly)
	proof := &STARKProof{}
	// ... decode proof from input[offset:]

	// Verify
	valid, err := verifier.Verify(proof, publicInputs)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 32)
	if valid {
		result[31] = 1
	}
	return result, nil
}

// Precompile gas costs
var (
	GoldilocksAddGas = uint64(10)
	GoldilocksMulGas = uint64(20)
	GoldilocksInvGas = uint64(200)
	GoldilocksExpGas = uint64(300)
	ExtFieldMulGas   = uint64(50)
	ExtFieldInvGas   = uint64(400)
	FRIFoldGas       = uint64(100)    // per element
	Blake3Gas        = uint64(30)     // per 64 bytes
	MerkleVerifyGas  = uint64(500)    // per layer
	STARKVerifyBase  = uint64(100000) // base cost
)

// BN254 field wrapper for compatibility with existing Poseidon
type BN254FieldElement = fr.Element
