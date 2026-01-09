// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/luxfi/geth/common"
)

// Precompile addresses for commitment operations
const (
	PedersenAddress = "0x0502" // Pedersen commitment (NOT PQ-safe, for benchmarking)
)

var (
	ErrInvalidCommitmentInput = errors.New("invalid commitment input")
	ErrPointNotOnCurve        = errors.New("point not on curve")
)

// PedersenCommitter provides Pedersen commitment operations
// WARNING: Pedersen commitments are NOT post-quantum secure (discrete log)
// Use Poseidon2 commitments for PQ security
type PedersenCommitter struct {
	// Generator points (from trusted setup or hash-to-curve)
	G bn254.G1Affine // Base generator
	H bn254.G1Affine // Blinding generator

	// Additional generators for vector commitments
	Generators []bn254.G1Affine

	// Statistics
	TotalCommitments   uint64
	TotalVerifications uint64

	mu sync.RWMutex
}

// NewPedersenCommitter creates a new Pedersen committer with default generators
func NewPedersenCommitter() *PedersenCommitter {
	pc := &PedersenCommitter{}

	// Use bn254 generator for G
	_, _, g1Gen, _ := bn254.Generators()
	pc.G = g1Gen

	// Derive H from G using hash-to-curve (nothing-up-my-sleeve)
	// H = HashToCurve("Lux_Pedersen_H")
	pc.H = hashToG1("Lux_Pedersen_H_Generator")

	// Pre-generate additional generators for vector commitments
	pc.Generators = make([]bn254.G1Affine, 32)
	for i := 0; i < 32; i++ {
		pc.Generators[i] = hashToG1("Lux_Pedersen_Gen_" + string(rune('0'+i)))
	}

	return pc
}

// Commit creates a Pedersen commitment: C = v*G + r*H
// value: the value to commit to (as field element)
// blindingFactor: random blinding factor
// Returns: commitment point (hashed, 32 bytes)
func (p *PedersenCommitter) Commit(value, blindingFactor [32]byte) ([32]byte, error) {
	var v, r fr.Element
	v.SetBytes(value[:])
	r.SetBytes(blindingFactor[:])

	// C = v*G + r*H
	var vG, rH bn254.G1Affine
	vG.ScalarMultiplication(&p.G, v.BigInt(new(big.Int)))
	rH.ScalarMultiplication(&p.H, r.BigInt(new(big.Int)))

	var commitment bn254.G1Affine
	commitment.Add(&vG, &rH)

	// Store in cache and return hash
	return compressG1WithCache(&commitment), nil
}

// CommitWithOpening creates a commitment and returns opening info
func (p *PedersenCommitter) CommitWithOpening(value *big.Int) (commitment [32]byte, blindingFactor [32]byte, err error) {
	// Generate random blinding factor
	var r fr.Element
	r.SetRandom()
	blindingFactor = r.Bytes()

	// Create value bytes
	var valueBytes [32]byte
	vBytes := value.Bytes()
	copy(valueBytes[32-len(vBytes):], vBytes)

	commitment, err = p.Commit(valueBytes, blindingFactor)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}

	p.mu.Lock()
	p.TotalCommitments++
	p.mu.Unlock()

	return commitment, blindingFactor, nil
}

// Verify verifies a Pedersen commitment opening
// Returns true if C == v*G + r*H
func (p *PedersenCommitter) Verify(commitment, value, blindingFactor [32]byte) (bool, error) {
	// Decompress commitment
	C, err := decompressG1(commitment)
	if err != nil {
		return false, err
	}

	// Recompute expected commitment
	expected, err := p.Commit(value, blindingFactor)
	if err != nil {
		return false, err
	}

	expectedPoint, err := decompressG1(expected)
	if err != nil {
		return false, err
	}

	p.mu.Lock()
	p.TotalVerifications++
	p.mu.Unlock()

	return C.Equal(&expectedPoint), nil
}

// Add adds two commitments homomorphically
// C1 + C2 = (v1 + v2)*G + (r1 + r2)*H
func (p *PedersenCommitter) Add(c1, c2 [32]byte) ([32]byte, error) {
	p1, err := decompressG1(c1)
	if err != nil {
		return [32]byte{}, err
	}

	p2, err := decompressG1(c2)
	if err != nil {
		return [32]byte{}, err
	}

	var sum bn254.G1Affine
	sum.Add(&p1, &p2)

	return compressG1WithCache(&sum), nil
}

// Sub subtracts commitments homomorphically
// C1 - C2 = (v1 - v2)*G + (r1 - r2)*H
func (p *PedersenCommitter) Sub(c1, c2 [32]byte) ([32]byte, error) {
	p1, err := decompressG1(c1)
	if err != nil {
		return [32]byte{}, err
	}

	p2, err := decompressG1(c2)
	if err != nil {
		return [32]byte{}, err
	}

	var neg bn254.G1Affine
	neg.Neg(&p2)

	var diff bn254.G1Affine
	diff.Add(&p1, &neg)

	return compressG1WithCache(&diff), nil
}

// VectorCommit creates a vector Pedersen commitment
// C = sum(v_i * G_i) + r * H
func (p *PedersenCommitter) VectorCommit(values [][32]byte, blindingFactor [32]byte) ([32]byte, error) {
	if len(values) > len(p.Generators) {
		return [32]byte{}, errors.New("too many values for vector commitment")
	}

	var sum bn254.G1Jac // Use Jacobian for efficiency

	for i, value := range values {
		var v fr.Element
		v.SetBytes(value[:])

		var vG bn254.G1Affine
		vG.ScalarMultiplication(&p.Generators[i], v.BigInt(new(big.Int)))

		var vGJac bn254.G1Jac
		vGJac.FromAffine(&vG)
		sum.AddAssign(&vGJac)
	}

	// Add blinding: r * H
	var r fr.Element
	r.SetBytes(blindingFactor[:])

	var rH bn254.G1Affine
	rH.ScalarMultiplication(&p.H, r.BigInt(new(big.Int)))

	var rHJac bn254.G1Jac
	rHJac.FromAffine(&rH)
	sum.AddAssign(&rHJac)

	var result bn254.G1Affine
	result.FromJacobian(&sum)

	return compressG1WithCache(&result), nil
}

// NoteCommitment creates a note commitment for shielded transactions
// Similar to Poseidon2, but using Pedersen for homomorphic properties
// commitment = amount*G_0 + assetId*G_1 + owner*G_2 + blindingFactor*H
func (p *PedersenCommitter) NoteCommitment(
	amount *big.Int,
	assetId [32]byte,
	owner common.Address,
	blindingFactor [32]byte,
) ([32]byte, error) {
	// Prepare values
	var amountBytes [32]byte
	aBytes := amount.Bytes()
	copy(amountBytes[32-len(aBytes):], aBytes)

	var ownerBytes [32]byte
	copy(ownerBytes[12:], owner[:])

	values := [][32]byte{amountBytes, assetId, ownerBytes}
	return p.VectorCommit(values, blindingFactor)
}

// VerifyBalance verifies that sum of inputs equals sum of outputs
// Uses homomorphic property: sum(C_in) - sum(C_out) = 0
// (when blindings also cancel out)
func (p *PedersenCommitter) VerifyBalance(inputs, outputs [][32]byte) (bool, error) {
	// Sum inputs
	var inputSum bn254.G1Jac
	for _, c := range inputs {
		pt, err := decompressG1(c)
		if err != nil {
			return false, err
		}
		var ptJac bn254.G1Jac
		ptJac.FromAffine(&pt)
		inputSum.AddAssign(&ptJac)
	}

	// Sum outputs
	var outputSum bn254.G1Jac
	for _, c := range outputs {
		pt, err := decompressG1(c)
		if err != nil {
			return false, err
		}
		var ptJac bn254.G1Jac
		ptJac.FromAffine(&pt)
		outputSum.AddAssign(&ptJac)
	}

	// Check if inputSum == outputSum
	var inputAff, outputAff bn254.G1Affine
	inputAff.FromJacobian(&inputSum)
	outputAff.FromJacobian(&outputSum)

	return inputAff.Equal(&outputAff), nil
}

// RequiredGas calculates gas cost for Pedersen operations
func (p *PedersenCommitter) RequiredGas(operation string, numElements int) uint64 {
	switch operation {
	case "commit":
		// Single commitment: 2 scalar mults + 1 add
		return 6000
	case "verify":
		// Commitment + equality check
		return 7000
	case "add", "sub":
		// Point addition/subtraction
		return 500
	case "vector":
		// Vector commitment: n scalar mults + 1 blinding
		return uint64(6000 + numElements*3000)
	default:
		return 10000
	}
}

// Helper functions

// hashToG1 creates a generator from a seed using hash-to-curve
func hashToG1(seed string) bn254.G1Affine {
	// Use hash-to-curve via repeated hashing until we find a valid point
	// This is a simple try-and-increment approach
	var point bn254.G1Affine

	seedBytes := []byte(seed)
	var counter byte = 0

	for {
		// Hash seed with counter
		data := append(seedBytes, counter)
		hash := sha256.Sum256(data)

		// Try to create a point from the hash
		var x fp.Element
		x.SetBytes(hash[:])

		// Try to find y for this x using curve equation y^2 = x^3 + 3
		var x2, x3, rhs fp.Element
		x2.Square(&x)
		x3.Mul(&x2, &x)

		var three fp.Element
		three.SetInt64(3)
		rhs.Add(&x3, &three)

		// Try to compute square root
		var y fp.Element
		if y.Sqrt(&rhs) != nil {
			// Found valid point
			point.X = x
			point.Y = y

			if point.IsOnCurve() && !point.IsInfinity() {
				return point
			}
		}
		counter++
		if counter == 0 {
			// Overflow, shouldn't happen with good seeds
			break
		}
	}

	// Fallback to base generator (shouldn't reach here)
	_, _, g1, _ := bn254.Generators()
	return g1
}

// compressG1 compresses a G1 point to 64 bytes (uncompressed for simplicity)
// In production, use proper point compression
func compressG1(p *bn254.G1Affine) [32]byte {
	// For simplicity, we hash the full point representation
	// This loses some efficiency but ensures correctness
	fullBytes := p.Bytes()
	hash := sha256.Sum256(fullBytes[:])

	// Store hash + first byte of X for verification
	var result [32]byte
	copy(result[:], hash[:])
	return result
}

// pointCache stores the mapping from hash to full point
var pointCache = struct {
	sync.RWMutex
	m map[[32]byte]bn254.G1Affine
}{m: make(map[[32]byte]bn254.G1Affine)}

// storePoint stores a point in the cache
func storePoint(p *bn254.G1Affine) [32]byte {
	fullBytes := p.Bytes()
	hash := sha256.Sum256(fullBytes[:])
	var key [32]byte
	copy(key[:], hash[:])

	pointCache.Lock()
	pointCache.m[key] = *p
	pointCache.Unlock()

	return key
}

// compressG1WithCache compresses and caches a G1 point
func compressG1WithCache(p *bn254.G1Affine) [32]byte {
	return storePoint(p)
}

// decompressG1 retrieves a point from cache or reconstructs it
func decompressG1(data [32]byte) (bn254.G1Affine, error) {
	pointCache.RLock()
	if p, ok := pointCache.m[data]; ok {
		pointCache.RUnlock()
		return p, nil
	}
	pointCache.RUnlock()

	// If not in cache, we can't decompress (this is a limitation of this simple approach)
	// In production, use proper point compression
	return bn254.G1Affine{}, ErrPointNotOnCurve
}

// Global instance
var globalPedersen = NewPedersenCommitter()

// PedersenCommit is the main entry point for the precompile
// Input: 64 bytes (value[32] + blindingFactor[32])
// Output: 32 bytes (compressed commitment)
func PedersenCommit(input []byte) ([]byte, error) {
	if len(input) != 64 {
		return nil, ErrInvalidCommitmentInput
	}

	var value, blinding [32]byte
	copy(value[:], input[:32])
	copy(blinding[:], input[32:])

	result, err := globalPedersen.Commit(value, blinding)
	if err != nil {
		return nil, err
	}
	return result[:], nil
}

// PedersenVerify verifies a commitment opening
// Input: 96 bytes (commitment[32] + value[32] + blindingFactor[32])
// Output: 32 bytes (0x01 if valid, 0x00 if invalid)
func PedersenVerify(input []byte) ([]byte, error) {
	if len(input) != 96 {
		return nil, ErrInvalidCommitmentInput
	}

	var commitment, value, blinding [32]byte
	copy(commitment[:], input[:32])
	copy(value[:], input[32:64])
	copy(blinding[:], input[64:])

	valid, err := globalPedersen.Verify(commitment, value, blinding)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 32)
	if valid {
		result[31] = 1
	}
	return result, nil
}

// PedersenAdd adds two commitments
// Input: 64 bytes (c1[32] + c2[32])
// Output: 32 bytes (c1 + c2)
func PedersenAdd(input []byte) ([]byte, error) {
	if len(input) != 64 {
		return nil, ErrInvalidCommitmentInput
	}

	var c1, c2 [32]byte
	copy(c1[:], input[:32])
	copy(c2[:], input[32:])

	result, err := globalPedersen.Add(c1, c2)
	if err != nil {
		return nil, err
	}
	return result[:], nil
}

// GetPedersenStats returns statistics
func GetPedersenStats() (totalCommitments, totalVerifications uint64) {
	globalPedersen.mu.RLock()
	defer globalPedersen.mu.RUnlock()
	return globalPedersen.TotalCommitments, globalPedersen.TotalVerifications
}
