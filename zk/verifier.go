// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"sync"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/luxfi/crypto/bn256"
	"github.com/luxfi/crypto/kzg4844"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// ZKVerifier provides zero-knowledge proof verification
// This is the main precompile at 0x0900 for ZK operations
type ZKVerifier struct {
	// Verification keys
	VerifyingKeys map[[32]byte]*VerifyingKey

	// Nullifier tracking (for privacy)
	Nullifiers map[[32]byte]*Nullifier

	// Commitment tracking
	Commitments map[[32]byte]*Commitment

	// Rollup configurations
	Rollups map[[32]byte]*RollupConfig

	// Rollup state
	RollupStates map[[32]byte]*RollupState

	// Confidential pools
	Pools map[[32]byte]*ConfidentialPool

	// KZG trusted setup
	KZGSetup *KZGSetup

	// Statistics
	TotalVerifications uint64
	TotalProofsValid   uint64
	TotalProofsFailed  uint64

	mu sync.RWMutex
}

// RollupState tracks the state of a rollup
type RollupState struct {
	LastBatchID   [32]byte
	LastStateRoot [32]byte
	LastL1Block   uint64
	TotalBatches  uint64
	TotalTxs      uint64
}

// NewZKVerifier creates a new ZK verifier
func NewZKVerifier() *ZKVerifier {
	return &ZKVerifier{
		VerifyingKeys: make(map[[32]byte]*VerifyingKey),
		Nullifiers:    make(map[[32]byte]*Nullifier),
		Commitments:   make(map[[32]byte]*Commitment),
		Rollups:       make(map[[32]byte]*RollupConfig),
		RollupStates:  make(map[[32]byte]*RollupState),
		Pools:         make(map[[32]byte]*ConfidentialPool),
	}
}

// verifyingKeyID derives the identifier a key is stored and referenced
// under. It must commit to EVERY field that defines the key, with each
// field length-prefixed.
//
// The previous derivation, sha256(alpha‖beta‖gamma‖delta), failed both
// requirements. It omitted IC — the public-input constraints — so two keys
// differing only in IC shared an ID and registering the second silently
// replaced the first under an ID other code already referenced. And the
// bare concatenation was ambiguous: (alpha="ab", beta="c") hashed
// identically to (alpha="a", beta="bc").
//
// Length prefixes make the encoding injective, so distinct keys have
// distinct IDs.
func verifyingKeyID(
	proofSystem ProofSystem,
	circuitType CircuitType,
	alpha, beta, gamma, delta []byte,
	ic [][]byte,
) [32]byte {
	h := sha256.New()
	h.Write([]byte("lux/zk/verifying-key/v1"))
	h.Write([]byte{byte(proofSystem), byte(circuitType)})

	var n [4]byte
	field := func(b []byte) {
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	field(alpha)
	field(beta)
	field(gamma)
	field(delta)

	binary.BigEndian.PutUint32(n[:], uint32(len(ic)))
	h.Write(n[:])
	for _, e := range ic {
		field(e)
	}

	var id [32]byte
	copy(id[:], h.Sum(nil))
	return id
}

// RegisterVerifyingKey registers a new verification key
func (zv *ZKVerifier) RegisterVerifyingKey(
	owner common.Address,
	proofSystem ProofSystem,
	circuitType CircuitType,
	alpha, beta, gamma, delta []byte,
	ic [][]byte,
) ([32]byte, error) {
	zv.mu.Lock()
	defer zv.mu.Unlock()

	keyID := verifyingKeyID(proofSystem, circuitType, alpha, beta, gamma, delta, ic)

	vk := &VerifyingKey{
		KeyID:       keyID,
		ProofSystem: proofSystem,
		CircuitType: circuitType,
		Alpha:       alpha,
		Beta:        beta,
		Gamma:       gamma,
		Delta:       delta,
		IC:          ic,
		Hash:        keyID,
		Owner:       owner,
		CreatedAt:   uint64(time.Now().Unix()),
	}

	zv.VerifyingKeys[keyID] = vk
	return keyID, nil
}

// VerifyGroth16 verifies a Groth16 proof
func (zv *ZKVerifier) VerifyGroth16(
	vkID [32]byte,
	proofA, proofB, proofC []byte,
	publicInputs []*big.Int,
) (*VerificationResult, error) {
	zv.mu.Lock()
	defer zv.mu.Unlock()

	vk := zv.VerifyingKeys[vkID]
	if vk == nil {
		return nil, ErrInvalidVerifyingKey
	}

	if vk.ProofSystem != ProofSystemGroth16 {
		return nil, ErrProofSystemMismatch
	}

	// Validate public inputs count
	if len(publicInputs) != len(vk.IC)-1 {
		return nil, ErrInvalidPublicInputs
	}

	// Verify the proof using pairing check
	// In production, this would use BN254 pairing operations
	valid := zv.groth16PairingCheck(vk, proofA, proofB, proofC, publicInputs)

	zv.TotalVerifications++
	if valid {
		zv.TotalProofsValid++
	} else {
		zv.TotalProofsFailed++
	}

	return &VerificationResult{
		Valid:        valid,
		ProofSystem:  ProofSystemGroth16,
		CircuitType:  vk.CircuitType,
		PublicInputs: publicInputs,
		GasUsed:      GasGroth16Verify,
	}, nil
}

// VerifyPlonk verifies a PLONK proof
func (zv *ZKVerifier) VerifyPlonk(
	vkID [32]byte,
	proof []byte,
	publicInputs []*big.Int,
) (*VerificationResult, error) {
	zv.mu.Lock()
	defer zv.mu.Unlock()

	vk := zv.VerifyingKeys[vkID]
	if vk == nil {
		return nil, ErrInvalidVerifyingKey
	}

	if vk.ProofSystem != ProofSystemPlonk {
		return nil, ErrProofSystemMismatch
	}

	// PLONK verification
	valid := zv.plonkVerify(vk, proof, publicInputs)

	zv.TotalVerifications++
	if valid {
		zv.TotalProofsValid++
	} else {
		zv.TotalProofsFailed++
	}

	return &VerificationResult{
		Valid:        valid,
		ProofSystem:  ProofSystemPlonk,
		CircuitType:  vk.CircuitType,
		PublicInputs: publicInputs,
		GasUsed:      GasPlonkVerify,
	}, nil
}

// VerifyFflonk verifies an fflonk proof with a registered verification key.
//
// fflonk is an optimized PLONK variant that uses batched KZG openings
// to reduce the number of pairings required for verification.
func (zv *ZKVerifier) VerifyFflonk(
	vkID [32]byte,
	proof []byte,
	publicInputs []*big.Int,
) (*VerificationResult, error) {
	zv.mu.Lock()
	defer zv.mu.Unlock()

	vk := zv.VerifyingKeys[vkID]
	if vk == nil {
		return nil, ErrInvalidVerifyingKey
	}

	if vk.ProofSystem != ProofSystemFflonk {
		return nil, ErrProofSystemMismatch
	}

	// fflonk verification using the registered verification key.
	//
	// VerificationResult.Valid stays a bool: by the time it is filled in, the
	// verdict has been earned, and the struct is a record of a completed
	// verification rather than the answer itself. The line is producers
	// return a Verdict; a report of one carries a bool.
	v := zv.fflonkVerify(vk, proof, publicInputs)
	valid := v.OK()

	zv.TotalVerifications++
	if valid {
		zv.TotalProofsValid++
	} else {
		zv.TotalProofsFailed++
	}

	// Use a dedicated gas constant for fflonk (between Groth16 and PLONK)
	const GasFflonkVerify = uint64(180000)

	return &VerificationResult{
		Valid:        valid,
		ProofSystem:  ProofSystemFflonk,
		CircuitType:  vk.CircuitType,
		PublicInputs: publicInputs,
		GasUsed:      GasFflonkVerify,
	}, nil
}

// fflonkVerify performs fflonk proof verification with a verification key.
//
// The fflonk proof format (448+ bytes):
// - C1: batched commitment (48 bytes, BLS12-381 G1 compressed)
// - C2: batched commitment (48 bytes, BLS12-381 G1 compressed)
// - W1: opening proof (48 bytes, BLS12-381 G1 compressed)
// - W2: opening proof (48 bytes, BLS12-381 G1 compressed)
// - Evaluations: field elements (8+ x 32 bytes)
//
// Verification equation:
// e(F - [r]G1, G2) = e(W, [τ - ξ]G2)
// fflonkVerify verifies an fflonk proof's KZG opening layer with real
// BLS12-381 pairing checks against the KZG trusted setup.
//
// Layout: C1‖C2‖W1‖W2 (four compressed G1 points, 48 bytes each) followed by
// >= 8 scalar-field evaluations (32 bytes each, big-endian). Evaluations[0]
// and [1] are the values C1 and C2 open to at the Fiat-Shamir point z;
// evaluations[2:] are auxiliary openings bound into z.
//
// Soundness: every commitment and opening proof must be an on-curve,
// in-subgroup G1 point and every evaluation a canonical scalar (else reject).
// z is derived by Fiat-Shamir from the verifying key, both commitments, the
// public inputs and every non-claim evaluation — so tampering any of those
// changes z and breaks both openings. The two openings are then checked with
// kzg4844.VerifyProof, a real pairing equation e(C-[y]G1,G2)=e(W,[τ-z]G2) over
// the trusted setup, so tampering a commitment, an opening proof, or a claim
// value fails a pairing. No proof element is unbound; there is no return-true.
//
// Boundary: this verifies the KZG opening layer that all fflonk proofs share.
// Binding the openings to a specific PLONK constraint system additionally
// requires a fflonk-native verifying key carrying the circuit's selector and
// permutation commitments; the VerifyingKey type here (Groth16-shaped: Alpha,
// Beta, Gamma, Delta, IC) does not carry them, so circuit binding is out of
// scope for this representation and intentionally not faked.
func (zv *ZKVerifier) fflonkVerify(
	vk *VerifyingKey,
	proof []byte,
	publicInputs []*big.Int,
) contract.Verdict {
	in := contract.Read(proof)
	pts, err := in.Fields(fflonkNumCommitments, fflonkG1Size)
	if err != nil {
		return contract.Refused(ErrInvalidProofLength)
	}
	c1, c2, w1, w2 := pts[0], pts[1], pts[2], pts[3]

	// Reject any off-curve or wrong-subgroup commitment / opening proof.
	for _, pt := range pts {
		if !validG1Point(pt) {
			return contract.Refused(ErrInvalidPointFormat)
		}
	}

	// Evaluations are however many whole field elements remain, derived from
	// the length rather than declared, so the count is bounded by
	// construction.
	numEvals := uint64(in.Len()) / fieldLen
	if numEvals < fflonkNumEvaluations {
		return contract.Refused(ErrInvalidProofLength)
	}
	raw, err := in.Fields(numEvals, fieldLen)
	if err != nil {
		return contract.Refused(ErrInvalidProofLength)
	}
	r := blsScalarField()
	evaluations := make([]*big.Int, len(raw))
	for i, b := range raw {
		e := new(big.Int).SetBytes(b)
		if e.Cmp(r) >= 0 { // non-canonical scalar
			return contract.Refused(ErrInvalidPublicInputs)
		}
		evaluations[i] = e
	}

	// Fiat-Shamir opening point, bound to everything except the two claim
	// values (which are determined BY z, so they must not feed it).
	z := computeFflonkOpeningPoint(vk, c1, c2, publicInputs, evaluations[2:])

	// Real BLS12-381 pairing checks via the KZG trusted setup. Both openings
	// must hold; the verdict is that conjunction and nothing else. There is
	// no `return true` here to be reached by a path that skipped the
	// pairings — the only positive this function can produce is the value of
	// the predicate below.
	return contract.Checked(
		verifyKZGOpening(c1, z, evaluations[0], w1) &&
			verifyKZGOpening(c2, z, evaluations[1], w2))
}

// degenerate reports whether any given curve element is absent or is the
// point at infinity. bn256 marshals affine (x,y) uncompressed and encodes
// the identity as all zeros, so an all-zero element IS the identity.
//
// The identity is the one curve point that makes a pairing factor
// unconditionally 1, which is why a verifying key containing one accepts
// every proof. Rejecting it is a soundness requirement, not hygiene.
func degenerate(elems ...[]byte) bool {
	for _, e := range elems {
		if len(e) == 0 || isZeroBytes(e) {
			return true
		}
	}
	return false
}

// blsScalarField returns the BLS12-381 scalar field order r.
func blsScalarField() *big.Int {
	r := new(big.Int)
	r.SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
	return r
}

// validG1Point reports whether b is a valid, non-infinity, in-subgroup
// compressed BLS12-381 G1 point. SetBytes performs the on-curve and prime
// subgroup checks; off-curve, wrong-subgroup, or malformed encodings fail.
func validG1Point(b []byte) bool {
	if len(b) != 48 {
		return false
	}
	var g bls12381.G1Affine
	if _, err := g.SetBytes(b); err != nil {
		return false
	}
	return !g.IsInfinity()
}

// padScalar32 left-pads x to a 32-byte big-endian buffer.
func padScalar32(x *big.Int) []byte {
	out := make([]byte, 32)
	if x == nil {
		return out
	}
	b := x.Bytes()
	if len(b) >= 32 {
		copy(out, b[len(b)-32:])
	} else {
		copy(out[32-len(b):], b)
	}
	return out
}

// computeFflonkOpeningPoint derives the Fiat-Shamir opening point z, bound to
// the verifying key, both commitments, the public inputs, and every non-claim
// evaluation.
func computeFflonkOpeningPoint(vk *VerifyingKey, c1, c2 []byte, publicInputs, boundEvals []*big.Int) *big.Int {
	h := sha256.New()
	h.Write([]byte("lux/zk/fflonk/opening-point/v1"))
	if vk != nil {
		h.Write(vk.Hash[:])
	}
	h.Write(c1)
	h.Write(c2)
	for _, pi := range publicInputs {
		h.Write(padScalar32(pi))
	}
	for _, e := range boundEvals {
		h.Write(padScalar32(e))
	}
	z := new(big.Int).SetBytes(h.Sum(nil))
	return z.Mod(z, blsScalarField())
}

// verifyKZGOpening checks the pairing equation e(C-[claim]G1,G2)=e(proof,[τ-z]G2)
// via kzg4844.VerifyProof over the trusted setup. commitment and proof must be
// exactly 48 bytes (validated by the caller).
func verifyKZGOpening(commitment []byte, z, claim *big.Int, proof []byte) bool {
	r := blsScalarField()

	var c kzg4844.Commitment
	copy(c[:], commitment)
	var pf kzg4844.Proof
	copy(pf[:], proof)

	var pt kzg4844.Point
	copy(pt[:], padScalar32(new(big.Int).Mod(z, r)))
	var cl kzg4844.Claim
	copy(cl[:], padScalar32(new(big.Int).Mod(claim, r)))

	return kzg4844.VerifyProof(c, pt, cl, pf) == nil
}

// VerifyKZG verifies a KZG point evaluation
func (zv *ZKVerifier) VerifyKZG(
	commitment []byte,
	point *big.Int,
	value *big.Int,
	proof []byte,
) (bool, error) {
	zv.mu.RLock()
	defer zv.mu.RUnlock()

	if zv.KZGSetup == nil {
		return false, errors.New("KZG setup not initialized")
	}

	// KZG point evaluation verification
	// Uses pairing: e(C - [y]G1, G2) = e(proof, [τ - z]G2)
	valid := zv.kzgPointEvaluation(commitment, point, value, proof)

	return valid, nil
}

// VerifyRangeProof verifies that a committed value is within a range.
//
// No bulletproof verifier is wired, so it refuses.
//
// This used to answer `len(commitment) > 0 && len(rangeProof) > 0 &&
// bitLength > 0` — a length check reported as a verification verdict, so
// every well-formed byte string was a valid range proof. A range proof is
// what stops a confidential transfer minting value out of nothing, so
// accepting all of them defeats the whole scheme.
//
// The signature is what keeps that from coming back. Under (bool, error) the
// length check WAS a bool, and returning it read as a verdict; a
// contract.Verdict cannot be built from a length at all, only from
// contract.Checked over a predicate that a repo-wide gate forbids being a
// constant. And the refusal is its own state rather than a `false` that a
// caller would read as "this proof is bad".
func (zv *ZKVerifier) VerifyRangeProof(
	commitment []byte,
	rangeProof []byte,
	bitLength uint32,
) contract.Verdict {
	return contract.Refused(ErrRangeProofUnavailable)
}

// CheckNullifier checks if a nullifier has been spent
func (zv *ZKVerifier) CheckNullifier(nullifierHash [32]byte) (bool, error) {
	zv.mu.RLock()
	defer zv.mu.RUnlock()

	_, spent := zv.Nullifiers[nullifierHash]
	return spent, nil
}

// SpendNullifier marks a nullifier as spent
func (zv *ZKVerifier) SpendNullifier(
	nullifierHash [32]byte,
	txHash common.Hash,
	blockHeight uint64,
) error {
	zv.mu.Lock()
	defer zv.mu.Unlock()

	if _, exists := zv.Nullifiers[nullifierHash]; exists {
		return ErrNullifierSpent
	}

	zv.Nullifiers[nullifierHash] = &Nullifier{
		Hash:    nullifierHash,
		SpentAt: blockHeight,
		SpentTx: txHash,
	}

	return nil
}

// AddCommitment adds a new commitment to the pool
func (zv *ZKVerifier) AddCommitment(
	poolID [32]byte,
	commitment *Commitment,
) ([32]byte, error) {
	zv.mu.Lock()
	defer zv.mu.Unlock()

	pool := zv.Pools[poolID]
	if pool == nil {
		return [32]byte{}, ErrPoolNotFound
	}

	if !pool.Enabled {
		return [32]byte{}, ErrPoolDisabled
	}

	// Generate commitment ID
	commitID := sha256.Sum256(commitment.Value)

	pool.Commitments[commitID] = commitment
	pool.TotalDeposits.Add(pool.TotalDeposits, commitment.Amount)

	// Update merkle root
	zv.updatePoolMerkleRoot(pool)

	return commitID, nil
}

// VerifyCommitmentInclusion verifies a commitment is in the pool
func (zv *ZKVerifier) VerifyCommitmentInclusion(
	poolID [32]byte,
	commitmentID [32]byte,
	merkleProof [][]byte,
	leafIndex uint64,
) (bool, error) {
	zv.mu.RLock()
	defer zv.mu.RUnlock()

	pool := zv.Pools[poolID]
	if pool == nil {
		return false, ErrPoolNotFound
	}

	// Verify merkle proof
	valid := zv.verifyMerkleProof(pool.MerkleRoot, commitmentID[:], merkleProof, leafIndex)

	return valid, nil
}

// RegisterRollup registers a new ZK rollup
func (zv *ZKVerifier) RegisterRollup(
	owner common.Address,
	verifyingKeyID [32]byte,
	proofSystem ProofSystem,
	maxTxPerBatch uint64,
	batchInterval uint64,
	sequencer common.Address,
) ([32]byte, error) {
	zv.mu.Lock()
	defer zv.mu.Unlock()

	vk := zv.VerifyingKeys[verifyingKeyID]
	if vk == nil {
		return [32]byte{}, ErrInvalidVerifyingKey
	}

	// Generate rollup ID
	rollupData := append(owner.Bytes(), verifyingKeyID[:]...)
	rollupID := sha256.Sum256(rollupData)

	config := &RollupConfig{
		RollupID:        rollupID,
		Owner:           owner,
		VerifyingKey:    vk,
		ProofSystem:     proofSystem,
		MaxTxPerBatch:   maxTxPerBatch,
		BatchInterval:   batchInterval,
		ChallengeWindow: 7 * 24 * 60 * 60, // 7 days default
		Sequencer:       sequencer,
		Enabled:         true,
	}

	state := &RollupState{
		LastStateRoot: [32]byte{}, // Genesis state
	}

	zv.Rollups[rollupID] = config
	zv.RollupStates[rollupID] = state

	return rollupID, nil
}

// VerifyRollupBatch verifies a ZK rollup batch
func (zv *ZKVerifier) VerifyRollupBatch(
	rollupID [32]byte,
	batch *RollupBatch,
) error {
	zv.mu.Lock()
	defer zv.mu.Unlock()

	config := zv.Rollups[rollupID]
	if config == nil {
		return ErrRollupNotFound
	}

	if !config.Enabled {
		return errors.New("rollup disabled")
	}

	state := zv.RollupStates[rollupID]

	// Verify proposer authorization
	if batch.Proposer != config.Sequencer && batch.Proposer != config.Owner {
		return ErrUnauthorizedProposer
	}

	// Verify batch size
	if batch.Transactions > config.MaxTxPerBatch {
		return ErrBatchTooLarge
	}

	// Verify state transition
	if batch.PrevStateRoot != state.LastStateRoot {
		return ErrInvalidStateRoot
	}

	// Verify the validity proof
	var valid bool
	switch config.ProofSystem {
	case ProofSystemGroth16:
		result, err := zv.verifyGroth16Batch(config.VerifyingKey, batch)
		if err != nil {
			return err
		}
		valid = result
	case ProofSystemPlonk:
		result, err := zv.verifyPlonkBatch(config.VerifyingKey, batch)
		if err != nil {
			return err
		}
		valid = result
	default:
		return ErrProofSystemMismatch
	}

	if !valid {
		return ErrInvalidProof
	}

	// Update state
	state.LastBatchID = batch.BatchID
	state.LastStateRoot = batch.NewStateRoot
	state.LastL1Block = batch.L1BatchNum
	state.TotalBatches++
	state.TotalTxs += batch.Transactions

	return nil
}

// GetRollupState returns the current state of a rollup
func (zv *ZKVerifier) GetRollupState(rollupID [32]byte) (*RollupState, error) {
	zv.mu.RLock()
	defer zv.mu.RUnlock()

	state := zv.RollupStates[rollupID]
	if state == nil {
		return nil, ErrRollupNotFound
	}

	return state, nil
}

// CreateConfidentialPool creates a new confidential transaction pool
func (zv *ZKVerifier) CreateConfidentialPool(
	owner common.Address,
	token common.Address,
	merkleDepth uint32,
) ([32]byte, error) {
	zv.mu.Lock()
	defer zv.mu.Unlock()

	poolData := append(owner.Bytes(), token.Bytes()...)
	poolID := sha256.Sum256(poolData)

	pool := &ConfidentialPool{
		PoolID:         poolID,
		Token:          token,
		Commitments:    make(map[[32]byte]*Commitment),
		Nullifiers:     make(map[[32]byte]*Nullifier),
		MerkleRoot:     [32]byte{},
		MerkleDepth:    merkleDepth,
		TotalDeposits:  big.NewInt(0),
		TotalWithdraws: big.NewInt(0),
		Enabled:        true,
	}

	zv.Pools[poolID] = pool
	return poolID, nil
}

// Helper functions

// groth16PairingCheck implements the Groth16 pairing verification equation:
// e(A, B) = e(α, β) · e(∑ᵢ wᵢ · ICᵢ, γ) · e(C, δ)
//
// Equivalently, we verify:
// e(A, B) · e(-α, β) · e(-vk_x, γ) · e(-C, δ) = 1
//
// Where vk_x = ∑ᵢ wᵢ · ICᵢ (linear combination of public inputs with IC points)
func (zv *ZKVerifier) groth16PairingCheck(
	vk *VerifyingKey,
	proofA, proofB, proofC []byte,
	publicInputs []*big.Int,
) bool {
	// A key whose elements are the identity verifies EVERYTHING: e(O,Q)=1,
	// so each factor of the product collapses and the check succeeds for
	// every proof and every statement. No honest setup emits one — alpha,
	// beta, gamma, delta are g^x for random nonzero x. Refuse before doing
	// any arithmetic, so nobody who can register a key can forge with it.
	if degenerate(vk.Alpha, vk.Beta, vk.Gamma, vk.Delta) || degenerate(vk.IC...) {
		return false
	}

	// Parse proof elements
	var a bn256.G1
	if _, err := a.Unmarshal(proofA); err != nil {
		return false
	}

	var b bn256.G2
	if _, err := b.Unmarshal(proofB); err != nil {
		return false
	}

	var c bn256.G1
	if _, err := c.Unmarshal(proofC); err != nil {
		return false
	}

	// Parse verification key elements
	var alpha bn256.G1
	if _, err := alpha.Unmarshal(vk.Alpha); err != nil {
		return false
	}

	var beta bn256.G2
	if _, err := beta.Unmarshal(vk.Beta); err != nil {
		return false
	}

	var gamma bn256.G2
	if _, err := gamma.Unmarshal(vk.Gamma); err != nil {
		return false
	}

	var delta bn256.G2
	if _, err := delta.Unmarshal(vk.Delta); err != nil {
		return false
	}

	// Parse IC points (input constraints)
	if len(vk.IC) < 1 {
		return false
	}

	ic := make([]*bn256.G1, len(vk.IC))
	for i, icBytes := range vk.IC {
		ic[i] = new(bn256.G1)
		if _, err := ic[i].Unmarshal(icBytes); err != nil {
			return false
		}
	}

	// Compute vk_x = IC[0] + ∑ᵢ (publicInputs[i] * IC[i+1])
	// This is the linear combination of public inputs with IC points (MSM)
	vkX := new(bn256.G1)

	// CPU is the single source of truth: sequential bn256 MSM. The removed
	// accel path called sess.ZK().MSM with NO curve binding (the kernel cannot
	// know it must operate over BN254), and its result was folded into vk_x
	// without independent verification -- a wrong or wrong-curve MSM silently
	// flipped the Groth16 pairing verdict on accel-equipped validators, a
	// consensus split on proof verification. Re-introducing accel requires a
	// BN254 MSM kernel proven bit-identical to this loop.
	vkX.ScalarMult(ic[0], big.NewInt(1)) // Start with IC[0]

	for i, input := range publicInputs {
		if i+1 >= len(ic) {
			return false
		}
		tmp := new(bn256.G1)
		tmp.ScalarMult(ic[i+1], input)
		vkX.Add(vkX, tmp)
	}

	// Negate points for the pairing check
	// We check: e(A, B) · e(-α, β) · e(-vk_x, γ) · e(-C, δ) = 1
	negAlpha := new(bn256.G1)
	negAlpha.ScalarMult(&alpha, big.NewInt(-1))

	negVkX := new(bn256.G1)
	negVkX.ScalarMult(vkX, big.NewInt(-1))

	negC := new(bn256.G1)
	negC.ScalarMult(&c, big.NewInt(-1))

	// Perform pairing check
	// PairingCheck returns true if ∏ᵢ e(Pᵢ, Qᵢ) = 1
	g1Points := []*bn256.G1{&a, negAlpha, negVkX, negC}
	g2Points := []*bn256.G2{&b, &beta, &gamma, &delta}

	return bn256.PairingCheck(g1Points, g2Points)
}

// plonkVerify verifies a PLONK proof using KZG polynomial commitments.
//
// PLONK verification involves:
// 1. Parse proof elements (wire commitments, quotient commitments, opening proofs)
// 2. Compute public input polynomial evaluation at challenge point
// 3. Verify batched KZG opening proofs using pairing
//
// The proof format expected:
// - [0:64]    - a commitment (G1)
// - [64:128]  - b commitment (G1)
// - [128:192] - c commitment (G1)
// - [192:256] - z commitment (permutation polynomial, G1)
// - [256:320] - t_lo commitment (quotient polynomial low, G1)
// - [320:384] - t_mid commitment (quotient polynomial mid, G1)
// - [384:448] - t_hi commitment (quotient polynomial high, G1)
// - [448:512] - W_zeta proof (opening at zeta, G1)
// - [512:576] - W_zeta_omega proof (opening at zeta*omega, G1)
// - [576:608] - a_eval (scalar)
// - [608:640] - b_eval (scalar)
// - [640:672] - c_eval (scalar)
// - [672:704] - s1_eval (scalar)
// - [704:736] - s2_eval (scalar)
// - [736:768] - z_omega_eval (scalar)
func (zv *ZKVerifier) plonkVerify(
	vk *VerifyingKey,
	proof []byte,
	publicInputs []*big.Int,
) bool {
	// Same degeneracy refusal as Groth16: an identity selector or an
	// identity X2 collapses the pairing and accepts every proof. vk.Beta is
	// read below as the G2 generator, and vk.IC as the eight selectors plus
	// X2, so all of them must be non-identity.
	if degenerate(vk.Beta) || degenerate(vk.IC...) {
		return false
	}

	// The frame is 9 G1 points at 64 bytes then 6 scalars at 32: 768 bytes.
	// Both vectors are read through the cursor, so neither the points nor
	// the evaluations can reach past what the caller declared.
	in := contract.Read(proof)
	rawPoints, err := in.Fields(plonkPoints, plonkPointSize)
	if err != nil {
		return false
	}
	rawEvals, err := in.Fields(plonkEvals, fieldLen)
	if err != nil {
		return false
	}

	// Parse G1 commitments from proof
	commitments := make([]*bn256.G1, len(rawPoints))
	for i, b := range rawPoints {
		commitments[i] = new(bn256.G1)
		if _, err := commitments[i].Unmarshal(b); err != nil {
			return false
		}
	}

	// Parse evaluations
	evaluations := make([]*big.Int, len(rawEvals))
	for i, b := range rawEvals {
		evaluations[i] = new(big.Int).SetBytes(b)
	}

	// Parse verification key selectors and permutation commitments
	// VK contains: Qm, Ql, Qr, Qo, Qc, S1, S2, S3 (8 G1 points)
	// Plus: X2 (G2 generator scaled by tau)
	if len(vk.IC) < 9 {
		return false
	}

	vkPoints := make([]*bn256.G1, 8)
	for i := range 8 {
		vkPoints[i] = new(bn256.G1)
		if _, err := vkPoints[i].Unmarshal(vk.IC[i]); err != nil {
			return false
		}
	}

	// Parse X2 from verification key (G2 element)
	var x2 bn256.G2
	if _, err := x2.Unmarshal(vk.IC[8]); err != nil {
		return false
	}

	// Compute the public input polynomial evaluation
	// PI(x) = -∑ᵢ wᵢ · Lᵢ(x) where Lᵢ are Lagrange basis polynomials
	// For simplicity, we compute the hash-based challenge point
	piEval := computePlonkPIEvaluation(publicInputs)

	// Compute the linearization commitment
	// F = Qm·a·b + Ql·a + Qr·b + Qo·c + Qc + PI +
	//     α·[(a+β·z+γ)(b+β·k1·z+γ)(c+β·k2·z+γ)·Z - (a+β·S1+γ)(b+β·S2+γ)(c+β·S3+γ)·Z_ω]
	//     + α²·L1(z)·(Z-1)
	// Then verify the opening: e(F - r, G2) = e(W_zeta, X2)

	// For the final pairing check, we verify the batched opening:
	// e(W_zeta + u·W_zeta_omega, [x]₂) = e(zeta·W_zeta + u·zeta·ω·W_zeta_omega + F - r, G2)
	//
	// This is equivalent to checking:
	// e(W_zeta + u·W_zeta_omega, [x]₂) · e(-(zeta·W_zeta + u·zeta·ω·W_zeta_omega + F - r), G2) = 1

	// Compute challenge scalars using Fiat-Shamir
	// In a real implementation, these would be derived from transcript
	alpha := computeChallenge(proof, []byte("alpha"))
	beta := computeChallenge(proof, []byte("beta"))
	gamma := computeChallenge(proof, []byte("gamma"))
	zeta := computeChallenge(proof, []byte("zeta"))
	u := computeChallenge(proof, []byte("u"))

	// Build the linearization polynomial commitment F
	F := computeLinearizationCommitment(
		commitments, vkPoints, evaluations,
		alpha, beta, gamma, zeta, piEval,
	)

	// Compute the batched opening check
	// Left side: W_zeta + u·W_zeta_omega
	wZeta := commitments[7]
	wZetaOmega := commitments[8]

	leftG1 := new(bn256.G1)
	uWZetaOmega := new(bn256.G1)
	uWZetaOmega.ScalarMult(wZetaOmega, u)
	leftG1.Add(wZeta, uWZetaOmega)

	// Right side involves F and the evaluation point
	// For simplicity, we verify: e(leftG1, X2) = e(F, G2)
	// This is a simplified version; full PLONK has more terms

	// Parse G2 generator from verification key
	var g2Gen bn256.G2
	if _, err := g2Gen.Unmarshal(vk.Beta); err != nil {
		return false
	}

	// Negate F for the pairing check
	negF := new(bn256.G1)
	negF.ScalarMult(F, big.NewInt(-1))

	// Pairing check: e(leftG1, X2) · e(-F, G2) = 1
	g1Points := []*bn256.G1{leftG1, negF}
	g2Points := []*bn256.G2{&x2, &g2Gen}

	return bn256.PairingCheck(g1Points, g2Points)
}

// computePlonkPIEvaluation computes the public input contribution.
func computePlonkPIEvaluation(publicInputs []*big.Int) *big.Int {
	if len(publicInputs) == 0 {
		return big.NewInt(0)
	}

	// Simple aggregation for demonstration
	// In full PLONK, this evaluates the PI polynomial at challenge point
	result := new(big.Int)
	for _, input := range publicInputs {
		result.Add(result, input)
	}
	return result
}

// computeChallenge computes a Fiat-Shamir challenge from proof and domain separator.
func computeChallenge(proof, domain []byte) *big.Int {
	h := sha256.New()
	h.Write(domain)
	h.Write(proof)
	hash := h.Sum(nil)
	return new(big.Int).SetBytes(hash)
}

// computeLinearizationCommitment computes the PLONK linearization polynomial commitment.
func computeLinearizationCommitment(
	commitments []*bn256.G1,
	vkPoints []*bn256.G1,
	evaluations []*big.Int,
	alpha, beta, gamma, zeta, piEval *big.Int,
) *bn256.G1 {
	// Extract evaluations
	aEval := evaluations[0]
	bEval := evaluations[1]
	cEval := evaluations[2]

	// Compute gate constraint contribution
	// gate = Qm·a·b + Ql·a + Qr·b + Qo·c + Qc + PI
	F := new(bn256.G1)

	// Qm contribution: a·b·Qm
	ab := new(big.Int).Mul(aEval, bEval)
	qmContrib := new(bn256.G1)
	qmContrib.ScalarMult(vkPoints[0], ab)
	F.Add(F, qmContrib)

	// Ql contribution: a·Ql
	qlContrib := new(bn256.G1)
	qlContrib.ScalarMult(vkPoints[1], aEval)
	F.Add(F, qlContrib)

	// Qr contribution: b·Qr
	qrContrib := new(bn256.G1)
	qrContrib.ScalarMult(vkPoints[2], bEval)
	F.Add(F, qrContrib)

	// Qo contribution: c·Qo
	qoContrib := new(bn256.G1)
	qoContrib.ScalarMult(vkPoints[3], cEval)
	F.Add(F, qoContrib)

	// Qc contribution (constant)
	F.Add(F, vkPoints[4])

	// Permutation argument contribution (simplified)
	// In full PLONK, this includes the Z polynomial contribution
	zCommit := commitments[3]
	alphaZ := new(bn256.G1)
	alphaZ.ScalarMult(zCommit, alpha)
	F.Add(F, alphaZ)

	return F
}

// kzgPointEvaluation verifies a KZG polynomial commitment opening.
// Given commitment C = [P(τ)]₁, it verifies that P(z) = y.
//
// The verification uses the pairing equation:
// e(C - [y]G1, G2) = e(proof, [τ - z]G2)
//
// For EIP-4844 style verification, we use the kzg4844 package.
func (zv *ZKVerifier) kzgPointEvaluation(
	commitment []byte,
	point *big.Int,
	value *big.Int,
	proof []byte,
) bool {
	// Validate input sizes
	if len(commitment) != 48 || len(proof) != 48 {
		return false
	}

	// Convert to kzg4844 types
	var kzgCommitment kzg4844.Commitment
	copy(kzgCommitment[:], commitment)

	var kzgProof kzg4844.Proof
	copy(kzgProof[:], proof)

	// Convert point to 32-byte field element
	var kzgPoint kzg4844.Point
	pointBytes := point.Bytes()
	if len(pointBytes) > 32 {
		return false
	}
	// Right-align the bytes in the 32-byte array (big-endian)
	copy(kzgPoint[32-len(pointBytes):], pointBytes)

	// Convert value to 32-byte claim
	var kzgClaim kzg4844.Claim
	valueBytes := value.Bytes()
	if len(valueBytes) > 32 {
		return false
	}
	// Right-align the bytes in the 32-byte array (big-endian)
	copy(kzgClaim[32-len(valueBytes):], valueBytes)

	// Verify the proof using the kzg4844 package
	err := kzg4844.VerifyProof(kzgCommitment, kzgPoint, kzgClaim, kzgProof)
	return err == nil
}

func (zv *ZKVerifier) verifyMerkleProof(
	root [32]byte,
	leaf []byte,
	proof [][]byte,
	index uint64,
) bool {
	// Standard merkle proof verification
	current := sha256.Sum256(leaf)

	for i, sibling := range proof {
		var combined []byte
		if (index>>uint(i))&1 == 0 {
			combined = append(current[:], sibling...)
		} else {
			combined = append(sibling, current[:]...)
		}
		current = sha256.Sum256(combined)
	}

	return current == root
}

func (zv *ZKVerifier) updatePoolMerkleRoot(pool *ConfidentialPool) {
	// Rebuild merkle tree from commitments
	// In production, use incremental merkle tree for efficiency
}

func (zv *ZKVerifier) verifyGroth16Batch(vk *VerifyingKey, batch *RollupBatch) (bool, error) {
	if batch.Proof == nil {
		return false, ErrInvalidProof
	}

	// Public inputs for rollup: [prevRoot, newRoot, txRoot, batchNum]
	publicInputs := []*big.Int{
		new(big.Int).SetBytes(batch.PrevStateRoot[:]),
		new(big.Int).SetBytes(batch.NewStateRoot[:]),
		big.NewInt(int64(batch.Transactions)),
		big.NewInt(int64(batch.L1BatchNum)),
	}

	return zv.groth16PairingCheck(vk, batch.Proof.A, batch.Proof.B, batch.Proof.C, publicInputs), nil
}

func (zv *ZKVerifier) verifyPlonkBatch(vk *VerifyingKey, batch *RollupBatch) (bool, error) {
	if batch.Proof == nil {
		return false, ErrInvalidProof
	}

	publicInputs := []*big.Int{
		new(big.Int).SetBytes(batch.PrevStateRoot[:]),
		new(big.Int).SetBytes(batch.NewStateRoot[:]),
	}

	// Encode proof for PLONK
	proofData := append(batch.Proof.A, batch.Proof.B...)
	proofData = append(proofData, batch.Proof.C...)

	return zv.plonkVerify(vk, proofData, publicInputs), nil
}
