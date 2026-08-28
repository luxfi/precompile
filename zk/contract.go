// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/luxfi/crypto/bn256"
	"github.com/luxfi/crypto/kzg4844"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	// Note: ErrInvalidPublicInputs is defined in types.go
	ErrInvalidInput         = contract.ErrInvalidInput
	ErrInvalidOperation     = errors.New("invalid operation selector")
	ErrInvalidProofLength   = errors.New("invalid proof length")
	ErrVerificationFailed   = errors.New("proof verification failed")
	ErrUnknownProofSystem   = errors.New("unknown proof system")
	ErrNotImplemented       = errors.New("proof system not yet implemented")
	ErrInvalidPointFormat   = errors.New("invalid elliptic curve point format")
	ErrVerifierRequired     = errors.New("verifier context required")
	ErrInvalidCommitmentLen = errors.New("invalid commitment length")
	ErrFflonkDisabled       = errors.New("fflonk verification disabled: unsound verifier (reserved opcode 0x03)")

	// ErrRangeProofUnavailable is returned by op 0x23 when no bulletproof
	// verifier is wired. It fails closed — an unverifiable range proof is
	// never reported as valid — and is a named sentinel so callers can
	// distinguish "no verifier here" from "this proof is bad", and so a
	// test can pin the refusal.
	ErrRangeProofUnavailable = errors.New("range proof: no bulletproof verifier registered")

	// ErrHalo2KeyIncomplete is returned when a Halo2 proof reaches the
	// keyed path but the verifying key carries no IPA commitment key, so
	// the closing equation cannot be evaluated. Fails closed.
	ErrHalo2KeyIncomplete = errors.New("halo2: verifying key carries no IPA commitment key")
)

// Operation selectors (first byte of input)
const (
	OpVerifyGroth16    = 0x01 // Verify Groth16 proof
	OpVerifyPLONK      = 0x02 // Verify PLONK proof
	OpVerifyFflonk     = 0x03 // Verify fflonk proof
	OpVerifyHalo2      = 0x04 // Verify Halo2 proof
	OpVerifyKZG        = 0x10 // Verify KZG commitment
	OpVerifyIPA        = 0x12 // Verify IPA commitment
	OpVerifyRangeProof = 0x23 // Verify Bulletproof range proof
	OpVerifyNullifier  = 0x21 // Verify nullifier
	OpVerifyCommitment = 0x22 // Verify Pedersen commitment
	OpVerifyBatch      = 0x30 // Verify batch of proofs
)

// Gas costs
const (
	GasGroth16Base    = 150000 // Base cost for Groth16
	GasPLONKBase      = 200000 // Base cost for PLONK
	GasFflonkBase     = 180000 // Base cost for fflonk
	GasHalo2Base      = 250000 // Base cost for Halo2
	GasKZGBase        = 50000  // Base cost for KZG
	GasIPABase        = 75000  // Base cost for IPA
	GasRangeProofBase = 30000  // Base cost for range proof
	GasNullifierBase  = 10000  // Base cost for nullifier check
	GasCommitmentBase = 20000  // Base cost for commitment
	GasPerPublicInput = 1000   // Per public input element
	GasPerBatchProof  = 50000  // Per proof in batch
)

type zkVerifyPrecompile struct {
	verifier *ZKVerifier
}

// Address returns the precompile address
func (p *zkVerifyPrecompile) Address() common.Address {
	return ZKVerifyContractAddress
}

// MinCallGas is the floor charged for any precompile call, including
// unknown opcodes, to prevent zero-cost abuse.
const MinCallGas uint64 = 21_000

// RequiredGas calculates gas for ZK operations.
//
// The floor is applied here, once, so no branch of the schedule can
// undercut it: price(op) is the per-op question, MinCallGas is the
// policy, and the two are decided in separate places.
func (p *zkVerifyPrecompile) RequiredGas(input []byte) uint64 {
	return max(price(input), MinCallGas)
}

// price returns the schedule cost of an op, with no knowledge of the
// floor. Zero means "this op carries no cost of its own" — an unknown
// selector, or an input too short to name one.
func price(input []byte) uint64 {
	if len(input) < 1 {
		return 0
	}

	op := input[0]

	switch op {
	case OpVerifyGroth16:
		publicInputs := countPublicInputs(input)
		return GasGroth16Base + uint64(publicInputs)*GasPerPublicInput

	case OpVerifyPLONK:
		publicInputs := countPublicInputs(input)
		return GasPLONKBase + uint64(publicInputs)*GasPerPublicInput

	case OpVerifyFflonk:
		publicInputs := countPublicInputs(input)
		return GasFflonkBase + uint64(publicInputs)*GasPerPublicInput

	case OpVerifyHalo2:
		publicInputs := countPublicInputs(input)
		return GasHalo2Base + uint64(publicInputs)*GasPerPublicInput

	case OpVerifyKZG:
		return GasKZGBase

	case OpVerifyIPA:
		return GasIPABase

	case OpVerifyRangeProof:
		return GasRangeProofBase

	case OpVerifyNullifier:
		return GasNullifierBase

	case OpVerifyCommitment:
		return GasCommitmentBase

	case OpVerifyBatch:
		// A zero count yields zero here; the floor in RequiredGas turns that
		// into MinCallGas, so an empty batch cannot buy a free dispatch into
		// verifyBatch. No overflow is reachable: the count is a uint32 capped
		// by the input length, so the product stays below
		// 2^32 * GasPerBatchProof, itself far below 2^64.
		return uint64(countBatchProofs(input)) * GasPerBatchProof

	default:
		return 0
	}
}

// Wire offsets, within the FULL precompile input, of the header shared by
// ops 0x01-0x04 (Groth16, PLONK, fflonk, Halo2). Stated once so the gas
// schedule and the verifiers cannot drift apart:
//
//	[0:1]                    op selector
//	[1:33]                   vkID
//	[33:37]                  numInputs (big-endian uint32)
//	[37:37+numInputs*32]     public inputs, 32 bytes each
//
// Each verifier is handed input[1:], so it reads numInputs at [32:36] of
// its own slice — verifyGroth16, verifyPLONK, verifyFflonk and
// parseHalo2Proof all agree on that. RequiredGas sees the whole input and
// must therefore read at [33:37].
const (
	numInputsOff = 1 + 32           // 33
	inputsOff    = numInputsOff + 4 // 37
	fieldLen     = 32
)

// PLONK proof frame, as verifyPLONKStructure walks it: nine G1 commitments
// and opening proofs, then six field-element evaluations. Named so the floor
// and the field count cannot drift apart — reading only the points would
// admit a 576-byte proof where the frame is 768.
const (
	plonkPoints    = 9
	plonkPointSize = 64
	plonkEvals     = 6
	plonkProofSize = plonkPoints*plonkPointSize + plonkEvals*fieldLen // 768
)

// halo2MaxRounds caps the declared IPA round count, in both the Halo2 parser
// and op 0x12. Eight to sixteen rounds covers any reasonable polynomial
// degree; past that the count is a claim about work nobody will do.
//
// ipaPointSize is the width of an op-0x12 fold point: uncompressed (x, y),
// where Halo2's own L/R points are 32-byte compressed.
// rangeProofMinSize is the smallest bulletproof body op 0x23 will look at.
const (
	halo2MaxRounds    = 32
	ipaPointSize      = 64
	rangeProofMinSize = 64
	g1Size            = 48 // BLS12-381 G1, compressed
)

// countPublicInputs returns how many public inputs the verifier will parse.
//
// It reads the SAME wire field the verifiers read. Reading any other field
// decouples price from work in both directions: execution that is not paid
// for, and a valid proof priced out of the block.
//
// The claimed count is capped by what the calldata can actually hold. A
// count above that is refused by the verifier in constant time (its
// expectedLen check), so charging for it would price work that can never
// happen. With the cap, gas is bounded by the length of the input.
func countPublicInputs(input []byte) int {
	in := contract.Read(input)
	if _, err := in.Bytes(numInputsOff); err != nil {
		return 0
	}
	claimed, err := in.Uint32()
	if err != nil {
		return 0
	}
	capacity := in.Len() / fieldLen
	if uint64(claimed) > uint64(capacity) {
		return capacity
	}
	return int(claimed)
}

// statement reads the frame ops 0x01-0x04 share: a 32-byte verifying-key id, a
// big-endian count, and that many 32-byte public inputs.
//
// Groth16, PLONK and fflonk each carried their own copy of this, which is
// three chances for the count to be bounded differently from how it is used.
// One reading, one bound. The count sizes nothing until its bytes are in
// hand: Bytes refuses a count the calldata cannot back BEFORE the slice of
// big.Ints is allocated, so a declared 2^32-1 inputs costs a refusal rather
// than a 137 GB allocation.
func statement(in *contract.Cursor) (vkID [32]byte, publicInputs []*big.Int, err error) {
	id, err := in.Bytes(32)
	if err != nil {
		return vkID, nil, ErrInvalidInput
	}
	copy(vkID[:], id)

	n, err := in.Uint32()
	if err != nil {
		return vkID, nil, ErrInvalidInput
	}
	raw, err := in.Fields(uint64(n), fieldLen)
	if err != nil {
		return vkID, nil, ErrInvalidProofLength
	}

	publicInputs = make([]*big.Int, len(raw))
	for i, f := range raw {
		publicInputs[i] = new(big.Int).SetBytes(f)
	}
	return vkID, publicInputs, nil
}

// countBatchProofs returns how many proofs op 0x30 will attempt. It reads
// the same field verifyBatch reads ([0:4] of input[1:]) and, as with
// countPublicInputs, caps the claim by what the calldata can hold: every
// batch entry carries at least a 1-byte type and a 4-byte length, and
// verifyBatch stops at the first entry that runs past the end.
func countBatchProofs(input []byte) int {
	const (
		countEnd = 5 // op selector(1) + numProofs(4)
		entryHdr = 5 // proofType(1) + proofDataLen(4)
	)
	in := contract.Read(input)
	if _, err := in.Byte(); err != nil {
		return 0
	}
	claimed, err := in.Uint32()
	if err != nil {
		return 0
	}
	capacity := in.Len() / entryHdr
	if uint64(claimed) > uint64(capacity) {
		return capacity
	}
	return int(claimed)
}

// Run executes the ZK verify precompile
func (p *zkVerifyPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	// Calculate required gas
	requiredGas := p.RequiredGas(input)
	remainingGas, err = contract.DeductGas(suppliedGas, requiredGas)
	if err != nil {
		return nil, 0, err
	}

	// Reading the selector through the cursor does more than tidy the split.
	// input[1:] keeps the calldata's spare capacity — the rest of EVM memory,
	// which the caller MSTOREd — so every verifier downstream would inherit
	// a slice that a stray s[a:b] could walk forward into. Rest caps what it
	// hands over, so the payload carries exactly the bytes the caller
	// declared and nothing behind them.
	in := contract.Read(input)
	op, err := in.Byte()
	if err != nil {
		return nil, remainingGas, ErrInvalidInput
	}
	data := in.Rest()

	switch op {
	case OpVerifyGroth16:
		valid, err := p.verifyGroth16(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	case OpVerifyPLONK:
		valid, err := p.verifyPLONK(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	case OpVerifyFflonk:
		// DISABLED: verifyFflonk has a soundness bug — a nil verifying-key
		// singleton path accepts a crafted proof for ANY statement (a
		// universal forge). Reserved at 0x03 for opcode-numbering stability;
		// refuses execution until a sound verifier ships. This is a security
		// disable, fully independent of any PQ profile. Builders needing
		// PLONK-family verification should use OpVerifyPLONK (0x02).
		return nil, remainingGas, ErrFflonkDisabled

	case OpVerifyHalo2:
		valid, err := p.verifyHalo2(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	case OpVerifyKZG:
		valid, err := p.verifyKZG(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	case OpVerifyIPA:
		valid, err := p.verifyIPA(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	case OpVerifyRangeProof:
		valid, err := p.verifyRangeProof(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	case OpVerifyNullifier:
		valid, err := p.verifyNullifier(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	case OpVerifyCommitment:
		valid, err := p.verifyCommitment(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	case OpVerifyBatch:
		valid, err := p.verifyBatch(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	default:
		return nil, remainingGas, ErrInvalidOperation
	}
}

// encodeBool encodes a boolean as 32-byte EVM word
func encodeBool(b bool) []byte {
	result := make([]byte, 32)
	if b {
		result[31] = 1
	}
	return result
}

// verifyGroth16 verifies a Groth16 proof using bn256 pairing.
//
// Input format:
// - [0:32]   vkID - verification key identifier
// - [32:36]  numInputs - number of public inputs (big-endian uint32)
// - [36:36+numInputs*32] publicInputs - public inputs (32 bytes each)
// - [36+numInputs*32:+64] proofA - G1 point (64 bytes)
// - [+64:+192] proofB - G2 point (128 bytes)
// - [+192:+256] proofC - G1 point (64 bytes)
//
// The Groth16 verification equation:
// e(A, B) = e(α, β) · e(∑ᵢ wᵢ · ICᵢ, γ) · e(C, δ)
func (p *zkVerifyPrecompile) verifyGroth16(data []byte) (bool, error) {
	in := contract.Read(data)
	vkID, publicInputs, err := statement(in)
	if err != nil {
		return false, err
	}

	proofA, err := in.Bytes(64)
	if err != nil {
		return false, ErrInvalidProofLength
	}
	proofB, err := in.Bytes(128)
	if err != nil {
		return false, ErrInvalidProofLength
	}
	proofC, err := in.Bytes(64)
	if err != nil {
		return false, ErrInvalidProofLength
	}

	// If we have a verifier with registered keys, use it
	if p.verifier != nil {
		result, err := p.verifier.VerifyGroth16(vkID, proofA, proofB, proofC, publicInputs)
		if err != nil {
			return false, err
		}
		return result.Valid, nil
	}

	// Standalone verification: validate proof structure at minimum
	return verifyGroth16PointsValid(proofA, proofB, proofC)
}

// verifyGroth16PointsValid performs structural validation of Groth16 proof points.
// This validates that the points are on the curve and in the correct subgroups.
// Full verification requires a registered verification key.
func verifyGroth16PointsValid(proofA, proofB, proofC []byte) (bool, error) {
	// Validate G1 point A
	var a bn256.G1
	if _, err := a.Unmarshal(proofA); err != nil {
		return false, ErrInvalidPointFormat
	}

	// Validate G2 point B
	var b bn256.G2
	if _, err := b.Unmarshal(proofB); err != nil {
		return false, ErrInvalidPointFormat
	}

	// Validate G1 point C
	var c bn256.G1
	if _, err := c.Unmarshal(proofC); err != nil {
		return false, ErrInvalidPointFormat
	}

	// Points are valid, but full verification requires a verification key
	return false, errors.New("groth16: verification key required - register key with ZKVerifier")
}

// verifyPLONK verifies a PLONK proof.
//
// Input format:
// - [0:32]   vkID - verification key identifier
// - [32:36]  numInputs - number of public inputs (big-endian uint32)
// - [36:36+numInputs*32] publicInputs - public inputs (32 bytes each)
// - [36+numInputs*32:...] proof - PLONK proof bytes (minimum 768 bytes)
//
// PLONK verification involves:
// 1. Parse proof elements (wire commitments, quotient commitments, opening proofs)
// 2. Compute public input polynomial evaluation at challenge point
// 3. Verify batched KZG opening proofs using pairing
func (p *zkVerifyPrecompile) verifyPLONK(data []byte) (bool, error) {
	in := contract.Read(data)
	vkID, publicInputs, err := statement(in)
	if err != nil {
		return false, err
	}

	// The proof is the rest, and it must be at least the fixed frame that
	// verifyPLONKStructure walks. Checking the floor here keeps the refusal
	// where the length is known rather than one call deeper.
	if in.Len() < plonkProofSize {
		return false, ErrInvalidProofLength
	}
	proof := in.Rest()

	// If we have a verifier with registered keys, use it
	if p.verifier != nil {
		result, err := p.verifier.VerifyPlonk(vkID, proof, publicInputs)
		if err != nil {
			return false, err
		}
		return result.Valid, nil
	}

	// Standalone: validate proof structure
	return verifyPLONKStructure(proof)
}

// verifyPLONKStructure validates PLONK proof structure.
// PLONK proof format:
// - [0:64]    - a commitment (G1)
// - [64:128]  - b commitment (G1)
// - [128:192] - c commitment (G1)
// - [192:256] - z commitment (permutation polynomial, G1)
// - [256:320] - t_lo commitment (quotient polynomial low, G1)
// - [320:384] - t_mid commitment (quotient polynomial mid, G1)
// - [384:448] - t_hi commitment (quotient polynomial high, G1)
// - [448:512] - W_zeta proof (opening at zeta, G1)
// - [512:576] - W_zeta_omega proof (opening at zeta*omega, G1)
// - [576:768] - evaluations (6 x 32 bytes)
func verifyPLONKStructure(proof []byte) (bool, error) {
	// The frame is the points AND the evaluations after them: 9 G1 points at
	// 64 bytes is 576, six evaluations make 768. Reading only the points
	// would admit a 576-byte proof this has always refused, so the tail is
	// required too — checked after the points rather than as a floor before
	// them, so that both refusals are reachable. A guard that dominates the
	// read under it makes that read's refusal dead, and a dead refusal is
	// one no test can hold to anything.
	in := contract.Read(proof)
	points, err := in.Fields(plonkPoints, plonkPointSize)
	if err != nil {
		return false, ErrInvalidProofLength
	}
	if in.Len() < plonkEvals*fieldLen {
		return false, ErrInvalidProofLength
	}

	// Validate that all 9 G1 points are well-formed
	for _, b := range points {
		var point bn256.G1
		if _, err := point.Unmarshal(b); err != nil {
			return false, ErrInvalidPointFormat
		}
	}

	// Structure is valid, but full verification requires a verification key
	return false, errors.New("plonk: verification key required - register key with ZKVerifier")
}

// verifyFflonk verifies an fflonk proof.
//
// fflonk is an optimized PLONK variant (from Polygon zkEVM) that reduces the
// number of pairings by batching all constraint polynomials into a single
// opening proof using KZG commitments over BLS12-381.
//
// Input format:
// - [0:32]    vkID - verification key identifier
// - [32:36]   numInputs - number of public inputs (big-endian uint32)
// - [36:36+numInputs*32] publicInputs - public inputs (32 bytes each)
// - [36+numInputs*32:...] proof data containing:
//   - C1 commitment (48 bytes, BLS12-381 G1 compressed)
//   - C2 commitment (48 bytes, BLS12-381 G1 compressed)
//   - W1 opening proof (48 bytes, BLS12-381 G1 compressed)
//   - W2 opening proof (48 bytes, BLS12-381 G1 compressed)
//   - Evaluations (8+ field elements, 32 bytes each)
//
// Minimum proof size: 4*48 + 8*32 = 192 + 256 = 448 bytes
//
// The fflonk verification uses batched KZG openings with the equation:
// e(F - [r]G1, G2) = e(W, [τ - ξ]G2)
func (p *zkVerifyPrecompile) verifyFflonk(data []byte) (bool, error) {
	in := contract.Read(data)
	vkID, publicInputs, err := statement(in)
	if err != nil {
		return false, err
	}

	if in.Len() < fflonkMinProofSize {
		return false, ErrInvalidProofLength
	}
	proof := in.Rest()

	// If we have a verifier with registered keys, use it
	if p.verifier != nil {
		result, err := p.verifier.VerifyFflonk(vkID, proof, publicInputs)
		if err != nil {
			return false, err
		}
		return result.Valid, nil
	}

	// Standalone: parse and validate proof structure, then verify
	return verifyFflonkProof(proof, publicInputs)
}

// fflonk proof format constants
const (
	// BLS12-381 G1 point size (compressed)
	fflonkG1Size = g1Size

	// Number of G1 commitments in fflonk proof: C1, C2, W1, W2
	fflonkNumCommitments = 4

	// Number of field element evaluations in standard fflonk
	fflonkNumEvaluations = 8

	// Minimum proof size: 4 commitments + 8 evaluations
	fflonkMinProofSize = fflonkNumCommitments*fflonkG1Size + fflonkNumEvaluations*32
)

// FflonkProof represents a parsed fflonk proof
type FflonkProof struct {
	// Polynomial commitments (BLS12-381 G1 points, compressed)
	C1 []byte // First batched commitment
	C2 []byte // Second batched commitment
	W1 []byte // Opening proof for first batch
	W2 []byte // Opening proof for second batch

	// Evaluations at challenge points (field elements)
	Evaluations []*big.Int
}

// parseFflonkProof parses raw proof bytes into structured format
func parseFflonkProof(proof []byte) (*FflonkProof, error) {
	// No up-front floor: the reads below enforce exactly the same minimum
	// (4 commitments plus 8 evaluations IS fflonkMinProofSize) and answer the
	// same error, so a floor here would only make their refusals dead. It
	// survived deletion under mutation for that reason — nothing could tell
	// the two apart, because there was nothing to tell apart.
	in := contract.Read(proof)
	pts, err := in.Fields(fflonkNumCommitments, fflonkG1Size)
	if err != nil {
		return nil, ErrInvalidProofLength
	}

	// Evaluations are however many whole field elements the rest holds. The
	// count is derived from the remaining length rather than declared, so it
	// is bounded by construction.
	numEvals := uint64(in.Len()) / fieldLen
	if numEvals < fflonkNumEvaluations {
		return nil, ErrInvalidProofLength
	}
	evals, err := in.Fields(numEvals, fieldLen)
	if err != nil {
		return nil, ErrInvalidProofLength
	}

	fp := &FflonkProof{
		C1:          append([]byte(nil), pts[0]...),
		C2:          append([]byte(nil), pts[1]...),
		W1:          append([]byte(nil), pts[2]...),
		W2:          append([]byte(nil), pts[3]...),
		Evaluations: make([]*big.Int, len(evals)),
	}
	for i, e := range evals {
		fp.Evaluations[i] = new(big.Int).SetBytes(e)
	}
	return fp, nil
}

// verifyFflonkProof verifies an fflonk proof using KZG pairing checks
func verifyFflonkProof(proof []byte, publicInputs []*big.Int) (bool, error) {
	// Parse the proof structure
	fp, err := parseFflonkProof(proof)
	if err != nil {
		return false, err
	}

	// Validate G1 points are well-formed (on curve, in subgroup)
	if err := validateBLS12381G1Point(fp.C1); err != nil {
		return false, errors.New("fflonk: invalid C1 commitment: " + err.Error())
	}
	if err := validateBLS12381G1Point(fp.C2); err != nil {
		return false, errors.New("fflonk: invalid C2 commitment: " + err.Error())
	}
	if err := validateBLS12381G1Point(fp.W1); err != nil {
		return false, errors.New("fflonk: invalid W1 proof: " + err.Error())
	}
	if err := validateBLS12381G1Point(fp.W2); err != nil {
		return false, errors.New("fflonk: invalid W2 proof: " + err.Error())
	}

	// Validate evaluations are in field
	for i, eval := range fp.Evaluations {
		if err := validateBLS12381Scalar(eval); err != nil {
			return false, errors.New("fflonk: invalid evaluation " + intToStr(i) + ": " + err.Error())
		}
	}

	// Compute Fiat-Shamir challenges from transcript
	xi := computeFflonkChallenge(proof, publicInputs, []byte("xi"))
	v := computeFflonkChallenge(proof, publicInputs, []byte("v"))

	// Verify the batched KZG opening using kzg4844
	valid, err := verifyFflonkKZGOpening(fp, xi, v, publicInputs)
	if err != nil {
		return false, err
	}

	return valid, nil
}

// intToStr converts small int to string without fmt package
func intToStr(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return "N"
}

// validateBLS12381G1Point validates a compressed BLS12-381 G1 point
func validateBLS12381G1Point(point []byte) error {
	if len(point) != 48 {
		return errors.New("invalid point length: expected 48 bytes")
	}

	// Check for point at infinity (all zeros)
	allZero := true
	for _, b := range point {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil // Point at infinity is valid
	}

	// First byte contains flags:
	// - Bit 7: compression flag (should be 1 for compressed)
	// - Bit 6: infinity flag (0 for non-infinity points)
	// - Bit 5: sign bit for y-coordinate reconstruction
	flags := point[0]

	// Check compression flag is set (bit 7)
	if flags&0x80 == 0 {
		return errors.New("point is not in compressed format")
	}

	// Check infinity flag is not set for non-zero points (bit 6)
	if flags&0x40 != 0 {
		return errors.New("infinity flag set but point is not all zeros")
	}

	// Validate x-coordinate is in field (< p)
	// BLS12-381 base field prime p
	bls12381P := new(big.Int)
	bls12381P.SetString("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16)

	// Extract x-coordinate (mask off flag bits from first byte)
	xBytes := make([]byte, 48)
	copy(xBytes, point)
	xBytes[0] &= 0x1f // Clear flag bits

	x := new(big.Int).SetBytes(xBytes)
	if x.Cmp(bls12381P) >= 0 {
		return errors.New("x-coordinate not in field")
	}

	return nil
}

// validateBLS12381Scalar validates a 32-byte BLS12-381 scalar field element
func validateBLS12381Scalar(elem *big.Int) error {
	if elem == nil {
		return errors.New("nil field element")
	}

	// BLS12-381 scalar field order r
	bls12381R := new(big.Int)
	bls12381R.SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

	if elem.Sign() < 0 || elem.Cmp(bls12381R) >= 0 {
		return errors.New("element not in scalar field")
	}

	return nil
}

// computeFflonkChallenge computes a Fiat-Shamir challenge for fflonk
func computeFflonkChallenge(proof []byte, publicInputs []*big.Int, domain []byte) *big.Int {
	h := sha256.New()

	// Domain separator
	h.Write(domain)

	// Include public inputs in transcript
	for _, input := range publicInputs {
		inputBytes := input.Bytes()
		// Pad to 32 bytes
		padded := make([]byte, 32)
		copy(padded[32-len(inputBytes):], inputBytes)
		h.Write(padded)
	}

	// Include proof data
	h.Write(proof)

	hash := h.Sum(nil)

	// Reduce modulo scalar field order
	challenge := new(big.Int).SetBytes(hash)
	bls12381R := new(big.Int)
	bls12381R.SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
	challenge.Mod(challenge, bls12381R)

	return challenge
}

// verifyFflonkKZGOpening verifies the batched KZG opening in fflonk
func verifyFflonkKZGOpening(
	fp *FflonkProof,
	xi, v *big.Int,
	publicInputs []*big.Int,
) (bool, error) {
	// fflonk batches multiple polynomial evaluations into a single KZG opening.
	// The verification uses the equation:
	//
	// e(F - [r]G1, G2) = e(W, [τ - ξ]G2)
	//
	// where:
	// - F is the batched commitment: C1 + v·C2 (linearization)
	// - r is the batched evaluation: y1 + v·y2 + v²·...
	// - W is the batched opening proof: W1 + v·W2
	// - ξ (xi) is the evaluation point challenge

	// Ensure we have enough evaluations
	if len(fp.Evaluations) < 2 {
		return false, errors.New("fflonk: insufficient evaluations")
	}

	// Construct the batched evaluation point from xi
	var point kzg4844.Point
	xiBytes := xi.Bytes()
	if len(xiBytes) > 32 {
		return false, errors.New("fflonk: xi too large")
	}
	copy(point[32-len(xiBytes):], xiBytes)

	// Construct the batched claim from evaluations
	// r = y0 + v·y1 + v²·y2 + ...
	batchedEval := new(big.Int).Set(fp.Evaluations[0])
	vPower := new(big.Int).Set(v)

	bls12381R := new(big.Int)
	bls12381R.SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

	for i := 1; i < len(fp.Evaluations); i++ {
		term := new(big.Int).Mul(vPower, fp.Evaluations[i])
		term.Mod(term, bls12381R)
		batchedEval.Add(batchedEval, term)
		batchedEval.Mod(batchedEval, bls12381R)
		vPower.Mul(vPower, v)
		vPower.Mod(vPower, bls12381R)
	}

	var claim kzg4844.Claim
	evalBytes := batchedEval.Bytes()
	if len(evalBytes) > 32 {
		return false, errors.New("fflonk: batched evaluation too large")
	}
	copy(claim[32-len(evalBytes):], evalBytes)

	// Use C1 as commitment and W1 as proof for the primary KZG check
	// (In full fflonk, we would batch C1+v·C2 and W1+v·W2)
	var commitment kzg4844.Commitment
	copy(commitment[:], fp.C1)

	var proof kzg4844.Proof
	copy(proof[:], fp.W1)

	// Verify using kzg4844 package
	if err := kzg4844.VerifyProof(commitment, point, claim, proof); err != nil {
		// Verification failed - this is expected for invalid proofs
		// Return false without error (invalid proof is not an error condition)
		return false, nil
	}

	// KZG verification passed
	return true, nil
}

// verifyHalo2 verifies a Halo2 proof.
//
// Halo2 uses inner product arguments (IPA) instead of pairings, making it
// potentially post-quantum secure with the right parameter choices.
// It is the proof system used by Zcash Orchard and many zkEVM projects.
//
// Input format:
// - [0:32]   vkID - verification key identifier
// - [32:36]  numInputs - number of public inputs (big-endian uint32)
// - [36:36+numInputs*32] publicInputs - public inputs (32 bytes each)
// - [36+numInputs*32:+4] numAdviceCommits - number of advice column commitments
// - [...:+numAdviceCommits*32] adviceCommitments - advice commitments (32 bytes each)
// - [...:+4] numInstanceCommits - number of instance column commitments
// - [...:+numInstanceCommits*32] instanceCommitments - instance commitments (32 bytes each)
// - [...:+4] numRounds - IPA rounds (log2 of polynomial degree)
// - [...:+numRounds*32] L points - left fold points
// - [...:+numRounds*32] R points - right fold points
// - [...:+32] a_scalar - final scalar value
// - [...:+32] evalPoint - evaluation challenge point
// - [...:+32] claimedEval - claimed evaluation result
//
// Halo2 verification involves:
// 1. Parse proof elements (advice/instance commitments, IPA proof)
// 2. Reconstruct transcript and compute Fiat-Shamir challenges
// 3. Verify IPA opening proofs (no pairings needed)
func (p *zkVerifyPrecompile) verifyHalo2(data []byte) (bool, error) {
	proof, err := parseHalo2Proof(data)
	if err != nil {
		return false, err
	}

	// If we have a verifier with registered keys, use full verification
	if p.verifier != nil {
		vk := p.verifier.VerifyingKeys[proof.vkID]
		if vk != nil && vk.ProofSystem == ProofSystemHalo2 {
			return verifyHalo2Full(proof, vk)
		}
	}

	// Standalone verification: validate proof structure and perform
	// transcript-based verification where possible
	return verifyHalo2Structural(proof)
}

// Halo2Proof represents a parsed Halo2 proof structure
type Halo2Proof struct {
	vkID                [32]byte
	publicInputs        []*big.Int
	adviceCommitments   [][]byte // 32-byte compressed points
	instanceCommitments [][]byte // 32-byte compressed points
	numRounds           uint32
	lPoints             [][]byte // Left fold points
	rPoints             [][]byte // Right fold points
	aScalar             []byte   // Final scalar (32 bytes)
	evalPoint           []byte   // Evaluation challenge (32 bytes)
	claimedEval         []byte   // Claimed evaluation (32 bytes)
}

// parseHalo2Proof parses raw bytes into a Halo2Proof structure
func parseHalo2Proof(data []byte) (*Halo2Proof, error) {
	in := contract.Read(data)
	proof := &Halo2Proof{}

	// vec reads a declared count followed by that many 32-byte elements. The
	// three vectors below had a copy of this each, with the count bounded in
	// one place and used to size an allocation in another; the count now
	// cannot outlive the bytes that back it, because Fields refuses before
	// it allocates.
	vec := func(missing, short string) ([][]byte, error) {
		n, err := in.Uint32()
		if err != nil {
			return nil, errors.New(missing)
		}
		f, err := in.Fields(uint64(n), fieldLen)
		if err != nil {
			return nil, errors.New(short)
		}
		return f, nil
	}

	id, err := in.Bytes(32)
	if err != nil {
		return nil, ErrInvalidInput
	}
	copy(proof.vkID[:], id)

	inputs, err := vec("halo2: missing public inputs count", "halo2: insufficient data for public inputs")
	if err != nil {
		return nil, err
	}
	proof.publicInputs = make([]*big.Int, len(inputs))
	for i, f := range inputs {
		proof.publicInputs[i] = new(big.Int).SetBytes(f)
	}

	if proof.adviceCommitments, err = vec(
		"halo2: missing advice commitments count",
		"halo2: insufficient data for advice commitments"); err != nil {
		return nil, err
	}
	if proof.instanceCommitments, err = vec(
		"halo2: missing instance commitments count",
		"halo2: insufficient data for instance commitments"); err != nil {
		return nil, err
	}

	// IPA rounds carry their own bound on top of the length: a proof with
	// more than 32 rounds is refused even when the calldata could hold it.
	proof.numRounds, err = in.Uint32()
	if err != nil {
		return nil, errors.New("halo2: missing IPA rounds count")
	}
	if proof.numRounds == 0 || proof.numRounds > halo2MaxRounds {
		return nil, errors.New("halo2: invalid number of IPA rounds (must be 1-32)")
	}

	if proof.lPoints, err = in.Fields(uint64(proof.numRounds), fieldLen); err != nil {
		return nil, errors.New("halo2: insufficient data for L points")
	}
	if proof.rPoints, err = in.Fields(uint64(proof.numRounds), fieldLen); err != nil {
		return nil, errors.New("halo2: insufficient data for R points")
	}

	if proof.aScalar, err = in.Bytes(fieldLen); err != nil {
		return nil, errors.New("halo2: missing final scalar")
	}
	if proof.evalPoint, err = in.Bytes(fieldLen); err != nil {
		return nil, errors.New("halo2: missing evaluation point")
	}
	if proof.claimedEval, err = in.Bytes(fieldLen); err != nil {
		return nil, errors.New("halo2: missing claimed evaluation")
	}

	return proof, nil
}

// verifyHalo2Structural performs structural validation and transcript-based
// verification of a Halo2 proof without requiring a registered verification key.
//
// This validates:
// 1. All commitments are valid curve points
// 2. IPA L/R points are valid
// 3. Transcript challenges are correctly derived (Fiat-Shamir)
// 4. The proof structure is internally consistent
func verifyHalo2Structural(proof *Halo2Proof) (bool, error) {
	// Validate all advice commitments are valid points
	for i, commit := range proof.adviceCommitments {
		if !isValidCompressedPoint(commit) {
			return false, errors.New("halo2: invalid advice commitment at index " + string(rune('0'+i)))
		}
	}

	// Validate all instance commitments are valid points
	for i, commit := range proof.instanceCommitments {
		if !isValidCompressedPoint(commit) {
			return false, errors.New("halo2: invalid instance commitment at index " + string(rune('0'+i)))
		}
	}

	// Validate L points
	for i, lPoint := range proof.lPoints {
		if !isValidCompressedPoint(lPoint) {
			return false, errors.New("halo2: invalid L point at round " + string(rune('0'+i)))
		}
	}

	// Validate R points
	for i, rPoint := range proof.rPoints {
		if !isValidCompressedPoint(rPoint) {
			return false, errors.New("halo2: invalid R point at round " + string(rune('0'+i)))
		}
	}

	// Validate scalar is in field
	if !isValidScalar(proof.aScalar) {
		return false, errors.New("halo2: invalid final scalar")
	}

	// Validate evaluation point is in field
	if !isValidScalar(proof.evalPoint) {
		return false, errors.New("halo2: invalid evaluation point")
	}

	// Validate claimed evaluation is in field
	if !isValidScalar(proof.claimedEval) {
		return false, errors.New("halo2: invalid claimed evaluation")
	}

	// Reconstruct and verify transcript challenges
	// This ensures the proof was constructed correctly using Fiat-Shamir
	challenges, err := computeHalo2Challenges(proof)
	if err != nil {
		return false, err
	}

	// Verify challenge consistency (non-zero, properly derived)
	for i, ch := range challenges {
		if isZeroBytes(ch) {
			return false, errors.New("halo2: zero challenge at round " + string(rune('0'+i)))
		}
	}

	// Structural validation passed
	// Note: Full verification requires the verification key to compute
	// the expected commitment from public inputs and verify the IPA
	return false, errors.New("halo2: structural validation passed - full verification requires registered verification key")
}

// verifyHalo2Full performs complete Halo2 verification with a verification key
func verifyHalo2Full(proof *Halo2Proof, vk *VerifyingKey) (bool, error) {
	// Reconstruct transcript challenges
	challenges, err := computeHalo2Challenges(proof)
	if err != nil {
		return false, err
	}

	// Compute the expected commitment from public inputs
	// In Halo2, this involves evaluating the instance polynomial
	expectedCommitment, err := computeHalo2InstanceCommitment(proof, vk)
	if err != nil {
		return false, err
	}

	// Verify the IPA opening proof. The IPA proves that the committed
	// polynomial evaluates to the claimed value at the evaluation point.
	//
	// The verdict and the reason are one value, so there is no way to take
	// the error while dropping the answer — which is how three tests came to
	// miss three verifiers that answered valid without verifying.
	v := verifyHalo2IPA(proof, vk, expectedCommitment, challenges)
	return v.OK(), v.Err()
}

// computeHalo2Challenges reconstructs the Fiat-Shamir transcript challenges
func computeHalo2Challenges(proof *Halo2Proof) ([][]byte, error) {
	// Initialize transcript with domain separator
	transcript := newHalo2Transcript()

	// Append public inputs
	for _, input := range proof.publicInputs {
		transcript.appendScalar(input.Bytes())
	}

	// Append advice commitments
	for _, commit := range proof.adviceCommitments {
		transcript.appendPoint(commit)
	}

	// Append instance commitments
	for _, commit := range proof.instanceCommitments {
		transcript.appendPoint(commit)
	}

	// Generate challenges for each IPA round
	challenges := make([][]byte, proof.numRounds)
	for i := uint32(0); i < proof.numRounds; i++ {
		// Append L and R points for this round
		transcript.appendPoint(proof.lPoints[i])
		transcript.appendPoint(proof.rPoints[i])

		// Generate challenge
		challenges[i] = transcript.challenge()
	}

	return challenges, nil
}

// computeHalo2InstanceCommitment computes commitment from public inputs
func computeHalo2InstanceCommitment(proof *Halo2Proof, vk *VerifyingKey) ([]byte, error) {
	if len(vk.IC) < len(proof.publicInputs)+1 {
		return nil, errors.New("halo2: verification key has insufficient IC points")
	}

	// Linear combination: IC[0] + sum(publicInputs[i] * IC[i+1])
	// Returns the first instance commitment when available, otherwise falls back to IC[0].
	// Full curve arithmetic over the commitment scheme's curve is handled by verifyHalo2IPA.
	if len(proof.instanceCommitments) > 0 {
		return proof.instanceCommitments[0], nil
	}

	return vk.IC[0], nil
}

// verifyHalo2IPA verifies the IPA opening proof.
//
// It answers a contract.Verdict rather than (bool, error) because this is the
// function that once answered `true` for every proof of every statement: it
// folded the rounds, assigned the result to _ under a comment saying it was
// used in full verification, and returned true. Nothing downstream re-checked
// it, so op 0x04 accepted anything whenever any Halo2 key was registered.
//
// Under (bool, error) that lie is one keyword. Under Verdict a positive can
// only come from contract.Checked, and TestCheckedIsNeverALiteral fails the
// build if Checked is ever handed a constant — so a claim of validity has to
// come from an expression that computed something. The zero Verdict, which is
// what a fall-through yields, denies.
func verifyHalo2IPA(proof *Halo2Proof, vk *VerifyingKey, commitment []byte, challenges [][]byte) contract.Verdict {
	if len(challenges) != int(proof.numRounds) {
		return contract.Refused(errors.New("halo2: challenge count mismatch"))
	}

	// The IPA verification equation:
	// We verify that the commitment opens to the claimed evaluation
	// at the evaluation point.
	//
	// For each round i:
	//   commitment' = commitment + x_i * L_i + x_i^{-1} * R_i
	//
	// After all rounds, we check:
	//   g0 * a + (a * b0) * Q == final_commitment
	//
	// Where:
	//   g0 is the folded generator
	//   b0 is the folded evaluation coefficient
	//   Q is the commitment key's auxiliary point
	//   a is the final scalar from the proof

	// Compute challenge inverses
	challengeInvs := make([][]byte, len(challenges))
	for i, ch := range challenges {
		inv, err := modInverse(ch)
		if err != nil {
			return contract.Refused(errors.New("halo2: failed to compute challenge inverse"))
		}
		challengeInvs[i] = inv
	}

	// Fold the commitment through all rounds
	foldedCommitment := make([]byte, 32)
	copy(foldedCommitment, commitment)

	for i := uint32(0); i < proof.numRounds; i++ {
		// commitment' = commitment + x * L + x^{-1} * R
		// This is a point addition with scalar multiplication
		foldedCommitment = foldCommitment(
			foldedCommitment,
			proof.lPoints[i],
			proof.rPoints[i],
			challenges[i],
			challengeInvs[i],
		)
	}

	// The closing equation is g0*a + (a*b0)*Q == foldedCommitment, where g0
	// is the folded SRS generator and Q the commitment key's auxiliary
	// point. Neither is available: VerifyingKey is Groth16-shaped
	// (Alpha/Beta/Gamma/Delta/IC) and carries no IPA commitment key.
	//
	// So the fold above is evidence, not a verdict, and there is no
	// contract.Checked to write here — the predicate that would go inside it
	// does not exist. That is the distinction the type carries: a refusal is
	// not a negative verdict, and errors.Is(v.Err(), contract.ErrNoVerifier)
	// tells a caller which one it got.
	_ = foldedCommitment
	return contract.Refused(ErrHalo2KeyIncomplete)
}

// halo2Transcript implements Fiat-Shamir transcript for Halo2
type halo2Transcript struct {
	state []byte
}

func newHalo2Transcript() *halo2Transcript {
	// Initialize with Halo2 domain separator
	h := sha256Hash([]byte("Halo2-IPA-Transcript"))
	return &halo2Transcript{state: h}
}

func (t *halo2Transcript) appendScalar(s []byte) {
	t.state = sha256Hash(append(t.state, s...))
}

func (t *halo2Transcript) appendPoint(p []byte) {
	t.state = sha256Hash(append(t.state, p...))
}

func (t *halo2Transcript) challenge() []byte {
	// Generate challenge and update state
	challenge := sha256Hash(append(t.state, []byte("challenge")...))
	t.state = sha256Hash(append(t.state, challenge...))
	return challenge
}

// sha256Hash computes SHA256 hash
func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// pallasFieldModulus is the base field modulus p of the Pallas curve
// (y^2 = x^3 + 5), the curve Halo2 commitments live on. Field elements (point
// coordinates) are reduced mod p. p = 2^254 + 0x224698fc094cf91b992d30ed00000001.
var pallasFieldModulus, _ = new(big.Int).SetString(
	"28948022309329048855892746252171976963363056481941560715954676764349967630337", 10)

// pallasScalarOrder is the order q of the Pallas group — the modulus for
// scalars (challenges, evaluations, the folding scalar), as distinct from
// the base field p above in which point COORDINATES live. Pallas has
// cofactor 1, so q is both the group order and the scalar field modulus.
// q = 2^254 + 0x224698fc0994a8dd8c46eb2100000001.
var pallasScalarOrder, _ = new(big.Int).SetString(
	"28948022309329048855892746252171976963363056481941647379679742748393362948097", 10)

// isValidCompressedPoint validates a 32-byte compressed Halo2 (Pallas) point.
//
// Encoding: 32 bytes big-endian; the top bit (0x80 of byte 0) is the y-sign
// bit and the remaining 255 bits are the x-coordinate. The all-zero encoding
// is the identity and is rejected here (a meaningful commitment is never the
// identity).
//
// Validation: x must be a canonical field element (x < p) and the curve
// equation y^2 = x^3 + 5 must have a solution, i.e. x^3 + 5 must be a
// quadratic residue mod p. Pallas has prime order (cofactor 1), so any point
// satisfying the curve equation is automatically in the prime-order subgroup;
// the on-curve test is therefore also the subgroup test. Off-curve x values
// (x^3 + 5 a non-residue), non-canonical x (x >= p), and wrong-length inputs
// are rejected.
func isValidCompressedPoint(p []byte) bool {
	if len(p) != 32 {
		return false
	}
	if isZeroBytes(p) {
		return false // identity encoding
	}
	// Recover x by clearing the sign bit (both y-signs are on-curve, so the
	// sign bit does not affect validity).
	buf := make([]byte, 32)
	copy(buf, p)
	buf[0] &^= 0x80
	x := new(big.Int).SetBytes(buf)
	if x.Cmp(pallasFieldModulus) >= 0 {
		return false // non-canonical x
	}
	// rhs = x^3 + 5 mod p
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, big.NewInt(5))
	rhs.Mod(rhs, pallasFieldModulus)
	return isQuadraticResidue(rhs, pallasFieldModulus)
}

// isQuadraticResidue reports whether a is a square mod the odd prime p, via
// Euler's criterion: a is a QR iff a == 0 or a^((p-1)/2) == 1 (mod p).
func isQuadraticResidue(a, p *big.Int) bool {
	if a.Sign() == 0 {
		return true
	}
	exp := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1)
	return new(big.Int).Exp(a, exp, p).Cmp(big.NewInt(1)) == 0
}

// isValidScalar checks if bytes represent a valid scalar in the field
func isValidScalar(s []byte) bool {
	if len(s) != 32 {
		return false
	}
	// The encoding must be CANONICAL: s < q. Accepting s >= q makes the
	// encoding non-injective — s and s+q denote the same field element but
	// are different bytes — so a proof could be re-encoded into a distinct
	// byte string that still verifies, and any transcript hashing those
	// bytes would bind to the encoding rather than to the value. This
	// function previously checked only the length, which is no check at
	// all: every 32-byte string passed. Zero is a legitimate scalar.
	return new(big.Int).SetBytes(s).Cmp(pallasScalarOrder) < 0
}

// isZeroBytes checks if all bytes are zero
func isZeroBytes(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// modInverse computes modular multiplicative inverse
// For field elements, this uses Fermat's little theorem: a^{-1} = a^{p-2} mod p
func modInverse(a []byte) ([]byte, error) {
	if isZeroBytes(a) {
		return nil, errors.New("cannot invert zero")
	}

	// Computes modular inverse using BN254 field modulus.
	// Pallas/Vesta curves use different moduli; callers should verify field compatibility.
	aInt := new(big.Int).SetBytes(a)

	// Use BN254 field modulus as approximation (full impl uses Pallas/Vesta)
	p := BN254P
	if aInt.Cmp(p) >= 0 {
		aInt.Mod(aInt, p)
	}

	// Compute a^{p-2} mod p
	pMinus2 := new(big.Int).Sub(p, big.NewInt(2))
	inv := new(big.Int).Exp(aInt, pMinus2, p)

	result := make([]byte, 32)
	invBytes := inv.Bytes()
	copy(result[32-len(invBytes):], invBytes)

	return result, nil
}

// foldCommitment performs commitment folding: C' = C + x*L + x^{-1}*R
// This is the core operation in each IPA round
func foldCommitment(c, l, r, x, xInv []byte) []byte {
	// In full implementation, this is elliptic curve arithmetic:
	// result = point_add(c, scalar_mul(l, x), scalar_mul(r, xInv))
	//
	// For structural validation, we combine the hashes
	combined := append(c, l...)
	combined = append(combined, r...)
	combined = append(combined, x...)
	combined = append(combined, xInv...)

	return sha256Hash(combined)
}

// verifyKZG verifies a KZG polynomial commitment opening using EIP-4844 format.
//
// Input format:
// - [0:48]    commitment - KZG commitment (compressed G1 point, BLS12-381)
// - [48:80]   point - evaluation point (32-byte field element)
// - [80:112]  claim - claimed evaluation value (32-byte field element)
// - [112:160] proof - KZG proof (compressed G1 point, BLS12-381)
//
// Verifies that p(point) = claim where p is the polynomial committed in commitment.
// Uses the pairing equation: e(C - [y]G1, G2) = e(proof, [τ - z]G2)
func (p *zkVerifyPrecompile) verifyKZG(data []byte) (bool, error) {
	// commitment(48) + point(32) + claim(32) + proof(48) = 160 bytes
	in := contract.Read(data)
	c, err := in.Bytes(g1Size)
	if err != nil {
		return false, ErrInvalidInput
	}
	z, err := in.Bytes(fieldLen)
	if err != nil {
		return false, ErrInvalidInput
	}
	y, err := in.Bytes(fieldLen)
	if err != nil {
		return false, ErrInvalidInput
	}
	pi, err := in.Bytes(g1Size)
	if err != nil {
		return false, ErrInvalidInput
	}

	var commitment kzg4844.Commitment
	var point kzg4844.Point
	var claim kzg4844.Claim
	var proof kzg4844.Proof
	copy(commitment[:], c)
	copy(point[:], z)
	copy(claim[:], y)
	copy(proof[:], pi)

	// A pairing that does not hold is an invalid proof, not an error.
	return kzg4844.VerifyProof(commitment, point, claim, proof) == nil, nil
}

// verifyIPA verifies an Inner Product Argument.
//
// IPA is used in Verkle trees and some ZK systems (like Halo2).
// The proof demonstrates that the prover knows vectors a, b such that
// <a, G> = C (commitment) and <a, b> = y (inner product result).
//
// Input format:
// - [0:32]    commitment - commitment point (compressed)
// - [32:64]   evalPoint - evaluation point (field element)
// - [64:96]   result - claimed inner product result (field element)
// - [96:100]  numRounds - number of IPA rounds (uint32, typically log2(vector_size))
// - [100:100+numRounds*64] L points - left fold points (numRounds x 64 bytes)
// - [...:...+numRounds*64] R points - right fold points (numRounds x 64 bytes)
// - [...:...+32] a_scalar - final scalar value (32 bytes)
//
// The IPA verifier checks that the commitment opens to the claimed value
// at the evaluation point using a logarithmic proof.
//
// Note: Full IPA verification requires the IPAConfig from crypto/ipa package.
// This function validates the proof structure.
func (p *zkVerifyPrecompile) verifyIPA(data []byte) (bool, error) {
	// commitment(32) + evalPoint(32) + result(32) + numRounds(4), then
	// numRounds L points and numRounds R points at 64 bytes each, then a
	// 32-byte final scalar.
	in := contract.Read(data)
	if _, err := in.Bytes(3 * fieldLen); err != nil {
		return false, ErrInvalidInput
	}
	numRounds, err := in.Uint32()
	if err != nil {
		return false, ErrInvalidInput
	}

	// Validate reasonable number of rounds (1-32 for 2^1 to 2^32 vector sizes)
	if numRounds == 0 || numRounds > halo2MaxRounds {
		return false, errors.New("ipa: invalid number of rounds")
	}

	if _, err := in.Fields(uint64(numRounds), ipaPointSize); err != nil {
		return false, ErrInvalidProofLength
	}
	if _, err := in.Fields(uint64(numRounds), ipaPointSize); err != nil {
		return false, ErrInvalidProofLength
	}
	if _, err := in.Bytes(fieldLen); err != nil {
		return false, ErrInvalidProofLength
	}

	// IPA verification requires the crypto/ipa package with proper configuration.
	// The full verification involves:
	// 1. Recompute challenges from transcript using Fiat-Shamir
	// 2. Fold the commitment using L, R points and challenges
	// 3. Compute folded generator g0 and scalar b0
	// 4. Verify: g0 * a + (a * b0) * Q == folded_commitment
	//
	// This requires the IPAConfig which includes SRS generators.
	return false, errors.New("ipa: full verification requires IPAConfig - use crypto/ipa.CheckIPAProof directly")
}

// verifyRangeProof verifies a Bulletproof-style range proof.
//
// Range proofs prove that a committed value lies in [0, 2^n) without revealing it.
// This is essential for confidential transactions where amounts must be positive.
//
// Input format:
// - [0:32]   commitment - Pedersen commitment to the value
// - [32:36]  bitLength - bit length of range (e.g., 64 for 64-bit range)
// - [36:...]  proof - Bulletproof range proof data
//
// Bulletproof range proofs use inner product arguments to achieve
// O(log n) proof size for n-bit ranges.
//
// Note: Bulletproof verification is not yet implemented.
func (p *zkVerifyPrecompile) verifyRangeProof(data []byte) (bool, error) {
	// commitment(32) + bitLength(4) + at least 64 bytes of proof = 100.
	//
	// Every short case answers ErrInvalidInput, which is what the single
	// `len(data) < 100` guard answered before. Two arms that stood here —
	// ErrInvalidCommitmentLen on a commitment that was never not 32 bytes,
	// and ErrInvalidProofLength on a remainder that could not be under 64
	// once the input cleared 100 — were unreachable under that guard, and an
	// unreachable arm is a refusal no caller can ever observe.
	in := contract.Read(data)
	commitment, err := in.Bytes(fieldLen)
	if err != nil {
		return false, ErrInvalidInput
	}
	bitLength, err := in.Uint32()
	if err != nil {
		return false, ErrInvalidInput
	}
	if in.Len() < rangeProofMinSize {
		return false, ErrInvalidInput
	}
	if bitLength == 0 || bitLength > 256 {
		return false, errors.New("range proof: invalid bit length (must be 1-256)")
	}
	rangeProof := in.Rest()

	// If we have a verifier, use it
	if p.verifier != nil {
		v := p.verifier.VerifyRangeProof(commitment, rangeProof, bitLength)
		return v.OK(), v.Err()
	}

	// No verifier wired: refuse. Never report an unverified proof as valid.
	return false, ErrRangeProofUnavailable
}

// verifyNullifier checks if a nullifier has been used (spent).
//
// Nullifiers are used in privacy-preserving protocols to prevent double-spending
// without revealing which note is being spent. Each note has a unique nullifier
// derived from the note's secret data.
//
// Input format:
// - [0:32] nullifierHash - the nullifier hash to check
//
// Returns:
// - true if the nullifier has NOT been spent (is valid for use)
// - false if the nullifier has already been spent (double-spend attempt)
func (p *zkVerifyPrecompile) verifyNullifier(data []byte) (bool, error) {
	h, err := contract.Read(data).Bytes(fieldLen)
	if err != nil {
		return false, ErrInvalidInput
	}
	var nullifierHash [32]byte
	copy(nullifierHash[:], h)

	// Check against the verifier's nullifier set
	if p.verifier != nil {
		spent, err := p.verifier.CheckNullifier(nullifierHash)
		if err != nil {
			return false, err
		}
		// Return true if NOT spent (valid for use)
		return !spent, nil
	}

	// Without a verifier context, we can't check state
	return false, errors.New("nullifier: verifier context required for state lookup")
}

// verifyCommitment verifies a Pedersen commitment opening or Merkle inclusion.
//
// Two modes are supported:
//
// Mode 1: Pedersen commitment opening verification (96 bytes)
// - [0:32]   commitment - the commitment to verify
// - [32:64]  value - the claimed committed value
// - [64:96]  blinding - the blinding factor
// Returns true if C == v*G + r*H
//
// Mode 2: Merkle inclusion proof (76+ bytes, first byte is 0x01)
// - [0:1]    mode - 0x01 for Merkle mode
// - [1:33]   poolID - pool identifier
// - [33:65]  commitmentID - commitment to verify
// - [65:73]  leafIndex - position in Merkle tree
// - [73:77]  proofLen - number of sibling hashes
// - [77:...]  merkleProof - sibling hashes (proofLen * 32 bytes)
func (p *zkVerifyPrecompile) verifyCommitment(data []byte) (bool, error) {
	if len(data) < 96 {
		return false, ErrInvalidInput
	}

	// Check if this is Merkle mode (first byte is 0x01)
	if isMerkleCommitment(data) {
		return p.verifyCommitmentMerkle(data[1:])
	}

	// Default: Pedersen commitment opening verification
	return p.verifyCommitmentPedersen(data)
}

// isMerkleCommitment reports whether a 0x22 (OpVerifyCommitment) payload
// selects the Merkle-inclusion sub-mode (hash-based, quantum-safe). This
// is the SINGLE source of truth for the sub-mode discriminator: both the
// strict-PQ gate in Run() and verifyCommitment's dispatch consult it, so
// the gate and the dispatch can never disagree about which bytes are the
// hash-based path. The condition is exactly the one verifyCommitment uses
// to route to verifyCommitmentMerkle.
//
// `data` is the post-selector payload (input[1:]), matching what
// verifyCommitment receives.
func isMerkleCommitment(data []byte) bool {
	return len(data) >= 77 && data[0] == 0x01
}

// verifyCommitmentPedersen verifies a Pedersen commitment opening.
// C = v*G + r*H
func (p *zkVerifyPrecompile) verifyCommitmentPedersen(data []byte) (bool, error) {
	f, err := contract.Read(data).Fields(3, fieldLen)
	if err != nil {
		return false, ErrInvalidInput
	}
	var commitment, value, blinding [32]byte
	copy(commitment[:], f[0])
	copy(value[:], f[1])
	copy(blinding[:], f[2])

	// Use the global Pedersen committer for verification
	return globalPedersen.Verify(commitment, value, blinding)
}

// verifyCommitmentMerkle verifies commitment inclusion in a Merkle tree.
func (p *zkVerifyPrecompile) verifyCommitmentMerkle(data []byte) (bool, error) {
	// poolID(32) + commitmentID(32) + leafIndex(8) + proofLen(4) = 76 bytes minimum
	in := contract.Read(data)
	ids, err := in.Fields(2, fieldLen)
	if err != nil {
		return false, ErrInvalidInput
	}
	var poolID, commitmentID [32]byte
	copy(poolID[:], ids[0])
	copy(commitmentID[:], ids[1])

	leafIndex, err := in.Uint64()
	if err != nil {
		return false, ErrInvalidInput
	}
	proofLen, err := in.Uint32()
	if err != nil {
		return false, ErrInvalidInput
	}
	merkleProof, err := in.Fields(uint64(proofLen), fieldLen)
	if err != nil {
		return false, ErrInvalidInput
	}

	// Verify using ZKVerifier if available
	if p.verifier != nil {
		return p.verifier.VerifyCommitmentInclusion(poolID, commitmentID, merkleProof, leafIndex)
	}

	return false, errors.New("commitment: verifier context required for Merkle proof verification")
}

// verifyBatch verifies a batch of proofs
// Input format: [4 bytes numProofs][for each: 1 byte proofType, 4 bytes proofDataLen, proofDataLen bytes proofData]
func (p *zkVerifyPrecompile) verifyBatch(data []byte) (bool, error) {
	in := contract.Read(data)
	numProofs, err := in.Uint32()
	if err != nil {
		return false, ErrInvalidInput
	}
	if numProofs == 0 {
		return false, ErrInvalidInput
	}

	for range numProofs {
		proofType, err := in.Byte()
		if err != nil {
			return false, ErrInvalidInput
		}
		proofDataLen, err := in.Uint32()
		if err != nil {
			return false, ErrInvalidInput
		}
		proofData, err := in.Bytes(uint64(proofDataLen))
		if err != nil {
			return false, ErrInvalidInput
		}

		// Verify based on proof type
		var valid bool
		switch proofType {
		case OpVerifyGroth16:
			valid, err = p.verifyGroth16(proofData)
		case OpVerifyPLONK:
			valid, err = p.verifyPLONK(proofData)
		case OpVerifyKZG:
			valid, err = p.verifyKZG(proofData)
		case OpVerifyRangeProof:
			valid, err = p.verifyRangeProof(proofData)
		default:
			return false, ErrUnknownProofSystem
		}

		if err != nil {
			return false, err
		}
		if !valid {
			return false, nil
		}
	}

	// All proofs verified successfully
	return true, nil
}
