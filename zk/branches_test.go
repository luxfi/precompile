// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// The refusal branches. Each one is a place a malformed proof is supposed
// to stop; a branch never taken in a test is a branch nobody has seen
// work.

// brnHalo2Offsets returns the byte offset of each element in a proof from
// buildTestHalo2Proof, so a test can corrupt exactly one of them.
type brnHalo2Offsets struct {
	advice, instance, lPoints, rPoints int
	aScalar, evalPoint, claimedEval    int
}

func brnHalo2Layout(numInputs, numAdvice, numInstance int, rounds uint32) brnHalo2Offsets {
	o := 32 + 4 + numInputs*32 // past vkID, numInputs, inputs
	advice := o + 4
	o = advice + numAdvice*32
	instance := o + 4
	o = instance + numInstance*32
	lp := o + 4
	rp := lp + int(rounds)*32
	a := rp + int(rounds)*32
	return brnHalo2Offsets{
		advice: advice, instance: instance, lPoints: lp, rPoints: rp,
		aScalar: a, evalPoint: a + 32, claimedEval: a + 64,
	}
}

// TestBrn_Halo2StructuralRejectsEachElement corrupts one element of an
// otherwise well-formed proof at a time. Every element must be validated;
// one that is not is an element a prover may choose freely.
func TestBrn_Halo2StructuralRejectsEachElement(t *testing.T) {
	const (
		numInputs   = 1
		numAdvice   = 2
		numInstance = 1
		rounds      = 3
	)
	off := brnHalo2Layout(numInputs, numAdvice, numInstance, rounds)
	base := buildTestHalo2Proof(numInputs, numAdvice, numInstance, rounds)

	// Control: the untouched fixture reaches the end of structural
	// validation and stops only for want of a verifying key.
	proof, err := parseHalo2Proof(base)
	require.NoError(t, err)
	ok, err := verifyHalo2Structural(proof)
	require.False(t, ok)
	require.ErrorContains(t, err, "structural validation passed")

	// 0xff is neither a canonical field element nor an on-curve x, so it
	// fails whichever predicate guards the slot it is written into.
	bad := bytes.Repeat([]byte{0xff}, 32)

	for _, c := range []struct {
		name   string
		offset int
		expect string
	}{
		{"advice commitment", off.advice, "advice commitment"},
		{"instance commitment", off.instance, "instance commitment"},
		{"L point", off.lPoints, "L point"},
		{"R point", off.rPoints, "R point"},
		{"final scalar", off.aScalar, "final scalar"},
		{"evaluation point", off.evalPoint, "evaluation point"},
		{"claimed evaluation", off.claimedEval, "claimed evaluation"},
	} {
		data := bytes.Clone(base)
		copy(data[c.offset:c.offset+32], bad)

		proof, err := parseHalo2Proof(data)
		require.NoErrorf(t, err, "%s: fixture must still parse", c.name)

		ok, err := verifyHalo2Structural(proof)
		require.Falsef(t, ok, "%s was accepted", c.name)
		require.ErrorContainsf(t, err, c.expect,
			"%s was not the element rejected", c.name)
	}
}

// TestBrn_FflonkProofRejectsEachElement walks the refusals in the
// DISABLED standalone verifier. It is unreachable from Run today, but it
// is still compiled and still exported through the package, so its
// refusals are pinned: if it is ever re-enabled these are the checks that
// have to be there.
func TestBrn_FflonkProofRejectsEachElement(t *testing.T) {
	valid := buildValidFflonkProof(t, fflonkTestVK(), []*big.Int{big.NewInt(1)}, 8)
	bad48 := bytes.Repeat([]byte{0xff}, 48)

	for _, c := range []struct {
		name   string
		offset int
		expect string
	}{
		{"C1", 0, "C1"},
		{"C2", 48, "C2"},
		{"W1", 96, "W1"},
		{"W2", 144, "W2"},
	} {
		data := bytes.Clone(valid)
		copy(data[c.offset:c.offset+48], bad48)
		ok, err := verifyFflonkProof(data, nil)
		require.Falsef(t, ok, "%s was accepted", c.name)
		require.ErrorContainsf(t, err, c.expect, "%s was not the element rejected", c.name)
	}

	// A non-canonical evaluation is refused, and the message names which.
	data := bytes.Clone(valid)
	copy(data[192+2*32:192+3*32], padScalar32(blsScalarField()))
	ok, err := verifyFflonkProof(data, nil)
	require.False(t, ok)
	require.ErrorContains(t, err, "invalid evaluation")

	// Too short to hold the fixed layout.
	_, err = verifyFflonkProof(make([]byte, 100), nil)
	require.ErrorIs(t, err, ErrInvalidProofLength)

	// Enough commitments but too few evaluations.
	_, err = parseFflonkProof(make([]byte, 192+7*32))
	require.ErrorIs(t, err, ErrInvalidProofLength)

	// The opening check needs at least two evaluations to batch.
	_, err = verifyFflonkKZGOpening(&FflonkProof{
		C1: valid[0:48], C2: valid[48:96], W1: valid[96:144], W2: valid[144:192],
		Evaluations: []*big.Int{big.NewInt(1)},
	}, big.NewInt(1), big.NewInt(1), nil)
	require.ErrorContains(t, err, "insufficient evaluations")

	// An out-of-range evaluation point is refused rather than truncated.
	tooBig := new(big.Int).Lsh(big.NewInt(1), 300)
	_, err = verifyFflonkKZGOpening(&FflonkProof{
		C1: valid[0:48], C2: valid[48:96], W1: valid[96:144], W2: valid[144:192],
		Evaluations: []*big.Int{big.NewInt(1), big.NewInt(2)},
	}, tooBig, big.NewInt(1), nil)
	require.ErrorContains(t, err, "xi too large")
}

// TestBrn_RunReturnsTheAbiWordOnSuccess covers the success arm of the
// dispatch for every op that can succeed. Until an op has been seen to
// return the true word, nothing distinguishes it from one that always
// errors.
func TestBrn_RunReturnsTheAbiWordOnSuccess(t *testing.T) {
	zv := NewZKVerifier()
	p := &zkVerifyPrecompile{verifier: zv}

	// Groth16: a satisfying proof, framed on the wire.
	public := []*big.Int{big.NewInt(11)}
	in := grBuild(t, public)
	id := grRegister(t, zv, in)

	wire := append([]byte{OpVerifyGroth16}, id[:]...)
	wire = binary.BigEndian.AppendUint32(wire, uint32(len(public)))
	for _, x := range public {
		wire = append(wire, padScalar32(x)...)
	}
	wire = append(wire, in.a...)
	wire = append(wire, in.b...)
	wire = append(wire, in.c...)

	ret, rem, err := p.Run(nil, addr0, ZKVerifyContractAddress, wire, 10_000_000, true)
	require.NoError(t, err)
	require.Equal(t, encodeBool(true), ret, "op 0x01 must report a verified proof")
	require.Equal(t, uint64(10_000_000)-p.RequiredGas(wire), rem)

	// Nullifier: unspent reports true, spent reports false.
	var n [32]byte
	copy(n[:], "an-unspent-nullifier")
	nul := append([]byte{OpVerifyNullifier}, n[:]...)
	ret, _, err = p.Run(nil, addr0, ZKVerifyContractAddress, nul, 10_000_000, true)
	require.NoError(t, err)
	require.Equal(t, encodeBool(true), ret)

	require.NoError(t, zv.SpendNullifier(n, common.Hash{}, 1))
	ret, _, err = p.Run(nil, addr0, ZKVerifyContractAddress, nul, 10_000_000, true)
	require.NoError(t, err)
	require.Equal(t, encodeBool(false), ret)

	// Commitment: a correct Pedersen opening reports true.
	var value, blinding [32]byte
	value[31] = 3
	blinding[31] = 4
	commitment, err := globalPedersen.Commit(value, blinding)
	require.NoError(t, err)
	if commitment[0] != 0x01 { // else the Merkle sub-mode claims it
		payload := append([]byte{OpVerifyCommitment}, commitment[:]...)
		payload = append(payload, value[:]...)
		payload = append(payload, blinding[:]...)
		ret, _, err = p.Run(nil, addr0, ZKVerifyContractAddress, payload, 10_000_000, true)
		require.NoError(t, err)
		require.Equal(t, encodeBool(true), ret)

		// And a wrong opening reports false rather than erroring.
		payload[33+31] ^= 0x01
		ret, _, err = p.Run(nil, addr0, ZKVerifyContractAddress, payload, 10_000_000, true)
		require.NoError(t, err)
		require.Equal(t, encodeBool(false), ret)
	}
}

// TestBrn_QuadraticResidueEdges covers the branches of the residue test
// that the brute-force sweep does not reach.
func TestBrn_QuadraticResidueEdges(t *testing.T) {
	p := big.NewInt(23)
	require.True(t, isQuadraticResidue(big.NewInt(0), p), "zero is a square")
	require.True(t, isQuadraticResidue(big.NewInt(1), p))
	require.False(t, isQuadraticResidue(big.NewInt(5), p), "5 is a non-residue mod 23")

	// Against the real Pallas field, so the big-integer path is exercised.
	require.True(t, isQuadraticResidue(big.NewInt(0), pallasFieldModulus))
	require.True(t, isQuadraticResidue(big.NewInt(4), pallasFieldModulus), "4 = 2^2")
}

// TestBrn_PedersenOpeningRefusals covers the sub-mode's own guards.
func TestBrn_PedersenOpeningRefusals(t *testing.T) {
	p := &zkVerifyPrecompile{}

	for n := range 96 {
		_, err := p.verifyCommitmentPedersen(make([]byte, n))
		require.ErrorIs(t, err, ErrInvalidInput)
	}

	// A commitment this process never produced cannot be opened, and that
	// is reported as an error rather than as a false verdict.
	unseen := make([]byte, 96)
	copy(unseen, bytes.Repeat([]byte{0x5a}, 32))
	_, err := p.verifyCommitmentPedersen(unseen)
	require.Error(t, err)
}

// TestBrn_Halo2FullRefusesAnIncompleteKey covers verifyHalo2Full's early
// exits: an IC too short for the declared public inputs, and the IPA
// refusal itself.
func TestBrn_Halo2FullRefusesAnIncompleteKey(t *testing.T) {
	data := buildTestHalo2Proof(2, 1, 1, 4)
	proof, err := parseHalo2Proof(data)
	require.NoError(t, err)

	// IC too short for two public inputs.
	ok, err := verifyHalo2Full(proof, &VerifyingKey{
		ProofSystem: ProofSystemHalo2, IC: [][]byte{{1}},
	})
	require.False(t, ok)
	require.ErrorContains(t, err, "insufficient IC points")

	// A long-enough IC gets past that and stops at the missing commitment
	// key, never at a verdict.
	ok, err = verifyHalo2Full(proof, &VerifyingKey{
		ProofSystem: ProofSystemHalo2, IC: [][]byte{{1}, {2}, {3}, {4}},
	})
	require.False(t, ok)
	require.ErrorIs(t, err, ErrHalo2KeyIncomplete)
}
