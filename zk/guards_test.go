// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/big"
	"testing"

	"github.com/luxfi/crypto/kzg4844"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// Each test here exists because a mutation survived: the guard it covers
// could be deleted outright and the rest of the suite stayed green. A
// guard nothing fails on is a guard nobody is keeping.

// TestGrd_BatchGasBoundedByCalldata closes the batch half of the gas cap.
// The header ops were covered; op 0x30 was not, so the cap could be
// removed and a caller could declare 2^32 proofs in ten bytes of calldata
// and be charged 2.1e14 gas — a valid batch priced out of every block.
func TestGrd_BatchGasBoundedByCalldata(t *testing.T) {
	const entryHdr = 5

	for _, size := range []int{5, 10, 25, 105, 1005} {
		in := make([]byte, size)
		in[0] = OpVerifyBatch
		binary.BigEndian.PutUint32(in[1:5], math.MaxUint32)

		got := ZKVerifyPrecompile.RequiredGas(in)
		fits := (size - entryHdr) / entryHdr
		ceiling := max(uint64(fits)*GasPerBatchProof, MinCallGas)

		require.LessOrEqualf(t, got, ceiling,
			"a %d-byte batch declaring 2^32 proofs was charged %d gas, but only "+
				"%d entries can fit", size, got, fits)
	}

	// And the price does track the count while the count is affordable.
	body := make([]byte, 5+entryHdr*20)
	body[0] = OpVerifyBatch
	binary.BigEndian.PutUint32(body[1:5], 20)
	full := ZKVerifyPrecompile.RequiredGas(body)
	binary.BigEndian.PutUint32(body[1:5], 10)
	half := ZKVerifyPrecompile.RequiredGas(body)
	require.Greater(t, full, half, "the declared count must still move the price")
}

// TestGrd_NonCanonicalPointRejected closes the canonical-x check on Halo2
// points. Clearing the sign bit leaves 255 bits of x, but the Pallas base
// field is only ~254 bits, so values in [p, 2^255) are expressible and
// non-canonical. About half of them still satisfy the curve equation
// after reduction, so the on-curve test alone does NOT reject them — only
// the range test does. Two encodings for one point is malleability: the
// same commitment can be written two ways and any transcript hashing the
// bytes binds to the encoding rather than the point.
func TestGrd_NonCanonicalPointRejected(t *testing.T) {
	// x = p + 1. Its cube plus five is a quadratic residue mod p, so this
	// passes the curve equation and is caught only by the range check.
	x := new(big.Int).Add(pallasFieldModulus, big.NewInt(1))
	require.Equal(t, 1, x.Cmp(pallasFieldModulus), "the fixture must be non-canonical")

	buf := make([]byte, 32)
	x.FillBytes(buf)
	require.Zero(t, buf[0]&0x80, "the sign bit must be clear or the test proves nothing")

	// The curve equation alone accepts it...
	reduced := new(big.Int).Mod(x, pallasFieldModulus)
	rhs := new(big.Int).Exp(reduced, big.NewInt(3), pallasFieldModulus)
	rhs.Add(rhs, big.NewInt(5))
	rhs.Mod(rhs, pallasFieldModulus)
	require.True(t, isQuadraticResidue(rhs, pallasFieldModulus),
		"fixture must satisfy the curve equation, else the range check is not what rejects it")

	// ...so the range check is the only thing that can reject it.
	require.False(t, isValidCompressedPoint(buf),
		"a non-canonical x-coordinate was accepted as a point")

	// The canonical representative of the same value IS accepted, which
	// shows the refusal is about the encoding and not the point.
	canon := make([]byte, 32)
	reduced.FillBytes(canon)
	require.True(t, isValidCompressedPoint(canon))
}

// TestGrd_Halo2RoundBoundEnforcedWhenDataFits closes the IPA round bound.
// The existing bounds tests used fixtures too short to hold the rounds
// they declared, so a length check refused them and the range check was
// never what bit. An unbounded round count means an unbounded allocation
// driven by four attacker-chosen bytes.
func TestGrd_Halo2RoundBoundEnforcedWhenDataFits(t *testing.T) {
	// Build a proof with 0 inputs / advice / instance and `rounds` rounds,
	// sized so every declared byte is actually present.
	build := func(rounds uint32) []byte {
		size := 32 + 4 + 4 + 4 + 4 + int(rounds)*32*2 + 32*3
		d := make([]byte, size)
		d[0] = 1 // non-zero vkID
		binary.BigEndian.PutUint32(d[44:48], rounds)
		return d
	}

	// In range: the round bound lets it through (it fails later, on the
	// point validation, which is the control that the fixture is well
	// formed enough to reach the rounds).
	ok, err := parseHalo2Proof(build(32))
	require.NoError(t, err, "32 rounds is in range and fully backed by bytes")
	require.Equal(t, uint32(32), ok.numRounds)

	// Out of range, with every declared byte present: only the bound can
	// reject these.
	for _, rounds := range []uint32{0, 33, 64, 1000} {
		d := build(rounds)
		require.GreaterOrEqualf(t, len(d), 48+int(rounds)*64+96,
			"fixture for %d rounds must be long enough", rounds)
		_, err := parseHalo2Proof(d)
		require.Errorf(t, err, "%d IPA rounds was accepted", rounds)
	}
}

// TestGrd_CommitmentLengthGuardCoversTheMerkleRoute closes the 0x22
// length guard. The existing sweep used all-zero payloads, which never
// select the Merkle sub-mode, so the Pedersen branch's own length check
// masked the outer one. A payload of 77..95 bytes starting 0x01 goes down
// the Merkle route, where the outer guard is the only one that applies.
func TestGrd_CommitmentLengthGuardCoversTheMerkleRoute(t *testing.T) {
	p := &zkVerifyPrecompile{verifier: NewZKVerifier()}

	for n := 77; n < 96; n++ {
		data := make([]byte, n)
		data[0] = 0x01 // selects the Merkle sub-mode
		require.Truef(t, isMerkleCommitment(data),
			"fixture of %d bytes must select the Merkle route", n)

		ok, err := p.verifyCommitment(data)
		require.Falsef(t, ok, "a %d-byte commitment payload was accepted", n)
		require.ErrorIsf(t, err, ErrInvalidInput,
			"a %d-byte payload must be refused by the length guard", n)
	}

	// At 96 bytes the payload is long enough and the refusal changes
	// character — it is no longer about length.
	ok96 := make([]byte, 96)
	ok96[0] = 0x01
	_, err := p.verifyCommitment(ok96)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrInvalidInput,
		"at 96 bytes the length guard must no longer be what refuses")
}

// TestGrd_Groth16BatchToleratesAShortKey closes the IC-bounds check in
// the pairing routine. VerifyGroth16 enforces arity before calling it, so
// that path can never violate the bound — but verifyGroth16Batch calls
// the pairing check directly with a FIXED four public inputs, whatever
// the key holds. Without the bound that is an out-of-range index, i.e. a
// panic, i.e. a node halted by a malformed rollup registration.
func TestGrd_Groth16BatchToleratesAShortKey(t *testing.T) {
	zv := NewZKVerifier()

	// Real, non-identity points so the degeneracy refusal does not
	// short-circuit before the loop is reached.
	shortIC := [][]byte{grG1(big.NewInt(2)), grG1(big.NewInt(3))}
	keyID, err := zv.RegisterVerifyingKey(common.Address{},
		ProofSystemGroth16, CircuitRollupBatch,
		grG1(big.NewInt(5)), grG2(big.NewInt(7)),
		grG2(big.NewInt(11)), grG2(big.NewInt(13)), shortIC)
	require.NoError(t, err)

	rollupID, err := zv.RegisterRollup(rolOwner, keyID, ProofSystemGroth16, 100, 60, rolSequencer)
	require.NoError(t, err)

	batch := &RollupBatch{
		RollupID:     rollupID,
		NewStateRoot: [32]byte{0x01},
		Transactions: 3,
		L1BatchNum:   1,
		Proposer:     rolSequencer,
		Proof: &Proof{
			ProofSystem: ProofSystemGroth16,
			A:           grG1(big.NewInt(17)),
			B:           grG2(big.NewInt(19)),
			C:           grG1(big.NewInt(23)),
		},
	}

	// The batch supplies four public inputs against a two-point IC. This
	// must refuse, not index past the end.
	require.NotPanics(t, func() {
		err := zv.VerifyRollupBatch(rollupID, batch)
		require.ErrorIs(t, err, ErrInvalidProof)
	})

	// Directly, so the bound is pinned independently of the rollup path.
	require.NotPanics(t, func() {
		vk := zv.VerifyingKeys[keyID]
		ok := zv.groth16PairingCheck(vk, batch.Proof.A, batch.Proof.B, batch.Proof.C,
			[]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)})
		require.False(t, ok, "more public inputs than IC points must not verify")
	})
}

// TestGrd_BLS12381NonCanonicalXRejected closes the field-range check on
// compressed BLS12-381 points. The validator masks the top three flag
// bits, leaving 381 bits of x — exactly the width of the base field
// modulus — so values at or above p are expressible. Only the range test
// rejects them; the flag tests pass and there is no on-curve test at all
// on this path. Two encodings for one x is malleability.
func TestGrd_BLS12381NonCanonicalXRejected(t *testing.T) {
	// Compression flag set, infinity flag clear, and the masked
	// x-coordinate is 0x1f followed by 47 x 0xff — far above p, whose
	// leading byte is 0x1a.
	bad := bytes.Repeat([]byte{0xff}, 48)
	bad[0] = 0x9f
	require.NotZero(t, bad[0]&0x80, "compression flag must be set")
	require.Zero(t, bad[0]&0x40, "infinity flag must be clear, or an earlier guard rejects")

	err := validateBLS12381G1Point(bad)
	require.Error(t, err, "a non-canonical x-coordinate was accepted")
	require.Contains(t, err.Error(), "not in field")

	// The flag checks in front of it still work, so the failure above is
	// specifically the range test.
	notCompressed := bytes.Clone(bad)
	notCompressed[0] = 0x1f
	require.ErrorContains(t, validateBLS12381G1Point(notCompressed), "compressed")

	infinityFlagged := bytes.Clone(bad)
	infinityFlagged[0] = 0xdf // both flags set on a non-zero point
	require.ErrorContains(t, validateBLS12381G1Point(infinityFlagged), "infinity")

	// A real commitment, whose x IS in the field, passes.
	real, err := kzg4844.BlobToCommitment(makeBlob(9, 8, 7))
	require.NoError(t, err)
	require.NoError(t, validateBLS12381G1Point(real[:]))
}

// TestGrd_InfinityIsNotAValidCommitment closes the identity check on
// BLS12-381 G1 points, and shows why it is load-bearing rather than
// hygiene.
//
// A commitment to a CONSTANT polynomial opens to the same value at every
// point, and its opening proof is the identity. So the triple
// (commit(c), c, identity) satisfies the KZG equation at ANY evaluation
// point — including one derived by Fiat-Shamir from a statement the
// prover never proved. Accepting the identity as an opening proof turns
// the fflonk verifier into a universal forge.
func TestGrd_InfinityIsNotAValidCommitment(t *testing.T) {
	// The canonical BLS12-381 infinity encoding: compression and infinity
	// flags set, everything else zero.
	inf := make([]byte, 48)
	inf[0] = 0xc0
	require.False(t, validG1Point(inf), "the identity was accepted as a G1 point")
	require.False(t, validG1Point(make([]byte, 48)), "all-zero bytes were accepted")

	// A genuine commitment is accepted, so the refusal is not blanket.
	real, err := kzg4844.BlobToCommitment(makeBlob(1, 2, 3))
	require.NoError(t, err)
	require.True(t, validG1Point(real[:]))

	// Now the forge itself. Commit to the constant 7; its opening proof at
	// any point is the identity, and the claimed value is 7 everywhere.
	blob := new(kzg4844.Blob)
	for i := 0; i < len(blob)/32; i++ {
		blob[i*32+31] = 7
	}
	c, err := kzg4844.BlobToCommitment(blob)
	require.NoError(t, err)
	var anywhere kzg4844.Point
	anywhere[31] = 3
	w, claim, err := kzg4844.ComputeProof(blob, anywhere)
	require.NoError(t, err)

	// The opening proof really is the identity, and the library really
	// does accept it at an unrelated point — that is the whole hazard.
	require.Equal(t, inf, w[:], "the constant-polynomial opening proof is the identity")
	var elsewhere kzg4844.Point
	elsewhere[31] = 99
	require.NoError(t, kzg4844.VerifyProof(c, elsewhere, claim, w),
		"one triple verifying at every point is what makes this a universal forge")

	// Assembled into an fflonk proof, both openings are of that constant,
	// so nothing about any statement is proved. It must be refused.
	proof := make([]byte, 0, 448)
	proof = append(proof, c[:]...)     // C1
	proof = append(proof, c[:]...)     // C2
	proof = append(proof, w[:]...)     // W1 = identity
	proof = append(proof, w[:]...)     // W2 = identity
	proof = append(proof, claim[:]...) // evaluations[0]
	proof = append(proof, claim[:]...) // evaluations[1]
	proof = append(proof, bytes.Repeat([]byte{0}, 6*32)...)
	require.Len(t, proof, 448)

	zv := NewZKVerifier()
	vk := fflonkTestVK()
	for _, pub := range sndStatements {
		require.Falsef(t, zv.fflonkVerify(vk, proof, pub).OK(),
			"the constant-polynomial forge verified for statement %v", pub)
	}
}
