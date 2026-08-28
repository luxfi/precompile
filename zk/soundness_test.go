// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/crypto/kzg4844"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// Soundness is the only property of a verifier that matters: it must not
// accept a proof of a false statement. A round-trip test ("a proof I built
// verifies") passes just as happily against a verifier that returns true
// unconditionally — which is exactly what two of the functions here used
// to do. Every test below is therefore a REFUSAL test.

// sndZeroG1 / sndZeroG2 are bn256's uncompressed affine encodings of the
// point at infinity — the identity of each group.
func sndZeroG1() []byte { return make([]byte, 64) }
func sndZeroG2() []byte { return make([]byte, 128) }

// sndStatements are unrelated public-input vectors. A verifier that
// accepts a single proof under all of them is not verifying anything.
var sndStatements = [][]*big.Int{
	nil,
	{big.NewInt(0)},
	{big.NewInt(1)},
	{big.NewInt(7777777)},
	{big.NewInt(0xdead), big.NewInt(0xbeef)},
}

// TestSound_DegenerateKeyRefused pins the fix for a live universal forge.
//
// A verifying key whose group elements are the identity satisfies the
// pairing equation unconditionally: e(O,Q) = 1, so every factor of the
// product collapses and the check succeeds for ANY proof and ANY
// statement. RegisterVerifyingKey accepts arbitrary bytes, so anyone who
// could register a key could forge every proof checked against it. Both
// Groth16 and PLONK were affected.
func TestSound_DegenerateKeyRefused(t *testing.T) {
	zv := NewZKVerifier()
	g1, g2 := sndZeroG1(), sndZeroG2()

	t.Run("groth16", func(t *testing.T) {
		id, err := zv.RegisterVerifyingKey(common.Address{},
			ProofSystemGroth16, CircuitTransfer, g1, g2, g2, g2, [][]byte{g1, g1})
		require.NoError(t, err)

		for _, pub := range sndStatements {
			if len(pub) != 1 {
				continue // VerifyGroth16 requires len(pub) == len(IC)-1
			}
			res, err := zv.VerifyGroth16(id, g1, g2, g1, pub)
			require.NoError(t, err)
			require.Falsef(t, res.Valid,
				"identity verifying key accepted statement %v", pub)
		}
	})

	t.Run("plonk", func(t *testing.T) {
		ic := [][]byte{g1, g1, g1, g1, g1, g1, g1, g1, g2}
		id, err := zv.RegisterVerifyingKey(common.Address{},
			ProofSystemPlonk, CircuitTransfer, g1, g2, g2, g2, ic)
		require.NoError(t, err)

		for _, pub := range sndStatements {
			res, err := zv.VerifyPlonk(id, make([]byte, 768), pub)
			require.NoError(t, err)
			require.Falsef(t, res.Valid,
				"identity verifying key accepted statement %v", pub)
		}
	})

	// The predicate itself: absent and identity elements are degenerate,
	// anything with a set bit is not.
	require.True(t, degenerate(nil))
	require.True(t, degenerate([]byte{}))
	require.True(t, degenerate(sndZeroG1()))
	require.True(t, degenerate([]byte{1}, sndZeroG1()), "one bad element taints the set")
	require.False(t, degenerate([]byte{0, 0, 1}))
}

// TestSound_Halo2KeyedPathRefuses pins the fix for the most direct forge
// in the package: verifyHalo2IPA folded the IPA rounds, discarded the
// result, and returned true. Op 0x04 therefore reported VALID for every
// proof and every statement as soon as any Halo2 key was registered — no
// degenerate key required.
func TestSound_Halo2KeyedPathRefuses(t *testing.T) {
	zv := NewZKVerifier()
	id, err := zv.RegisterVerifyingKey(common.Address{},
		ProofSystemHalo2, CircuitTransfer,
		sndZeroG1(), sndZeroG2(), sndZeroG2(), sndZeroG2(),
		[][]byte{sndZeroG1(), sndZeroG1(), sndZeroG1()})
	require.NoError(t, err)

	p := &zkVerifyPrecompile{verifier: zv}

	for _, shape := range [][4]int{{1, 2, 1, 8}, {2, 3, 2, 8}, {1, 1, 1, 4}} {
		data := buildTestHalo2Proof(shape[0], shape[1], shape[2], uint32(shape[3]))
		copy(data[0:32], id[:])

		ok, err := p.verifyHalo2(data)
		require.Falsef(t, ok, "halo2 accepted an unchecked proof (shape %v)", shape)
		require.Error(t, err)
	}

	// Same through the precompile entry: never a VALID word.
	data := buildTestHalo2Proof(1, 2, 1, 8)
	copy(data[0:32], id[:])
	ret, _, err := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress,
		append([]byte{OpVerifyHalo2}, data...), 10_000_000, true)
	require.Error(t, err)
	require.Nil(t, ret)
}

// TestSound_NoKeyPathNeverAccepts covers the nil-verifying-key class
// across every system. With no verifier attached, none may return
// (true, nil) for any input — that shape is precisely what got fflonk
// disabled.
func TestSound_NoKeyPathNeverAccepts(t *testing.T) {
	p := &zkVerifyPrecompile{} // no verifier

	sizes := []int{0, 1, 35, 36, 37, 100, 292, 804, 1024}
	fills := []byte{0x00, 0x01, 0xff, 0xa5}

	check := func(name string, fn func([]byte) (bool, error)) {
		for _, n := range sizes {
			for _, fill := range fills {
				in := bytes.Repeat([]byte{fill}, n)
				ok, err := fn(in)
				if ok {
					require.Failf(t, "no-key path ACCEPTED",
						"%s returned true with no verifying key (len=%d fill=0x%02x err=%v)",
						name, n, fill, err)
				}
			}
		}
	}
	check("groth16", p.verifyGroth16)
	check("plonk", p.verifyPLONK)
	check("halo2", p.verifyHalo2)
	check("ipa", p.verifyIPA)
	check("rangeproof", p.verifyRangeProof)
	check("nullifier", p.verifyNullifier)
}

// TestSound_FflonkRefusedAtEntry pins defect (b): op 0x03 must refuse,
// whatever it is handed. The verifier behind it is unsound; the refusal is
// the security control, so it is pinned here and must not be relaxed
// without replacing the verifier.
func TestSound_FflonkRefusedAtEntry(t *testing.T) {
	inputs := [][]byte{
		{OpVerifyFflonk},
		{OpVerifyFflonk, 0, 0, 0, 0},
		append([]byte{OpVerifyFflonk}, bytes.Repeat([]byte{0xff}, 1024)...),
	}
	// Also a fully well-formed payload, so the refusal is not an accident
	// of malformed input.
	valid := buildValidFflonkProof(t, fflonkTestVK(), []*big.Int{big.NewInt(7)}, 8)
	wellFormed := make([]byte, inputsOff)
	wellFormed[0] = OpVerifyFflonk
	inputs = append(inputs, append(wellFormed, valid...))

	for i, in := range inputs {
		ret, _, err := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress,
			in, 100_000_000, true)
		require.ErrorIsf(t, err, ErrFflonkDisabled, "input %d must be refused", i)
		require.Nilf(t, ret, "input %d must return no result word", i)
	}
}

// TestSound_FflonkForgeIsReal demonstrates WHY the refusal above must
// stay, so that a future reader cannot mistake it for excess caution.
//
// A commitment to a CONSTANT polynomial opens to the same value at every
// point, and its opening proof is the identity. The standalone fflonk
// decision function derives its evaluation point by Fiat-Shamir from the
// statement — but a constant polynomial does not care where it is opened,
// so one fixed triple satisfies the check under every statement. That is a
// universal forge: it proves nothing and verifies always.
func TestSound_FflonkForgeIsReal(t *testing.T) {
	blob := new(kzg4844.Blob)
	for i := 0; i < len(blob)/32; i++ {
		blob[i*32+31] = 7 // every evaluation 7 => the polynomial IS 7
	}
	c1, err := kzg4844.BlobToCommitment(blob)
	require.NoError(t, err)
	var anywhere kzg4844.Point
	anywhere[31] = 3
	w1, claim, err := kzg4844.ComputeProof(blob, anywhere)
	require.NoError(t, err)

	fp := &FflonkProof{C1: c1[:], C2: c1[:], W1: w1[:], W2: w1[:]}
	fp.Evaluations = make([]*big.Int, 8)
	for i := range fp.Evaluations {
		fp.Evaluations[i] = big.NewInt(0)
	}
	fp.Evaluations[0] = new(big.Int).SetBytes(claim[:])

	accepted := 0
	for _, pub := range sndStatements {
		xi := computeFflonkChallenge([]byte("transcript"), pub, []byte("xi"))
		v := computeFflonkChallenge([]byte("transcript"), pub, []byte("v"))
		ok, err := verifyFflonkKZGOpening(fp, xi, v, pub)
		require.NoError(t, err)
		if ok {
			accepted++
		}
	}
	require.Equal(t, len(sndStatements), accepted,
		"the forge is expected to satisfy the unsound decision function for "+
			"every statement; if this now fails the verifier changed and this "+
			"test should be re-derived, not deleted")

	// Today one thing stops that triple at the precompile boundary besides
	// the disable: the point validator rejects the CANONICAL BLS12-381
	// infinity encoding (0xc0 || zeros) while accepting the non-canonical
	// all-zero encoding. That asymmetry is accidental, not a control —
	// pinned here so that "correcting" it is a conscious act.
	canonicalInfinity := make([]byte, 48)
	canonicalInfinity[0] = 0xc0
	require.Error(t, validateBLS12381G1Point(canonicalInfinity),
		"canonical infinity is currently rejected")
	require.NoError(t, validateBLS12381G1Point(make([]byte, 48)),
		"non-canonical all-zero infinity is currently accepted")
}

// TestSound_FflonkUnreachable proves the unsound body cannot be reached
// through any dispatch: not the op, and not as a batch member.
func TestSound_FflonkUnreachable(t *testing.T) {
	// Direct op: refused (covered above, asserted again as the batch
	// control).
	_, _, err := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress,
		[]byte{OpVerifyFflonk, 0, 0, 0, 0}, 10_000_000, true)
	require.ErrorIs(t, err, ErrFflonkDisabled)

	// As a batch entry, 0x03 is not in verifyBatch's dispatch and must be
	// rejected as an unknown system rather than silently verified.
	batch := []byte{OpVerifyBatch, 0, 0, 0, 1, OpVerifyFflonk, 0, 0, 0, 0}
	_, _, err = ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress,
		batch, 10_000_000, true)
	require.ErrorIs(t, err, ErrUnknownProofSystem)
}

// TestSound_StatementBinding is the core soundness property on the one
// path that performs real pairing checks: a proof valid for statement A
// must NOT verify against statement B.
func TestSound_StatementBinding(t *testing.T) {
	zv := NewZKVerifier()
	vk := fflonkTestVK()
	stmtA := []*big.Int{big.NewInt(7), big.NewInt(42)}
	proof := buildValidFflonkProof(t, vk, stmtA, 8)

	require.True(t, zv.fflonkVerify(vk, proof, stmtA),
		"control: the proof must verify for the statement it was made for")

	for _, stmtB := range [][]*big.Int{
		nil,
		{big.NewInt(7)},
		{big.NewInt(8), big.NewInt(42)},
		{big.NewInt(7), big.NewInt(43)},
		{big.NewInt(42), big.NewInt(7)}, // same values, reordered
		{big.NewInt(7), big.NewInt(42), big.NewInt(0)},
	} {
		require.Falsef(t, zv.fflonkVerify(vk, proof, stmtB),
			"proof for %v verified against %v", stmtA, stmtB)
	}

	// Binding to the KEY as well: the same proof under a different key.
	other := &VerifyingKey{ProofSystem: ProofSystemFflonk, Hash: [32]byte{0xAA}}
	require.False(t, zv.fflonkVerify(other, proof, stmtA),
		"proof verified under a different verifying key")
}

// TestSound_ProofElementTampering flips a bit in every element of a valid
// proof in turn. Each must be rejected; an element that can be corrupted
// without detection is not bound by the verification equation.
func TestSound_ProofElementTampering(t *testing.T) {
	zv := NewZKVerifier()
	vk := fflonkTestVK()
	pub := []*big.Int{big.NewInt(7)}
	valid := buildValidFflonkProof(t, vk, pub, 8)
	require.True(t, zv.fflonkVerify(vk, valid, pub), "control")

	// 4 compressed G1 points (48 bytes each) then 8 scalars (32 each).
	type elem struct {
		name  string
		start int
		size  int
	}
	elems := []elem{
		{"C1", 0, 48}, {"C2", 48, 48}, {"W1", 96, 48}, {"W2", 144, 48},
	}
	for i := range 8 {
		elems = append(elems, elem{"eval" + string(rune('0'+i)), 192 + i*32, 32})
	}

	for _, e := range elems {
		for _, off := range []int{0, e.size / 2, e.size - 1} {
			tampered := bytes.Clone(valid)
			tampered[e.start+off] ^= 0x01
			require.Falsef(t, zv.fflonkVerify(vk, tampered, pub),
				"a bit flip in %s at byte %d was not detected", e.name, off)
		}
	}
}

// TestSound_RangeProofRefuses pins defect (c). No bulletproof verifier is
// wired, so op 0x23 must refuse with a named sentinel rather than report a
// verdict it cannot justify.
func TestSound_RangeProofRefuses(t *testing.T) {
	p := &zkVerifyPrecompile{}
	data := make([]byte, 200)
	data[35] = 64 // bitLength = 64, a well-formed request

	ok, err := p.verifyRangeProof(data)
	require.False(t, ok)
	require.ErrorIs(t, err, ErrRangeProofUnavailable)

	// Through the precompile, and still charged for.
	in := append([]byte{OpVerifyRangeProof}, data...)
	need := ZKVerifyPrecompile.RequiredGas(in)
	require.GreaterOrEqual(t, need, MinCallGas)
	ret, _, err := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress, in, need, true)
	require.ErrorIs(t, err, ErrRangeProofUnavailable)
	require.Nil(t, ret)

	// The structural guards still refuse first, so the sentinel means
	// exactly "no verifier", not "any bad input".
	short := make([]byte, 99)
	_, err = p.verifyRangeProof(short)
	require.ErrorIs(t, err, ErrInvalidInput)

	zeroBits := make([]byte, 200) // bitLength == 0
	_, err = p.verifyRangeProof(zeroBits)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrRangeProofUnavailable)
}

// TestSound_RangeProofRefusesWithVerifierAttached pins the fix for a live
// forge on the same op. Attaching a ZKVerifier used to route 0x23 to a
// helper that answered `len(commitment)>0 && len(proof)>0 && bits>0` — a
// length check dressed as a verdict, so every byte string was a valid
// range proof. Range proofs are what stop a confidential transfer minting
// value from nothing, so accepting all of them defeats the scheme.
func TestSound_RangeProofRefusesWithVerifierAttached(t *testing.T) {
	zv := NewZKVerifier()
	p := &zkVerifyPrecompile{verifier: zv}

	for _, n := range []int{100, 200, 1024} {
		for _, fill := range []byte{0x00, 0x01, 0xff} {
			data := bytes.Repeat([]byte{fill}, n)
			data[32], data[33], data[34], data[35] = 0, 0, 0, 64 // bitLength = 64
			ok, err := p.verifyRangeProof(data)
			require.Falsef(t, ok, "accepted a range proof of %d bytes of 0x%02x", n, fill)
			require.ErrorIs(t, err, ErrRangeProofUnavailable)
		}
	}

	// Directly on the verifier, which is also a public entry point.
	ok, err := zv.VerifyRangeProof(make([]byte, 32), make([]byte, 128), 64)
	require.False(t, ok)
	require.ErrorIs(t, err, ErrRangeProofUnavailable)

	// And as a batch member: verifyBatch dispatches 0x23, so the refusal
	// must propagate rather than being swallowed into a passing batch.
	body := make([]byte, 200)
	body[35] = 64
	batch := []byte{OpVerifyBatch, 0, 0, 0, 1, OpVerifyRangeProof}
	batch = binary.BigEndian.AppendUint32(batch, uint32(len(body)))
	batch = append(batch, body...)

	_, _, err = ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress,
		batch, 10_000_000, true)
	require.ErrorIs(t, err, ErrRangeProofUnavailable,
		"a batch containing an uncheckable range proof must not report success")
}

// TestSound_VerifyingKeyIDIsInjective pins the fix for a key-substitution
// defect: the ID hashed only alpha..delta by bare concatenation, so a key
// could be replaced under an ID other code already referenced.
func TestSound_VerifyingKeyIDIsInjective(t *testing.T) {
	zv := NewZKVerifier()
	a, b, c, d := []byte("alpha"), []byte("beta"), []byte("gamma"), []byte("delta")

	reg := func(alpha, beta []byte, ic [][]byte) [32]byte {
		id, err := zv.RegisterVerifyingKey(common.Address{},
			ProofSystemGroth16, CircuitTransfer, alpha, beta, c, d, ic)
		require.NoError(t, err)
		return id
	}

	// Differing only in IC — the public-input constraints — must not
	// collide. Previously it did, and the second registration silently
	// replaced the first.
	one := reg(a, b, [][]byte{[]byte("ic-one")})
	two := reg(a, b, [][]byte{[]byte("ic-TWO-different")})
	require.NotEqual(t, one, two, "keys differing in IC shared an ID")
	require.Equal(t, []byte("ic-one"), zv.VerifyingKeys[one].IC[0],
		"the first key was overwritten by the second")

	// Differing only in the number of IC points must not collide either.
	require.NotEqual(t,
		reg(a, b, [][]byte{[]byte("x")}),
		reg(a, b, [][]byte{[]byte("x"), []byte("y")}))

	// Bare concatenation was ambiguous across the field boundary.
	require.NotEqual(t,
		reg([]byte("ab"), []byte("c"), [][]byte{a}),
		reg([]byte("a"), []byte("bc"), [][]byte{a}),
		"the field boundary is not committed to")

	// The proof system is part of a key's identity.
	sameArgs := func(ps ProofSystem) [32]byte {
		id, err := zv.RegisterVerifyingKey(common.Address{},
			ps, CircuitTransfer, a, b, c, d, [][]byte{a})
		require.NoError(t, err)
		return id
	}
	require.NotEqual(t, sameArgs(ProofSystemGroth16), sameArgs(ProofSystemPlonk))

	// And it is a pure function of its inputs.
	require.Equal(t,
		verifyingKeyID(ProofSystemGroth16, CircuitTransfer, a, b, c, d, [][]byte{a}),
		verifyingKeyID(ProofSystemGroth16, CircuitTransfer, a, b, c, d, [][]byte{a}))
}

// TestSound_RegisterDoesNotAliasCallerBuffers pins that registration
// copies nothing into a caller's spare capacity. The ID derivation used
// append(alpha, beta...), which writes through alpha's backing array
// whenever it has room.
func TestSound_RegisterDoesNotAliasCallerBuffers(t *testing.T) {
	zv := NewZKVerifier()
	buf := make([]byte, 5, 128)
	copy(buf, "AAAAA")
	snapshot := bytes.Clone(buf[:cap(buf)])

	_, err := zv.RegisterVerifyingKey(common.Address{},
		ProofSystemGroth16, CircuitTransfer,
		buf, []byte("BBBBB"), []byte("C"), []byte("D"), [][]byte{[]byte("E")})
	require.NoError(t, err)

	require.Equal(t, snapshot, buf[:cap(buf)],
		"registration wrote into the caller's backing array")
}

// TestSound_Deterministic pins that verification is a pure function of its
// input. A verifier that consults the clock, a random source, or map
// iteration order would split consensus between nodes.
func TestSound_Deterministic(t *testing.T) {
	inputs := [][]byte{
		{OpVerifyGroth16, 0, 0, 0, 0},
		{OpVerifyPLONK, 0, 0, 0, 0},
		{OpVerifyFflonk, 0, 0, 0, 0},
		{OpVerifyHalo2, 0, 0, 0, 0},
		{OpVerifyKZG},
		{OpVerifyBatch, 0, 0, 0, 2, OpVerifyGroth16, 0, 0, 0, 0},
		bytes.Repeat([]byte{0xa5}, 600),
	}
	for i := range inputs {
		if len(inputs[i]) > 0 && i == len(inputs)-1 {
			inputs[i][0] = OpVerifyHalo2
		}
	}

	for _, in := range inputs {
		wantGas := ZKVerifyPrecompile.RequiredGas(in)
		wantRet, wantRem, wantErr := ZKVerifyPrecompile.Run(
			nil, addr0, ZKVerifyContractAddress, in, 50_000_000, true)

		for range 25 {
			require.Equal(t, wantGas, ZKVerifyPrecompile.RequiredGas(in),
				"gas is not a pure function of the input")

			ret, rem, err := ZKVerifyPrecompile.Run(
				nil, addr0, ZKVerifyContractAddress, in, 50_000_000, true)
			require.Equal(t, wantRet, ret)
			require.Equal(t, wantRem, rem)
			if wantErr == nil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Equal(t, wantErr.Error(), err.Error())
			}
		}
	}
}

// TestSound_ReadOnlyIsIrrelevant pins that verification does not depend on
// the EVM's static-call flag: a proof either verifies or it does not, and
// a verifier that behaved differently under staticcall would let callers
// choose their verdict.
func TestSound_ReadOnlyIsIrrelevant(t *testing.T) {
	for op := range 0x40 {
		in := make([]byte, 300)
		in[0] = byte(op)
		gas := ZKVerifyPrecompile.RequiredGas(in) + 1_000_000

		roRet, roRem, roErr := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress, in, gas, true)
		rwRet, rwRem, rwErr := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress, in, gas, false)

		require.Equalf(t, roRet, rwRet, "op 0x%02x returned differently under staticcall", op)
		require.Equal(t, roRem, rwRem)
		require.Equalf(t, errors.Is(roErr, rwErr) || (roErr == nil) == (rwErr == nil), true,
			"op 0x%02x errored differently under staticcall: %v vs %v", op, roErr, rwErr)
	}
}
