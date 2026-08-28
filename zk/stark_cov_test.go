// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"math/rand"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helpers (all prefixed stk)
// ---------------------------------------------------------------------------

const stkP uint64 = 0xFFFFFFFF00000001

var stkMod = new(big.Int).SetUint64(stkP)

// stkAddRef is the arithmetic oracle: (a+b) mod p computed in big.Int.
func stkAddRef(a, b uint64) uint64 {
	r := new(big.Int).Add(new(big.Int).SetUint64(a), new(big.Int).SetUint64(b))
	return r.Mod(r, stkMod).Uint64()
}

// stkSubRef is the arithmetic oracle: (a-b) mod p computed in big.Int.
func stkSubRef(a, b uint64) uint64 {
	r := new(big.Int).Sub(new(big.Int).SetUint64(a), new(big.Int).SetUint64(b))
	return r.Mod(r, stkMod).Uint64()
}

// stkMulRef is the arithmetic oracle: (a*b) mod p computed in big.Int.
func stkMulRef(a, b uint64) uint64 {
	r := new(big.Int).Mul(new(big.Int).SetUint64(a), new(big.Int).SetUint64(b))
	return r.Mod(r, stkMod).Uint64()
}

// stkLeaf renders a field value the way VerifyQuery commits it.
func stkLeaf(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

// stkTree builds the exact tree shape verifyMerkleProof consumes:
// leaves are sha256(preimage), internal nodes are sha256(left||right),
// and the sibling for position p is p^1. len(leaves) must be a power of two.
func stkTree(leaves [][]byte) ([32]byte, [][][32]byte) {
	level := make([][32]byte, len(leaves))
	for i, l := range leaves {
		level[i] = sha256.Sum256(l)
	}
	proofs := make([][][32]byte, len(leaves))
	pos := make([]int, len(leaves))
	for i := range pos {
		pos[i] = i
	}
	for len(level) > 1 {
		for leaf := range proofs {
			proofs[leaf] = append(proofs[leaf], level[pos[leaf]^1])
			pos[leaf] /= 2
		}
		next := make([][32]byte, len(level)/2)
		for i := range next {
			buf := make([]byte, 0, 64)
			buf = append(buf, level[2*i][:]...)
			buf = append(buf, level[2*i+1][:]...)
			next[i] = sha256.Sum256(buf)
		}
		level = next
	}
	return level[0], proofs
}

// stkValues builds a layer of n pseudo-random field values.
func stkValues(n int, seed int64) []uint64 {
	rng := rand.New(rand.NewSource(seed))
	out := make([]uint64, n)
	for i := range out {
		out[i] = rng.Uint64() % stkP
	}
	return out
}

// stkFixture is a fully-consistent two-layer FRI query: every value is
// genuinely committed at its index, and every layer is the true fold of
// the one above it.
type stkFixture struct {
	v      *FRIVerifier
	commit *FRICommitment
	query  *FRIQueryResponse
	alphas []uint64
}

func stkNewFixture(index uint64) stkFixture {
	v := NewFRIVerifier(8, 4, 2, 1<<20)
	alphas := []uint64{0x1234_5678_9abc_def0 % stkP, 0x0fed_cba9_8765_4321 % stkP}

	l0 := stkValues(8, 11)
	l1 := v.FoldLayer(l0, alphas[0])
	l2 := v.FoldLayer(l1, alphas[1])

	leaves0 := make([][]byte, len(l0))
	for i, x := range l0 {
		leaves0[i] = stkLeaf(x)
	}
	leaves1 := make([][]byte, len(l1))
	for i, x := range l1 {
		leaves1[i] = stkLeaf(x)
	}
	root0, proofs0 := stkTree(leaves0)
	root1, proofs1 := stkTree(leaves1)

	return stkFixture{
		v: v,
		commit: &FRICommitment{
			Root:       root0,
			NumLayers:  2,
			LayerRoots: [][32]byte{root0, root1},
		},
		query: &FRIQueryResponse{
			Index:     index,
			Values:    []uint64{l0[index], l1[index/2], l2[index/4]},
			AuthPaths: [][][32]byte{proofs0[index], proofs1[index/2]},
		},
		alphas: alphas,
	}
}

// stkClone deep-copies the mutable parts of a fixture so a negative case
// cannot leak into the next one.
func (f stkFixture) stkClone() stkFixture {
	commit := *f.commit
	commit.LayerRoots = append([][32]byte(nil), f.commit.LayerRoots...)

	query := *f.query
	query.Values = append([]uint64(nil), f.query.Values...)
	query.AuthPaths = make([][][32]byte, len(f.query.AuthPaths))
	for i, p := range f.query.AuthPaths {
		query.AuthPaths[i] = append([][32]byte(nil), p...)
	}
	return stkFixture{v: f.v, commit: &commit, query: &query, alphas: append([]uint64(nil), f.alphas...)}
}

// stkChallenges replays STARKVerifier.Verify's Fiat-Shamir sequence so a
// test can predict the folding challenges and query indices the verifier
// will demand.
func stkChallenges(programHash [32]byte, publicInputs []uint64, proof *STARKProof, numQueries uint64) (alphas, indices []uint64) {
	t := NewTranscript("STARK-v1")
	t.Append(programHash[:])
	for _, pi := range publicInputs {
		t.Append(stkLeaf(pi))
	}
	t.Append(proof.TraceCommitment[:])
	t.Challenge() // constraint mixing
	t.Append(proof.ConstraintCommitment[:])
	t.Challenge() // ood point
	t.Challenge() // deep alpha
	t.Challenge() // deep beta
	t.Append(proof.FRICommitment.Root[:])

	alphas = make([]uint64, len(proof.FRICommitment.LayerRoots))
	for i := range alphas {
		alphas[i] = t.Challenge()
	}
	indices = make([]uint64, numQueries)
	for i := range indices {
		indices[i] = t.Challenge() % (1 << 20)
	}
	return alphas, indices
}

// ---------------------------------------------------------------------------
// field arithmetic
// ---------------------------------------------------------------------------

func TestStk_SubIsGroupSubtraction(t *testing.T) {
	f := &GoldilocksField{}

	// a - a == 0 for every probe, including the wrap branch's boundary.
	for _, a := range []uint64{0, 1, 2, 7, 1 << 31, 1 << 32, stkP - 2, stkP - 1} {
		require.Zerof(t, f.Sub(a, a), "a-a must be 0 for a=%#x", a)
	}

	// Sub agrees with big.Int modular subtraction on the whole canonical
	// range, and Add undoes it. Both branches of the `a >= b` split are hit.
	edges := []uint64{0, 1, 2, 3, (1 << 32) - 1, 1 << 32, stkP / 2, stkP - 3, stkP - 2, stkP - 1}
	for _, a := range edges {
		for _, b := range edges {
			got := f.Sub(a, b)
			require.Equalf(t, stkSubRef(a, b), got, "Sub(%#x,%#x)", a, b)
			require.Lessf(t, got, stkP, "Sub(%#x,%#x) must stay reduced", a, b)
			require.Equalf(t, a, f.Add(got, b), "Add(Sub(a,b),b) must be a for a=%#x b=%#x", a, b)
		}
	}

	rng := rand.New(rand.NewSource(3))
	for range 20000 {
		a, b := rng.Uint64()%stkP, rng.Uint64()%stkP
		require.Equal(t, stkSubRef(a, b), f.Sub(a, b))
		require.Equal(t, f.Sub(0, f.Sub(b, a)), f.Sub(a, b)) // -(b-a) == a-b
	}
}

func TestStk_SubIsWrongForNonCanonicalInput(t *testing.T) {
	f := &GoldilocksField{}
	// Documented observation, not an endorsement: Sub assumes both operands
	// are already reduced. Fed a value above the modulus it returns a result
	// that disagrees with modular arithmetic. Callers must reduce first.
	const nonCanonical = 0xFFFFFFFFFFFFFFFF
	require.NotEqual(t, stkSubRef(0, nonCanonical), f.Sub(0, nonCanonical),
		"if this now matches, Sub grew input reduction and this test should assert equality")
	require.Equal(t, uint64(0xFFFFFFFF00000002), f.Sub(0, nonCanonical))
}

func TestStk_InvIsTheMultiplicativeInverse(t *testing.T) {
	f := &GoldilocksField{}

	for _, a := range []uint64{1, 2, 3, 7, 1 << 32, stkP / 2, stkP - 2, stkP - 1} {
		inv := f.Inv(a)
		require.Equalf(t, uint64(1), f.Mul(a, inv), "a*Inv(a) must be 1 for a=%#x", a)
		require.Equalf(t, a, f.Inv(inv), "Inv is an involution for a=%#x", a)
		require.Equalf(t, stkMulRef(a, inv), uint64(1), "oracle agrees for a=%#x", a)
	}

	rng := rand.New(rand.NewSource(5))
	for range 5000 {
		a := rng.Uint64()%(stkP-1) + 1
		require.Equal(t, uint64(1), f.Mul(a, f.Inv(a)))
	}
}

func TestStk_InvZeroIsZeroAndIsNotAnInverse(t *testing.T) {
	f := &GoldilocksField{}
	// The code documents `if a == 0 { return 0 }`. Pin that, and pin the
	// consequence: the value handed back is NOT usable as an inverse, so a
	// caller that skips the zero check gets 0 rather than a wrong-but-
	// plausible unit.
	require.Zero(t, f.Inv(0))
	require.NotEqual(t, uint64(1), f.Mul(0, f.Inv(0)))
	require.Zero(t, f.Mul(0, f.Inv(0)))

	// ExtInv swallows it: a zero norm yields the zero element with no error.
	got := ExtInv(ExtensionField{A: 0, B: 0})
	require.Equal(t, ExtensionField{A: 0, B: 0}, got)

	// The extension is a genuine field only because 7 is a non-residue.
	// Euler's criterion: 7^((p-1)/2) == p-1 == -1.
	e := new(big.Int).Rsh(new(big.Int).Sub(stkMod, big.NewInt(1)), 1)
	require.Equal(t, stkP-1, new(big.Int).Exp(big.NewInt(7), e, stkMod).Uint64(),
		"X^2-7 must stay irreducible or ExtInv has zero divisors to divide by")
}

func TestStk_ExtensionFieldObeysItsAxioms(t *testing.T) {
	one := ExtensionField{A: 1}
	xs := []ExtensionField{
		{A: 1, B: 0}, {A: 0, B: 1}, {A: 2, B: 3},
		{A: stkP - 1, B: 7}, {A: 7, B: stkP - 1}, {A: 12345, B: 67890},
	}

	for _, x := range xs {
		require.Equal(t, x, ExtMul(x, one), "1 is the identity")
		require.Equal(t, one, ExtMul(x, ExtInv(x)), "x * x^-1 == 1")
		for _, y := range xs {
			require.Equal(t, ExtMul(x, y), ExtMul(y, x), "multiplication commutes")
		}
	}

	// X^2 == 7, which is the relation the whole extension is built on.
	x := ExtensionField{A: 0, B: 1}
	require.Equal(t, ExtensionField{A: 7, B: 0}, ExtMul(x, x))

	// Zero is absorbing and has no inverse to hand back.
	require.Equal(t, ExtensionField{}, ExtMul(ExtensionField{}, xs[2]))
}

// ---------------------------------------------------------------------------
// FRIVerifier construction + folding
// ---------------------------------------------------------------------------

func TestStk_NewFRIVerifierKeepsItsParameters(t *testing.T) {
	v := NewFRIVerifier(8, 40, 2, 1<<20)
	require.Equal(t, uint64(8), v.BlowupFactor)
	require.Equal(t, uint64(40), v.NumQueries)
	require.Equal(t, uint64(2), v.FoldingFactor)
	require.Equal(t, uint64(1<<20), v.MaxDegree)

	// Distinct instances, no shared state.
	other := NewFRIVerifier(16, 80, 4, 1<<10)
	require.NotSame(t, v, other)
	require.Equal(t, uint64(8), v.BlowupFactor)

	// Nothing validates the parameters; a zero folding factor is accepted
	// here and only explodes later (see TestStk_VerifyQueryPanicsOnZeroFold).
	require.Zero(t, NewFRIVerifier(0, 0, 0, 0).FoldingFactor)
}

func TestStk_FoldLayerMatchesTheFoldEquation(t *testing.T) {
	v := NewFRIVerifier(8, 4, 2, 1<<20)
	values := stkValues(16, 21)

	for _, alpha := range []uint64{0, 1, 2, 0xdeadbeef, stkP - 1} {
		got := v.FoldLayer(values, alpha)
		require.Len(t, got, len(values)/2)
		for i := range got {
			want := stkAddRef(values[2*i], stkMulRef(alpha, values[2*i+1]))
			require.Equalf(t, want, got[i], "fold index %d alpha=%#x", i, alpha)
			require.Lessf(t, got[i], stkP, "fold output must stay reduced")
		}
	}

	// alpha = 0 collapses the fold to the even coefficients; alpha = 1 sums
	// the pair. Both are the fold equation, not a special case in the code.
	require.Equal(t, []uint64{values[0], values[2]}, v.FoldLayer(values[:4], 0))
	require.Equal(t,
		[]uint64{stkAddRef(values[0], values[1]), stkAddRef(values[2], values[3])},
		v.FoldLayer(values[:4], 1))
}

func TestStk_FoldLayerLengthHandling(t *testing.T) {
	v := NewFRIVerifier(8, 4, 2, 1<<20)
	for _, tc := range []struct {
		name string
		in   []uint64
		want int
	}{
		{"nil", nil, 0},
		{"empty", []uint64{}, 0},
		{"single element has no partner", []uint64{7}, 0},
		{"pair", []uint64{7, 9}, 1},
		{"odd length drops the tail", []uint64{7, 9, 11}, 1},
		{"eight", stkValues(8, 1), 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := v.FoldLayer(tc.in, 3)
			require.NotNil(t, got, "FoldLayer must return an allocated slice, never nil")
			require.Len(t, got, tc.want)
		})
	}

	// The dropped tail is silent: folding [a,b,c] gives the same answer as
	// folding [a,b]. A caller handing an odd layer loses c with no signal.
	require.Equal(t, v.FoldLayer([]uint64{7, 9}, 3), v.FoldLayer([]uint64{7, 9, 11}, 3))
}

// ---------------------------------------------------------------------------
// verifyMerkleProof — the load-bearing comparison
// ---------------------------------------------------------------------------

func TestStk_MerkleProofAcceptsEveryHonestLeaf(t *testing.T) {
	leaves := make([][]byte, 8)
	for i := range leaves {
		leaves[i] = stkLeaf(uint64(100 + i))
	}
	root, proofs := stkTree(leaves)

	for i := range leaves {
		require.Truef(t, verifyMerkleProof(root, leaves[i], uint64(i), proofs[i]),
			"honest leaf %d must verify", i)
	}
}

func TestStk_MerkleProofRejectsTampering(t *testing.T) {
	leaves := make([][]byte, 8)
	for i := range leaves {
		leaves[i] = stkLeaf(uint64(100 + i))
	}
	root, proofs := stkTree(leaves)
	const honest = 3

	t.Run("different root", func(t *testing.T) {
		for bit := range 32 {
			bad := root
			bad[bit] ^= 1 << (bit % 8)
			require.Falsef(t, verifyMerkleProof(bad, leaves[honest], honest, proofs[honest]),
				"root byte %d flipped must be rejected", bit)
		}
	})

	t.Run("any sibling bit flipped", func(t *testing.T) {
		for lvl := range proofs[honest] {
			for byteIdx := range 32 {
				for _, mask := range []byte{0x01, 0x80} {
					bad := append([][32]byte(nil), proofs[honest]...)
					sib := bad[lvl]
					sib[byteIdx] ^= mask
					bad[lvl] = sib
					require.Falsef(t, verifyMerkleProof(root, leaves[honest], honest, bad),
						"level %d byte %d mask %#x must be rejected", lvl, byteIdx, mask)
				}
			}
		}
	})

	t.Run("different index within the tree", func(t *testing.T) {
		for _, other := range []uint64{0, 1, 2, 4, 5, 6, 7} {
			require.Falsef(t, verifyMerkleProof(root, leaves[honest], other, proofs[honest]),
				"proof for leaf %d must not verify at index %d", honest, other)
		}
	})

	t.Run("different leaf", func(t *testing.T) {
		for i := range leaves {
			if i == honest {
				continue
			}
			require.Falsef(t, verifyMerkleProof(root, leaves[i], honest, proofs[honest]),
				"leaf %d must not verify against leaf %d's path", i, honest)
		}
		require.False(t, verifyMerkleProof(root, nil, honest, proofs[honest]))
		require.False(t, verifyMerkleProof(root, []byte{}, honest, proofs[honest]))
	})

	t.Run("truncated or lengthened path", func(t *testing.T) {
		require.False(t, verifyMerkleProof(root, leaves[honest], honest, proofs[honest][:2]))
		require.False(t, verifyMerkleProof(root, leaves[honest], honest, nil))
		longer := append(append([][32]byte(nil), proofs[honest]...), [32]byte{})
		require.False(t, verifyMerkleProof(root, leaves[honest], honest, longer))
	})
}

func TestStk_MerkleProofIgnoresIndexBitsAboveTheTree(t *testing.T) {
	leaves := make([][]byte, 8)
	for i := range leaves {
		leaves[i] = stkLeaf(uint64(100 + i))
	}
	root, proofs := stkTree(leaves)
	const honest = 3

	// Only the low log2(n) bits of index are consumed, one per proof level.
	// Any index congruent to 3 mod 8 verifies against leaf 3's path, so the
	// claimed position is not bound to the committed tree size.
	for _, alias := range []uint64{3, 11, 19, 1 << 20, 3 + (1 << 40)} {
		if alias%8 != 3 {
			continue
		}
		require.Truef(t, verifyMerkleProof(root, leaves[honest], alias, proofs[honest]),
			"index %d aliases to slot 3 and is accepted", alias)
	}
	require.True(t, verifyMerkleProof(root, leaves[honest], 3+8, proofs[honest]))
}

func TestStk_MerkleProofHasNoDomainSeparation(t *testing.T) {
	// Leaves are hashed as sha256(leaf) and internal nodes as
	// sha256(left||right) with no tag distinguishing the two. So the 64-byte
	// preimage of an internal node is accepted as a *leaf* under an empty
	// path: a second preimage for the root, no tree membership required.
	a := sha256.Sum256(stkLeaf(1))
	b := sha256.Sum256(stkLeaf(2))
	forged := make([]byte, 0, 64)
	forged = append(forged, a[:]...)
	forged = append(forged, b[:]...)
	root := sha256.Sum256(forged)

	require.True(t, verifyMerkleProof(root, forged, 0, nil),
		"a node preimage is accepted as a leaf; if this now fails the tree grew domain separation")
	require.True(t, verifyMerkleProof(root, forged, 12345, nil),
		"and the claimed index is irrelevant when the path is empty")
}

func TestStk_MerkleProofDoesNotMutateItsInputs(t *testing.T) {
	leaves := [][]byte{stkLeaf(1), stkLeaf(2), stkLeaf(3), stkLeaf(4)}
	root, proofs := stkTree(leaves)

	leaf := append([]byte(nil), leaves[2]...)
	path := append([][32]byte(nil), proofs[2]...)
	before := append([]byte(nil), leaf...)
	beforePath := append([][32]byte(nil), path...)

	require.True(t, verifyMerkleProof(root, leaf, 2, path))
	require.Equal(t, before, leaf, "leaf slice must not be written through")
	require.Equal(t, beforePath, path, "auth path must not be written through")

	// Repeat verification is pure.
	require.True(t, verifyMerkleProof(root, leaf, 2, path))
}

// ---------------------------------------------------------------------------
// VerifyQuery
// ---------------------------------------------------------------------------

func TestStk_VerifyQueryAcceptsEveryHonestIndex(t *testing.T) {
	for idx := range uint64(8) {
		f := stkNewFixture(idx)
		require.NoErrorf(t, f.v.VerifyQuery(f.commit, f.query, f.alphas), "honest query at index %d", idx)
	}
}

func TestStk_VerifyQueryRejectsBadResponseLength(t *testing.T) {
	base := stkNewFixture(3)
	for _, tc := range []struct {
		name   string
		values []uint64
	}{
		{"empty", []uint64{}},
		{"nil", nil},
		{"one short", base.query.Values[:2]},
		{"two short", base.query.Values[:1]},
		{"one long", append(append([]uint64(nil), base.query.Values...), 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := base.stkClone()
			f.query.Values = tc.values
			err := f.v.VerifyQuery(f.commit, f.query, f.alphas)
			require.ErrorContains(t, err, "invalid query response length")
		})
	}

	// The guard is len(Values) == len(alphas)+1: shrink alphas instead and
	// the same response is now the wrong length.
	f := base.stkClone()
	require.ErrorContains(t, f.v.VerifyQuery(f.commit, f.query, f.alphas[:1]), "invalid query response length")
	require.ErrorContains(t, f.v.VerifyQuery(f.commit, f.query, nil), "invalid query response length")
}

func TestStk_VerifyQueryRejectsMerkleTampering(t *testing.T) {
	base := stkNewFixture(3)

	t.Run("wrong value at layer 0", func(t *testing.T) {
		f := base.stkClone()
		f.query.Values[0] ^= 1
		require.ErrorContains(t, f.v.VerifyQuery(f.commit, f.query, f.alphas), "merkle proof verification failed")
	})

	t.Run("wrong value at layer 1", func(t *testing.T) {
		f := base.stkClone()
		f.query.Values[1] ^= 1
		require.ErrorContains(t, f.v.VerifyQuery(f.commit, f.query, f.alphas), "merkle proof verification failed")
	})

	t.Run("wrong root at each layer", func(t *testing.T) {
		for lvl := range base.commit.LayerRoots {
			f := base.stkClone()
			f.commit.LayerRoots[lvl][0] ^= 0x80
			require.ErrorContains(t, f.v.VerifyQuery(f.commit, f.query, f.alphas), "merkle proof verification failed")
		}
	})

	t.Run("sibling bit flipped in any path", func(t *testing.T) {
		for lvl := range base.query.AuthPaths {
			for step := range base.query.AuthPaths[lvl] {
				f := base.stkClone()
				sib := f.query.AuthPaths[lvl][step]
				sib[31] ^= 1
				f.query.AuthPaths[lvl][step] = sib
				require.ErrorContainsf(t, f.v.VerifyQuery(f.commit, f.query, f.alphas),
					"merkle proof verification failed", "layer %d step %d", lvl, step)
			}
		}
	})

	t.Run("index moved off its slot", func(t *testing.T) {
		for _, other := range []uint64{0, 1, 2, 4, 5, 6, 7} {
			f := base.stkClone()
			f.query.Index = other
			require.Errorf(t, f.v.VerifyQuery(f.commit, f.query, f.alphas), "index %d must not reuse slot 3's paths", other)
		}
	})

	t.Run("layer roots swapped", func(t *testing.T) {
		f := base.stkClone()
		f.commit.LayerRoots[0], f.commit.LayerRoots[1] = f.commit.LayerRoots[1], f.commit.LayerRoots[0]
		require.ErrorContains(t, f.v.VerifyQuery(f.commit, f.query, f.alphas), "merkle proof verification failed")
	})

	t.Run("empty auth path at a layer", func(t *testing.T) {
		f := base.stkClone()
		f.query.AuthPaths[0] = nil
		require.ErrorContains(t, f.v.VerifyQuery(f.commit, f.query, f.alphas), "merkle proof verification failed")
	})
}

func TestStk_VerifyQueryDoesNotCheckTheFold(t *testing.T) {
	// Every value is honestly committed, but the challenges handed in are not
	// the ones the layers were folded with. VerifyQuery computes `expected`
	// and then discards it (`_ = expected`), so an inconsistent fold is
	// accepted. This pins the hole; it is a soundness gap, not a feature.
	f := stkNewFixture(3)
	require.NoError(t, f.v.VerifyQuery(f.commit, f.query, []uint64{0, 0}),
		"if this now errors, the fold check went live and this test should assert rejection")
	require.NoError(t, f.v.VerifyQuery(f.commit, f.query, []uint64{f.alphas[1], f.alphas[0]}))
}

func TestStk_VerifyQueryAcceptsAnEmptyCommitment(t *testing.T) {
	// No committed layers means the loop body never runs, so any response of
	// the right length verifies. A commitment carrying no layers is vacuously
	// valid.
	v := NewFRIVerifier(8, 4, 2, 1<<20)
	err := v.VerifyQuery(
		&FRICommitment{},
		&FRIQueryResponse{Index: 1 << 40, Values: []uint64{0}},
		nil,
	)
	require.NoError(t, err, "vacuous accept; if this now errors the emptiness check went live")
}

func TestStk_VerifyQueryPanicsOnShortAuthPaths(t *testing.T) {
	// The length guard ties Values to alphas but nothing ties AuthPaths to
	// LayerRoots, so a response with fewer paths than committed layers indexes
	// past the end. In a precompile this is a panic on attacker-shaped input.
	f := stkNewFixture(3)
	f.query.AuthPaths = f.query.AuthPaths[:1]
	require.Panics(t, func() { _ = f.v.VerifyQuery(f.commit, f.query, f.alphas) })

	f2 := stkNewFixture(3)
	f2.query.AuthPaths = nil
	require.Panics(t, func() { _ = f2.v.VerifyQuery(f2.commit, f2.query, f2.alphas) })
}

func TestStk_VerifyQueryPanicsWhenLayersOutnumberValues(t *testing.T) {
	// Values is sized against alphas, but the loop runs over LayerRoots. A
	// commitment declaring more layers than the response has values reads past
	// the end of Values once the earlier layers verify.
	v := NewFRIVerifier(8, 4, 2, 1<<20)
	const value uint64 = 0xabcdef
	layer0 := sha256.Sum256(stkLeaf(value)) // single-leaf tree: root == sha256(leaf)

	commit := &FRICommitment{LayerRoots: [][32]byte{layer0, {}}}
	query := &FRIQueryResponse{Index: 0, Values: []uint64{value}, AuthPaths: [][][32]byte{nil, nil}}

	// The length guard passes (1 value, 0 alphas) and layer 0 verifies, so the
	// loop advances to layer 1 and indexes Values out of range.
	require.Panics(t, func() { _ = v.VerifyQuery(commit, query, nil) })

	// With the second layer removed the very same response verifies, which
	// isolates the panic to the missing layer/value agreement.
	require.NoError(t, v.VerifyQuery(&FRICommitment{LayerRoots: [][32]byte{layer0}}, query, nil))
}

func TestStk_VerifyQueryPanicsOnZeroFold(t *testing.T) {
	// NewFRIVerifier accepts FoldingFactor 0; the index update then divides
	// by zero on the first layer.
	f := stkNewFixture(3)
	f.v = NewFRIVerifier(8, 4, 0, 1<<20)
	require.Panics(t, func() { _ = f.v.VerifyQuery(f.commit, f.query, f.alphas) })
}

// ---------------------------------------------------------------------------
// Transcript — Fiat-Shamir must bind
// ---------------------------------------------------------------------------

func TestStk_TranscriptIsDeterministic(t *testing.T) {
	build := func() []uint64 {
		tr := NewTranscript("STARK-v1")
		tr.Append([]byte("program"))
		tr.Append(stkLeaf(42))
		out := make([]uint64, 8)
		for i := range out {
			out[i] = tr.Challenge()
		}
		return out
	}

	want := build()
	for range 50 {
		require.Equal(t, want, build(), "challenges must not depend on wall clock, map order or allocation")
	}

	// Same across goroutines, so nothing global leaks in.
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := build()
			mu.Lock()
			defer mu.Unlock()
			require.Equal(t, want, got)
		}()
	}
	wg.Wait()
}

func TestStk_TranscriptBindsEveryInput(t *testing.T) {
	first := func(label string, msgs ...[]byte) uint64 {
		tr := NewTranscript(label)
		for _, m := range msgs {
			tr.Append(m)
		}
		return tr.Challenge()
	}

	base := first("STARK-v1", []byte("a"), []byte("b"))

	require.NotEqual(t, base, first("STARK-v2", []byte("a"), []byte("b")), "label must bind")
	require.NotEqual(t, base, first("", []byte("a"), []byte("b")), "empty label is still a label")
	require.NotEqual(t, base, first("STARK-v1", []byte("A"), []byte("b")), "message content must bind")
	require.NotEqual(t, base, first("STARK-v1", []byte("b"), []byte("a")), "message order must bind")
	require.NotEqual(t, base, first("STARK-v1", []byte("a")), "message count must bind")
	require.NotEqual(t, base, first("STARK-v1", []byte("a"), []byte("b"), nil), "an empty append still advances the state")
	require.NotEqual(t, base, first("STARK-v1", []byte("ab")), "one append of ab must differ from two of a then b")

	// One flipped bit anywhere in the appended data changes the challenge.
	msg := []byte("the quick brown fox")
	ref := first("STARK-v1", msg)
	for i := range msg {
		for _, mask := range []byte{0x01, 0x40} {
			flipped := append([]byte(nil), msg...)
			flipped[i] ^= mask
			require.NotEqualf(t, ref, first("STARK-v1", flipped), "byte %d mask %#x", i, mask)
		}
	}
}

func TestStk_ChallengeAdvancesAndStaysInField(t *testing.T) {
	tr := NewTranscript("STARK-v1")
	seen := map[uint64]bool{}
	for range 512 {
		c := tr.Challenge()
		require.Less(t, c, stkP, "challenge must be a field element")
		require.Zero(t, c>>63, "top bit is masked off")
		require.False(t, seen[c], "the state advances, so challenges do not repeat")
		seen[c] = true
	}

	// Append between challenges changes what comes next.
	a := NewTranscript("STARK-v1")
	b := NewTranscript("STARK-v1")
	require.Equal(t, a.Challenge(), b.Challenge())
	a.Append([]byte("x"))
	require.NotEqual(t, a.Challenge(), b.Challenge())
}

func TestStk_AppendDoesNotAliasCallerMemory(t *testing.T) {
	data := []byte("mutable")
	tr := NewTranscript("STARK-v1")
	tr.Append(data)
	after := tr.Challenge()

	// The caller's buffer is untouched...
	require.Equal(t, []byte("mutable"), data)

	// ...and mutating it afterwards cannot rewrite history.
	data[0] = 'M'
	tr2 := NewTranscript("STARK-v1")
	tr2.Append([]byte("mutable"))
	require.Equal(t, after, tr2.Challenge())
}

// ---------------------------------------------------------------------------
// STARKVerifier
// ---------------------------------------------------------------------------

func TestStk_NewSTARKVerifierWiresItsFRIParameters(t *testing.T) {
	var h [32]byte
	h[0] = 9
	v := NewSTARKVerifier(h, 12, 34)

	require.Equal(t, h, v.ProgramHash)
	require.Equal(t, uint64(12), v.TraceWidth)
	require.Equal(t, uint64(34), v.NumConstraints)
	require.NotNil(t, v.FRI, "a verifier without FRI parameters cannot verify or price anything")
	require.Positive(t, v.FRI.NumQueries)
	require.Positive(t, v.FRI.BlowupFactor)
	require.Positive(t, v.FRI.FoldingFactor, "a zero folding factor would divide by zero in VerifyQuery")
	require.Positive(t, v.FRI.MaxDegree)

	require.NotSame(t, v.FRI, NewSTARKVerifier(h, 12, 34).FRI, "verifiers must not share FRI state")
}

func TestStk_VerifyIsDeterministicAndReinitialisesTheTranscript(t *testing.T) {
	var h [32]byte
	h[0] = 1
	v := NewSTARKVerifier(h, 1, 1)
	proof := &STARKProof{}

	ok1, err1 := v.Verify(proof, []uint64{1, 2, 3})
	ok2, err2 := v.Verify(proof, []uint64{1, 2, 3})
	require.NoError(t, err1)
	require.NoError(t, err2)
	require.Equal(t, ok1, ok2, "a second call must not depend on the first call's transcript")
}

func TestStk_VerifyAcceptsAnEmptyProof(t *testing.T) {
	// STARKProof{} carries no FRI queries and no committed layers, so the
	// query loop never runs and Verify returns true. Nothing in Verify
	// constrains the trace, the constraints or the OOD evaluations.
	var h [32]byte
	v := NewSTARKVerifier(h, 4, 4)
	ok, err := v.Verify(&STARKProof{}, nil)
	require.NoError(t, err)
	require.True(t, ok, "vacuous accept; if this now fails, Verify grew real checks")
}

func TestStk_VerifyBindsPublicInputsAndProgram(t *testing.T) {
	var h [32]byte
	h[0] = 7
	v := &STARKVerifier{ProgramHash: h, TraceWidth: 2, NumConstraints: 2, FRI: NewFRIVerifier(8, 1, 2, 1<<20)}

	publicInputs := []uint64{11, 22}
	proof := &STARKProof{TraceCommitment: [32]byte{1}, ConstraintCommitment: [32]byte{2}}
	alphas, indices := stkChallenges(h, publicInputs, proof, v.FRI.NumQueries)
	require.Empty(t, alphas)

	// A query answering the challenge-derived index verifies.
	proof.FRIQueries = []FRIQueryResponse{{Index: indices[0], Values: []uint64{0}}}
	ok, err := v.Verify(proof, publicInputs)
	require.NoError(t, err)
	require.True(t, ok)

	// Change a public input and the same proof no longer answers the right
	// index: Fiat-Shamir binds the statement.
	ok, err = v.Verify(proof, []uint64{11, 23})
	require.ErrorContains(t, err, "query index mismatch")
	require.False(t, ok)

	// Same for dropping an input, for the program hash and for the
	// commitments folded into the transcript.
	ok, err = v.Verify(proof, publicInputs[:1])
	require.ErrorContains(t, err, "query index mismatch")
	require.False(t, ok)

	other := &STARKVerifier{ProgramHash: [32]byte{8}, FRI: NewFRIVerifier(8, 1, 2, 1<<20)}
	ok, err = other.Verify(proof, publicInputs)
	require.ErrorContains(t, err, "query index mismatch")
	require.False(t, ok)

	tampered := *proof
	tampered.TraceCommitment = [32]byte{99}
	ok, err = v.Verify(&tampered, publicInputs)
	require.ErrorContains(t, err, "query index mismatch")
	require.False(t, ok)

	tampered2 := *proof
	tampered2.ConstraintCommitment = [32]byte{99}
	ok, err = v.Verify(&tampered2, publicInputs)
	require.ErrorContains(t, err, "query index mismatch")
	require.False(t, ok)
}

func TestStk_VerifyPropagatesQueryFailure(t *testing.T) {
	var h [32]byte
	h[0] = 21
	v := &STARKVerifier{ProgramHash: h, FRI: NewFRIVerifier(8, 1, 2, 1<<20)}
	proof := &STARKProof{FRICommitment: FRICommitment{LayerRoots: [][32]byte{{1}}}}
	_, indices := stkChallenges(h, nil, proof, v.FRI.NumQueries)

	// Right index, malformed response: the error surfaces from VerifyQuery.
	proof.FRIQueries = []FRIQueryResponse{{Index: indices[0], Values: []uint64{1, 2, 3}}}
	ok, err := v.Verify(proof, nil)
	require.ErrorContains(t, err, "invalid query response length")
	require.False(t, ok)

	// Right index and length, wrong Merkle data.
	proof.FRIQueries = []FRIQueryResponse{{
		Index:     indices[0],
		Values:    []uint64{1, 2},
		AuthPaths: [][][32]byte{nil},
	}}
	ok, err = v.Verify(proof, nil)
	require.ErrorContains(t, err, "merkle proof verification failed")
	require.False(t, ok)
}

func TestStk_VerifyPanicsOnMoreQueriesThanChallenges(t *testing.T) {
	// queryIndices is sized from NumQueries but the loop ranges over the
	// proof's queries, so a proof carrying more queries than the verifier
	// budgeted reads past the end of queryIndices.
	var h [32]byte
	h[0] = 44
	v := &STARKVerifier{ProgramHash: h, FRI: NewFRIVerifier(8, 1, 2, 1<<20)}
	proof := &STARKProof{}
	_, indices := stkChallenges(h, nil, proof, 1)

	// The first query is fully valid, so the loop survives it and then reads
	// queryIndices[1], which the verifier never generated.
	good := FRIQueryResponse{Index: indices[0], Values: []uint64{0}}
	proof.FRIQueries = []FRIQueryResponse{good}
	ok, err := v.Verify(proof, nil)
	require.NoError(t, err)
	require.True(t, ok)

	proof.FRIQueries = []FRIQueryResponse{good, good}
	require.Panics(t, func() { _, _ = v.Verify(proof, nil) })
}

func TestStk_VerifyIsSafeUnderConcurrentUse(t *testing.T) {
	var h [32]byte
	h[0] = 3
	v := NewSTARKVerifier(h, 1, 1)

	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ok, err := v.Verify(&STARKProof{}, []uint64{uint64(i)})
			require.NoError(t, err)
			require.True(t, ok)
		}(i)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// gas
// ---------------------------------------------------------------------------

func TestStk_RequiredGasIsNeverFreeAndGrows(t *testing.T) {
	var h [32]byte
	v := NewSTARKVerifier(h, 1, 1)

	require.Positive(t, v.RequiredGas(0), "verification is never free")

	// Non-decreasing in proof size, and strictly increasing across each
	// 32-byte hashing boundary.
	prev := v.RequiredGas(0)
	for size := 1; size <= 4096; size++ {
		got := v.RequiredGas(size)
		require.GreaterOrEqualf(t, got, prev, "gas must not fall as the proof grows (size %d)", size)
		if size%32 == 0 {
			require.Greaterf(t, got, v.RequiredGas(size-32), "an extra 32 bytes must cost more (size %d)", size)
		}
		prev = got
	}

	// Strictly increasing in the query budget, which is the dominant cost.
	cheap := &STARKVerifier{FRI: NewFRIVerifier(8, 10, 2, 1<<20)}
	dear := &STARKVerifier{FRI: NewFRIVerifier(8, 100, 2, 1<<20)}
	require.Greater(t, dear.RequiredGas(0), cheap.RequiredGas(0))
	require.Greater(t, dear.RequiredGas(1024), cheap.RequiredGas(1024))

	// Even with no queries the base cost stands.
	require.Positive(t, (&STARKVerifier{FRI: NewFRIVerifier(0, 0, 0, 0)}).RequiredGas(0))

	// Pricing is a pure function of the two inputs.
	require.Equal(t, v.RequiredGas(777), v.RequiredGas(777))
}

// ---------------------------------------------------------------------------
// registry
// ---------------------------------------------------------------------------

func TestStk_RegistryRoundTrip(t *testing.T) {
	var missing [32]byte
	copy(missing[:], "stk-registry-never-registered")
	got, ok := GetSTARKVerifier(missing)
	require.False(t, ok)
	require.Nil(t, got)

	var h [32]byte
	copy(h[:], "stk-registry-round-trip")
	v := NewSTARKVerifier(h, 3, 4)
	RegisterSTARKVerifier(h, v)

	got, ok = GetSTARKVerifier(h)
	require.True(t, ok)
	require.Same(t, v, got)

	// Registration is keyed on the whole hash: a one-bit neighbour misses.
	near := h
	near[31] ^= 1
	_, ok = GetSTARKVerifier(near)
	require.False(t, ok)

	// Re-registering replaces.
	v2 := NewSTARKVerifier(h, 5, 6)
	RegisterSTARKVerifier(h, v2)
	got, ok = GetSTARKVerifier(h)
	require.True(t, ok)
	require.Same(t, v2, got)

	// A nil verifier registers as present-but-nil; Get reports ok.
	RegisterSTARKVerifier(near, nil)
	got, ok = GetSTARKVerifier(near)
	require.True(t, ok)
	require.Nil(t, got)
}

func TestStk_RegistryIsSafeUnderConcurrentUse(t *testing.T) {
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var h [32]byte
			copy(h[:], "stk-concurrent")
			h[31] = byte(i)
			RegisterSTARKVerifier(h, NewSTARKVerifier(h, uint64(i), 1))
			got, ok := GetSTARKVerifier(h)
			require.True(t, ok)
			require.Equal(t, uint64(i), got.TraceWidth)
		}(i)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// STARKVerifyPrecompile
// ---------------------------------------------------------------------------

func stkPrecompileInput(programHash [32]byte, publicInputs []uint64) []byte {
	in := make([]byte, 36)
	copy(in, programHash[:])
	binary.BigEndian.PutUint32(in[32:36], uint32(len(publicInputs)))
	for _, pi := range publicInputs {
		in = append(in, stkLeaf(pi)...)
	}
	return in
}

func TestStk_PrecompileRejectsMalformedInput(t *testing.T) {
	var known [32]byte
	copy(known[:], "stk-precompile-known-program")
	RegisterSTARKVerifier(known, NewSTARKVerifier(known, 1, 1))

	var unknown [32]byte
	copy(unknown[:], "stk-precompile-unknown-program")

	short := make([]byte, 36)
	copy(short, known[:])

	for _, tc := range []struct {
		name  string
		input []byte
		want  string
	}{
		{"nil", nil, "input too short"},
		{"empty", []byte{}, "input too short"},
		{"one byte", []byte{0}, "input too short"},
		{"hash only", make([]byte, 32), "input too short"},
		{"one byte short of the header", make([]byte, 35), "input too short"},
		{"unknown program", stkPrecompileInput(unknown, nil), "unknown program"},
		{"public input count exceeds the payload", func() []byte {
			in := append([]byte(nil), short...)
			binary.BigEndian.PutUint32(in[32:36], 1)
			return in
		}(), "input too short for public inputs"},
		{"last public input truncated", func() []byte {
			in := stkPrecompileInput(known, []uint64{1, 2})
			return in[:len(in)-1]
		}(), "input too short for public inputs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := STARKVerifyPrecompile(tc.input)
			require.ErrorContains(t, err, tc.want)
			require.Nil(t, out)
		})
	}

	// The header boundary is exactly 36 bytes: 35 is refused, 36 is parsed.
	_, err := STARKVerifyPrecompile(make([]byte, 35))
	require.ErrorContains(t, err, "input too short")
	_, err = STARKVerifyPrecompile(make([]byte, 36))
	require.ErrorContains(t, err, "unknown program", "36 bytes is enough to reach program lookup")
}

func TestStk_PrecompileAcceptsAnythingForARegisteredProgram(t *testing.T) {
	// The entry point never decodes a proof: it builds STARKProof{} and
	// verifies that. So for any registered program every well-formed header
	// returns the 32-byte true word, whatever payload follows.
	var h [32]byte
	copy(h[:], "stk-precompile-accepts-anything")
	RegisterSTARKVerifier(h, NewSTARKVerifier(h, 2, 2))

	for _, publicInputs := range [][]uint64{nil, {1}, {1, 2, 3}} {
		out, err := STARKVerifyPrecompile(stkPrecompileInput(h, publicInputs))
		require.NoError(t, err)
		require.Len(t, out, 32)
		require.EqualValues(t, 1, out[31], "encoded as a 32-byte big-endian one")
		require.Equal(t, make([]byte, 31), out[:31])
	}

	// Trailing garbage where the proof should be is ignored entirely.
	in := append(stkPrecompileInput(h, []uint64{5}), make([]byte, 512)...)
	out, err := STARKVerifyPrecompile(in)
	require.NoError(t, err)
	require.EqualValues(t, 1, out[31],
		"if this now fails, the entry point started decoding the proof and these tests need rewriting")

	// Extra public inputs beyond the declared count are ignored, so two
	// different payloads yield the same answer.
	out2, err := STARKVerifyPrecompile(append(stkPrecompileInput(h, []uint64{5}), stkLeaf(6)...))
	require.NoError(t, err)
	require.Equal(t, out, out2)
}
