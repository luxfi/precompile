// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// ---------- helpers ----------

// posLeaf builds a 32-byte value whose leading bytes are distinct per tag, so
// that inputs differ in the prefix the hasher keys its cache on.
func posLeaf(tag byte) [32]byte {
	var b [32]byte
	b[0] = tag
	b[31] = tag ^ 0xA5
	return b
}

// posInput concatenates field elements into a hasher input.
func posInput(elems ...[32]byte) []byte {
	out := make([]byte, 0, len(elems)*32)
	for _, e := range elems {
		out = append(out, e[:]...)
	}
	return out
}

// posOffload is the set of accelerator hooks poseidon.go consults.
type posOffload struct {
	hash       func([]byte) ([]byte, error)
	pair       func(left, right [32]byte) ([32]byte, error)
	commitment func(value, blinding, salt [32]byte) ([32]byte, error)
	nullifier  func(key, commitment, index [32]byte) ([32]byte, error)
}

// posAccelerate installs accelerator hooks for the duration of one test and
// puts the package back the way it found it.
func posAccelerate(t *testing.T, o posOffload) {
	t.Helper()
	oldOn := useGPU
	oldHash, oldPair := gpuHashFunc, gpuHashPairFunc
	oldCommit, oldNull := gpuCommitmentFunc, gpuNullifierFunc
	t.Cleanup(func() {
		useGPU = oldOn
		gpuHashFunc, gpuHashPairFunc = oldHash, oldPair
		gpuCommitmentFunc, gpuNullifierFunc = oldCommit, oldNull
	})
	useGPU = true
	gpuHashFunc, gpuHashPairFunc = o.hash, o.pair
	gpuCommitmentFunc, gpuNullifierFunc = o.commitment, o.nullifier
}

// posSentinel returns a recognisable 32-byte answer.
func posSentinel(tag byte) [32]byte {
	var b [32]byte
	for i := range b {
		b[i] = tag
	}
	return b
}

var errPosOffload = errors.New("accelerator unavailable")

// ---------- Hash: input validation ----------

func TestPos_HashRejectsMalformedLength(t *testing.T) {
	h := NewPoseidon2Hasher()

	for _, n := range []int{0, 1, 2, 31, 33, 63, 65, 95, 127} {
		t.Run(fmt.Sprintf("%dbytes", n), func(t *testing.T) {
			got, err := h.Hash(make([]byte, n))
			require.ErrorIs(t, err, ErrInvalidInputLength, "%d bytes is not a whole number of field elements", n)
			require.Equal(t, [32]byte{}, got)
		})
	}

	got, err := h.Hash(nil)
	require.ErrorIs(t, err, ErrInvalidInputLength, "nil input must be refused")
	require.Equal(t, [32]byte{}, got)
}

func TestPos_HashEnforcesElementCeiling(t *testing.T) {
	h := NewPoseidon2Hasher()

	// The boundary is the interesting part: 16 elements is the largest input
	// the sponge accepts, 17 is the first it must refuse.
	for n := 1; n <= 16; n++ {
		input := make([]byte, n*32)
		input[0] = byte(n)
		got, err := h.Hash(input)
		require.NoError(t, err, "%d elements must be accepted", n)
		require.NotEqual(t, [32]byte{}, got)
	}

	for _, n := range []int{17, 18, 32, 100} {
		input := make([]byte, n*32)
		input[0] = byte(n)
		got, err := h.Hash(input)
		require.ErrorIs(t, err, ErrTooManyInputs, "%d elements must be refused", n)
		require.Equal(t, [32]byte{}, got)
	}
}

// ---------- Hash: the function it is meant to be ----------

func TestPos_HashSeparatesDistinctInputs(t *testing.T) {
	seen := map[[32]byte][]byte{}
	for i := range 64 {
		input := posInput(posLeaf(byte(i)))
		got, err := NewPoseidon2Hasher().Hash(input)
		require.NoError(t, err)
		require.NotEqual(t, [32]byte{}, got)

		prior, dup := seen[got]
		require.False(t, dup, "input %x collided with %x", input, prior)
		seen[got] = input
	}

	// A single flipped bit anywhere in the element must change the digest.
	base := posLeaf(1)
	ref, err := NewPoseidon2Hasher().Hash(base[:])
	require.NoError(t, err)
	for _, pos := range []int{0, 7, 15, 30, 31} {
		flipped := base
		flipped[pos] ^= 0x01
		got, err := NewPoseidon2Hasher().Hash(flipped[:])
		require.NoError(t, err)
		require.NotEqual(t, ref, got, "flipping byte %d left the digest unchanged", pos)
	}
}

func TestPos_HashIsIndependentOfTheHasherItRanOn(t *testing.T) {
	input := posInput(posLeaf(0x11), posLeaf(0x22))

	first, err := NewPoseidon2Hasher().Hash(input)
	require.NoError(t, err)

	// A second, unrelated hasher must agree. A hash whose answer depends on
	// which instance computed it is not a hash.
	second := NewPoseidon2Hasher()
	_, err = second.Hash(posInput(posLeaf(0x99)))
	require.NoError(t, err)
	got, err := second.Hash(input)
	require.NoError(t, err)
	require.Equal(t, first, got)
}

func TestPos_HashNeverReturnsAStaleAnswer(t *testing.T) {
	// The cache key must be the whole input. It used to fold only the first
	// 32 bytes and the length, so two inputs sharing a prefix shared a slot
	// and the second call returned the FIRST input's digest — the hash
	// stopped being a function of its input, and its answer depended on what
	// the process had hashed before.
	h := NewPoseidon2Hasher()

	shared := posLeaf(0x42)
	a := posInput(shared, posLeaf(0x01), posLeaf(0x02))
	b := posInput(shared, posLeaf(0x03), posLeaf(0x04))
	require.NotEqual(t, a, b)

	ha, err := h.Hash(a)
	require.NoError(t, err)
	hb, err := h.Hash(b)
	require.NoError(t, err)
	require.NotEqual(t, ha, hb, "a shared prefix selected the answer")

	// Each answer must equal the one a cold hasher computes.
	for _, c := range []struct {
		in  []byte
		got [32]byte
	}{{a, ha}, {b, hb}} {
		truth, err := NewPoseidon2Hasher().Hash(c.in)
		require.NoError(t, err)
		require.Equal(t, truth, c.got, "the cache changed the digest")
	}

	// The same property one level up: a Merkle node must depend on BOTH
	// children. With the old key, HashPair(a,b1) == HashPair(a,b2), which
	// collapses every subtree sharing a left child and makes inclusion
	// proofs forgeable.
	hp := NewPoseidon2Hasher()
	left, r1, r2 := posLeaf(0x11), posLeaf(0x22), posLeaf(0x33)
	n1, err := hp.HashPair(left, r1)
	require.NoError(t, err)
	n2, err := hp.HashPair(left, r2)
	require.NoError(t, err)
	require.NotEqual(t, n1, n2, "a Merkle node ignored its right child")

	// And a commitment must depend on its blinding factor and salt.
	hc := NewPoseidon2Hasher()
	v, b1, s1 := posLeaf(0x01), posLeaf(0x02), posLeaf(0x03)
	c1, err := hc.Commitment(v, b1, s1)
	require.NoError(t, err)
	c2, err := hc.Commitment(v, posLeaf(0x04), s1)
	require.NoError(t, err)
	c3, err := hc.Commitment(v, b1, posLeaf(0x05))
	require.NoError(t, err)
	require.NotEqual(t, c1, c2, "the blinding factor did not bind")
	require.NotEqual(t, c1, c3, "the salt did not bind")

	// And a nullifier must depend on the note it spends.
	hn := NewPoseidon2Hasher()
	key := posLeaf(0x77)
	nA, err := hn.NullifierHash(key, posLeaf(0xA1), 0)
	require.NoError(t, err)
	nB, err := hn.NullifierHash(key, posLeaf(0xB2), 0)
	require.NoError(t, err)
	require.NotEqual(t, nA, nB, "one nullifier served two different notes")
}

func TestPos_HashSeparatesInputsOfDifferentLength(t *testing.T) {
	// Length is the only thing keeping a prefix and its extension apart, so it
	// has to reach the cache slot. Otherwise Hash(a||b) would answer for
	// Hash(a||b||c) as well.
	h := NewPoseidon2Hasher()
	prefix := posLeaf(0x34)

	short := posInput(prefix, posLeaf(0x35))
	long := posInput(prefix, posLeaf(0x35), posLeaf(0x36))

	hs, err := h.Hash(short)
	require.NoError(t, err)
	hl, err := h.Hash(long)
	require.NoError(t, err)
	require.NotEqual(t, hs, hl, "an extended input was served the shorter one's digest")

	coldShort, err := NewPoseidon2Hasher().Hash(short)
	require.NoError(t, err)
	coldLong, err := NewPoseidon2Hasher().Hash(long)
	require.NoError(t, err)
	require.Equal(t, coldShort, hs)
	require.Equal(t, coldLong, hl)
}

func TestPos_CacheKeyNamesTheInput(t *testing.T) {
	// Distinct inputs must occupy distinct cache slots, whatever they share.
	h := NewPoseidon2Hasher()
	single := posLeaf(0x33)
	other := posLeaf(0x39)
	two := posInput(single, posLeaf(0x01))
	three := posInput(single, posLeaf(0x01), posLeaf(0x02))

	for _, in := range [][]byte{single[:], other[:], two, three} {
		_, err := h.Hash(in)
		require.NoError(t, err)
	}
	require.Len(t, h.cache, 4, "distinct inputs must not share a cache slot")

	// Re-hashing an input hits its own slot and adds nothing.
	_, err := h.Hash(three)
	require.NoError(t, err)
	require.Len(t, h.cache, 4)
	require.Equal(t, uint64(1), h.CacheHits)
}

func TestPos_HashHonoursItsCacheBound(t *testing.T) {
	h := NewPoseidon2Hasher()
	h.cacheMax = 0

	a := posInput(posLeaf(0x42), posLeaf(0x01))
	b := posInput(posLeaf(0x42), posLeaf(0x02))

	ha, err := h.Hash(a)
	require.NoError(t, err)
	hb, err := h.Hash(b)
	require.NoError(t, err)
	require.Empty(t, h.cache, "nothing may be stored once the bound is reached")

	// With nothing cached, the digests are the true ones and differ.
	require.NotEqual(t, ha, hb)
	truthA, err := NewPoseidon2Hasher().Hash(a)
	require.NoError(t, err)
	truthB, err := NewPoseidon2Hasher().Hash(b)
	require.NoError(t, err)
	require.Equal(t, truthA, ha)
	require.Equal(t, truthB, hb)

	// A bound of one admits exactly one entry.
	h2 := NewPoseidon2Hasher()
	h2.cacheMax = 1
	_, err = h2.Hash(a)
	require.NoError(t, err)
	_, err = h2.Hash(posInput(posLeaf(0x77), posLeaf(0x01)))
	require.NoError(t, err)
	require.Len(t, h2.cache, 1)
}

func TestPos_HashAccountsForHitsAndMisses(t *testing.T) {
	h := NewPoseidon2Hasher()
	input := posInput(posLeaf(0x31))

	_, err := h.Hash(input)
	require.NoError(t, err)
	require.EqualValues(t, 1, h.CacheMisses)
	require.EqualValues(t, 0, h.CacheHits)
	require.EqualValues(t, 1, h.TotalHashes)

	for i := range 3 {
		_, err := h.Hash(input)
		require.NoError(t, err)
		require.EqualValues(t, i+1, h.CacheHits)
		require.EqualValues(t, 1, h.CacheMisses, "a repeat must not be counted as a miss")
		require.EqualValues(t, 1, h.TotalHashes, "a served hit is not a new hash")
	}

	// A refused input never reaches the accounting.
	_, err = h.Hash(make([]byte, 5))
	require.Error(t, err)
	require.EqualValues(t, 1, h.CacheMisses)
	require.EqualValues(t, 1, h.TotalHashes)
}

// ---------- domain separation ----------

func TestPos_HashPairIsOrdered(t *testing.T) {
	left, right := posLeaf(0x10), posLeaf(0x20)

	ab, err := NewPoseidon2Hasher().HashPair(left, right)
	require.NoError(t, err)
	ba, err := NewPoseidon2Hasher().HashPair(right, left)
	require.NoError(t, err)
	require.NotEqual(t, ab, ba, "a Merkle node must depend on which child is which")

	aa, err := NewPoseidon2Hasher().HashPair(left, left)
	require.NoError(t, err)
	require.NotEqual(t, ab, aa)
	require.NotEqual(t, ba, aa)
}

func TestPos_ConstructionsShareOneDomain(t *testing.T) {
	// DEFECT (reported, not fixed): HashPair, Commitment and NullifierHash all
	// forward to Hash over the plain concatenation with no domain tag, so a
	// digest produced for one purpose is a valid digest for another. A
	// nullifier is a commitment; a commitment is an inner Merkle node.
	left, right := posLeaf(0x10), posLeaf(0x20)

	pair, err := NewPoseidon2Hasher().HashPair(left, right)
	require.NoError(t, err)
	flat, err := NewPoseidon2Hasher().Hash(posInput(left, right))
	require.NoError(t, err)
	require.Equal(t, flat, pair, "current behaviour: HashPair(a,b) is Hash(a||b)")

	key, note := posLeaf(0x31), posLeaf(0x32)
	nullifier, err := NewPoseidon2Hasher().NullifierHash(key, note, 5)
	require.NoError(t, err)

	var index [32]byte
	index[31] = 5
	commitment, err := NewPoseidon2Hasher().Commitment(key, note, index)
	require.NoError(t, err)
	require.Equal(t, commitment, nullifier,
		"current behaviour: a nullifier and a commitment over the same words are the same digest")
}

func TestPos_NonCanonicalFieldElementIsAccepted(t *testing.T) {
	// DEFECT (reported, not fixed): ErrInvalidFieldElement is declared but
	// never returned. Inputs are reduced mod r by fr.SetBytes, so a value and
	// that value plus the modulus are the same field element and hash alike.
	var canonical [32]byte
	canonical[31] = 5

	var shifted [32]byte
	over := new(big.Int).Add(fr.Modulus(), big.NewInt(5))
	ob := over.Bytes()
	require.Len(t, ob, 32)
	copy(shifted[:], ob)
	require.NotEqual(t, canonical, shifted)

	a, err := NewPoseidon2Hasher().Hash(canonical[:])
	require.NoError(t, err)
	b, err := NewPoseidon2Hasher().Hash(shifted[:])
	require.NoError(t, err)
	require.Equal(t, a, b, "current behaviour: two byte strings, one field element, one digest")
}

// ---------- Commitment ----------

func TestPos_CommitmentSeparatesItsFields(t *testing.T) {
	value, blinding, salt := posLeaf(0x01), posLeaf(0x02), posLeaf(0x03)

	base, err := NewPoseidon2Hasher().Commitment(value, blinding, salt)
	require.NoError(t, err)
	require.NotEqual(t, [32]byte{}, base)

	repeat, err := NewPoseidon2Hasher().Commitment(value, blinding, salt)
	require.NoError(t, err)
	require.Equal(t, base, repeat, "a commitment must be a function of its opening")

	for name, tc := range map[string][3][32]byte{
		"value":    {posLeaf(0x04), blinding, salt},
		"blinding": {value, posLeaf(0x05), salt},
		"salt":     {value, blinding, posLeaf(0x06)},
		"rotated":  {salt, value, blinding},
	} {
		got, err := NewPoseidon2Hasher().Commitment(tc[0], tc[1], tc[2])
		require.NoError(t, err)
		require.NotEqual(t, base, got, "changing the %s must change the commitment", name)
	}
}

func TestPos_CommitmentKeepsHidingOnAWarmHasher(t *testing.T) {
	// The cache key used to cover only the first 32 bytes — for a commitment,
	// the value. Every commitment to the same value on one hasher then
	// returned the first one's digest, so the blinding factor contributed
	// nothing and the commitment became a public function of the value: a
	// total loss of hiding. The key is now the whole input.
	h := NewPoseidon2Hasher()
	value := posLeaf(0x77)

	first, err := h.Commitment(value, posLeaf(0x01), posLeaf(0x02))
	require.NoError(t, err)
	second, err := h.Commitment(value, posLeaf(0xAA), posLeaf(0xBB))
	require.NoError(t, err)
	require.NotEqual(t, first, second,
		"the same value under different blinding produced the same commitment")

	// Warm and cold must agree, so the cache cannot alter a commitment.
	cold, err := NewPoseidon2Hasher().Commitment(value, posLeaf(0xAA), posLeaf(0xBB))
	require.NoError(t, err)
	require.Equal(t, cold, second)
}

// ---------- nullifiers ----------

func TestPos_NullifierBindsTheLeafIndex(t *testing.T) {
	key, note := posLeaf(0x41), posLeaf(0x42)

	seen := map[[32]byte]uint64{}
	for _, idx := range []uint64{0, 1, 2, 255, 256, 65535, 1 << 32, math.MaxUint64} {
		got, err := NewPoseidon2Hasher().NullifierHash(key, note, idx)
		require.NoError(t, err)
		require.NotEqual(t, [32]byte{}, got)

		prior, dup := seen[got]
		require.False(t, dup, "index %d and %d produced the same nullifier", idx, prior)
		seen[got] = idx
	}

	// Index zero is the empty big-endian encoding; it must still be a well
	// defined position and not a special case.
	zero, err := NewPoseidon2Hasher().NullifierHash(key, note, 0)
	require.NoError(t, err)
	var zeroIndex [32]byte
	explicit, err := NewPoseidon2Hasher().Commitment(key, note, zeroIndex)
	require.NoError(t, err)
	require.Equal(t, explicit, zero, "index 0 encodes as 32 zero bytes")
}

func TestPos_NullifierStaysPerNoteOnAWarmHasher(t *testing.T) {
	// The cache key for a nullifier used to be the nullifier key alone, so
	// two different notes at two different positions shared a nullifier —
	// exactly the value a shielded pool relies on being unique per note, and
	// therefore a double-spend. The key is now the whole input.
	h := NewPoseidon2Hasher()
	key := posLeaf(0x51)

	a, err := h.NullifierHash(key, posLeaf(0x01), 1)
	require.NoError(t, err)
	b, err := h.NullifierHash(key, posLeaf(0x02), 2)
	require.NoError(t, err)
	require.NotEqual(t, a, b, "two notes shared one nullifier")

	// Warm and cold must agree.
	cold, err := NewPoseidon2Hasher().NullifierHash(key, posLeaf(0x02), 2)
	require.NoError(t, err)
	require.Equal(t, cold, b)
}

func TestPos_NoteCommitmentBindsEveryField(t *testing.T) {
	amount := big.NewInt(1000)
	asset := posLeaf(0x01)
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")
	blinding := posLeaf(0x02)

	base, err := NewPoseidon2Hasher().NoteCommitment(amount, asset, owner, blinding)
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		amount   *big.Int
		asset    [32]byte
		owner    common.Address
		blinding [32]byte
	}{
		"amount":   {big.NewInt(1001), asset, owner, blinding},
		"asset":    {amount, posLeaf(0x03), owner, blinding},
		"owner":    {amount, asset, common.HexToAddress("0xdeadbeef"), blinding},
		"blinding": {amount, asset, owner, posLeaf(0x04)},
		"zero":     {big.NewInt(0), asset, owner, blinding},
	} {
		got, err := NewPoseidon2Hasher().NoteCommitment(tc.amount, tc.asset, tc.owner, tc.blinding)
		require.NoError(t, err)
		require.NotEqual(t, base, got, "changing the %s must change the note", name)
	}
}

// ---------- Merkle ----------

func TestPos_MerkleRootRefusesAnEmptyTree(t *testing.T) {
	got, err := NewPoseidon2Hasher().MerkleRoot(nil)
	require.Error(t, err)
	require.Equal(t, [32]byte{}, got)

	got, err = NewPoseidon2Hasher().MerkleRoot([][32]byte{})
	require.Error(t, err)
	require.Equal(t, [32]byte{}, got)
}

func TestPos_MerkleRootPadsWithZeroLeaves(t *testing.T) {
	for _, n := range []int{2, 3, 5, 7, 8, 9} {
		leaves := make([][32]byte, n)
		for i := range leaves {
			leaves[i] = posLeaf(byte(i + 1))
		}

		root, err := NewPoseidon2Hasher().MerkleRoot(leaves)
		require.NoError(t, err)

		// Padding to the next power of two by hand must give the same answer.
		size := 1
		for size < n {
			size *= 2
		}
		padded := make([][32]byte, size)
		copy(padded, leaves)
		manual, err := NewPoseidon2Hasher().MerkleRoot(padded)
		require.NoError(t, err)
		require.Equal(t, root, manual, "%d leaves must pad to %d", n, size)

		// Changing any leaf must move the root.
		for i := range leaves {
			altered := make([][32]byte, n)
			copy(altered, leaves)
			altered[i] = posLeaf(0xF0 | byte(i))
			got, err := NewPoseidon2Hasher().MerkleRoot(altered)
			require.NoError(t, err)
			require.NotEqual(t, root, got, "leaf %d of %d is not bound by the root", i, n)
		}
	}
}

func TestPos_MerkleRootOfOneLeafIsTheLeaf(t *testing.T) {
	// DEFECT (reported, not fixed): leaves and inner nodes live in the same
	// domain, so a one-leaf tree's root is the leaf verbatim. Any 32 bytes are
	// therefore a valid root with an empty proof, and an inner node can be
	// presented as a leaf.
	leaf := posLeaf(0x63)
	root, err := NewPoseidon2Hasher().MerkleRoot([][32]byte{leaf})
	require.NoError(t, err)
	require.Equal(t, leaf, root, "current behaviour: no leaf/node separation")

	ok, err := NewPoseidon2Hasher().VerifyMerkleProof(leaf, nil, nil, root)
	require.NoError(t, err)
	require.True(t, ok, "an empty proof authenticates the root against itself")
}

func TestPos_MerkleProofVerifiesEveryLeaf(t *testing.T) {
	leaves := make([][32]byte, 8)
	for i := range leaves {
		leaves[i] = posLeaf(byte(i + 1))
	}
	root, err := NewPoseidon2Hasher().MerkleRoot(leaves)
	require.NoError(t, err)

	for i := range leaves {
		proof, isLeft, err := NewPoseidon2Hasher().MerkleProof(leaves, i)
		require.NoError(t, err)
		require.Len(t, proof, 3, "an eight leaf tree is three levels deep")
		require.Len(t, isLeft, len(proof))

		ok, err := NewPoseidon2Hasher().VerifyMerkleProof(leaves[i], proof, isLeft, root)
		require.NoError(t, err)
		require.True(t, ok, "leaf %d must verify against its own root", i)
	}
}

func TestPos_MerkleProofDoesNotTransfer(t *testing.T) {
	leaves := make([][32]byte, 8)
	for i := range leaves {
		leaves[i] = posLeaf(byte(i + 1))
	}
	root, err := NewPoseidon2Hasher().MerkleRoot(leaves)
	require.NoError(t, err)

	proofs := make([][][32]byte, len(leaves))
	dirs := make([][]bool, len(leaves))
	for i := range leaves {
		proofs[i], dirs[i], err = NewPoseidon2Hasher().MerkleProof(leaves, i)
		require.NoError(t, err)
	}

	for i := range leaves {
		for j := range leaves {
			if i == j {
				continue
			}
			// Another leaf under leaf i's proof.
			ok, err := NewPoseidon2Hasher().VerifyMerkleProof(leaves[j], proofs[i], dirs[i], root)
			require.NoError(t, err)
			require.False(t, ok, "leaf %d passed under leaf %d's proof", j, i)

			// Leaf i under its own siblings but another position's directions.
			ok, err = NewPoseidon2Hasher().VerifyMerkleProof(leaves[i], proofs[i], dirs[j], root)
			require.NoError(t, err)
			require.False(t, ok, "leaf %d passed at position %d", i, j)
		}
	}
}

func TestPos_MerkleProofRejectsTampering(t *testing.T) {
	leaves := make([][32]byte, 8)
	for i := range leaves {
		leaves[i] = posLeaf(byte(i + 1))
	}
	root, err := NewPoseidon2Hasher().MerkleRoot(leaves)
	require.NoError(t, err)

	const target = 3
	proof, isLeft, err := NewPoseidon2Hasher().MerkleProof(leaves, target)
	require.NoError(t, err)

	t.Run("tampered sibling", func(t *testing.T) {
		for level := range proof {
			bad := make([][32]byte, len(proof))
			copy(bad, proof)
			bad[level][0] ^= 0x01

			ok, err := NewPoseidon2Hasher().VerifyMerkleProof(leaves[target], bad, isLeft, root)
			require.NoError(t, err)
			require.False(t, ok, "a flipped bit in the level %d sibling was accepted", level)
		}
	})

	t.Run("wrong root", func(t *testing.T) {
		bad := root
		bad[0] ^= 0x01
		ok, err := NewPoseidon2Hasher().VerifyMerkleProof(leaves[target], proof, isLeft, bad)
		require.NoError(t, err)
		require.False(t, ok)

		ok, err = NewPoseidon2Hasher().VerifyMerkleProof(leaves[target], proof, isLeft, [32]byte{})
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("wrong leaf", func(t *testing.T) {
		ok, err := NewPoseidon2Hasher().VerifyMerkleProof(posLeaf(0xEE), proof, isLeft, root)
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("truncated proof", func(t *testing.T) {
		ok, err := NewPoseidon2Hasher().VerifyMerkleProof(leaves[target], proof[:2], isLeft[:2], root)
		require.NoError(t, err)
		require.False(t, ok)

		ok, err = NewPoseidon2Hasher().VerifyMerkleProof(leaves[target], nil, nil, root)
		require.NoError(t, err)
		require.False(t, ok, "an empty proof must not authenticate a leaf of a deeper tree")
	})

	t.Run("extended proof", func(t *testing.T) {
		long := append(append([][32]byte{}, proof...), posLeaf(0x99))
		dirs := append(append([]bool{}, isLeft...), true)
		ok, err := NewPoseidon2Hasher().VerifyMerkleProof(leaves[target], long, dirs, root)
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("length mismatch", func(t *testing.T) {
		for _, tc := range []struct {
			name          string
			proof         [][32]byte
			isLeft        []bool
			expectRefusal bool
		}{
			{"more siblings than directions", proof, isLeft[:1], true},
			{"more directions than siblings", proof[:1], isLeft, true},
			{"directions without siblings", nil, isLeft, true},
			{"siblings without directions", proof, nil, true},
		} {
			ok, err := NewPoseidon2Hasher().VerifyMerkleProof(leaves[target], tc.proof, tc.isLeft, root)
			require.Error(t, err, tc.name)
			require.False(t, ok, tc.name)
		}
	})
}

func TestPos_MerkleProofGuardsTheIndex(t *testing.T) {
	leaves := make([][32]byte, 4)
	for i := range leaves {
		leaves[i] = posLeaf(byte(i + 1))
	}

	for name, tc := range map[string]struct {
		leaves [][32]byte
		index  int
	}{
		"empty tree":       {nil, 0},
		"empty tree slice": {[][32]byte{}, 0},
		"one past the end": {leaves, len(leaves)},
		"far past the end": {leaves, 1 << 20},
	} {
		proof, isLeft, err := NewPoseidon2Hasher().MerkleProof(tc.leaves, tc.index)
		require.Error(t, err, name)
		require.Nil(t, proof, name)
		require.Nil(t, isLeft, name)
	}

	// A one-leaf tree has no siblings to prove against.
	proof, isLeft, err := NewPoseidon2Hasher().MerkleProof([][32]byte{posLeaf(1)}, 0)
	require.NoError(t, err)
	require.Empty(t, proof)
	require.Empty(t, isLeft)
}

func TestPos_MerkleSubtreesSeparateOnASharedLeftChild(t *testing.T) {
	// The cache used to key a node on its LEFT child alone, so two subtrees
	// sharing a left child collapsed onto one digest. It bit INSIDE a single
	// MerkleRoot call: here leaves 1 and 3 share a left neighbour, and leaf 3
	// stopped reaching the root, so a proof issued for one leaf
	// authenticated a substituted one. The key is now the whole input.
	shared := posLeaf(0x01)
	original := [][32]byte{shared, posLeaf(0x02), shared, posLeaf(0x03)}
	forged := [][32]byte{shared, posLeaf(0x02), shared, posLeaf(0xFF)}

	rootA, err := NewPoseidon2Hasher().MerkleRoot(original)
	require.NoError(t, err)
	rootB, err := NewPoseidon2Hasher().MerkleRoot(forged)
	require.NoError(t, err)
	require.NotEqual(t, rootA, rootB,
		"a changed leaf did not reach the root")

	// One hasher serving a pool — building the root, issuing the proof and
	// checking it — must REFUSE the substituted leaf against the honest root.
	node := NewPoseidon2Hasher()
	root, err := node.MerkleRoot(original)
	require.NoError(t, err)
	proof, isLeft, err := node.MerkleProof(original, 3)
	require.NoError(t, err)

	ok, err := node.VerifyMerkleProof(forged[3], proof, isLeft, root)
	require.NoError(t, err)
	require.False(t, ok, "a substituted leaf verified against the honest root")

	// The honest leaf still verifies, so the refusal above is not blanket.
	ok, err = node.VerifyMerkleProof(original[3], proof, isLeft, root)
	require.NoError(t, err)
	require.True(t, ok, "the genuine leaf must still verify")

	// Turning the cache off must not change any of it: the cache is now
	// transparent, so warm and cold roots agree.
	cold := func(leaves [][32]byte) [32]byte {
		h := NewPoseidon2Hasher()
		h.cacheMax = 0
		root, err := h.MerkleRoot(leaves)
		require.NoError(t, err)
		return root
	}
	require.Equal(t, cold(original), rootA, "the cache changed the root")
	require.Equal(t, cold(forged), rootB, "the cache changed the root")
	require.NotEqual(t, cold(original), cold(forged))
}

// ---------- gas ----------

func TestPos_RequiredGasPricesEveryAcceptedInput(t *testing.T) {
	h := NewPoseidon2Hasher()

	require.Zero(t, h.RequiredGas(0), "there is no work in an empty input")
	for _, n := range []int{1, 2, 31, 33, 63, 65, 95} {
		require.Zero(t, h.RequiredGas(n), "%d bytes is refused, so it is not priced", n)
	}

	// Anything the hasher will actually process must cost something.
	for n := 1; n <= 16; n++ {
		input := make([]byte, n*32)
		input[0] = byte(n)
		_, err := h.Hash(input)
		require.NoError(t, err)
		require.NotZero(t, h.RequiredGas(n*32), "%d elements must not hash for free", n)
	}
}

func TestPos_RequiredGasGrowsLinearlyWithElements(t *testing.T) {
	h := NewPoseidon2Hasher()

	prev := h.RequiredGas(32)
	require.NotZero(t, prev)
	var step uint64
	for n := 2; n <= 64; n++ {
		got := h.RequiredGas(n * 32)
		require.Greater(t, got, prev, "%d elements must cost more than %d", n, n-1)
		if n > 2 {
			require.Equal(t, step, got-prev, "pricing must be linear in the element count")
		}
		step = got - prev
		prev = got
	}

	// There is a fixed overhead on top of the per-element charge.
	require.Greater(t, h.RequiredGas(32), step, "the base charge must exceed one element")
}

// ---------- accelerator hooks ----------

func TestPos_AcceleratorTakesOverEachOperation(t *testing.T) {
	posAccelerate(t, posOffload{
		hash: func([]byte) ([]byte, error) {
			s := posSentinel(0xA1)
			return s[:], nil
		},
		pair: func(left, right [32]byte) ([32]byte, error) {
			return posSentinel(0xA2), nil
		},
		commitment: func(value, blinding, salt [32]byte) ([32]byte, error) {
			return posSentinel(0xA3), nil
		},
		nullifier: func(key, commitment, index [32]byte) ([32]byte, error) {
			return posSentinel(0xA4), nil
		},
	})

	h := NewPoseidon2Hasher()

	got, err := h.Hash(posInput(posLeaf(0xC1)))
	require.NoError(t, err)
	require.Equal(t, posSentinel(0xA1), got)

	pair, err := h.HashPair(posLeaf(0xC2), posLeaf(0xC3))
	require.NoError(t, err)
	require.Equal(t, posSentinel(0xA2), pair)

	commitment, err := h.Commitment(posLeaf(0xC4), posLeaf(0xC5), posLeaf(0xC6))
	require.NoError(t, err)
	require.Equal(t, posSentinel(0xA3), commitment)

	nullifier, err := h.NullifierHash(posLeaf(0xC7), posLeaf(0xC8), 9)
	require.NoError(t, err)
	require.Equal(t, posSentinel(0xA4), nullifier)
}

func TestPos_AcceleratorReceivesTheEncodedIndex(t *testing.T) {
	var seenKey, seenNote, seenIndex [32]byte
	posAccelerate(t, posOffload{
		nullifier: func(key, commitment, index [32]byte) ([32]byte, error) {
			seenKey, seenNote, seenIndex = key, commitment, index
			return posSentinel(0xB1), nil
		},
	})

	h := NewPoseidon2Hasher()
	key, note := posLeaf(0x71), posLeaf(0x72)

	for _, idx := range []uint64{0, 1, 258, math.MaxUint64} {
		_, err := h.NullifierHash(key, note, idx)
		require.NoError(t, err)
		require.Equal(t, key, seenKey)
		require.Equal(t, note, seenNote)

		var want [32]byte
		b := new(big.Int).SetUint64(idx).Bytes()
		copy(want[32-len(b):], b)
		require.Equal(t, want, seenIndex, "index %d must arrive right aligned big endian", idx)
	}
}

func TestPos_AcceleratorFailuresPropagate(t *testing.T) {
	fail := posOffload{
		hash:       func([]byte) ([]byte, error) { return nil, errPosOffload },
		pair:       func(left, right [32]byte) ([32]byte, error) { return [32]byte{}, errPosOffload },
		commitment: func(v, b, s [32]byte) ([32]byte, error) { return [32]byte{}, errPosOffload },
		nullifier:  func(k, c, i [32]byte) ([32]byte, error) { return [32]byte{}, errPosOffload },
	}
	posAccelerate(t, fail)

	h := NewPoseidon2Hasher()
	leaves := [][32]byte{posLeaf(1), posLeaf(2), posLeaf(3), posLeaf(4)}

	got, err := h.Hash(posInput(posLeaf(0xD1)))
	require.ErrorIs(t, err, errPosOffload)
	require.Equal(t, [32]byte{}, got)

	_, err = h.HashPair(posLeaf(0xD2), posLeaf(0xD3))
	require.ErrorIs(t, err, errPosOffload)

	_, err = h.Commitment(posLeaf(0xD4), posLeaf(0xD5), posLeaf(0xD6))
	require.ErrorIs(t, err, errPosOffload)

	_, err = h.NullifierHash(posLeaf(0xD7), posLeaf(0xD8), 1)
	require.ErrorIs(t, err, errPosOffload)

	// Everything built on HashPair must surface the failure rather than
	// carrying on with a zero digest.
	root, err := h.MerkleRoot(leaves)
	require.ErrorIs(t, err, errPosOffload)
	require.Equal(t, [32]byte{}, root)

	proof, isLeft, err := h.MerkleProof(leaves, 1)
	require.ErrorIs(t, err, errPosOffload)
	require.Nil(t, proof)
	require.Nil(t, isLeft)

	ok, err := h.VerifyMerkleProof(leaves[0], [][32]byte{leaves[1]}, []bool{true}, [32]byte{})
	require.ErrorIs(t, err, errPosOffload)
	require.False(t, ok, "a failed hash must not be read as a verified proof")
}

func TestPos_AcceleratorAbsentHookFallsBack(t *testing.T) {
	// The switch is two conditions: enabled, and a hook actually installed.
	// With the flag on but no hook the pure Go path must still answer.
	posAccelerate(t, posOffload{})

	h := NewPoseidon2Hasher()
	input := posInput(posLeaf(0xE1), posLeaf(0xE2))

	got, err := h.Hash(input)
	require.NoError(t, err)
	cold, err := NewPoseidon2Hasher().Hash(input)
	require.NoError(t, err)
	require.Equal(t, cold, got)

	pair, err := h.HashPair(posLeaf(0xE1), posLeaf(0xE2))
	require.NoError(t, err)
	require.Equal(t, cold, pair)

	commitment, err := h.Commitment(posLeaf(0xE3), posLeaf(0xE4), posLeaf(0xE5))
	require.NoError(t, err)
	require.NotEqual(t, [32]byte{}, commitment)

	nullifier, err := h.NullifierHash(posLeaf(0xE6), posLeaf(0xE7), 3)
	require.NoError(t, err)
	require.NotEqual(t, [32]byte{}, nullifier)
}

func TestPos_AcceleratorShortAnswerIsZeroPadded(t *testing.T) {
	// DEFECT (reported, not fixed): the accelerator's answer is copied into a
	// fixed 32-byte digest with no length check, so a truncated result is
	// silently accepted and padded with zeros.
	posAccelerate(t, posOffload{
		hash: func([]byte) ([]byte, error) { return []byte{0x01, 0x02, 0x03}, nil },
	})

	got, err := NewPoseidon2Hasher().Hash(posInput(posLeaf(0xF1)))
	require.NoError(t, err)
	require.Equal(t, []byte{0x01, 0x02, 0x03}, got[:3])
	require.Equal(t, make([]byte, 29), got[3:], "current behaviour: the tail is zero filled")
}

// ---------- precompile entry points ----------

func TestPos_Poseidon2HashEntryPoint(t *testing.T) {
	for _, n := range []int{0, 1, 31, 33, 63} {
		out, err := Poseidon2Hash(make([]byte, n))
		require.ErrorIs(t, err, ErrInvalidInputLength, "%d bytes accepted", n)
		require.Nil(t, out)
	}
	out, err := Poseidon2Hash(nil)
	require.ErrorIs(t, err, ErrInvalidInputLength)
	require.Nil(t, out)

	out, err = Poseidon2Hash(make([]byte, 17*32))
	require.ErrorIs(t, err, ErrTooManyInputs)
	require.Nil(t, out)

	input := posInput(posLeaf(0x21), posLeaf(0x22))
	out, err = Poseidon2Hash(input)
	require.NoError(t, err)
	require.Len(t, out, 32)

	direct, err := globalPoseidon2.Hash(input)
	require.NoError(t, err)
	require.Equal(t, direct[:], out, "the entry point must answer what the hasher answers")

	other, err := Poseidon2Hash(posInput(posLeaf(0x23), posLeaf(0x24)))
	require.NoError(t, err)
	require.NotEqual(t, out, other)
}

func TestPos_Poseidon2CommitmentEntryPoint(t *testing.T) {
	value, blinding, salt := posLeaf(0x25), posLeaf(0x26), posLeaf(0x27)

	out, err := Poseidon2Commitment(value, blinding, salt)
	require.NoError(t, err)
	require.Len(t, out, 32)

	direct, err := globalPoseidon2.Commitment(value, blinding, salt)
	require.NoError(t, err)
	require.Equal(t, direct[:], out)

	other, err := Poseidon2Commitment(posLeaf(0x28), blinding, salt)
	require.NoError(t, err)
	require.NotEqual(t, out, other)

	// A failing accelerator must surface as an error, not as a zero digest.
	posAccelerate(t, posOffload{
		commitment: func(v, b, s [32]byte) ([32]byte, error) { return [32]byte{}, errPosOffload },
	})
	out, err = Poseidon2Commitment(posLeaf(0x29), blinding, salt)
	require.ErrorIs(t, err, errPosOffload)
	require.Nil(t, out)
}

func TestPos_GetPoseidon2StatsIsMonotonic(t *testing.T) {
	hashes0, hits0, misses0 := GetPoseidon2Stats()

	input := posInput(posLeaf(0x2A), posLeaf(0x2B))
	_, err := Poseidon2Hash(input)
	require.NoError(t, err)

	hashes1, hits1, misses1 := GetPoseidon2Stats()
	require.Equal(t, hashes0+1, hashes1, "a fresh input is a new hash")
	require.Equal(t, misses0+1, misses1)
	require.Equal(t, hits0, hits1)

	_, err = Poseidon2Hash(input)
	require.NoError(t, err)

	hashes2, hits2, misses2 := GetPoseidon2Stats()
	require.Equal(t, hashes1, hashes2, "a repeat is served from the cache")
	require.Equal(t, misses1, misses2)
	require.Equal(t, hits1+1, hits2)
}
