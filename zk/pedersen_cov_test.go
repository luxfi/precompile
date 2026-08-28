// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// ---------- helpers ----------

// pedScalar renders u as the canonical 32-byte encoding of a BN254 scalar.
func pedScalar(u uint64) [32]byte {
	var e fr.Element
	e.SetUint64(u)
	return e.Bytes()
}

// pedRandScalar returns a uniform scalar and its canonical encoding.
func pedRandScalar(t *testing.T) (fr.Element, [32]byte) {
	t.Helper()
	var e fr.Element
	_, err := e.SetRandom()
	require.NoError(t, err)
	return e, e.Bytes()
}

// pedUnknown returns 32 bytes that name no point the process has ever committed
// to, and proves it by checking the lookup fails.
func pedUnknown(t *testing.T, tag byte) [32]byte {
	t.Helper()
	var k [32]byte
	k[0] = 0x5A
	k[1] = tag
	for i := 2; i < 32; i++ {
		k[i] = byte(i*7) ^ tag
	}
	_, err := decompressG1(k)
	require.ErrorIs(t, err, ErrPointNotOnCurve, "fixture must not name a cached point")
	return k
}

// pedPoint multiplies the BN254 base generator by k.
func pedPoint(k int64) bn254.G1Affine {
	_, _, g1, _ := bn254.Generators()
	var out bn254.G1Affine
	out.ScalarMultiplication(&g1, big.NewInt(k))
	return out
}

// ---------- Commit / Verify ----------

func TestPed_CommitIsDeterministicAndSeparating(t *testing.T) {
	p := NewPedersenCommitter()

	v1, r1 := pedScalar(100), pedScalar(7)
	v2, r2 := pedScalar(101), pedScalar(8)

	c, err := p.Commit(v1, r1)
	require.NoError(t, err)

	again, err := p.Commit(v1, r1)
	require.NoError(t, err)
	require.Equal(t, c, again, "commitment must be a function of (value, blinding)")

	// Changing either input must move the commitment. Same value under a
	// different blinding is the property that makes the scheme hiding at all:
	// if it did not move, the commitment would leak the value directly.
	otherBlinding, err := p.Commit(v1, r2)
	require.NoError(t, err)
	require.NotEqual(t, c, otherBlinding, "same value, new blinding must give a new commitment")

	otherValue, err := p.Commit(v2, r1)
	require.NoError(t, err)
	require.NotEqual(t, c, otherValue, "new value, same blinding must give a new commitment")
	require.NotEqual(t, otherBlinding, otherValue)
}

func TestPed_VerifyAcceptsOnlyTheRealOpening(t *testing.T) {
	p := NewPedersenCommitter()

	value, blinding := pedScalar(4242), pedScalar(999)
	c, err := p.Commit(value, blinding)
	require.NoError(t, err)

	ok, err := p.Verify(c, value, blinding)
	require.NoError(t, err)
	require.True(t, ok, "the true opening must verify")

	zero := [32]byte{}
	cases := []struct {
		name           string
		value, binding [32]byte
	}{
		{"wrong value", pedScalar(4243), blinding},
		{"wrong blinding", value, pedScalar(1000)},
		{"both wrong", pedScalar(1), pedScalar(2)},
		{"zero value", zero, blinding},
		{"zero blinding", value, zero},
		{"all zero", zero, zero},
		{"value and blinding swapped", blinding, value},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := p.Verify(c, tc.value, tc.binding)
			require.NoError(t, err)
			require.False(t, ok, "a verifier that accepts %q is broken", tc.name)
		})
	}
}

func TestPed_VerifyRejectsTheIdentityCommitment(t *testing.T) {
	p := NewPedersenCommitter()

	// Commit(0,0) is the point at infinity. It must not act as a wildcard that
	// opens to arbitrary values.
	zero := [32]byte{}
	identity, err := p.Commit(zero, zero)
	require.NoError(t, err)

	var inf bn254.G1Affine
	require.Equal(t, compressG1(&inf), identity, "Commit(0,0) is the identity element")

	ok, err := p.Verify(identity, zero, zero)
	require.NoError(t, err)
	require.True(t, ok)

	for _, tc := range [][2][32]byte{
		{pedScalar(1), zero},
		{zero, pedScalar(1)},
		{pedScalar(5), pedScalar(5)},
	} {
		ok, err := p.Verify(identity, tc[0], tc[1])
		require.NoError(t, err)
		require.False(t, ok, "identity commitment must not open to a non-zero value")
	}
}

func TestPed_VerifyRefusesUnknownCommitments(t *testing.T) {
	p := NewPedersenCommitter()
	value, blinding := pedScalar(3), pedScalar(4)

	for _, tc := range []struct {
		name string
		c    [32]byte
	}{
		{"never committed", pedUnknown(t, 0x01)},
		{"all zero", [32]byte{}},
		{"all ones", [32]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := p.Verify(tc.c, value, blinding)
			require.Error(t, err)
			require.False(t, ok, "an unresolvable commitment must never verify")
		})
	}

	// A single flipped bit of a real commitment must not resolve either.
	real, err := p.Commit(value, blinding)
	require.NoError(t, err)
	near := real
	near[17] ^= 0x01
	ok, err := p.Verify(near, value, blinding)
	require.Error(t, err)
	require.False(t, ok)
}

func TestPed_NonCanonicalOpeningIsAccepted(t *testing.T) {
	// DEFECT (reported, not fixed): value and blinding are reduced mod r by
	// fr.SetBytes, so an opening whose bytes differ from the committed bytes
	// still verifies. Byte-level binding does not hold. This pins the current
	// behaviour so a fix is visible.
	p := NewPedersenCommitter()

	value, blinding := pedScalar(10), pedScalar(11)
	c, err := p.Commit(value, blinding)
	require.NoError(t, err)

	var shifted [32]byte
	over := new(big.Int).Add(fr.Modulus(), big.NewInt(10))
	ob := over.Bytes()
	require.Len(t, ob, 32, "value + r must still fit in 32 bytes")
	copy(shifted[:], ob)
	require.NotEqual(t, value, shifted)

	ok, err := p.Verify(c, shifted, blinding)
	require.NoError(t, err)
	require.True(t, ok, "current behaviour: a second, different byte string opens the same commitment")
}

// ---------- CommitWithOpening ----------

func TestPed_CommitWithOpeningProducesAVerifiableOpening(t *testing.T) {
	p := NewPedersenCommitter()

	for _, amount := range []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(1_000_000),
		new(big.Int).Sub(fr.Modulus(), big.NewInt(1)),
	} {
		c, blinding, err := p.CommitWithOpening(amount)
		require.NoError(t, err)

		var value [32]byte
		vb := amount.Bytes()
		copy(value[32-len(vb):], vb)

		ok, err := p.Verify(c, value, blinding)
		require.NoError(t, err)
		require.True(t, ok, "opening returned by CommitWithOpening(%s) must verify", amount)

		wrong, err := p.Verify(c, pedScalar(amount.Uint64()+1), blinding)
		require.NoError(t, err)
		require.False(t, wrong)
	}
}

func TestPed_CommitWithOpeningDrawsFreshBlinding(t *testing.T) {
	p := NewPedersenCommitter()
	amount := big.NewInt(500)

	seen := map[[32]byte]bool{}
	commitments := map[[32]byte]bool{}
	for range 8 {
		c, blinding, err := p.CommitWithOpening(amount)
		require.NoError(t, err)
		require.False(t, seen[blinding], "blinding factor repeated: randomness is not fresh")
		require.False(t, commitments[c], "commitment repeated for the same value")
		seen[blinding] = true
		commitments[c] = true
	}
}

func TestPed_CommitWithOpeningCountsCommitments(t *testing.T) {
	p := NewPedersenCommitter()
	require.Zero(t, p.TotalCommitments)

	for i := range 5 {
		_, _, err := p.CommitWithOpening(big.NewInt(int64(i)))
		require.NoError(t, err)
		require.EqualValues(t, i+1, p.TotalCommitments, "one commitment counted per call")
	}

	// Commit alone does not count: the counter tracks openings handed out, not
	// commitments produced.
	before := p.TotalCommitments
	_, err := p.Commit(pedScalar(1), pedScalar(2))
	require.NoError(t, err)
	require.Equal(t, before, p.TotalCommitments)
}

func TestPed_VerifyCountsVerifications(t *testing.T) {
	p := NewPedersenCommitter()
	require.Zero(t, p.TotalVerifications)

	c, err := p.Commit(pedScalar(1), pedScalar(2))
	require.NoError(t, err)

	for i := range 4 {
		_, err := p.Verify(c, pedScalar(1), pedScalar(2))
		require.NoError(t, err)
		require.EqualValues(t, i+1, p.TotalVerifications)
	}

	// A rejected verification short-circuits before the counter, so failures
	// are invisible to the statistics.
	before := p.TotalVerifications
	_, err = p.Verify(pedUnknown(t, 0x02), pedScalar(1), pedScalar(2))
	require.Error(t, err)
	require.Equal(t, before, p.TotalVerifications)
}

// ---------- homomorphism ----------

func TestPed_AddIsHomomorphic(t *testing.T) {
	p := NewPedersenCommitter()

	a, b := pedScalar(10), pedScalar(20)
	var av, bv fr.Element
	av.SetUint64(10)
	bv.SetUint64(20)
	r1e, r1 := pedRandScalar(t)
	r2e, r2 := pedRandScalar(t)

	c1, err := p.Commit(a, r1)
	require.NoError(t, err)
	c2, err := p.Commit(b, r2)
	require.NoError(t, err)

	var sumV, sumR fr.Element
	sumV.Add(&av, &bv)
	sumR.Add(&r1e, &r2e)
	sumVb, sumRb := sumV.Bytes(), sumR.Bytes()

	direct, err := p.Commit(sumVb, sumRb)
	require.NoError(t, err)

	added, err := p.Add(c1, c2)
	require.NoError(t, err)
	require.Equal(t, direct, added, "Commit(a,r1)+Commit(b,r2) must be Commit(a+b, r1+r2)")

	// The combined commitment opens to the combined opening and nothing else.
	ok, err := p.Verify(added, sumVb, sumRb)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = p.Verify(added, a, r1)
	require.NoError(t, err)
	require.False(t, ok)

	// Addition of points is commutative, so the operation must be too.
	swapped, err := p.Add(c2, c1)
	require.NoError(t, err)
	require.Equal(t, added, swapped)
}

func TestPed_SubUndoesAdd(t *testing.T) {
	p := NewPedersenCommitter()

	_, r1 := pedRandScalar(t)
	_, r2 := pedRandScalar(t)
	c1, err := p.Commit(pedScalar(7), r1)
	require.NoError(t, err)
	c2, err := p.Commit(pedScalar(9), r2)
	require.NoError(t, err)

	sum, err := p.Add(c1, c2)
	require.NoError(t, err)

	back, err := p.Sub(sum, c2)
	require.NoError(t, err)
	require.Equal(t, c1, back, "Sub must invert Add")

	backOther, err := p.Sub(sum, c1)
	require.NoError(t, err)
	require.Equal(t, c2, backOther)

	// Subtracting a commitment from itself yields the identity, which is
	// exactly the commitment to zero under a zero blinding.
	zero := [32]byte{}
	identity, err := p.Commit(zero, zero)
	require.NoError(t, err)
	self, err := p.Sub(c1, c1)
	require.NoError(t, err)
	require.Equal(t, identity, self)

	// Sub is not symmetric: c1-c2 and c2-c1 are different points.
	fwd, err := p.Sub(c1, c2)
	require.NoError(t, err)
	rev, err := p.Sub(c2, c1)
	require.NoError(t, err)
	require.NotEqual(t, fwd, rev)
}

func TestPed_AddAndSubRefuseUnknownOperands(t *testing.T) {
	p := NewPedersenCommitter()
	known, err := p.Commit(pedScalar(1), pedScalar(1))
	require.NoError(t, err)
	unknownA := pedUnknown(t, 0x03)
	unknownB := pedUnknown(t, 0x04)

	ops := map[string]func(a, b [32]byte) ([32]byte, error){
		"add": p.Add,
		"sub": p.Sub,
	}
	cases := []struct {
		name string
		a, b [32]byte
	}{
		{"left unknown", unknownA, known},
		{"right unknown", known, unknownB},
		{"both unknown", unknownA, unknownB},
		{"left zero", [32]byte{}, known},
		{"right zero", known, [32]byte{}},
	}
	for opName, op := range ops {
		for _, tc := range cases {
			t.Run(opName+"/"+tc.name, func(t *testing.T) {
				got, err := op(tc.a, tc.b)
				require.Error(t, err)
				require.Equal(t, [32]byte{}, got, "no result may be handed back on error")
			})
		}
	}
}

// ---------- vector commitments ----------

func TestPed_VectorCommitBinding(t *testing.T) {
	p := NewPedersenCommitter()
	_, blinding := pedRandScalar(t)

	values := [][32]byte{pedScalar(1), pedScalar(2), pedScalar(3)}
	c, err := p.VectorCommit(values, blinding)
	require.NoError(t, err)

	same, err := p.VectorCommit([][32]byte{pedScalar(1), pedScalar(2), pedScalar(3)}, blinding)
	require.NoError(t, err)
	require.Equal(t, c, same, "vector commitment must be a function of its inputs")

	// Every position is bound by its own generator, so permuting the vector
	// must move the commitment: otherwise a note's amount and asset id could
	// be swapped without detection.
	permuted, err := p.VectorCommit([][32]byte{pedScalar(2), pedScalar(1), pedScalar(3)}, blinding)
	require.NoError(t, err)
	require.NotEqual(t, c, permuted, "position must matter")

	changed, err := p.VectorCommit([][32]byte{pedScalar(1), pedScalar(2), pedScalar(4)}, blinding)
	require.NoError(t, err)
	require.NotEqual(t, c, changed)

	_, otherBlinding := pedRandScalar(t)
	reblinded, err := p.VectorCommit(values, otherBlinding)
	require.NoError(t, err)
	require.NotEqual(t, c, reblinded)

	// A non-zero element added to the tail moves the commitment.
	grown, err := p.VectorCommit(append(append([][32]byte{}, values...), pedScalar(4)), blinding)
	require.NoError(t, err)
	require.NotEqual(t, c, grown)

	// DEFECT (reported, not fixed): length is NOT bound. A zero element
	// contributes the identity, so any number of trailing zeros compresses to
	// the same commitment as the shorter vector. A three-field note and a
	// four-field note whose fourth field is zero are indistinguishable.
	for _, pad := range [][][32]byte{
		append(append([][32]byte{}, values...), [32]byte{}),
		append(append([][32]byte{}, values...), [32]byte{}, [32]byte{}),
	} {
		padded, err := p.VectorCommit(pad, blinding)
		require.NoError(t, err)
		require.Equal(t, c, padded,
			"current behaviour: trailing zero elements are invisible to the commitment")
	}
}

func TestPed_VectorCommitLengthBound(t *testing.T) {
	p := NewPedersenCommitter()
	blinding := pedScalar(5)
	limit := len(p.Generators)
	require.Positive(t, limit)

	for _, n := range []int{0, 1, limit - 1, limit} {
		values := make([][32]byte, n)
		for i := range values {
			values[i] = pedScalar(uint64(i + 1))
		}
		c, err := p.VectorCommit(values, blinding)
		require.NoError(t, err, "%d values is within the generator supply", n)
		if n > 0 {
			require.NotEqual(t, [32]byte{}, c)
		}
	}

	for _, n := range []int{limit + 1, limit * 2} {
		got, err := p.VectorCommit(make([][32]byte, n), blinding)
		require.Error(t, err, "%d values exceeds the generator supply", n)
		require.Equal(t, [32]byte{}, got)
	}

	// The empty vector is just the blinding, so it must match r*H and not the
	// identity.
	empty, err := p.VectorCommit(nil, blinding)
	require.NoError(t, err)
	identity, err := p.Commit([32]byte{}, [32]byte{})
	require.NoError(t, err)
	require.NotEqual(t, identity, empty)
}

func TestPed_NoteCommitmentBindsEveryField(t *testing.T) {
	p := NewPedersenCommitter()

	amount := big.NewInt(1000)
	var asset [32]byte
	asset[31] = 1
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")
	blinding := pedScalar(77)

	base, err := p.NoteCommitment(amount, asset, owner, blinding)
	require.NoError(t, err)

	repeat, err := p.NoteCommitment(amount, asset, owner, blinding)
	require.NoError(t, err)
	require.Equal(t, base, repeat)

	var otherAsset [32]byte
	otherAsset[31] = 2

	variants := map[string][32]byte{}
	for name, mk := range map[string]func() ([32]byte, error){
		"amount": func() ([32]byte, error) { return p.NoteCommitment(big.NewInt(1001), asset, owner, blinding) },
		"asset":  func() ([32]byte, error) { return p.NoteCommitment(amount, otherAsset, owner, blinding) },
		"owner": func() ([32]byte, error) {
			return p.NoteCommitment(amount, asset, common.HexToAddress("0xdead"), blinding)
		},
		"blinding": func() ([32]byte, error) { return p.NoteCommitment(amount, asset, owner, pedScalar(78)) },
	} {
		got, err := mk()
		require.NoError(t, err)
		require.NotEqual(t, base, got, "changing the %s must change the note", name)
		variants[name] = got
	}
	require.Len(t, variants, 4)
	distinct := map[[32]byte]bool{base: true}
	for name, v := range variants {
		require.False(t, distinct[v], "%s variant collided with another note", name)
		distinct[v] = true
	}
}

// ---------- balance ----------

func TestPed_VerifyBalanceAcceptsOnlyBalancedSets(t *testing.T) {
	p := NewPedersenCommitter()

	var a, b fr.Element
	a.SetUint64(30)
	b.SetUint64(70)
	r1e, r1 := pedRandScalar(t)
	r2e, r2 := pedRandScalar(t)

	ab, bb := a.Bytes(), b.Bytes()
	in1, err := p.Commit(ab, r1)
	require.NoError(t, err)
	in2, err := p.Commit(bb, r2)
	require.NoError(t, err)

	var sumV, sumR fr.Element
	sumV.Add(&a, &b)
	sumR.Add(&r1e, &r2e)
	sumVb, sumRb := sumV.Bytes(), sumR.Bytes()
	out, err := p.Commit(sumVb, sumRb)
	require.NoError(t, err)

	ok, err := p.VerifyBalance([][32]byte{in1, in2}, [][32]byte{out})
	require.NoError(t, err)
	require.True(t, ok, "inputs summing to the outputs must balance")

	// Money must not appear: dropping an input, dropping an output, or paying
	// out more than came in all have to fail.
	for name, tc := range map[string][2][][32]byte{
		"missing input":  {{in1}, {out}},
		"missing output": {{in1, in2}, nil},
		"extra output":   {{in1, in2}, {out, in1}},
		"inflated value": {{in1}, {in2}},
		"swapped sides":  {{out}, {in1}},
	} {
		ok, err := p.VerifyBalance(tc[0], tc[1])
		require.NoError(t, err, name)
		require.False(t, ok, "%s must not balance", name)
	}

	// Order within each side is irrelevant: the check is over a sum.
	ok, err = p.VerifyBalance([][32]byte{in2, in1}, [][32]byte{out})
	require.NoError(t, err)
	require.True(t, ok)
}

func TestPed_VerifyBalanceRefusesUnknownCommitments(t *testing.T) {
	p := NewPedersenCommitter()
	known, err := p.Commit(pedScalar(1), pedScalar(1))
	require.NoError(t, err)
	unknown := pedUnknown(t, 0x05)

	for name, tc := range map[string][2][][32]byte{
		"unknown input":       {{unknown}, {known}},
		"unknown among known": {{known, unknown}, {known}},
		"unknown output":      {{known}, {unknown}},
		"zero input":          {{{}}, {known}},
	} {
		ok, err := p.VerifyBalance(tc[0], tc[1])
		require.Error(t, err, name)
		require.False(t, ok, "%s must not report a balance", name)
	}
}

func TestPed_VerifyBalanceOnEmptySides(t *testing.T) {
	p := NewPedersenCommitter()

	// Nothing in, nothing out: both sides are the identity, so this balances.
	ok, err := p.VerifyBalance(nil, nil)
	require.NoError(t, err)
	require.True(t, ok)

	// But an empty side against a real commitment must not.
	c, err := p.Commit(pedScalar(1), pedScalar(1))
	require.NoError(t, err)
	ok, err = p.VerifyBalance(nil, [][32]byte{c})
	require.NoError(t, err)
	require.False(t, ok)
	ok, err = p.VerifyBalance([][32]byte{c}, nil)
	require.NoError(t, err)
	require.False(t, ok)

	// A zero-valued note under a zero blinding is the identity, so it balances
	// against nothing at all. Documented here because it is load-bearing: the
	// check is over points, not over declared amounts.
	zero := [32]byte{}
	identity, err := p.Commit(zero, zero)
	require.NoError(t, err)
	ok, err = p.VerifyBalance(nil, [][32]byte{identity})
	require.NoError(t, err)
	require.True(t, ok)
}

// ---------- gas ----------

func TestPed_RequiredGasPricesWork(t *testing.T) {
	p := NewPedersenCommitter()

	commit := p.RequiredGas("commit", 1)
	verify := p.RequiredGas("verify", 1)
	add := p.RequiredGas("add", 1)
	sub := p.RequiredGas("sub", 1)
	unknown := p.RequiredGas("no-such-operation", 1)

	for name, g := range map[string]uint64{
		"commit": commit, "verify": verify, "add": add, "sub": sub, "unknown": unknown,
	} {
		require.NotZero(t, g, "%s must not be free", name)
	}

	require.Equal(t, add, sub, "a point subtraction is a negation plus an addition")
	require.Less(t, add, commit, "a point addition is cheaper than two scalar multiplications")
	require.Less(t, commit, verify, "verifying is committing plus a comparison")
	require.GreaterOrEqual(t, unknown, verify, "an unrecognised operation must not undercharge")
}

func TestPed_RequiredGasTracksVectorLength(t *testing.T) {
	p := NewPedersenCommitter()

	prev := p.RequiredGas("vector", 0)
	require.NotZero(t, prev)
	var step uint64
	for n := 1; n <= 32; n++ {
		got := p.RequiredGas("vector", n)
		require.Greater(t, got, prev, "vector gas must grow with the number of elements")
		require.GreaterOrEqual(t, got, p.RequiredGas("commit", n),
			"a vector commitment does at least the work of a single commitment")
		if n > 1 {
			require.Equal(t, step, got-prev, "pricing must be linear in the element count")
		}
		step = got - prev
		prev = got
	}
}

func TestPed_RequiredGasIgnoresLengthForFixedSizeOps(t *testing.T) {
	p := NewPedersenCommitter()
	for _, op := range []string{"commit", "verify", "add", "sub", "unknown"} {
		base := p.RequiredGas(op, 0)
		for _, n := range []int{1, 10, 1000} {
			require.Equal(t, base, p.RequiredGas(op, n),
				"%s consumes a fixed-size input, so its price must not vary", op)
		}
	}
}

// ---------- generators and encoding ----------

func TestPed_HashToG1YieldsUsableGenerators(t *testing.T) {
	a := hashToG1("Lux_Pedersen_H_Generator")
	require.True(t, a.IsOnCurve())
	require.False(t, a.IsInfinity())

	again := hashToG1("Lux_Pedersen_H_Generator")
	require.True(t, a.Equal(&again), "hash-to-curve must be deterministic")

	b := hashToG1("Lux_Pedersen_H_Generator ")
	require.True(t, b.IsOnCurve())
	require.False(t, a.Equal(&b), "a one-character change must give a different generator")

	empty := hashToG1("")
	require.True(t, empty.IsOnCurve())
	require.False(t, empty.IsInfinity())

	// Sweep a wide spread of seeds: try-and-increment must land on the curve
	// every time, never on the identity, and never twice on the same point.
	seen := map[[32]byte]string{}
	for i := range 200 {
		seed := fmt.Sprintf("Lux_Pedersen_sweep_%d", i)
		pt := hashToG1(seed)
		require.True(t, pt.IsOnCurve(), "seed %q left the curve", seed)
		require.False(t, pt.IsInfinity(), "seed %q produced the identity", seed)

		key := compressG1(&pt)
		prior, dup := seen[key]
		require.False(t, dup, "seeds %q and %q share a generator", seed, prior)
		seen[key] = seed
	}
}

func TestPed_GeneratorsAreIndependent(t *testing.T) {
	p := NewPedersenCommitter()
	_, _, g1, _ := bn254.Generators()

	require.True(t, p.G.Equal(&g1), "G is the curve's base generator")
	require.True(t, p.H.IsOnCurve())
	require.False(t, p.H.IsInfinity())
	require.False(t, p.G.Equal(&p.H), "the blinding generator must not be G")

	seen := map[[32]byte]string{
		compressG1(&p.G): "G",
		compressG1(&p.H): "H",
	}
	require.Len(t, p.Generators, 32)
	for i := range p.Generators {
		gen := p.Generators[i]
		require.True(t, gen.IsOnCurve(), "generator %d off curve", i)
		require.False(t, gen.IsInfinity(), "generator %d is the identity", i)
		key := compressG1(&gen)
		prior, dup := seen[key]
		require.False(t, dup, "generator %d duplicates %s", i, prior)
		seen[key] = "generator"
	}
}

func TestPed_CompressAndDecompressRoundTrip(t *testing.T) {
	points := map[string]bn254.G1Affine{
		"infinity": {},
		"base":     pedPoint(1),
		"double":   pedPoint(2),
		"triple":   pedPoint(3),
		"large":    pedPoint(987654321),
	}

	digests := map[[32]byte]string{}
	for name, pt := range points {
		key := compressG1WithCache(&pt)

		prior, dup := digests[key]
		require.False(t, dup, "%s and %s compressed to the same 32 bytes", name, prior)
		digests[key] = name

		got, err := decompressG1(key)
		require.NoError(t, err, "%s must round trip", name)
		require.True(t, got.Equal(&pt), "%s did not survive the round trip", name)

		require.Equal(t, compressG1(&pt), key,
			"compressG1 and compressG1WithCache must agree on the digest")
	}
}

func TestPed_DecompressRefusesWhatItCannotResolve(t *testing.T) {
	// compressG1 computes the digest but does not register the point, so its
	// output alone cannot be resolved. Only compressG1WithCache produces a
	// usable handle.
	pt := pedPoint(0x0DEADBEE)
	digest := compressG1(&pt)
	got, err := decompressG1(digest)
	require.ErrorIs(t, err, ErrPointNotOnCurve)
	require.True(t, got.IsInfinity(), "a failed lookup must not hand back a usable point")

	// Registering the same point makes the same digest resolve.
	require.Equal(t, digest, compressG1WithCache(&pt))
	got, err = decompressG1(digest)
	require.NoError(t, err)
	require.True(t, got.Equal(&pt))

	// Near misses stay refused.
	for i := range 8 {
		near := digest
		near[i*4] ^= 0x80
		_, err := decompressG1(near)
		require.ErrorIs(t, err, ErrPointNotOnCurve, "flipped bit at byte %d resolved", i*4)
	}
}

// ---------- precompile entry points ----------

func TestPed_PrecompileRejectsMalformedInput(t *testing.T) {
	entries := map[string]struct {
		fn   func([]byte) ([]byte, error)
		want int
	}{
		"PedersenCommit": {PedersenCommit, 64},
		"PedersenVerify": {PedersenVerify, 96},
		"PedersenAdd":    {PedersenAdd, 64},
	}
	lengths := []int{0, 1, 31, 32, 63, 64, 65, 95, 96, 97, 128, 1024}

	for name, e := range entries {
		for _, n := range lengths {
			if n == e.want {
				continue
			}
			t.Run(fmt.Sprintf("%s/%dbytes", name, n), func(t *testing.T) {
				out, err := e.fn(make([]byte, n))
				require.ErrorIs(t, err, ErrInvalidCommitmentInput, "%s accepted %d bytes", name, n)
				require.Nil(t, out)
			})
		}
		out, err := e.fn(nil)
		require.ErrorIs(t, err, ErrInvalidCommitmentInput, "%s accepted nil", name)
		require.Nil(t, out)
	}
}

func TestPed_PrecompileCommitVerifyAddAgree(t *testing.T) {
	value, blinding := pedScalar(12345), pedScalar(6789)

	input := make([]byte, 64)
	copy(input[:32], value[:])
	copy(input[32:], blinding[:])

	c, err := PedersenCommit(input)
	require.NoError(t, err)
	require.Len(t, c, 32)

	// The entry point must agree with the committer it wraps.
	direct, err := globalPedersen.Commit(value, blinding)
	require.NoError(t, err)
	require.Equal(t, direct[:], c)

	verifyInput := make([]byte, 96)
	copy(verifyInput[:32], c)
	copy(verifyInput[32:64], value[:])
	copy(verifyInput[64:], blinding[:])

	out, err := PedersenVerify(verifyInput)
	require.NoError(t, err)
	require.Len(t, out, 32)
	require.Equal(t, byte(1), out[31], "a true opening must answer 1")
	require.Equal(t, make([]byte, 31), out[:31], "the answer is left padded")

	// Corrupting the value flips the answer to zero without erroring.
	bad := make([]byte, 96)
	copy(bad, verifyInput)
	bad[63] ^= 0x01
	out, err = PedersenVerify(bad)
	require.NoError(t, err)
	require.Equal(t, make([]byte, 32), out, "a false opening must answer 0")

	// Corrupting the blinding likewise.
	bad = make([]byte, 96)
	copy(bad, verifyInput)
	bad[95] ^= 0x01
	out, err = PedersenVerify(bad)
	require.NoError(t, err)
	require.Equal(t, make([]byte, 32), out)

	// Addition through the entry point matches the committer.
	v2, r2 := pedScalar(1), pedScalar(2)
	second := make([]byte, 64)
	copy(second[:32], v2[:])
	copy(second[32:], r2[:])
	c2, err := PedersenCommit(second)
	require.NoError(t, err)

	addInput := make([]byte, 64)
	copy(addInput[:32], c)
	copy(addInput[32:], c2)
	sum, err := PedersenAdd(addInput)
	require.NoError(t, err)
	require.Len(t, sum, 32)

	var k1, k2 [32]byte
	copy(k1[:], c)
	copy(k2[:], c2)
	expected, err := globalPedersen.Add(k1, k2)
	require.NoError(t, err)
	require.Equal(t, expected[:], sum)
}

func TestPed_PrecompileSurfacesUnresolvableCommitments(t *testing.T) {
	unknown := pedUnknown(t, 0x06)
	value, blinding := pedScalar(1), pedScalar(2)

	verifyInput := make([]byte, 96)
	copy(verifyInput[:32], unknown[:])
	copy(verifyInput[32:64], value[:])
	copy(verifyInput[64:], blinding[:])

	// It fails closed: an error, never a 1.
	out, err := PedersenVerify(verifyInput)
	require.Error(t, err)
	require.Nil(t, out)

	known, err := globalPedersen.Commit(value, blinding)
	require.NoError(t, err)
	addInput := make([]byte, 64)
	copy(addInput[:32], unknown[:])
	copy(addInput[32:], known[:])
	out, err = PedersenAdd(addInput)
	require.Error(t, err)
	require.Nil(t, out)

	copy(addInput[:32], known[:])
	copy(addInput[32:], unknown[:])
	out, err = PedersenAdd(addInput)
	require.Error(t, err)
	require.Nil(t, out)
}

func TestPed_GetPedersenStatsIsMonotonic(t *testing.T) {
	c0, v0 := GetPedersenStats()

	_, _, err := globalPedersen.CommitWithOpening(big.NewInt(31337))
	require.NoError(t, err)
	c1, v1 := GetPedersenStats()
	require.Equal(t, c0+1, c1, "an opening must be counted")
	require.Equal(t, v0, v1)

	value, blinding := pedScalar(555), pedScalar(666)
	commitment, err := globalPedersen.Commit(value, blinding)
	require.NoError(t, err)
	verifyInput := make([]byte, 96)
	copy(verifyInput[:32], commitment[:])
	copy(verifyInput[32:64], value[:])
	copy(verifyInput[64:], blinding[:])
	_, err = PedersenVerify(verifyInput)
	require.NoError(t, err)

	c2, v2 := GetPedersenStats()
	require.Equal(t, c1, c2, "Commit does not count as an opening")
	require.Equal(t, v1+1, v2, "a verification must be counted")
}
