// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helpers (all prefixed com)
// ---------------------------------------------------------------------------

// comWord renders n as a 32-byte big-endian word.
func comWord(n uint64) [32]byte {
	var b [32]byte
	new(big.Int).SetUint64(n).FillBytes(b[:])
	return b
}

// comAddr builds a distinguishable address.
func comAddr(n byte) common.Address {
	var a common.Address
	a[19] = n
	return a
}

// comNote is a reference note input every note test perturbs.
func comNote() NoteInput {
	return NoteInput{
		Amount:         big.NewInt(1_000_000),
		AssetID:        comWord(0xa55e7),
		Owner:          comAddr(7),
		BlindingFactor: comWord(0xb11d),
		SchemeType:     SchemePoseidon2,
	}
}

// comReceipt is a reference receipt every ComputeReceiptID test perturbs.
func comReceipt() ValidityReceipt {
	return ValidityReceipt{
		ReceiptID:     comWord(0xdead),
		MerkleRoot:    comWord(1),
		Nullifiers:    [][32]byte{comWord(2), comWord(3)},
		PoolID:        comWord(4),
		AssetID:       comWord(5),
		SourceChainID: 6,
		TargetChainID: 7,
		CircuitID:     comWord(8),
		Timestamp:     9,
		ProofType:     ProofTypeSTARK,
		ZKProofDigest: comWord(10),
	}
}

// comPreimage rebuilds, independently of the code under test, the byte string
// ComputeReceiptID hashes: root ‖ nullifiers ‖ pool ‖ asset ‖ src ‖ dst ‖
// circuit, zero-padded up to a 32-byte multiple. Written with
// encoding/binary so it cross-checks the hand-rolled shift loop in the source.
func comPreimage(r ValidityReceipt) []byte {
	var data []byte
	data = append(data, r.MerkleRoot[:]...)
	for _, n := range r.Nullifiers {
		data = append(data, n[:]...)
	}
	data = append(data, r.PoolID[:]...)
	data = append(data, r.AssetID[:]...)

	be := make([]byte, 8)
	binary.BigEndian.PutUint64(be, r.SourceChainID)
	data = append(data, be...)
	binary.BigEndian.PutUint64(be, r.TargetChainID)
	data = append(data, be...)

	data = append(data, r.CircuitID[:]...)

	padded := make([]byte, ((len(data)+31)/32)*32)
	copy(padded, data)
	return padded
}

// comNullifierPreimage rebuilds the 96-byte string NullifierHash builds.
func comNullifierPreimage(key, commitment [32]byte, leafIndex uint64) []byte {
	in := make([]byte, 96)
	copy(in[:32], key[:])
	copy(in[32:64], commitment[:])
	idx := new(big.Int).SetUint64(leafIndex).Bytes()
	copy(in[96-len(idx):], idx)
	return in
}

// comFieldModulus is the BN254 scalar modulus as a 32-byte word. Both schemes
// funnel their inputs through fr.Element, so this word reduces to zero.
func comFieldModulus() [32]byte {
	var b [32]byte
	fr.Modulus().FillBytes(b[:])
	return b
}

// ---------------------------------------------------------------------------
// Commit — binding and hiding
// ---------------------------------------------------------------------------

func TestCom_CommitIsDeterministicAndBinding(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fresh func() CommitmentScheme
	}{
		{"poseidon2", func() CommitmentScheme { return NewPoseidon2Scheme() }},
		{"pedersen", func() CommitmentScheme { return NewPedersenScheme() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			commit := func(value, blind [32]byte) [32]byte {
				c, err := tc.fresh().Commit(value, blind)
				require.NoError(t, err)
				return c
			}

			value, blind := comWord(42), comWord(99)
			base := commit(value, blind)
			require.NotEqual(t, [32]byte{}, base, "a commitment must not be the zero word")
			require.Equal(t, base, commit(value, blind), "committing is a pure function of its inputs")

			// Binding: distinct values must reach distinct commitments.
			seen := map[[32]byte]uint64{}
			for v := range uint64(64) {
				c := commit(comWord(v), blind)
				prev, dup := seen[c]
				require.Falsef(t, dup, "values %d and %d collide", prev, v)
				seen[c] = v
			}

			// Hiding: distinct blinding factors must move the commitment.
			blinds := map[[32]byte]uint64{}
			for b := range uint64(64) {
				c := commit(value, comWord(b))
				prev, dup := blinds[c]
				require.Falsef(t, dup, "blinding factors %d and %d collide", prev, b)
				blinds[c] = b
			}

			// A single flipped bit in either input moves the commitment.
			for i := range 32 {
				bitValue := value
				bitValue[i] ^= 1
				require.NotEqualf(t, base, commit(bitValue, blind), "value byte %d", i)

				bitBlind := blind
				bitBlind[i] ^= 1
				require.NotEqualf(t, base, commit(value, bitBlind), "blinding byte %d", i)
			}

			// Value and blinding are not interchangeable.
			require.NotEqual(t, commit(comWord(1), comWord(2)), commit(comWord(2), comWord(1)))
		})
	}
}

func TestCom_CommitSchemesDoNotAgreeWithEachOther(t *testing.T) {
	value, blind := comWord(42), comWord(99)

	pos, err := NewPoseidon2Scheme().Commit(value, blind)
	require.NoError(t, err)
	ped, err := NewPedersenScheme().Commit(value, blind)
	require.NoError(t, err)
	require.NotEqual(t, pos, ped, "the two schemes must produce distinct commitments")

	// Poseidon2Scheme.Commit pins the salt to zero, so it is exactly the
	// hasher's three-input commitment with a zero third element.
	zeroSalt, err := NewPoseidon2Hasher().Commitment(value, blind, [32]byte{})
	require.NoError(t, err)
	require.Equal(t, pos, zeroSalt)

	salted, err := NewPoseidon2Hasher().Commitment(value, blind, comWord(1))
	require.NoError(t, err)
	require.NotEqual(t, pos, salted, "a non-zero salt must not reproduce the scheme's commitment")
}

func TestCom_CommitIsOnlyBindingModuloTheScalarField(t *testing.T) {
	// Both schemes parse their 32-byte inputs as fr.Element, which reduces mod
	// the BN254 scalar modulus, and neither rejects a non-canonical word. So a
	// value equal to the modulus is indistinguishable from zero.
	modulus := comFieldModulus()
	blind := comWord(99)

	for _, tc := range []struct {
		name  string
		fresh func() CommitmentScheme
	}{
		{"poseidon2", func() CommitmentScheme { return NewPoseidon2Scheme() }},
		{"pedersen", func() CommitmentScheme { return NewPedersenScheme() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zero, err := tc.fresh().Commit([32]byte{}, blind)
			require.NoError(t, err)
			aliased, err := tc.fresh().Commit(modulus, blind)
			require.NoError(t, err)
			require.Equal(t, zero, aliased,
				"value 0 and value r collide; if this now differs the scheme grew canonical-input validation")

			// The same aliasing applies to the blinding factor.
			b0, err := tc.fresh().Commit(comWord(1), [32]byte{})
			require.NoError(t, err)
			bR, err := tc.fresh().Commit(comWord(1), modulus)
			require.NoError(t, err)
			require.Equal(t, b0, bR)
		})
	}
}

func TestCom_ReusingASchemeChangesNothing(t *testing.T) {
	// Poseidon2Scheme memoises inside its hasher. Memoisation must be
	// invisible: a reused instance must answer exactly as a cold one, and two
	// inputs that agree on their leading bytes must not be conflated. Commit
	// lays its input out as value ‖ blinding ‖ salt, so a memo that looked
	// only at the front would return the first blinding factor's commitment
	// for every later one and the scheme would stop hiding.
	scheme := NewPoseidon2Scheme()
	value := comWord(0xc0ffee)

	first, err := scheme.Commit(value, comWord(1))
	require.NoError(t, err)
	second, err := scheme.Commit(value, comWord(2))
	require.NoError(t, err)
	require.NotEqual(t, first, second, "a reused instance must still see the blinding factor")

	// Each answer matches what a cold instance computes, so history cannot
	// change the result.
	for _, tc := range []struct {
		blind [32]byte
		want  [32]byte
	}{{comWord(1), first}, {comWord(2), second}} {
		cold, err := NewPoseidon2Scheme().Commit(value, tc.blind)
		require.NoError(t, err)
		require.Equal(t, tc.want, cold)
	}

	// Replaying the first input still returns the first answer.
	replay, err := scheme.Commit(value, comWord(1))
	require.NoError(t, err)
	require.Equal(t, first, replay)
}

func TestCom_DefaultSchemeAgreesWithAColdScheme(t *testing.T) {
	// DefaultScheme is a package-level Poseidon2Scheme whose hasher lives for
	// the life of the process, so it accumulates every note the process has
	// ever committed. Notes sharing an amount must still commit differently:
	// NoteCommitment lays its input out as amount ‖ asset ‖ owner ‖ blinding,
	// and everything after the amount has to count.
	amount := big.NewInt(0x1005_2026)

	first, err := DefaultScheme.NoteCommitment(amount, comWord(1), comAddr(1), comWord(1))
	require.NoError(t, err)
	second, err := DefaultScheme.NoteCommitment(amount, comWord(2), comAddr(2), comWord(2))
	require.NoError(t, err)
	require.NotEqual(t, first, second, "two owners must not share a note commitment")

	coldA, err := NewPoseidon2Scheme().NoteCommitment(amount, comWord(1), comAddr(1), comWord(1))
	require.NoError(t, err)
	coldB, err := NewPoseidon2Scheme().NoteCommitment(amount, comWord(2), comAddr(2), comWord(2))
	require.NoError(t, err)
	require.Equal(t, coldA, first, "the shared scheme must agree with a cold one")
	require.Equal(t, coldB, second)

	// Each field after the amount moves the commitment on its own.
	for name, note := range map[string][3]any{
		"asset":    {comWord(9), comAddr(1), comWord(1)},
		"owner":    {comWord(1), comAddr(9), comWord(1)},
		"blinding": {comWord(1), comAddr(1), comWord(9)},
	} {
		got, err := DefaultScheme.NoteCommitment(amount, note[0].([32]byte), note[1].(common.Address), note[2].([32]byte))
		require.NoError(t, err)
		require.NotEqualf(t, first, got, "changing %s must move the note commitment", name)
	}
}

// ---------------------------------------------------------------------------
// scheme metadata
// ---------------------------------------------------------------------------

func TestCom_RequiredGasIsNeverFreeAndRanksTheSchemes(t *testing.T) {
	pos := NewPoseidon2Scheme()
	ped := NewPedersenScheme()

	require.Positive(t, pos.RequiredGas(), "a commitment is never free")
	require.Positive(t, ped.RequiredGas())

	// The curve scheme does two scalar multiplications and a point addition;
	// the hash scheme does neither. Pricing must reflect that ordering.
	require.Greater(t, ped.RequiredGas(), pos.RequiredGas(),
		"the pre-quantum curve scheme must not be priced below the hash scheme")

	// Pricing carries no state: same answer from every instance and call.
	require.Equal(t, pos.RequiredGas(), NewPoseidon2Scheme().RequiredGas())
	require.Equal(t, ped.RequiredGas(), NewPedersenScheme().RequiredGas())
	require.Equal(t, pos.RequiredGas(), pos.RequiredGas())

	// Gas and post-quantum safety travel together: the cheap scheme is the
	// PQ-safe one, which is why it is the default.
	require.True(t, pos.IsPQSafe())
	require.False(t, ped.IsPQSafe())
	require.True(t, DefaultScheme.IsPQSafe(), "the default must be the post-quantum-safe scheme")
	require.Equal(t, pos.RequiredGas(), DefaultScheme.RequiredGas())
}

func TestCom_GetScheme(t *testing.T) {
	for _, tc := range []struct {
		name     string
		in       SchemeType
		pqSafe   bool
		wantErr  bool
		gas      uint64
		concrete any
	}{
		{name: "poseidon2", in: SchemePoseidon2, pqSafe: true, gas: NewPoseidon2Scheme().RequiredGas(), concrete: &Poseidon2Scheme{}},
		{name: "pedersen", in: SchemePedersen, pqSafe: false, gas: NewPedersenScheme().RequiredGas(), concrete: &PedersenScheme{}},
		{name: "next unused id", in: SchemeType(2), wantErr: true},
		{name: "max id", in: SchemeType(255), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GetScheme(tc.in)
			if tc.wantErr {
				require.ErrorContains(t, err, "unknown commitment scheme")
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			require.IsType(t, tc.concrete, got)
			require.Equal(t, tc.pqSafe, got.IsPQSafe())
			require.Equal(t, tc.gas, got.RequiredGas())
		})
	}

	// Every call hands back a fresh scheme, so callers cannot poison each
	// other through a shared instance.
	a, err := GetScheme(SchemePoseidon2)
	require.NoError(t, err)
	b, err := GetScheme(SchemePoseidon2)
	require.NoError(t, err)
	require.NotSame(t, a, b)

	// Zero is the post-quantum-safe identifier, so a zero-valued NoteInput
	// resolves to the safe scheme rather than failing.
	require.Equal(t, SchemePoseidon2, SchemeType(0))
	zeroValued, err := GetScheme(NoteInput{}.SchemeType)
	require.NoError(t, err)
	require.True(t, zeroValued.IsPQSafe())
}

// ---------------------------------------------------------------------------
// CreateNote
// ---------------------------------------------------------------------------

func TestCom_CreateNoteCarriesItsInputsAndCommits(t *testing.T) {
	for _, scheme := range []SchemeType{SchemePoseidon2, SchemePedersen} {
		in := comNote()
		in.SchemeType = scheme

		note, err := CreateNote(in)
		require.NoError(t, err)
		require.NotNil(t, note)

		require.Equal(t, in.Amount, note.Amount)
		require.Equal(t, in.AssetID, note.AssetID)
		require.Equal(t, in.Owner, note.Owner)
		require.Equal(t, in.BlindingFactor, note.BlindingFactor)
		require.Equal(t, in.SchemeType, note.SchemeType)
		require.Zero(t, note.LeafIndex, "leaf index is assigned on tree insertion, not at creation")
		require.NotEqual(t, [32]byte{}, note.Commitment)

		// The commitment is the chosen scheme's own note commitment.
		s, err := GetScheme(scheme)
		require.NoError(t, err)
		want, err := s.NoteCommitment(in.Amount, in.AssetID, in.Owner, in.BlindingFactor)
		require.NoError(t, err)
		require.Equal(t, want, note.Commitment)
	}

	// The two schemes commit to the same note differently.
	pos, err := CreateNote(comNote())
	require.NoError(t, err)
	pedIn := comNote()
	pedIn.SchemeType = SchemePedersen
	ped, err := CreateNote(pedIn)
	require.NoError(t, err)
	require.NotEqual(t, pos.Commitment, ped.Commitment)
}

func TestCom_CreateNoteRejectsAnUnknownScheme(t *testing.T) {
	for _, bad := range []SchemeType{2, 3, 128, 255} {
		in := comNote()
		in.SchemeType = bad
		note, err := CreateNote(in)
		require.ErrorContains(t, err, "unknown commitment scheme")
		require.Nil(t, note, "a failed creation must not hand back a half-built note")
	}
}

func TestCom_CreateNoteBindsEveryField(t *testing.T) {
	base, err := CreateNote(comNote())
	require.NoError(t, err)

	for name, mutate := range map[string]func(*NoteInput){
		"amount":   func(n *NoteInput) { n.Amount = big.NewInt(1_000_001) },
		"asset":    func(n *NoteInput) { n.AssetID = comWord(0xa55e8) },
		"owner":    func(n *NoteInput) { n.Owner = comAddr(8) },
		"blinding": func(n *NoteInput) { n.BlindingFactor = comWord(0xb11e) },
		"scheme":   func(n *NoteInput) { n.SchemeType = SchemePedersen },
	} {
		t.Run(name, func(t *testing.T) {
			in := comNote()
			mutate(&in)
			note, err := CreateNote(in)
			require.NoError(t, err)
			require.NotEqual(t, base.Commitment, note.Commitment,
				"changing %s must move the commitment", name)
		})
	}

	// Zero is a legal amount and still commits to something distinct.
	in := comNote()
	in.Amount = big.NewInt(0)
	zero, err := CreateNote(in)
	require.NoError(t, err)
	require.NotEqual(t, base.Commitment, zero.Commitment)

	// CreateNote takes a fresh scheme per call, so it does not inherit the
	// shared-instance cache collapse that DefaultScheme suffers.
	sameAmount := comNote()
	sameAmount.Owner = comAddr(9)
	other, err := CreateNote(sameAmount)
	require.NoError(t, err)
	require.NotEqual(t, base.Commitment, other.Commitment)
}

func TestCom_CreateNotePanicsOnAnUnvalidatedAmount(t *testing.T) {
	// Amount is copied into a fixed 32-byte window with no width check, so a
	// wider value slices out of range, and a nil Amount is dereferenced. Both
	// are reachable straight from a caller-supplied NoteInput.
	for _, scheme := range []SchemeType{SchemePoseidon2, SchemePedersen} {
		wide := comNote()
		wide.SchemeType = scheme
		wide.Amount = new(big.Int).Lsh(big.NewInt(1), 256) // 33 bytes
		require.Panics(t, func() { _, _ = CreateNote(wide) })

		missing := comNote()
		missing.SchemeType = scheme
		missing.Amount = nil
		require.Panics(t, func() { _, _ = CreateNote(missing) })
	}

	// One bit below the window is accepted, which locates the boundary.
	edge := comNote()
	edge.Amount = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	_, err := CreateNote(edge)
	require.NoError(t, err)

	// A negative amount takes the absolute value's bytes: -1 commits exactly
	// as 1 does, so sign is not carried into the commitment.
	neg := comNote()
	neg.Amount = big.NewInt(-1)
	negNote, err := CreateNote(neg)
	require.NoError(t, err)
	pos := comNote()
	pos.Amount = big.NewInt(1)
	posNote, err := CreateNote(pos)
	require.NoError(t, err)
	require.Equal(t, posNote.Commitment, negNote.Commitment,
		"big.Int.Bytes drops the sign; if this now differs the amount grew a sign check")
}

// ---------------------------------------------------------------------------
// Nullifier
// ---------------------------------------------------------------------------

func TestCom_NullifierRoutesThroughTheGlobalHasher(t *testing.T) {
	// Every branch of Nullifier hashes exactly (key, commitment, leafIndex).
	//
	// The expected value is taken from a PRIVATE hasher: the global one keys
	// its memo on the leading 32 bytes plus the length, which for a nullifier
	// is the key alone, so an oracle read back through the global hasher would
	// answer from the memo and agree with any arguments at all. Each scheme
	// gets its own nullifier key so the global's first call is a genuine
	// computation rather than a memo hit.
	note, err := CreateNote(comNote())
	require.NoError(t, err)
	note.LeafIndex = 17

	for i, scheme := range []SchemeType{SchemePoseidon2, SchemePedersen, SchemeType(200)} {
		key := comWord(0x40de_0000 + uint64(i)) // used nowhere else in the package
		n := *note
		n.SchemeType = scheme

		want, err := NewPoseidon2Hasher().NullifierHash(key, n.Commitment, n.LeafIndex)
		require.NoError(t, err)

		got, err := n.Nullifier(key)
		require.NoError(t, err)
		require.Equalf(t, want, got, "scheme %d must not change the nullifier derivation", scheme)
	}

	// The leaf index is part of the derivation, not decoration: a note at a
	// different position in the tree hashes different data.
	moved := *note
	moved.LeafIndex = 18
	shifted, err := NewPoseidon2Hasher().NullifierHash(comWord(0x40de_0000), moved.Commitment, moved.LeafIndex)
	require.NoError(t, err)
	original, err := NewPoseidon2Hasher().NullifierHash(comWord(0x40de_0000), note.Commitment, note.LeafIndex)
	require.NoError(t, err)
	require.NotEqual(t, original, shifted)
}

func TestCom_NullifierIsDeterministicAndBindsItsKey(t *testing.T) {
	note, err := CreateNote(comNote())
	require.NoError(t, err)
	key := comWord(0x4e17)

	base, err := note.Nullifier(key)
	require.NoError(t, err)
	require.NotEqual(t, [32]byte{}, base)

	for range 8 {
		again, err := note.Nullifier(key)
		require.NoError(t, err)
		require.Equal(t, base, again, "the nullifier is a pure function of key, commitment and leaf index")
	}

	// Each of the three inputs binds on its own.
	t.Run("key", func(t *testing.T) {
		seen := map[[32]byte]uint64{}
		for k := range uint64(64) {
			n, err := note.Nullifier(comWord(k))
			require.NoError(t, err)
			prev, dup := seen[n]
			require.Falsef(t, dup, "nullifier keys %d and %d collide", prev, k)
			seen[n] = k
		}
	})

	t.Run("leaf index", func(t *testing.T) {
		seen := map[[32]byte]uint64{}
		for i := range uint64(64) {
			moved := *note
			moved.LeafIndex = i
			n, err := moved.Nullifier(key)
			require.NoError(t, err)
			prev, dup := seen[n]
			require.Falsef(t, dup, "leaf indices %d and %d collide", prev, i)
			seen[n] = i
		}
	})

	t.Run("commitment", func(t *testing.T) {
		for i := range 32 {
			other := *note
			other.Commitment[i] ^= 1
			n, err := other.Nullifier(key)
			require.NoError(t, err)
			require.NotEqualf(t, base, n, "commitment byte %d", i)
		}
	})
}

func TestCom_NullifierIgnoresTheSchemeType(t *testing.T) {
	// Both branches hash with Poseidon2 by design: a nullifier is a hash, not
	// a commitment, so it stays post-quantum safe even for Pedersen notes. The
	// scheme tag is therefore not domain-separated into the nullifier, and a
	// note relabelled after creation nullifies identically.
	key := comWord(0x4e17)
	note, err := CreateNote(comNote())
	require.NoError(t, err)

	viaPoseidon, err := note.Nullifier(key)
	require.NoError(t, err)

	relabelled := *note
	relabelled.SchemeType = SchemePedersen
	viaPedersen, err := relabelled.Nullifier(key)
	require.NoError(t, err)
	require.Equal(t, viaPoseidon, viaPedersen)

	// Including a tag GetScheme would refuse: Nullifier never consults it.
	unknown := *note
	unknown.SchemeType = SchemeType(200)
	viaUnknown, err := unknown.Nullifier(key)
	require.NoError(t, err)
	require.Equal(t, viaPoseidon, viaUnknown)

	// A genuine Pedersen note commits differently, so it nullifies
	// differently: the scheme reaches the nullifier only through the
	// commitment, never as a tag of its own.
	in := comNote()
	in.SchemeType = SchemePedersen
	pedNote, err := CreateNote(in)
	require.NoError(t, err)
	require.NotEqual(t, note.Commitment, pedNote.Commitment)

	pedNullifier, err := pedNote.Nullifier(key)
	require.NoError(t, err)
	require.NotEqual(t, viaPoseidon, pedNullifier)
}

func TestCom_TwoNotesUnderOneKeyNullifyDifferently(t *testing.T) {
	// Nullifier hashes key ‖ commitment ‖ leafIndex through a process-wide
	// hasher. Two different notes spent under the same nullifier key must not
	// collapse onto one nullifier, or spending one would mark the other spent.
	key := comWord(0x4e17)

	a := *comMustNote(t, comNote())
	a.Commitment = comWord(0xaaaa)
	b := a
	b.Commitment = comWord(0xbbbb)
	b.LeafIndex = 1

	require.NotEqual(t, comNullifierPreimage(key, a.Commitment, a.LeafIndex),
		comNullifierPreimage(key, b.Commitment, b.LeafIndex),
		"the two notes really do hash different data")

	na, err := a.Nullifier(key)
	require.NoError(t, err)
	nb, err := b.Nullifier(key)
	require.NoError(t, err)
	require.NotEqual(t, na, nb, "one key must not nullify two notes at once")

	// Each answer is what a cold hasher computes, so a long-lived process
	// cannot drift from a fresh one.
	coldA, err := NewPoseidon2Hasher().NullifierHash(key, a.Commitment, a.LeafIndex)
	require.NoError(t, err)
	coldB, err := NewPoseidon2Hasher().NullifierHash(key, b.Commitment, b.LeafIndex)
	require.NoError(t, err)
	require.Equal(t, coldA, na)
	require.Equal(t, coldB, nb)
}

// comMustNote builds a note or fails the test.
func comMustNote(t *testing.T, in NoteInput) *Note {
	t.Helper()
	n, err := CreateNote(in)
	require.NoError(t, err)
	return n
}

// ---------------------------------------------------------------------------
// ComputeReceiptID
// ---------------------------------------------------------------------------

func TestCom_ReceiptIDHashesTheDeclaredPreimage(t *testing.T) {
	// Pin the exact encoding: field order, big-endian chain ids, and the
	// zero-padding up to a 32-byte multiple.
	//
	// The expected digest is taken from a PRIVATE hasher, and the receipt uses
	// a merkle root that appears nowhere else, so the global hasher's memo —
	// keyed on the root and the length — cannot answer either side from cache
	// and hide a disagreement in the bytes between them.
	r := comReceipt()
	r.MerkleRoot = comWord(0x5eed_1234)
	preimage := comPreimage(r)
	// 144 bytes of fixed fields plus 32 per nullifier is always 16 short of a
	// 32-byte multiple, so every receipt is padded by exactly 16 zero bytes.
	require.Len(t, preimage, 224, "2 nullifiers: 208 bytes of data padded to 224")
	require.Zero(t, len(preimage)%32)
	require.Equal(t, make([]byte, 16), preimage[208:], "the tail is zero padding")

	want, err := NewPoseidon2Hasher().Hash(preimage)
	require.NoError(t, err)
	got, err := r.ComputeReceiptID()
	require.NoError(t, err)
	require.Equal(t, want, got)

	// The 16 trailing bytes of a no-nullifier receipt are pad, not data.
	empty := comReceipt()
	empty.MerkleRoot = comWord(0x5eed_5678)
	empty.Nullifiers = nil
	pre := comPreimage(empty)
	require.Len(t, pre, 160)
	require.Equal(t, make([]byte, 16), pre[144:], "the tail is zero padding")

	wantEmpty, err := NewPoseidon2Hasher().Hash(pre)
	require.NoError(t, err)
	gotEmpty, err := empty.ComputeReceiptID()
	require.NoError(t, err)
	require.Equal(t, wantEmpty, gotEmpty)

	// The two chain ids sit at fixed offsets in big-endian order, ahead of the
	// circuit id. Reading them back out of the preimage pins the layout
	// independently of the digest.
	off := 32 + 32*len(r.Nullifiers) + 64
	require.EqualValues(t, r.SourceChainID, binary.BigEndian.Uint64(preimage[off:off+8]))
	require.EqualValues(t, r.TargetChainID, binary.BigEndian.Uint64(preimage[off+8:off+16]))
	require.Equal(t, r.CircuitID[:], preimage[off+16:off+48])
}

func TestCom_ReceiptIDIsDeterministic(t *testing.T) {
	r := comReceipt()
	first, err := r.ComputeReceiptID()
	require.NoError(t, err)
	require.NotEqual(t, [32]byte{}, first)

	for range 8 {
		again, err := r.ComputeReceiptID()
		require.NoError(t, err)
		require.Equal(t, first, again)
	}

	// A separately built but identical receipt agrees.
	other := comReceipt()
	sameAgain, err := other.ComputeReceiptID()
	require.NoError(t, err)
	require.Equal(t, first, sameAgain)
}

func TestCom_ReceiptPreimageBindsSevenFields(t *testing.T) {
	// What the digest covers, checked on the preimage so the result does not
	// depend on the hasher's memoisation.
	base := comPreimage(comReceipt())

	seen := map[string]string{string(base): "base"}
	for name, mutate := range map[string]func(*ValidityReceipt){
		"merkle root":            func(r *ValidityReceipt) { r.MerkleRoot = comWord(0x1111) },
		"nullifier value":        func(r *ValidityReceipt) { r.Nullifiers[0] = comWord(0x2222) },
		"nullifier order":        func(r *ValidityReceipt) { r.Nullifiers[0], r.Nullifiers[1] = r.Nullifiers[1], r.Nullifiers[0] },
		"nullifier added":        func(r *ValidityReceipt) { r.Nullifiers = append(r.Nullifiers, comWord(0x3333)) },
		"nullifier removed":      func(r *ValidityReceipt) { r.Nullifiers = r.Nullifiers[:1] },
		"all nullifiers removed": func(r *ValidityReceipt) { r.Nullifiers = nil },
		"pool id":                func(r *ValidityReceipt) { r.PoolID = comWord(0x4444) },
		"asset id":               func(r *ValidityReceipt) { r.AssetID = comWord(0x5555) },
		"source chain":           func(r *ValidityReceipt) { r.SourceChainID = 0x6666 },
		"target chain":           func(r *ValidityReceipt) { r.TargetChainID = 0x7777 },
		"chains swapped":         func(r *ValidityReceipt) { r.SourceChainID, r.TargetChainID = r.TargetChainID, r.SourceChainID },
		"circuit id":             func(r *ValidityReceipt) { r.CircuitID = comWord(0x8888) },
		"high chain byte":        func(r *ValidityReceipt) { r.SourceChainID |= 1 << 56 },
	} {
		r := comReceipt()
		mutate(&r)
		got := string(comPreimage(r))
		if prev, dup := seen[got]; dup {
			t.Fatalf("changing %q leaves the same preimage as %q", name, prev)
		}
		seen[got] = name
	}
}

func TestCom_ReceiptIDExcludesFourFields(t *testing.T) {
	// The digest covers root, nullifiers, pool, asset, both chain ids and the
	// circuit id. Timestamp, ProofType, ZKProofDigest and the previous
	// ReceiptID are outside it, so receipts differing only in those share an
	// identifier. Most consequentially, a STARK receipt and a Groth16 receipt
	// over the same batch are the same receipt.
	base := comReceipt()
	baseID, err := base.ComputeReceiptID()
	require.NoError(t, err)
	basePre := comPreimage(base)

	for name, mutate := range map[string]func(*ValidityReceipt){
		"timestamp":     func(r *ValidityReceipt) { r.Timestamp = 0xffff },
		"proof type":    func(r *ValidityReceipt) { r.ProofType = ProofTypeGroth16 },
		"proof digest":  func(r *ValidityReceipt) { r.ZKProofDigest = comWord(0xbeef) },
		"prior receipt": func(r *ValidityReceipt) { r.ReceiptID = comWord(0xfeed) },
	} {
		t.Run(name, func(t *testing.T) {
			r := comReceipt()
			mutate(&r)
			require.Equal(t, basePre, comPreimage(r), "%s never reaches the preimage", name)

			id, err := r.ComputeReceiptID()
			require.NoError(t, err)
			require.Equal(t, baseID, id,
				"%s is outside the digest; if this now differs the preimage grew and this test should assert inequality", name)
		})
	}
	require.NotEqual(t, ProofTypeSTARK, ProofTypeGroth16, "two distinct proof types that hash the same")
}

func TestCom_ReceiptIDBindsEveryHashedField(t *testing.T) {
	// The preimage test above proves the encoding covers seven fields. This
	// carries that through the digest: every one of them must move the
	// identifier a chain will key its bridge state on.
	base := comReceipt()
	baseID, err := base.ComputeReceiptID()
	require.NoError(t, err)

	seen := map[[32]byte]string{baseID: "base"}
	for name, mutate := range map[string]func(*ValidityReceipt){
		"merkle root":            func(r *ValidityReceipt) { r.MerkleRoot = comWord(0x1111) },
		"nullifier value":        func(r *ValidityReceipt) { r.Nullifiers[0] = comWord(0x2222) },
		"nullifier order":        func(r *ValidityReceipt) { r.Nullifiers[0], r.Nullifiers[1] = r.Nullifiers[1], r.Nullifiers[0] },
		"nullifier added":        func(r *ValidityReceipt) { r.Nullifiers = append(r.Nullifiers, comWord(0x3333)) },
		"nullifier removed":      func(r *ValidityReceipt) { r.Nullifiers = r.Nullifiers[:1] },
		"all nullifiers removed": func(r *ValidityReceipt) { r.Nullifiers = nil },
		"pool id":                func(r *ValidityReceipt) { r.PoolID = comWord(0x4444) },
		"asset id":               func(r *ValidityReceipt) { r.AssetID = comWord(0x5555) },
		"source chain":           func(r *ValidityReceipt) { r.SourceChainID = 0x6666 },
		"target chain":           func(r *ValidityReceipt) { r.TargetChainID = 0x7777 },
		"chains swapped":         func(r *ValidityReceipt) { r.SourceChainID, r.TargetChainID = r.TargetChainID, r.SourceChainID },
		"circuit id":             func(r *ValidityReceipt) { r.CircuitID = comWord(0x8888) },
		"high chain byte":        func(r *ValidityReceipt) { r.SourceChainID |= 1 << 56 },
	} {
		r := comReceipt()
		mutate(&r)
		id, err := r.ComputeReceiptID()
		require.NoError(t, err)
		if prev, dup := seen[id]; dup {
			t.Fatalf("changing %q gives the same receipt id as %q", name, prev)
		}
		seen[id] = name
	}

	// Two receipts differing everywhere at once are also distinct, and each
	// agrees with a cold hasher, so a long-lived process cannot drift.
	other := comReceipt()
	other.PoolID, other.AssetID, other.CircuitID = comWord(0x4444), comWord(0x5555), comWord(0x8888)
	other.SourceChainID = 0x6666
	otherID, err := other.ComputeReceiptID()
	require.NoError(t, err)
	require.NotEqual(t, baseID, otherID)

	cold, err := NewPoseidon2Hasher().Hash(comPreimage(other))
	require.NoError(t, err)
	require.Equal(t, cold, otherID)
}

func TestCom_ReceiptIDRunsOutOfRoomAtTwelveNullifiers(t *testing.T) {
	// The preimage is 144 bytes plus 32 per nullifier, padded up to a 32-byte
	// multiple, and Poseidon2 takes at most 16 field elements. That caps a
	// receipt at 11 nullifiers; the twelfth is refused rather than truncated.
	for k := range 12 {
		r := comReceipt()
		r.Nullifiers = make([][32]byte, k)
		for i := range r.Nullifiers {
			r.Nullifiers[i] = comWord(uint64(i) + 100)
		}
		require.LessOrEqual(t, len(comPreimage(r))/32, 16)

		id, err := r.ComputeReceiptID()
		require.NoErrorf(t, err, "%d nullifiers must fit", k)
		require.NotEqual(t, [32]byte{}, id)
	}

	for _, k := range []int{12, 13, 40} {
		r := comReceipt()
		r.Nullifiers = make([][32]byte, k)
		require.Greater(t, len(comPreimage(r))/32, 16)

		id, err := r.ComputeReceiptID()
		require.ErrorIsf(t, err, ErrTooManyInputs, "%d nullifiers must be refused", k)
		require.Equal(t, [32]byte{}, id, "a refused receipt must not hand back a usable id")
	}
}

func TestCom_ReceiptIDDoesNotMutateTheReceipt(t *testing.T) {
	r := comReceipt()
	before := comReceipt()

	_, err := r.ComputeReceiptID()
	require.NoError(t, err)
	require.Equal(t, before, r, "computing the id must not write back into the receipt")

	// In particular it does not populate ReceiptID itself; that is the
	// caller's job.
	require.Equal(t, comWord(0xdead), r.ReceiptID)
}
