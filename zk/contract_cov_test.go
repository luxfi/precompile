// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/luxfi/crypto/kzg4844"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/modules"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------
// dispatch
// ---------------------------------------------------------------------

// TestCtr_AddressMatchesRegistration: the address the precompile reports
// must be the one the module registry serves it at, or calls land nowhere.
func TestCtr_AddressMatchesRegistration(t *testing.T) {
	p := &zkVerifyPrecompile{}
	require.Equal(t, ZKVerifyContractAddress, p.Address())

	m, ok := modules.GetPrecompileModuleByAddress(ZKVerifyContractAddress)
	require.True(t, ok, "no module registered at the reported address")
	require.Equal(t, ConfigKey, m.ConfigKey)
}

// TestCtr_EncodeBool pins the ABI word: solidity reads a bool as a
// 32-byte big-endian word, so the flag belongs in the LAST byte. Putting
// it anywhere else makes every caller read false.
func TestCtr_EncodeBool(t *testing.T) {
	f := encodeBool(false)
	require.Len(t, f, 32)
	require.Equal(t, make([]byte, 32), f)

	tr := encodeBool(true)
	require.Len(t, tr, 32)
	require.Equal(t, byte(1), tr[31], "the flag must be the low-order byte")
	require.Equal(t, make([]byte, 31), tr[:31], "the high bytes must be clear")

	// Each call must return a fresh buffer; a shared one would let a
	// caller mutate the next result.
	a, b := encodeBool(true), encodeBool(true)
	a[0] = 0xff
	require.Equal(t, byte(0), b[0])
}

// TestCtr_UnknownOpsRejected: only the declared selectors dispatch.
func TestCtr_UnknownOpsRejected(t *testing.T) {
	known := map[byte]bool{
		OpVerifyGroth16: true, OpVerifyPLONK: true, OpVerifyFflonk: true,
		OpVerifyHalo2: true, OpVerifyKZG: true, OpVerifyIPA: true,
		OpVerifyRangeProof: true, OpVerifyNullifier: true,
		OpVerifyCommitment: true, OpVerifyBatch: true,
	}
	for op := 0; op <= 0xff; op++ {
		if known[byte(op)] {
			continue
		}
		in := make([]byte, 256)
		in[0] = byte(op)
		_, _, err := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress,
			in, 10_000_000, true)
		require.ErrorIsf(t, err, ErrInvalidOperation, "op 0x%02x dispatched", op)
	}

	// An empty input names no op at all.
	_, _, err := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress, nil, 10_000_000, true)
	require.ErrorIs(t, err, ErrInvalidInput)
}

// ---------------------------------------------------------------------
// KZG (op 0x10) — real EIP-4844 proofs against the production setup
// ---------------------------------------------------------------------

// ctrKZG builds a genuine commitment/point/claim/proof quadruple.
func ctrKZG(t *testing.T, vals ...uint64) (kzg4844.Commitment, kzg4844.Point, kzg4844.Claim, kzg4844.Proof) {
	t.Helper()
	var blob kzg4844.Blob
	for i, v := range vals {
		binary.BigEndian.PutUint64(blob[i*32+24:i*32+32], v)
	}
	c, err := kzg4844.BlobToCommitment(&blob)
	require.NoError(t, err)

	var pt kzg4844.Point
	pt[31] = 0x11
	pr, claim, err := kzg4844.ComputeProof(&blob, pt)
	require.NoError(t, err)
	return c, pt, claim, pr
}

func ctrKZGInput(c kzg4844.Commitment, pt kzg4844.Point, cl kzg4844.Claim, pr kzg4844.Proof) []byte {
	out := make([]byte, 0, 160)
	out = append(out, c[:]...)
	out = append(out, pt[:]...)
	out = append(out, cl[:]...)
	return append(out, pr[:]...)
}

// TestCtr_KZGAcceptsRealProof is the control for the negatives below: a
// genuine opening from the EIP-4844 trusted setup must verify through the
// precompile, and report the ABI true word.
func TestCtr_KZGAcceptsRealProof(t *testing.T) {
	c, pt, cl, pr := ctrKZG(t, 3, 5, 7)
	in := append([]byte{OpVerifyKZG}, ctrKZGInput(c, pt, cl, pr)...)

	ret, _, err := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress,
		in, 10_000_000, true)
	require.NoError(t, err)
	require.Equal(t, encodeBool(true), ret, "a genuine KZG opening must verify")
}

// TestCtr_KZGRejectsEveryTamper is the soundness test: each element of a
// valid opening is corrupted in turn, and none may still verify.
func TestCtr_KZGRejectsEveryTamper(t *testing.T) {
	p := &zkVerifyPrecompile{}
	c, pt, cl, pr := ctrKZG(t, 3, 5, 7)
	good := ctrKZGInput(c, pt, cl, pr)

	ok, err := p.verifyKZG(good)
	require.NoError(t, err)
	require.True(t, ok, "control: the untampered opening must verify")

	regions := []struct {
		name        string
		start, size int
	}{
		{"commitment", 0, 48},
		{"point", 48, 32},
		{"claim", 80, 32},
		{"proof", 112, 48},
	}
	for _, r := range regions {
		for _, off := range []int{0, r.size / 2, r.size - 1} {
			bad := bytes.Clone(good)
			bad[r.start+off] ^= 0x01
			ok, err := p.verifyKZG(bad)
			require.Falsef(t, ok, "a bit flip in %s at %d still verified", r.name, off)
			require.NoErrorf(t, err, "an invalid proof is a false verdict, not an error")
		}
	}

	// A claim from a DIFFERENT polynomial must not open this commitment —
	// the statement is bound, not just the bytes.
	_, _, otherClaim, _ := ctrKZG(t, 11, 13, 17)
	swapped := bytes.Clone(good)
	copy(swapped[80:112], otherClaim[:])
	ok, _ = p.verifyKZG(swapped)
	require.False(t, ok, "a claim from another polynomial verified")

	// All-zero input must not verify.
	ok, _ = p.verifyKZG(make([]byte, 160))
	require.False(t, ok)
}

// TestCtr_KZGLengthGuard: anything shorter than the fixed 160-byte layout
// is refused before parsing, and one byte long is still accepted (trailing
// bytes are ignored by the fixed layout).
func TestCtr_KZGLengthGuard(t *testing.T) {
	p := &zkVerifyPrecompile{}
	for n := range 160 {
		_, err := p.verifyKZG(make([]byte, n))
		require.ErrorIsf(t, err, ErrInvalidInput, "%d bytes was not refused", n)
	}

	c, pt, cl, pr := ctrKZG(t, 1, 2)
	long := append(ctrKZGInput(c, pt, cl, pr), bytes.Repeat([]byte{0xff}, 64)...)
	ok, err := p.verifyKZG(long)
	require.NoError(t, err)
	require.True(t, ok, "trailing bytes must not change the verdict")
}

// ---------------------------------------------------------------------
// IPA (op 0x12)
// ---------------------------------------------------------------------

// TestCtr_IPAGuards walks the structural checks. The op has no verifier,
// so the only correct outcome is a refusal — but it must refuse for the
// RIGHT reason, or the guards are not doing their job.
func TestCtr_IPAGuards(t *testing.T) {
	p := &zkVerifyPrecompile{}

	for n := range 100 {
		_, err := p.verifyIPA(make([]byte, n))
		require.ErrorIsf(t, err, ErrInvalidInput, "%d bytes must be refused as short", n)
	}

	mk := func(rounds uint32, total int) []byte {
		d := make([]byte, total)
		binary.BigEndian.PutUint32(d[96:100], rounds)
		return d
	}

	// Round count must be in 1..32.
	for _, r := range []uint32{0, 33, 1 << 20, ^uint32(0)} {
		ok, err := p.verifyIPA(mk(r, 100_000))
		require.False(t, ok)
		require.Errorf(t, err, "round count %d was accepted", r)
		require.NotErrorIs(t, err, ErrInvalidProofLength)
	}

	// In-range rounds, but the body cannot hold the L/R points.
	for _, r := range []uint32{1, 8, 32} {
		need := 100 + int(r)*128 + 32
		_, err := p.verifyIPA(mk(r, need-1))
		require.ErrorIsf(t, err, ErrInvalidProofLength, "rounds=%d short body accepted", r)

		// Exactly enough clears the structural guards and reaches the
		// (unimplemented) verification, which refuses without claiming a
		// verdict.
		ok, err := p.verifyIPA(mk(r, need))
		require.False(t, ok)
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrInvalidProofLength)
		require.NotErrorIs(t, err, ErrInvalidInput)
	}
}

// ---------------------------------------------------------------------
// nullifier (op 0x21)
// ---------------------------------------------------------------------

// TestCtr_Nullifier pins the double-spend semantics: the op answers
// "unspent" (true) only for a nullifier the verifier has not recorded, and
// flips to false once spent. Getting this backwards permits double spends.
func TestCtr_Nullifier(t *testing.T) {
	zv := NewZKVerifier()
	p := &zkVerifyPrecompile{verifier: zv}

	var n [32]byte
	copy(n[:], "a-nullifier-that-is-not-yet-spent")

	ok, err := p.verifyNullifier(n[:])
	require.NoError(t, err)
	require.True(t, ok, "an unspent nullifier must be usable")

	require.NoError(t, zv.SpendNullifier(n, common.Hash{0x01}, 7))

	ok, err = p.verifyNullifier(n[:])
	require.NoError(t, err)
	require.False(t, ok, "a spent nullifier must be refused — this is the double-spend check")

	// Spending twice is refused at the verifier.
	require.ErrorIs(t, zv.SpendNullifier(n, common.Hash{0x02}, 8), ErrNullifierSpent)

	// A different nullifier is unaffected.
	var other [32]byte
	copy(other[:], "a-different-nullifier")
	ok, _ = p.verifyNullifier(other[:])
	require.True(t, ok)

	// Only the first 32 bytes matter, and fewer is refused.
	for i := range 32 {
		_, err := p.verifyNullifier(make([]byte, i))
		require.ErrorIs(t, err, ErrInvalidInput)
	}
	ok, err = p.verifyNullifier(append(other[:], 0xff, 0xff))
	require.NoError(t, err)
	require.True(t, ok)

	// Without a verifier there is no state to consult, so it must refuse
	// rather than answer "unspent".
	bare := &zkVerifyPrecompile{}
	ok, err = bare.verifyNullifier(n[:])
	require.False(t, ok)
	require.Error(t, err)
}

// ---------------------------------------------------------------------
// commitment (op 0x22)
// ---------------------------------------------------------------------

// TestCtr_CommitmentPedersen exercises the Pedersen opening sub-mode.
func TestCtr_CommitmentPedersen(t *testing.T) {
	p := &zkVerifyPrecompile{}

	var value, blinding [32]byte
	value[31] = 42
	blinding[31] = 99
	commitment, err := globalPedersen.Commit(value, blinding)
	require.NoError(t, err)

	build := func(c, v, b [32]byte) []byte {
		out := make([]byte, 0, 96)
		out = append(out, c[:]...)
		out = append(out, v[:]...)
		return append(out, b[:]...)
	}

	// Route only if the discriminator does not claim it (see
	// TestCtr_CommitmentSubmodeIsAmbiguous).
	if commitment[0] != 0x01 {
		ok, err := p.verifyCommitment(build(commitment, value, blinding))
		require.NoError(t, err)
		require.True(t, ok, "a correct opening must verify")
	}

	// Wrong value, wrong blinding, wrong commitment: all refused. This is
	// the binding property — one commitment, one opening.
	var otherValue, otherBlinding [32]byte
	otherValue[31] = 43
	otherBlinding[31] = 100

	for _, bad := range [][]byte{
		build(commitment, otherValue, blinding),
		build(commitment, value, otherBlinding),
		build(commitment, otherValue, otherBlinding),
		build([32]byte{0xAB}, value, blinding),
	} {
		if bad[0] == 0x01 {
			continue
		}
		ok, _ := p.verifyCommitment(bad)
		require.False(t, ok, "an incorrect opening verified")
	}

	// Length guard.
	for n := range 96 {
		_, err := p.verifyCommitment(make([]byte, n))
		require.ErrorIs(t, err, ErrInvalidInput)
	}
}

// TestCtr_CommitmentSubmodeIsAmbiguous documents a real collision: the
// 0x22 sub-mode is selected by the FIRST BYTE of the payload, but in
// Pedersen mode that byte is the first byte of the commitment — which is a
// SHA-256 output and therefore 0x01 about one time in 256. Such a
// commitment is silently routed to the Merkle branch and misjudged.
func TestCtr_CommitmentSubmodeIsAmbiguous(t *testing.T) {
	// The discriminator consults only length and the first byte.
	ped := make([]byte, 96)
	ped[0] = 0x02
	require.False(t, isMerkleCommitment(ped))

	// A Pedersen payload whose commitment happens to begin 0x01 is claimed
	// by the Merkle branch, even though the remaining bytes are a
	// value/blinding pair.
	collide := make([]byte, 96)
	collide[0] = 0x01
	require.True(t, isMerkleCommitment(collide),
		"a Pedersen commitment starting 0x01 is misrouted to the Merkle branch")

	// Short payloads starting 0x01 fall back to Pedersen — so the routing
	// of identical leading bytes depends on length as well.
	short := make([]byte, 76)
	short[0] = 0x01
	require.False(t, isMerkleCommitment(short))

	// Demonstrate the misjudgement end to end: the same 96 bytes are read
	// as two different requests, differing only in that leading byte. The
	// Merkle branch reports a missing pool; the Pedersen branch reports
	// that it cannot open the commitment. Same payload, different question.
	p := &zkVerifyPrecompile{}
	merkleRouted := make([]byte, 96)
	merkleRouted[0] = 0x01
	_, errMerkle := p.verifyCommitment(merkleRouted)
	require.Error(t, errMerkle)

	pedRouted := bytes.Clone(merkleRouted)
	pedRouted[0] = 0x02
	_, errPed := p.verifyCommitment(pedRouted)
	require.Error(t, errPed)

	require.NotEqual(t, errMerkle.Error(), errPed.Error(),
		"the leading byte silently selects a different verification; if this "+
			"no longer holds, the ambiguity was resolved and this test should "+
			"be re-derived rather than deleted")
}

// TestCtr_CommitmentMerkle exercises the Merkle-inclusion sub-mode against
// a real tree, including the negatives that matter: wrong index, wrong
// root, tampered sibling.
func TestCtr_CommitmentMerkle(t *testing.T) {
	zv := NewZKVerifier()
	p := &zkVerifyPrecompile{verifier: zv}

	var poolID, commitID [32]byte
	copy(poolID[:], "pool")
	copy(commitID[:], "commitment-leaf")

	// Build a 2-level proof the verifier's own hashing agrees with:
	// leaf -> sha256(leaf); then fold with each sibling by index bit.
	sib0 := bytes.Repeat([]byte{0xA1}, 32)
	sib1 := bytes.Repeat([]byte{0xB2}, 32)
	const index = uint64(0b10) // right at level 0? no: bit0=0, bit1=1

	cur := sha256.Sum256(commitID[:])
	for i, sib := range [][]byte{sib0, sib1} {
		var combined []byte
		if (index>>uint(i))&1 == 0 {
			combined = append(bytes.Clone(cur[:]), sib...)
		} else {
			combined = append(bytes.Clone(sib), cur[:]...)
		}
		cur = sha256.Sum256(combined)
	}

	zv.Pools[poolID] = &ConfidentialPool{
		PoolID:      poolID,
		MerkleRoot:  cur,
		Commitments: map[[32]byte]*Commitment{},
		Nullifiers:  map[[32]byte]*Nullifier{},
		Enabled:     true,
	}

	build := func(pool, leaf [32]byte, idx uint64, sibs [][]byte) []byte {
		out := []byte{0x01}
		out = append(out, pool[:]...)
		out = append(out, leaf[:]...)
		out = binary.BigEndian.AppendUint64(out, idx)
		out = binary.BigEndian.AppendUint32(out, uint32(len(sibs)))
		for _, s := range sibs {
			out = append(out, s...)
		}
		return out
	}

	good := build(poolID, commitID, index, [][]byte{sib0, sib1})
	ok, err := p.verifyCommitment(good)
	require.NoError(t, err)
	require.True(t, ok, "control: a correct inclusion proof must verify")

	// Same proof at a different index folds differently and must fail.
	for _, badIdx := range []uint64{0, 1, 3, 1 << 40} {
		if badIdx == index {
			continue
		}
		ok, _ := p.verifyCommitment(build(poolID, commitID, badIdx, [][]byte{sib0, sib1}))
		require.Falsef(t, ok, "the proof verified at the wrong index %d", badIdx)
	}

	// A tampered sibling must fail.
	for i := range 2 {
		sibs := [][]byte{bytes.Clone(sib0), bytes.Clone(sib1)}
		sibs[i][0] ^= 0x01
		ok, _ := p.verifyCommitment(build(poolID, commitID, index, sibs))
		require.Falsef(t, ok, "a tampered sibling at level %d was accepted", i)
	}

	// A different leaf must fail.
	var otherLeaf [32]byte
	copy(otherLeaf[:], "some-other-commitment")
	ok, _ = p.verifyCommitment(build(poolID, commitID, index, [][]byte{sib1, sib0}))
	require.False(t, ok, "reordered siblings were accepted")
	ok, _ = p.verifyCommitment(build(poolID, otherLeaf, index, [][]byte{sib0, sib1}))
	require.False(t, ok, "a different leaf was accepted under the same root")

	// An unknown pool is an error, not a false verdict.
	var ghost [32]byte
	copy(ghost[:], "no-such-pool")
	_, err = p.verifyCommitment(build(ghost, commitID, index, [][]byte{sib0, sib1}))
	require.ErrorIs(t, err, ErrPoolNotFound)

	// Truncated proof body: the declared sibling count must be backed by
	// bytes.
	trunc := good[:len(good)-1]
	_, err = p.verifyCommitment(trunc)
	require.ErrorIs(t, err, ErrInvalidInput)

	// Without a verifier there is no tree to consult.
	bare := &zkVerifyPrecompile{}
	ok, err = bare.verifyCommitment(good)
	require.False(t, ok)
	require.Error(t, err)
}

// TestCtr_PedersenVerificationIsProcessLocal documents a consensus hazard.
//
// compressG1 does not compress: it SHA-256 hashes the point and stores the
// preimage in a process-local map, and decompressG1 can only recover
// points that map has seen. So verifying a Pedersen opening depends on
// what THIS process has previously committed, not on the bytes supplied.
// Two validators therefore answer op 0x22 differently for the same call.
func TestCtr_PedersenVerificationIsProcessLocal(t *testing.T) {
	// A commitment this process never produced cannot be opened at all,
	// however well-formed the request is.
	var unseen, value, blinding [32]byte
	copy(unseen[:], "a commitment made by another node")
	_, err := globalPedersen.Verify(unseen, value, blinding)
	require.Error(t, err,
		"verification depends on process-local state, so a commitment from "+
			"another node cannot be checked here")

	// Whereas one made locally can — the only difference is local history.
	value[31] = 5
	blinding[31] = 6
	local, err := globalPedersen.Commit(value, blinding)
	require.NoError(t, err)
	ok, err := globalPedersen.Verify(local, value, blinding)
	require.NoError(t, err)
	require.True(t, ok)
}

// ---------------------------------------------------------------------
// batch (op 0x30)
// ---------------------------------------------------------------------

// ctrBatch frames a batch body from (type, payload) entries.
func ctrBatch(entries ...struct {
	typ  byte
	data []byte
}) []byte {
	out := []byte{OpVerifyBatch}
	out = binary.BigEndian.AppendUint32(out, uint32(len(entries)))
	for _, e := range entries {
		out = append(out, e.typ)
		out = binary.BigEndian.AppendUint32(out, uint32(len(e.data)))
		out = append(out, e.data...)
	}
	return out
}

type ctrEntry = struct {
	typ  byte
	data []byte
}

// TestCtr_Batch pins the aggregate semantics: a batch is valid only if
// every member is, an unknown member type is refused rather than skipped,
// and a truncated frame is refused rather than read past.
func TestCtr_Batch(t *testing.T) {
	p := &zkVerifyPrecompile{}

	// A zero count is refused (and TestGas_BatchIsNeverFree pins that it
	// is still charged for).
	_, err := p.verifyBatch([]byte{0, 0, 0, 0})
	require.ErrorIs(t, err, ErrInvalidInput)

	// Fewer than four bytes cannot even name a count.
	for n := range 4 {
		_, err := p.verifyBatch(make([]byte, n))
		require.ErrorIs(t, err, ErrInvalidInput)
	}

	// An unknown member type stops the batch.
	for _, typ := range []byte{0x00, OpVerifyFflonk, OpVerifyHalo2, OpVerifyBatch, 0xff} {
		in := ctrBatch(ctrEntry{typ, make([]byte, 8)})
		_, _, err := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress, in, 10_000_000, true)
		require.ErrorIsf(t, err, ErrUnknownProofSystem, "member type 0x%02x was dispatched", typ)
	}

	// A member whose declared length runs past the frame is refused.
	frame := []byte{0, 0, 0, 1, OpVerifyKZG, 0xff, 0xff, 0xff, 0xff}
	_, err = p.verifyBatch(frame)
	require.ErrorIs(t, err, ErrInvalidInput)

	// A member header that runs past the frame is refused.
	_, err = p.verifyBatch([]byte{0, 0, 0, 1, OpVerifyKZG, 0, 0})
	require.ErrorIs(t, err, ErrInvalidInput)

	// More members declared than supplied.
	_, err = p.verifyBatch(append([]byte{0, 0, 0, 3}, 0x10, 0, 0, 0, 0))
	require.ErrorIs(t, err, ErrInvalidInput)

	// A batch of genuine KZG openings verifies; corrupting ANY member
	// makes the whole batch fail. A batch verifier that passed while one
	// member was invalid would be the entire point of the op, broken.
	c, pt, cl, pr := ctrKZG(t, 2, 4, 6)
	good := ctrKZGInput(c, pt, cl, pr)
	all := ctrBatch(
		ctrEntry{OpVerifyKZG, good},
		ctrEntry{OpVerifyKZG, good},
		ctrEntry{OpVerifyKZG, good},
	)
	ret, _, err := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress, all, 10_000_000, true)
	require.NoError(t, err)
	require.Equal(t, encodeBool(true), ret, "a batch of valid openings must verify")

	for i := range 3 {
		entries := []ctrEntry{
			{OpVerifyKZG, bytes.Clone(good)},
			{OpVerifyKZG, bytes.Clone(good)},
			{OpVerifyKZG, bytes.Clone(good)},
		}
		entries[i].data[100] ^= 0x01
		in := ctrBatch(entries...)
		ret, _, err := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress, in, 10_000_000, true)
		require.NoError(t, err)
		require.Equalf(t, encodeBool(false), ret, "batch passed with member %d corrupted", i)
	}
}

// ---------------------------------------------------------------------
// PLONK (op 0x02)
// ---------------------------------------------------------------------

// TestCtr_PLONKStructure covers the no-key path: it must validate the nine
// G1 points and then refuse, never claiming a verdict without a key.
func TestCtr_PLONKStructure(t *testing.T) {
	p := &zkVerifyPrecompile{}

	// Short header.
	for n := range 36 {
		_, err := p.verifyPLONK(make([]byte, n))
		require.ErrorIs(t, err, ErrInvalidInput)
	}

	// Declared inputs the body cannot hold.
	hdr := make([]byte, 36+768)
	binary.BigEndian.PutUint32(hdr[32:36], 1)
	_, err := p.verifyPLONK(hdr)
	require.ErrorIs(t, err, ErrInvalidProofLength)

	// A body of all-zero G1 points parses (infinity is a valid encoding)
	// and then refuses for want of a key.
	body := make([]byte, 36+768)
	ok, err := p.verifyPLONK(body)
	require.False(t, ok)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrInvalidProofLength)

	// A malformed G1 point is rejected as such.
	bad := make([]byte, 36+768)
	for i := 36; i < 36+64; i++ {
		bad[i] = 0xff
	}
	_, err = p.verifyPLONK(bad)
	require.ErrorIs(t, err, ErrInvalidPointFormat)

	// verifyPLONKStructure directly: too short, and each point slot.
	_, err = verifyPLONKStructure(make([]byte, 767))
	require.ErrorIs(t, err, ErrInvalidProofLength)
	for i := range 9 {
		proof := make([]byte, 768)
		for j := i * 64; j < (i+1)*64; j++ {
			proof[j] = 0xff
		}
		_, err := verifyPLONKStructure(proof)
		require.ErrorIsf(t, err, ErrInvalidPointFormat, "point %d not validated", i)
	}
}

// TestCtr_PLONKKeyedPath routes through a registered key so the keyed
// branch is exercised, and pins that a mismatched system is refused.
func TestCtr_PLONKKeyedPath(t *testing.T) {
	zv := NewZKVerifier()
	g1 := bytes.Repeat([]byte{0x01}, 64)
	g2 := bytes.Repeat([]byte{0x02}, 128)
	ic := [][]byte{g1, g1, g1, g1, g1, g1, g1, g1, g2}

	id, err := zv.RegisterVerifyingKey(common.Address{},
		ProofSystemPlonk, CircuitTransfer, g1, g2, g2, g2, ic)
	require.NoError(t, err)

	p := &zkVerifyPrecompile{verifier: zv}
	data := make([]byte, 36+768)
	copy(data[0:32], id[:])

	ok, err := p.verifyPLONK(data)
	require.NoError(t, err)
	require.False(t, ok, "a zero proof must not verify against a real key")

	// An unregistered key is an error, not a verdict.
	unknown := make([]byte, 36+768)
	unknown[0] = 0xFE
	_, err = p.verifyPLONK(unknown)
	require.ErrorIs(t, err, ErrInvalidVerifyingKey)

	// A Groth16 key presented to the PLONK op is refused.
	gid, err := zv.RegisterVerifyingKey(common.Address{},
		ProofSystemGroth16, CircuitTransfer, g1, g2, g2, g2, [][]byte{g1})
	require.NoError(t, err)
	mismatch := make([]byte, 36+768)
	copy(mismatch[0:32], gid[:])
	_, err = p.verifyPLONK(mismatch)
	require.ErrorIs(t, err, ErrProofSystemMismatch)

	// Too few IC points for the PLONK layout: refuse, do not index past.
	sid, err := zv.RegisterVerifyingKey(common.Address{},
		ProofSystemPlonk, CircuitTransfer, g1, g2, g2, g2, [][]byte{g1, g1})
	require.NoError(t, err)
	short := make([]byte, 36+768)
	copy(short[0:32], sid[:])
	ok, err = p.verifyPLONK(short)
	require.NoError(t, err)
	require.False(t, ok)
}

// ---------------------------------------------------------------------
// Groth16 header handling (op 0x01)
// ---------------------------------------------------------------------

// TestCtr_Groth16Lengths pins the length arithmetic that the gas schedule
// now mirrors: exactly expectedLen clears, one byte fewer does not.
func TestCtr_Groth16Lengths(t *testing.T) {
	p := &zkVerifyPrecompile{}

	for n := range 36 {
		_, err := p.verifyGroth16(make([]byte, n))
		require.ErrorIs(t, err, ErrInvalidInput)
	}

	for _, n := range []uint32{0, 1, 4, 17} {
		expected := 32 + 4 + int(n)*32 + 256

		short := make([]byte, expected-1)
		binary.BigEndian.PutUint32(short[32:36], n)
		_, err := p.verifyGroth16(short)
		require.ErrorIsf(t, err, ErrInvalidProofLength, "n=%d: one byte short was accepted", n)

		exact := make([]byte, expected)
		binary.BigEndian.PutUint32(exact[32:36], n)
		_, err = p.verifyGroth16(exact)
		require.NotErrorIsf(t, err, ErrInvalidProofLength, "n=%d: exact length rejected", n)
	}

	// A declared count far beyond the body is refused, not allocated for.
	huge := make([]byte, 36+256)
	binary.BigEndian.PutUint32(huge[32:36], ^uint32(0))
	_, err := p.verifyGroth16(huge)
	require.ErrorIs(t, err, ErrInvalidProofLength)

	// Malformed proof points are reported as such.
	bad := make([]byte, 36+256)
	for i := 36; i < 100; i++ {
		bad[i] = 0xff
	}
	_, err = p.verifyGroth16(bad)
	require.ErrorIs(t, err, ErrInvalidPointFormat)

	// verifyGroth16PointsValid directly: each of the three slots.
	valid := make([]byte, 256)
	for i, region := range [][2]int{{0, 64}, {64, 128}, {192, 64}} {
		proof := bytes.Clone(valid)
		for j := region[0]; j < region[0]+region[1]; j++ {
			proof[j] = 0xff
		}
		_, err := verifyGroth16PointsValid(proof[0:64], proof[64:192], proof[192:256])
		require.Errorf(t, err, "slot %d not validated", i)
	}
}

// ---------------------------------------------------------------------
// Halo2 helpers
// ---------------------------------------------------------------------

// TestCtr_Halo2Helpers covers the field and point predicates the Halo2
// structural path depends on. Each is a guard: if it accepts what it
// should reject, a malformed proof reaches the arithmetic.
func TestCtr_Halo2Helpers(t *testing.T) {
	// isZeroBytes.
	require.True(t, isZeroBytes(nil))
	require.True(t, isZeroBytes(make([]byte, 32)))
	require.False(t, isZeroBytes([]byte{0, 0, 1}))

	// isValidScalar: must reject non-canonical values (>= the field
	// order), which are the classic malleability vector.
	require.False(t, isValidScalar(make([]byte, 31)), "wrong length")
	require.False(t, isValidScalar(bytes.Repeat([]byte{0xff}, 32)), "far above the order")
	small := make([]byte, 32)
	small[31] = 1
	require.True(t, isValidScalar(small))

	// modInverse: zero has no inverse; a nonzero scalar does, and the
	// inverse is a canonical 32-byte scalar.
	_, err := modInverse(make([]byte, 32))
	require.Error(t, err, "zero must have no inverse")
	_, err = modInverse(make([]byte, 31))
	require.Error(t, err, "wrong length must be refused")
	inv, err := modInverse(small)
	require.NoError(t, err)
	require.Len(t, inv, 32)
	require.True(t, isValidScalar(inv))

	// foldCommitment must be a function of every argument: changing any
	// one must change the fold, or that argument is unbound.
	base := [5][]byte{
		bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32),
		bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32),
		bytes.Repeat([]byte{5}, 32),
	}
	want := foldCommitment(base[0], base[1], base[2], base[3], base[4])
	for i := range base {
		mutated := base
		mutated[i] = bytes.Clone(base[i])
		mutated[i][0] ^= 0xff
		got := foldCommitment(mutated[0], mutated[1], mutated[2], mutated[3], mutated[4])
		require.NotEqualf(t, want, got, "argument %d does not affect the fold", i)
	}

	// intToStr is only used to label errors; it must not panic or collide
	// for the small indices it is called with.
	seen := map[string]bool{}
	for i := range 10 {
		s := intToStr(i)
		require.False(t, seen[s], "intToStr collides at %d", i)
		seen[s] = true
	}
	require.Equal(t, "N", intToStr(10))
	require.Equal(t, "N", intToStr(1000))
}

// TestCtr_Halo2TranscriptBinds pins Fiat-Shamir: the challenge must be a
// deterministic function of everything appended, and must change when any
// of it changes. A transcript that ignored an input would let a prover
// vary that input freely after seeing the challenge.
func TestCtr_Halo2TranscriptBinds(t *testing.T) {
	mk := func(scalars, points [][]byte) []byte {
		tr := newHalo2Transcript()
		for _, s := range scalars {
			tr.appendScalar(s)
		}
		for _, p := range points {
			tr.appendPoint(p)
		}
		return tr.challenge()
	}

	s := [][]byte{bytes.Repeat([]byte{1}, 32)}
	p := [][]byte{bytes.Repeat([]byte{2}, 32)}

	require.Equal(t, mk(s, p), mk(s, p), "the transcript must be deterministic")

	other := [][]byte{bytes.Repeat([]byte{9}, 32)}
	require.NotEqual(t, mk(s, p), mk(other, p), "a scalar does not bind")
	require.NotEqual(t, mk(s, p), mk(s, other), "a point does not bind")
	require.NotEqual(t, mk(s, p), mk(p, s), "ordering does not bind")

	// Successive challenges from one transcript must differ, or every
	// round shares a challenge.
	tr := newHalo2Transcript()
	tr.appendPoint(p[0])
	first := bytes.Clone(tr.challenge())
	tr.appendPoint(p[0])
	require.NotEqual(t, first, tr.challenge(), "the transcript does not advance")
}

// TestCtr_Halo2InstanceCommitment covers the IC-bounds guard: a key with
// too few IC points for the declared public inputs must be refused, not
// indexed past.
func TestCtr_Halo2InstanceCommitment(t *testing.T) {
	data := buildTestHalo2Proof(2, 1, 1, 4)
	proof, err := parseHalo2Proof(data)
	require.NoError(t, err)
	require.Len(t, proof.publicInputs, 2)

	tooFew := &VerifyingKey{ProofSystem: ProofSystemHalo2, IC: [][]byte{{1}, {2}}}
	_, err = computeHalo2InstanceCommitment(proof, tooFew)
	require.Error(t, err, "insufficient IC points must be refused")

	enough := &VerifyingKey{
		ProofSystem: ProofSystemHalo2,
		IC:          [][]byte{{1}, {2}, {3}, {4}},
	}
	got, err := computeHalo2InstanceCommitment(proof, enough)
	require.NoError(t, err)
	require.Equal(t, proof.instanceCommitments[0], got,
		"the instance commitment must come from the proof when present")

	// With no instance commitments it falls back to IC[0].
	proof.instanceCommitments = nil
	got, err = computeHalo2InstanceCommitment(proof, enough)
	require.NoError(t, err)
	require.Equal(t, []byte{1}, got)
}

// TestCtr_Halo2ParseBounds walks every length guard in the parser. Each
// declared count must be backed by bytes; none may read past the input.
func TestCtr_Halo2ParseBounds(t *testing.T) {
	full := buildTestHalo2Proof(1, 1, 1, 4)

	for n := range len(full) {
		_, err := parseHalo2Proof(full[:n])
		require.Errorf(t, err, "a %d-byte prefix parsed as a complete proof", n)
	}

	// Round count must be 1..32.
	for _, rounds := range []uint32{0, 33, 1 << 20} {
		data := buildTestHalo2ProofWithRounds(rounds)
		_, err := parseHalo2Proof(data)
		require.Errorf(t, err, "round count %d was accepted", rounds)
	}

	// An overstated public-input count is refused.
	bad := bytes.Clone(full)
	binary.BigEndian.PutUint32(bad[32:36], 1<<20)
	_, err := parseHalo2Proof(bad)
	require.Error(t, err)
}

// TestCtr_ValidCompressedPoint pins the curve check used across the Halo2
// path: off-curve x-coordinates and non-canonical field elements must be
// rejected, or a proof can carry points that are not group elements.
func TestCtr_ValidCompressedPoint(t *testing.T) {
	require.False(t, isValidCompressedPoint(make([]byte, 31)), "wrong length")
	require.False(t, isValidCompressedPoint(nil))

	// A real on-curve point is accepted.
	require.True(t, isValidCompressedPoint(realCompressedPallasPoint(1)))

	// The all-ones x-coordinate is not in the field.
	require.False(t, isValidCompressedPoint(bytes.Repeat([]byte{0xff}, 32)))

	// isQuadraticResidue on a small prime, checked against brute force.
	p := big.NewInt(23)
	squares := map[int64]bool{}
	for i := int64(1); i < 23; i++ {
		squares[new(big.Int).Mod(big.NewInt(i*i), p).Int64()] = true
	}
	for a := int64(1); a < 23; a++ {
		require.Equalf(t, squares[a], isQuadraticResidue(big.NewInt(a), p),
			"residue verdict wrong for %d mod 23", a)
	}
}
