// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"bytes"
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// A verifier is only shown to work when it does BOTH halves: accept a
// proof that satisfies the equation, and reject everything else. Tests
// that only ever feed it garbage cannot distinguish a real verifier from
// `return false`, and tests that only feed it a valid proof cannot
// distinguish one from `return true`.
//
// There is no trusted setup here, so instead we PICK the trapdoor. Choose
// scalars for every group element and solve the verification equation in
// the exponent for C. The resulting proof satisfies
//
//	e(A,B) = e(alpha,beta) . e(vk_x,gamma) . e(C,delta)
//
// exactly as an honestly-generated one does — the pairing check cannot
// tell the difference, which is what makes it a usable control.

// grOrder is the BN254 group order r.
func grOrder() *big.Int { return fr.Modulus() }

// grG1 returns [k]G1 marshalled the way bn256.G1.Unmarshal expects
// (64 bytes: 32-byte x, 32-byte y, big-endian).
func grG1(k *big.Int) []byte {
	_, _, g1, _ := bn254.Generators()
	var p bn254.G1Affine
	p.ScalarMultiplication(&g1, new(big.Int).Mod(k, grOrder()))
	return p.Marshal()
}

// grG2 returns [k]G2 marshalled as bn256.G2.Unmarshal expects
// (128 bytes: x.A1, x.A0, y.A1, y.A0).
func grG2(k *big.Int) []byte {
	_, _, _, g2 := bn254.Generators()
	var p bn254.G2Affine
	p.ScalarMultiplication(&g2, new(big.Int).Mod(k, grOrder()))
	return p.Marshal()
}

// grInstance is a Groth16 statement with a known trapdoor.
type grInstance struct {
	vk     *VerifyingKey
	a      []byte // proof A (G1)
	b      []byte // proof B (G2)
	c      []byte // proof C (G1)
	public []*big.Int
}

// grBuild produces a verifying key and a proof that genuinely satisfies
// the pairing equation for the given public inputs.
func grBuild(t *testing.T, public []*big.Int) grInstance {
	t.Helper()
	r := grOrder()
	n := func(v int64) *big.Int { return big.NewInt(v) }

	alpha, beta := n(3), n(5)
	gamma, delta := n(7), n(11)
	pa, pb := n(13), n(17)

	// IC scalars: one for the constant term plus one per public input.
	ic := make([]*big.Int, len(public)+1)
	for i := range ic {
		ic[i] = n(int64(23 + 7*i))
	}

	// vk_x = IC[0] + sum(public[i] * IC[i+1]), in the exponent.
	vkx := new(big.Int).Set(ic[0])
	for i, x := range public {
		term := new(big.Int).Mul(new(big.Int).Mod(x, r), ic[i+1])
		vkx.Add(vkx, term)
	}
	vkx.Mod(vkx, r)

	// Solve a*b - alpha*beta - vk_x*gamma - c*delta == 0 for c.
	lhs := new(big.Int).Mul(pa, pb)
	lhs.Sub(lhs, new(big.Int).Mul(alpha, beta))
	lhs.Sub(lhs, new(big.Int).Mul(vkx, gamma))
	lhs.Mod(lhs, r)
	c := new(big.Int).Mul(lhs, new(big.Int).ModInverse(delta, r))
	c.Mod(c, r)

	icBytes := make([][]byte, len(ic))
	for i, s := range ic {
		icBytes[i] = grG1(s)
	}

	return grInstance{
		vk: &VerifyingKey{
			ProofSystem: ProofSystemGroth16,
			CircuitType: CircuitTransfer,
			Alpha:       grG1(alpha),
			Beta:        grG2(beta),
			Gamma:       grG2(gamma),
			Delta:       grG2(delta),
			IC:          icBytes,
		},
		a:      grG1(pa),
		b:      grG2(pb),
		c:      grG1(c),
		public: public,
	}
}

// grRegister installs the instance's key on a verifier and returns its ID.
func grRegister(t *testing.T, zv *ZKVerifier, in grInstance) [32]byte {
	t.Helper()
	id, err := zv.RegisterVerifyingKey(common.Address{},
		ProofSystemGroth16, CircuitTransfer,
		in.vk.Alpha, in.vk.Beta, in.vk.Gamma, in.vk.Delta, in.vk.IC)
	require.NoError(t, err)
	return id
}

// TestGr_AcceptsASatisfyingProof is the control the rest depend on: the
// pairing check must actually accept. Without it, every negative test
// below would pass against a verifier hard-wired to reject.
func TestGr_AcceptsASatisfyingProof(t *testing.T) {
	for _, public := range [][]*big.Int{
		{},
		{big.NewInt(1)},
		{big.NewInt(42), big.NewInt(1337)},
		{big.NewInt(0), big.NewInt(0), big.NewInt(0)},
	} {
		zv := NewZKVerifier()
		in := grBuild(t, public)
		id := grRegister(t, zv, in)

		res, err := zv.VerifyGroth16(id, in.a, in.b, in.c, in.public)
		require.NoError(t, err)
		require.Truef(t, res.Valid,
			"a proof satisfying the pairing equation was rejected (%d public inputs)",
			len(public))
		require.Equal(t, ProofSystemGroth16, res.ProofSystem)
	}
}

// TestGr_StatementBinding is the soundness property: the SAME proof must
// not verify for a different statement. This is what the public-input MSM
// exists to enforce — if vk_x ignored the inputs, a single proof would
// prove everything.
func TestGr_StatementBinding(t *testing.T) {
	zv := NewZKVerifier()
	stmtA := []*big.Int{big.NewInt(42), big.NewInt(1337)}
	in := grBuild(t, stmtA)
	id := grRegister(t, zv, in)

	res, err := zv.VerifyGroth16(id, in.a, in.b, in.c, in.public)
	require.NoError(t, err)
	require.True(t, res.Valid, "control")

	for _, stmtB := range [][]*big.Int{
		{big.NewInt(43), big.NewInt(1337)},
		{big.NewInt(42), big.NewInt(1338)},
		{big.NewInt(1337), big.NewInt(42)}, // reordered
		{big.NewInt(0), big.NewInt(0)},
		{new(big.Int).Sub(grOrder(), big.NewInt(1)), big.NewInt(1337)},
	} {
		res, err := zv.VerifyGroth16(id, in.a, in.b, in.c, stmtB)
		require.NoError(t, err)
		require.Falsef(t, res.Valid, "the proof for %v verified against %v", stmtA, stmtB)
	}

	// A public input congruent mod r denotes the SAME field element, so it
	// must still verify — the MSM works in the scalar field, not on bytes.
	shifted := []*big.Int{
		new(big.Int).Add(stmtA[0], grOrder()),
		stmtA[1],
	}
	res, err = zv.VerifyGroth16(id, in.a, in.b, in.c, shifted)
	require.NoError(t, err)
	require.True(t, res.Valid,
		"a scalar congruent mod r denotes the same statement and must verify")

	// Wrong arity is refused outright.
	_, err = zv.VerifyGroth16(id, in.a, in.b, in.c, []*big.Int{big.NewInt(42)})
	require.ErrorIs(t, err, ErrInvalidPublicInputs)
	_, err = zv.VerifyGroth16(id, in.a, in.b, in.c,
		append(slices.Clone(stmtA), big.NewInt(1)))
	require.ErrorIs(t, err, ErrInvalidPublicInputs)
}

// TestGr_ProofElementTampering flips a bit in each proof element in turn.
// Every one must be rejected, or that element is not bound by the
// equation and a prover could vary it freely.
func TestGr_ProofElementTampering(t *testing.T) {
	zv := NewZKVerifier()
	in := grBuild(t, []*big.Int{big.NewInt(9)})
	id := grRegister(t, zv, in)

	res, err := zv.VerifyGroth16(id, in.a, in.b, in.c, in.public)
	require.NoError(t, err)
	require.True(t, res.Valid, "control")

	for _, el := range []struct {
		name string
		buf  []byte
	}{{"A", in.a}, {"B", in.b}, {"C", in.c}} {
		for _, off := range []int{0, len(el.buf) / 2, len(el.buf) - 1} {
			bad := bytes.Clone(el.buf)
			bad[off] ^= 0x01

			a, b, c := in.a, in.b, in.c
			switch el.name {
			case "A":
				a = bad
			case "B":
				b = bad
			case "C":
				c = bad
			}
			res, err := zv.VerifyGroth16(id, a, b, c, in.public)
			// A corrupted encoding either fails to parse (Valid false) or
			// parses to a different point and fails the pairing. Never valid.
			require.NoError(t, err)
			require.Falsef(t, res.Valid,
				"a bit flip in %s at byte %d still verified", el.name, off)
		}
	}

	// Swapping A and C (both G1) must not verify.
	res, err = zv.VerifyGroth16(id, in.c, in.b, in.a, in.public)
	require.NoError(t, err)
	require.False(t, res.Valid, "A and C are interchangeable")

	// The identity in place of any proof element must not verify.
	for i, sub := range [][3][]byte{
		{make([]byte, 64), in.b, in.c},
		{in.a, make([]byte, 128), in.c},
		{in.a, in.b, make([]byte, 64)},
	} {
		res, err := zv.VerifyGroth16(id, sub[0], sub[1], sub[2], in.public)
		require.NoError(t, err)
		require.Falsef(t, res.Valid, "the identity was accepted as proof element %d", i)
	}
}

// TestGr_KeyBinding: a proof must not carry over to a different key.
func TestGr_KeyBinding(t *testing.T) {
	zv := NewZKVerifier()
	public := []*big.Int{big.NewInt(5)}
	in := grBuild(t, public)
	id := grRegister(t, zv, in)

	res, err := zv.VerifyGroth16(id, in.a, in.b, in.c, public)
	require.NoError(t, err)
	require.True(t, res.Valid, "control")

	// A key differing in a single element must reject the same proof.
	for _, mut := range []func(*VerifyingKey){
		func(k *VerifyingKey) { k.Alpha = grG1(big.NewInt(4)) },
		func(k *VerifyingKey) { k.Beta = grG2(big.NewInt(6)) },
		func(k *VerifyingKey) { k.Gamma = grG2(big.NewInt(8)) },
		func(k *VerifyingKey) { k.Delta = grG2(big.NewInt(12)) },
		func(k *VerifyingKey) { k.IC[0] = grG1(big.NewInt(99)) },
		func(k *VerifyingKey) { k.IC[1] = grG1(big.NewInt(98)) },
	} {
		alt := *in.vk
		alt.IC = slices.Clone(in.vk.IC)
		mut(&alt)

		altID, err := zv.RegisterVerifyingKey(common.Address{},
			ProofSystemGroth16, CircuitTransfer,
			alt.Alpha, alt.Beta, alt.Gamma, alt.Delta, alt.IC)
		require.NoError(t, err)

		res, err := zv.VerifyGroth16(altID, in.a, in.b, in.c, public)
		require.NoError(t, err)
		require.False(t, res.Valid, "the proof verified under a modified key")
	}
}

// TestGr_ThroughThePrecompile drives the same instance through op 0x01,
// so the wire framing, the gas schedule and the verifier all agree on
// where the public inputs are.
func TestGr_ThroughThePrecompile(t *testing.T) {
	zv := NewZKVerifier()
	public := []*big.Int{big.NewInt(42), big.NewInt(1337)}
	in := grBuild(t, public)
	id := grRegister(t, zv, in)
	p := &zkVerifyPrecompile{verifier: zv}

	wire := func(vkID [32]byte, pub []*big.Int, a, b, c []byte) []byte {
		out := make([]byte, 0, 1+inputsOff+len(pub)*32+256)
		out = append(out, OpVerifyGroth16)
		out = append(out, vkID[:]...)
		var n [4]byte
		n[3] = byte(len(pub))
		out = append(out, n[:]...)
		for _, x := range pub {
			out = append(out, padScalar32(x)...)
		}
		out = append(out, a...)
		out = append(out, b...)
		return append(out, c...)
	}

	full := wire(id, public, in.a, in.b, in.c)

	// The gas schedule must price the count the verifier will parse.
	require.Equal(t,
		uint64(GasGroth16Base)+uint64(len(public))*GasPerPublicInput,
		ZKVerifyPrecompile.RequiredGas(full))

	ok, err := p.verifyGroth16(full[1:])
	require.NoError(t, err)
	require.True(t, ok, "a satisfying proof must verify through the wire format")

	// Changing a public-input word on the wire must flip the verdict —
	// this is the end-to-end statement binding.
	tampered := bytes.Clone(full)
	tampered[inputsOff+31] ^= 0x01
	ok, err = p.verifyGroth16(tampered[1:])
	require.NoError(t, err)
	require.False(t, ok, "a modified public input still verified")

	// Understating the count changes which bytes are read as the proof and
	// must not verify.
	under := bytes.Clone(full)
	under[inputsOff-1] = 1
	ok, _ = p.verifyGroth16(under[1:])
	require.False(t, ok)
}

// TestGr_PlonkParsesRealPoints drives plonkVerify past its parsing with
// genuine curve points, so the challenge derivation and linearisation run
// rather than short-circuiting on a malformed key.
func TestGr_PlonkParsesRealPoints(t *testing.T) {
	zv := NewZKVerifier()

	ic := make([][]byte, 9)
	for i := range 8 {
		ic[i] = grG1(big.NewInt(int64(i + 2)))
	}
	ic[8] = grG2(big.NewInt(31)) // X2

	id, err := zv.RegisterVerifyingKey(common.Address{},
		ProofSystemPlonk, CircuitTransfer,
		grG1(big.NewInt(41)), grG2(big.NewInt(43)),
		grG2(big.NewInt(47)), grG2(big.NewInt(53)), ic)
	require.NoError(t, err)

	// Nine real G1 commitments plus six scalars.
	proof := make([]byte, 0, 768)
	for i := range 9 {
		proof = append(proof, grG1(big.NewInt(int64(101+i)))...)
	}
	for i := range 6 {
		proof = append(proof, padScalar32(big.NewInt(int64(1000+i)))...)
	}
	require.Len(t, proof, 768)

	public := []*big.Int{big.NewInt(7), big.NewInt(9)}
	res, err := zv.VerifyPlonk(id, proof, public)
	require.NoError(t, err)
	require.False(t, res.Valid,
		"an arbitrary set of curve points is not a PLONK proof and must not verify")

	// Every element must influence the verdict path without panicking, and
	// none of these arbitrary proofs may verify.
	for i := range 9 {
		bad := bytes.Clone(proof)
		bad[i*64] ^= 0x01
		res, err := zv.VerifyPlonk(id, bad, public)
		require.NoError(t, err)
		require.False(t, res.Valid)
	}
	for _, pub := range [][]*big.Int{nil, {big.NewInt(1)}, {big.NewInt(7), big.NewInt(10)}} {
		res, err := zv.VerifyPlonk(id, proof, pub)
		require.NoError(t, err)
		require.False(t, res.Valid)
	}

	// A proof one byte short of the layout is refused.
	res, err = zv.VerifyPlonk(id, proof[:767], public)
	require.NoError(t, err)
	require.False(t, res.Valid)
}

// TestGr_PadScalar32 pins the scalar encoding used on the wire: exactly
// 32 big-endian bytes, right-aligned, and oversized values truncated to
// their low 32 bytes rather than overflowing the buffer.
func TestGr_PadScalar32(t *testing.T) {
	require.Equal(t, make([]byte, 32), padScalar32(nil))
	require.Equal(t, make([]byte, 32), padScalar32(big.NewInt(0)))

	one := padScalar32(big.NewInt(1))
	require.Len(t, one, 32)
	require.Equal(t, byte(1), one[31], "small values must be right-aligned")

	// Exactly 32 bytes round-trips.
	max32 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	require.Equal(t, bytes.Repeat([]byte{0xff}, 32), padScalar32(max32))

	// More than 32 bytes keeps the LOW 32, and stays 32 bytes.
	big33 := new(big.Int).Lsh(big.NewInt(1), 264)
	big33.Add(big33, big.NewInt(0xAB))
	got := padScalar32(big33)
	require.Len(t, got, 32)
	require.Equal(t, byte(0xAB), got[31])
}
