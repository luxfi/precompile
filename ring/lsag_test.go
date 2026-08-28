// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ring

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// --- deterministic corpus -------------------------------------------------
//
// Nothing here reads the wall clock, math/rand or a map. A test that reaches
// a branch reaches it on every run, so the coverage number is a fact about
// the suite rather than about the day.

// detBytes is SHA-256 in counter mode over a fixed seed: a byte source that
// satisfies io.Reader and replays identically.
type detBytes struct {
	seed []byte
	ctr  uint64
	buf  []byte
}

func det(seed string) *detBytes { return &detBytes{seed: []byte(seed)} }

func (d *detBytes) Read(p []byte) (int, error) {
	for i := range p {
		if len(d.buf) == 0 {
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], d.ctr)
			d.ctr++
			h := sha256.Sum256(append(append([]byte{}, d.seed...), c[:]...))
			d.buf = h[:]
		}
		p[i] = d.buf[0]
		d.buf = d.buf[1:]
	}
	return len(p), nil
}

// detKey derives a fixed secp256k1 keypair from a label.
func detKey(label string) (sk, pk []byte) {
	curve := secp256k1.S256()
	h := sha256.Sum256([]byte("lux-ring-test-key/" + label))
	d := new(big.Int).SetBytes(h[:])
	d.Mod(d, new(big.Int).Sub(curve.N, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	x, y := curve.ScalarBaseMult(d.Bytes())
	return d.FillBytes(make([]byte, 32)), secp256k1.CompressPubkey(x, y)
}

// detRing returns n fixed members, labelled label/0 .. label/n-1.
func detRing(t *testing.T, label string, n int) (ring [][]byte, sks [][]byte) {
	t.Helper()
	ring = make([][]byte, n)
	sks = make([][]byte, n)
	for i := range n {
		sks[i], ring[i] = detKey(label + "/" + string(rune('a'+i)))
	}
	return ring, sks
}

// mustSign produces a signature that must verify, from the deterministic source.
func mustSign(t *testing.T, ring [][]byte, sk []byte, idx int, msg []byte, seed string) *LSAGSignature {
	t.Helper()
	sig, err := signOffChain(ring, sk, idx, msg, det(seed))
	require.NoError(t, err)
	return sig
}

// run calls the precompile with exactly the gas it asks for.
func run(input []byte) ([]byte, uint64, error) {
	gas := RingSignaturePrecompile.RequiredGas(input)
	return RingSignaturePrecompile.Run(nil, common.Address{}, ContractAddress, input, gas, false)
}

// verifies reports the precompile's answer as a bool, failing on any error.
func verifies(t *testing.T, input []byte) bool {
	t.Helper()
	out, _, err := run(input)
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Contains(t, []byte{0x00, 0x01}, out[0], "verify answers one boolean byte")
	return out[0] == 0x01
}

// --- correctness ----------------------------------------------------------

// Every ring size and every signer position must verify. A verifier that
// only closed the loop for signerIdx==0, or that mis-indexed s[i], fails here.
func TestVerifyAcceptsHonestSignature(t *testing.T) {
	for _, n := range []int{2, 3, 5, 8} {
		ring, sks := detRing(t, "honest", n)
		for idx := range n {
			msg := []byte{byte(n), byte(idx), 'm', 's', 'g'}
			sig := mustSign(t, ring, sks[idx], idx, msg, "honest-sign")
			in := buildVerifyInput(SchemeLSAGSecp256k1, ring, sig.Serialize(), msg)
			require.True(t, verifies(t, in), "ring size %d, signer %d", n, idx)
		}
	}
}

// The empty message is a legitimate message, not a missing field.
func TestVerifyAcceptsEmptyMessage(t *testing.T) {
	ring, sks := detRing(t, "emptymsg", 3)
	sig := mustSign(t, ring, sks[1], 1, nil, "emptymsg-sign")
	in := buildVerifyInput(SchemeLSAGSecp256k1, ring, sig.Serialize(), nil)
	require.True(t, verifies(t, in))
}

// Consensus: the same calldata must always give the same answer.
func TestVerifyIsDeterministic(t *testing.T) {
	ring, sks := detRing(t, "determ", 3)
	msg := []byte("determinism")
	sig := mustSign(t, ring, sks[2], 2, msg, "determ-sign")
	in := buildVerifyInput(SchemeLSAGSecp256k1, ring, sig.Serialize(), msg)

	first, _, err := run(in)
	require.NoError(t, err)
	for range 4 {
		out, _, err := run(in)
		require.NoError(t, err)
		require.Equal(t, first, out)
	}
}

// --- linkability: the property LSAG exists for -----------------------------

// The key image is x*H(P_signer): a function of the signer's key alone. Two
// signatures by the same signer -- different message, different ring, different
// randomness -- must carry the same image, or the linking that stops a double
// spend does not work.
func TestKeyImageLinksSameSigner(t *testing.T) {
	ringA, sksA := detRing(t, "linkA", 3)
	ringB, _ := detRing(t, "linkB", 4)
	// Put the same signer into a second, otherwise-unrelated ring.
	ringB[2] = ringA[0]

	msgA := []byte("first spend")
	msgB := []byte("second spend, different ring")

	sigA := mustSign(t, ringA, sksA[0], 0, msgA, "link-seed-A")
	sigB := mustSign(t, ringB, sksA[0], 2, msgB, "link-seed-B")

	require.True(t, verifies(t, buildVerifyInput(SchemeLSAGSecp256k1, ringA, sigA.Serialize(), msgA)))
	require.True(t, verifies(t, buildVerifyInput(SchemeLSAGSecp256k1, ringB, sigB.Serialize(), msgB)))

	require.Equal(t, sigA.KeyImage, sigB.KeyImage,
		"same signer must yield the same key image -- linkability is the whole point")
	require.NotEqual(t, sigA.Serialize(), sigB.Serialize(),
		"the signatures themselves must still differ")
}

// The randomness must not leak into the image either: signing twice over the
// same message with different alpha gives two different signatures with one image.
func TestKeyImageIgnoresSigningRandomness(t *testing.T) {
	ring, sks := detRing(t, "alpha", 3)
	msg := []byte("same message twice")

	one := mustSign(t, ring, sks[1], 1, msg, "alpha-seed-1")
	two := mustSign(t, ring, sks[1], 1, msg, "alpha-seed-2")

	require.NotEqual(t, one.Serialize(), two.Serialize(), "different alpha, different signature")
	require.Equal(t, one.KeyImage, two.KeyImage)
	require.True(t, verifies(t, buildVerifyInput(SchemeLSAGSecp256k1, ring, one.Serialize(), msg)))
	require.True(t, verifies(t, buildVerifyInput(SchemeLSAGSecp256k1, ring, two.Serialize(), msg)))
}

// Different signers of the SAME ring and message must not collide, or every
// member would look like a double spend of every other.
func TestKeyImageSeparatesDifferentSigners(t *testing.T) {
	const n = 4
	ring, sks := detRing(t, "distinct", n)
	msg := []byte("one message, four signers")

	seen := make(map[string]int, n)
	for idx := range n {
		sig := mustSign(t, ring, sks[idx], idx, msg, "distinct-seed")
		require.True(t, verifies(t, buildVerifyInput(SchemeLSAGSecp256k1, ring, sig.Serialize(), msg)))

		key := string(sig.KeyImage)
		prev, dup := seen[key]
		require.False(t, dup, "signers %d and %d share a key image", prev, idx)
		seen[key] = idx
	}
	require.Len(t, seen, n)
}

// The image must be a real curve point -- a forgeable or off-curve image
// would be rejected by the verifier and break linking.
func TestKeyImageIsOnCurve(t *testing.T) {
	curve := secp256k1.S256()
	ring, sks := detRing(t, "imgcurve", 2)
	sig := mustSign(t, ring, sks[0], 0, []byte("m"), "imgcurve-seed")

	require.Len(t, sig.KeyImage, CompressedPubKeySize)
	x, y := secp256k1.DecompressPubkey(sig.KeyImage)
	require.NotNil(t, x)
	require.True(t, curve.IsOnCurve(x, y))
}

// --- primitives ------------------------------------------------------------

func TestSerializeRoundTrip(t *testing.T) {
	for _, n := range []int{2, 3, 7} {
		ring, sks := detRing(t, "roundtrip", n)
		sig := mustSign(t, ring, sks[0], 0, []byte("rt"), "rt-seed")

		raw := sig.Serialize()
		require.Len(t, raw, CompressedPubKeySize+n*ScalarSize*2, "wire length is 33 + 64n")

		got, err := parseLSAGSignature(raw, n)
		require.NoError(t, err)
		require.Equal(t, sig.KeyImage, got.KeyImage)
		require.Len(t, got.C, n)
		require.Len(t, got.S, n)
		for i := range n {
			require.Zero(t, sig.C[i].Cmp(got.C[i]), "c[%d]", i)
			require.Zero(t, sig.S[i].Cmp(got.S[i]), "s[%d]", i)
		}
		require.Equal(t, raw, got.Serialize(), "re-serialising is the identity")
	}
}

// Scalars shorter than 32 bytes must be left-padded, not left-shifted: an
// unpadded field would slide every following scalar and change the meaning.
func TestSerializePadsShortScalars(t *testing.T) {
	sig := &LSAGSignature{
		KeyImage: make([]byte, CompressedPubKeySize),
		C:        []*big.Int{big.NewInt(1), big.NewInt(2)},
		S:        []*big.Int{big.NewInt(0x0102), big.NewInt(255)},
	}
	raw := sig.Serialize()
	require.Len(t, raw, CompressedPubKeySize+2*ScalarSize*2)

	got, err := parseLSAGSignature(raw, 2)
	require.NoError(t, err)
	require.Zero(t, got.C[0].Cmp(big.NewInt(1)))
	require.Zero(t, got.C[1].Cmp(big.NewInt(2)))
	require.Zero(t, got.S[0].Cmp(big.NewInt(0x0102)))
	require.Zero(t, got.S[1].Cmp(big.NewInt(255)))
}

func TestPadTo32(t *testing.T) {
	for _, n := range []int{0, 1, 2, 31} {
		in := make([]byte, n)
		for i := range in {
			in[i] = byte(i + 1)
		}
		out := padTo32(in)
		require.Len(t, out, 32, "input of %d bytes", n)
		require.Equal(t, in, out[32-n:], "the value is right-aligned")
		for _, b := range out[:32-n] {
			require.Zero(t, b, "the pad is zero")
		}
	}

	// At and above 32 bytes the input is returned untouched -- padding a
	// 33-byte value into 32 would silently drop its top byte.
	for _, n := range []int{32, 33, 64} {
		in := make([]byte, n)
		in[0] = 0xAA
		require.Equal(t, in, padTo32(in))
	}
}

// The challenge must depend on the message and on all four coordinates.
// A verifier that dropped or transposed one of them would still look
// self-consistent; it would just accept forgeries.
func TestHashRingBindsEveryArgument(t *testing.T) {
	base := []*big.Int{big.NewInt(11), big.NewInt(22), big.NewInt(33), big.NewInt(44)}
	msg := []byte("bind")
	want := hashRing(msg, base[0], base[1], base[2], base[3])

	require.Zero(t, want.Cmp(hashRing(msg, base[0], base[1], base[2], base[3])),
		"hashRing is deterministic")

	require.NotZero(t, want.Cmp(hashRing([]byte("bine"), base[0], base[1], base[2], base[3])),
		"message must be bound")

	for i := range base {
		arg := []*big.Int{base[0], base[1], base[2], base[3]}
		arg[i] = new(big.Int).Add(base[i], big.NewInt(1))
		require.NotZero(t, want.Cmp(hashRing(msg, arg[0], arg[1], arg[2], arg[3])),
			"coordinate %d must be bound", i)
	}

	// Transposing L and R must change the challenge, or (L,R) and (R,L)
	// would be interchangeable.
	require.NotZero(t, want.Cmp(hashRing(msg, base[2], base[3], base[0], base[1])),
		"L and R must not be interchangeable")

	// Length extension: H over concatenated padded fields must not confuse a
	// long message with a short one plus coordinates.
	require.NotZero(t,
		hashRing([]byte("bind"), base[0], base[1], base[2], base[3]).Cmp(
			hashRing(append([]byte("bind"), padTo32(base[0].Bytes())...), base[1], base[2], base[3], big.NewInt(0))))
}

// hashToPoint is the map whose discrete log must be unknown. It must also be
// injective enough that two ring members do not share a point.
func TestHashToPointSeparatesInputs(t *testing.T) {
	curve := secp256k1.S256()
	seen := make(map[string]bool)
	for i := range 16 {
		_, pk := detKey("h2c/" + string(rune('a'+i)))
		pt := hashToPoint(pk)
		require.True(t, curve.IsOnCurve(pt.X, pt.Y))
		key := pt.X.String() + ":" + pt.Y.String()
		require.False(t, seen[key], "two distinct keys mapped to the same point")
		seen[key] = true
	}
	require.Len(t, seen, 16)
}

// A one-bit change in the input must move the point.
func TestHashToPointAvalanches(t *testing.T) {
	_, pk := detKey("avalanche")
	base := hashToPoint(pk)
	for bit := range 8 {
		flipped := append([]byte{}, pk...)
		flipped[len(flipped)-1] ^= 1 << bit
		pt := hashToPoint(flipped)
		require.False(t, pt.X.Cmp(base.X) == 0 && pt.Y.Cmp(base.Y) == 0,
			"flipping bit %d left the point unchanged", bit)
	}
}

func TestBatchHashToPointMatchesHashToPoint(t *testing.T) {
	ring, _ := detRing(t, "batch", 5)
	got := batchHashToPoint(ring)
	require.Len(t, got, len(ring))
	for i, pk := range ring {
		want := hashToPoint(pk)
		require.Zero(t, got[i].X.Cmp(want.X), "member %d X", i)
		require.Zero(t, got[i].Y.Cmp(want.Y), "member %d Y", i)
	}

	// lsagVerify treats a nil result as failure; the batch never returns one,
	// not even for an empty ring, so that guard is dead weight rather than a
	// live refusal path.
	require.NotNil(t, batchHashToPoint(nil))
	require.Empty(t, batchHashToPoint(nil))
}

// --- known answers ---------------------------------------------------------
//
// Verification is consensus: two nodes must agree bit for bit. The vectors
// below are frozen outputs of this implementation, so they do not prove the
// construction against an independent reference -- they prove that nobody
// changed it. A refactor that reorders the hash preimage, retags the
// hash-to-curve DST or repacks the wire format is invisible to every
// round-trip test in this file (signer and verifier move together) and
// visible here.

func TestHashRingKnownAnswer(t *testing.T) {
	got := hashRing([]byte("lux-lsag-kat"), big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4))
	require.Equal(t,
		"dc6f21fcc2806f70e34aecbeec8971c5e6632ea2a66d343c5be98e77ee5a7087",
		hex.EncodeToString(got.FillBytes(make([]byte, 32))),
		"the challenge preimage is m || Lx || Ly || Rx || Ry, each field 32 bytes")
}

func TestHashToPointKnownAnswer(t *testing.T) {
	pk, err := hex.DecodeString("03cddbb01f2833ecbebc91cc6d829dec5fe86a18ccf5be1e184f289f87fc1b1b5f")
	require.NoError(t, err)

	pt := hashToPoint(pk)
	require.Equal(t, "8d9ef0d1f41d4fc339b6224751004b9fc51d9c746837b4b297a7f932ee6caf87",
		hex.EncodeToString(pt.X.FillBytes(make([]byte, 32))))
	require.Equal(t, "9fcaf7c0936262836715f0cfecf97225306606d0c67d73b1204269d5f7a2fbbe",
		hex.EncodeToString(pt.Y.FillBytes(make([]byte, 32))))
}

// A frozen calldata blob that must verify, and the key image it links to.
// If this stops returning 0x01, the chain has forked.
func TestVerifyKnownAnswer(t *testing.T) {
	const calldata = "02010302fbeadff55470a0e7360b3e05f1f2dc0b3bed6bdb9000a15588836c4bba0b0cef" +
		"02e43cb5f5382a6364c4a2e3aae4ae6fb5434b79c4bd0c78e070303bc95e4fd0f8" +
		"03029e90b55c2fb065d92463d38162959acad1a209809c87987167ebdd8b8e50800" +
		"2fc91adc4ee21791254d761a1e9b0ba5db7dd50142b623e8fe600b5eed8646884" +
		"4235b30b773993588d4df9b6f53fb20097aaee40e289454e18cf80e0f79fe489" +
		"890eeb8e17510102b16c9e686cca2da17ff1781918ffb31335509ed4d834c191" +
		"c86e0b215de0df08f05ba2319f9bd553286736055154ae38664c9145b69b243a" +
		"3a81e3b513349ec5d4ce45674e67c4e687c867ebb44158120066ddb9e1cb90da" +
		"598e244de7ac3c916a9ebd193571da7087d0b70afb6d821ea9efde6d8b7edf2f" +
		"063c7e009b05a947e2fb5ed5545c55eb91a5c4a66f94315f3ddd6920cc0d8d4f" +
		"6c75782d6c7361672d6b6e6f776e2d616e73776572"

	in, err := hex.DecodeString(calldata)
	require.NoError(t, err)
	require.True(t, verifies(t, in), "the frozen vector must still verify")
	require.Equal(t, uint64(GasVerifyBase+3*GasVerifyPerMember), RingSignaturePrecompile.RequiredGas(in))

	// The key image sits at the head of the signature, after 3 ring members.
	imgAt := headerLen + 1 + 3*CompressedPubKeySize
	require.Equal(t, "02fc91adc4ee21791254d761a1e9b0ba5db7dd50142b623e8fe600b5eed8646884",
		hex.EncodeToString(in[imgAt:imgAt+CompressedPubKeySize]))
}
