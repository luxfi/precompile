// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ring

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// A precompile is judged by what it refuses. Everything below is a refusal:
// the calldata is attacker-chosen, so every path that is not an honest
// signature must end in an error or 0x00 -- never 0x01, and never a panic,
// which in a validator is a chain halt.

// headerLen is op + scheme; ringLen and sigLen follow the wire format.
const headerLen = 2

func ringLen(n int) int { return 1 + n*CompressedPubKeySize }
func sigLen(n int) int  { return CompressedPubKeySize + 2*n*ScalarSize }

// submit runs input the way the EVM does: a window into memory whose spare
// capacity belongs to the caller, who filled it before making the call. Every
// refusal in this file goes through it. Over a fixture built by append the
// spare region is zeroed, so a read past the declared end looks like a run of
// harmless zeros and the test passes whether or not the bound it means to
// exercise is there; 0xA5 makes an over-read visible as an over-read.
func submit(input []byte, gas uint64) ([]byte, uint64, error) {
	return RingSignaturePrecompile.Run(
		nil, common.Address{}, ContractAddress, contract.Poisoned(input, 256), gas, false)
}

// fixture returns a ring, the signer's signature over msg, and the calldata
// that verifies.
func fixture(t *testing.T, label string, n, signer int, msg []byte) (ring [][]byte, sig *LSAGSignature, input []byte) {
	t.Helper()
	ring, sks := detRing(t, label, n)
	sig = mustSign(t, ring, sks[signer], signer, msg, label+"-seed")
	input = buildVerifyInput(SchemeLSAGSecp256k1, ring, sig.Serialize(), msg)
	require.True(t, verifies(t, input), "fixture must verify before it is broken")
	return ring, sig, input
}

// offCurve returns 33 bytes that are not a compressed secp256k1 point.
func offCurve(t *testing.T, label string) []byte {
	t.Helper()
	_, pk := detKey(label)
	bad := append([]byte{}, pk...)
	for i := range 256 {
		bad[CompressedPubKeySize-1] = byte(i)
		if x, _ := secp256k1.DecompressPubkey(bad); x == nil {
			return bad
		}
	}
	t.Fatalf("no off-curve encoding found near %s", label)
	return nil
}

// --- header ---------------------------------------------------------------

func TestRefuseShortCalldata(t *testing.T) {
	for n := range headerLen + 1 {
		in := make([]byte, n)
		if n > 0 {
			in[0] = OpVerify
		}
		if n > 1 {
			in[1] = SchemeLSAGSecp256k1
		}
		// The price is billed off the size byte, so two bytes of calldata must
		// cost nothing even when a third byte lies just past the declared end:
		// reading it would bill 165 members the caller never supplied.
		require.Zero(t, RingSignaturePrecompile.RequiredGas(contract.Poisoned(in, 256)),
			"%d bytes must cost nothing", n)

		_, _, err := submit(in, 1_000_000)
		require.ErrorIs(t, err, ErrInvalidInput, "%d bytes", n)
	}
}

// Short calldata is refused as short calldata whatever it names. The whole
// three-byte header is read before the operation is dispatched, so a two-byte
// call naming an unknown op or scheme still answers ErrInvalidInput rather than
// reporting on the op or the scheme -- both of which are decided by a byte the
// caller did supply, over a size byte they did not.
func TestShortCalldataOutranksWhatItNames(t *testing.T) {
	for _, op := range []byte{0x00, OpVerify, 0xFF} {
		for _, scheme := range []byte{0x00, SchemeLSAGSecp256k1, SchemeLatticeLSAG, 0xFF} {
			for n := range headerLen + 1 {
				_, _, err := submit([]byte{op, scheme}[:n], 1_000_000)
				require.ErrorIs(t, err, ErrInvalidInput,
					"op 0x%02x scheme 0x%02x over %d bytes", op, scheme, n)
			}
		}
	}
}

// Only 0x02 is an operation. 0x01 (sign) and 0x04 (compute key image) took a
// private key in calldata and were removed; they must not come back by accident.
func TestRefuseUnsupportedOp(t *testing.T) {
	for _, op := range []byte{0x00, 0x01, 0x03, 0x04, 0x05, 0x7F, 0xFF} {
		in := append([]byte{op, SchemeLSAGSecp256k1, 2}, make([]byte, 300)...)
		require.Zero(t, RingSignaturePrecompile.RequiredGas(contract.Poisoned(in, 256)),
			"op 0x%02x must cost nothing", op)

		out, _, err := submit(in, 1_000_000)
		require.Error(t, err, "op 0x%02x", op)
		require.Contains(t, err.Error(), "unsupported operation")
		require.Nil(t, out, "a refused op returns no data")
	}
}

// verify() implements exactly one scheme. Every other scheme id -- including
// the ones RequiredGas bills for -- must be refused.
func TestRefuseUnsupportedScheme(t *testing.T) {
	ring, sig, _ := fixture(t, "scheme", 2, 0, []byte("m"))

	for _, scheme := range []byte{0x00, SchemeLSAGEd25519, SchemeDualRing, SchemeLatticeLSAG, 0x11, 0xFF} {
		in := buildVerifyInput(scheme, ring, sig.Serialize(), []byte("m"))
		out, _, err := submit(in, 10_000_000)
		require.ErrorIs(t, err, ErrInvalidScheme, "scheme 0x%02x", scheme)
		require.Nil(t, out)
	}
}

// --- ring size -------------------------------------------------------------

// A ring of one is a signature: it names its signer. Zero is nothing at all.
func TestRefuseRingSmallerThanTwo(t *testing.T) {
	ring, sig, _ := fixture(t, "small", 2, 0, nil)
	body := append(append([]byte{}, ring[0]...), ring[1]...)
	body = append(body, sig.Serialize()...)

	for _, n := range []byte{0, 1} {
		in := append([]byte{OpVerify, SchemeLSAGSecp256k1, n}, body...)
		_, _, err := submit(in, 10_000_000)
		require.ErrorIs(t, err, ErrInvalidRingSize, "ring size %d", n)
	}

	// Two is the first size that is allowed through to parsing.
	in := append([]byte{OpVerify, SchemeLSAGSecp256k1, 2}, body...)
	require.True(t, verifies(t, in))
}

// The size byte is a claim, not a measurement: a large claim over a small
// buffer must be refused rather than read past the end.
func TestRefuseRingLargerThanCalldata(t *testing.T) {
	ring, sig, _ := fixture(t, "overclaim", 2, 0, []byte("m"))
	body := append(append(append([]byte{}, ring[0]...), ring[1]...), sig.Serialize()...)

	for _, n := range []byte{3, 4, 16, 255} {
		in := append([]byte{OpVerify, SchemeLSAGSecp256k1, n}, body...)
		_, _, err := submit(in, 10_000_000)
		require.ErrorIs(t, err, ErrInvalidInput, "declared ring size %d over %d bytes", n, len(body))
	}
}

// The size byte governs two lengths -- the ring and, through it, the signature
// -- and each is measured against the calldata rather than against whatever
// lies behind it. Both fields are walked to exactly one byte past what the call
// carries, so an unbounded read would find 0xA5 and answer over it: not a
// panic, not a halt, just a verdict about bytes nobody declared or paid for.
func TestDeclaredLengthCannotReachPastCalldata(t *testing.T) {
	_, _, in := fixture(t, "reach", 2, 0, nil) // empty message: calldata ends at the signature
	ringEnd := headerLen + ringLen(2)

	// One member short of the two claimed: the missing 33 bytes are in the
	// poisoned tail, and the second member must not be read from there.
	_, _, err := submit(in[:ringEnd-1], 10_000_000)
	require.ErrorIs(t, err, ErrInvalidInput, "a ring of two over one member and a byte")

	// The ring is whole; the signature the size byte implies is one byte short.
	_, _, err = submit(in[:len(in)-1], 10_000_000)
	require.ErrorIs(t, err, ErrInvalidInput, "a signature one byte past the calldata")

	// A size byte far past the calldata: 255 members over a ring of two.
	over := append([]byte{OpVerify, SchemeLSAGSecp256k1, 255}, in[headerLen+1:]...)
	_, _, err = submit(over, 10_000_000)
	require.ErrorIs(t, err, ErrInvalidInput, "255 members over two members' bytes")

	// The exact call still verifies, so the three refusals above are about the
	// declared lengths and nothing else.
	require.True(t, verifies(t, in))
}

// --- length boundaries -----------------------------------------------------

// One byte short of each length-checked field must be refused; the exact
// length must be accepted. Off-by-one in either direction is a parser bug.
func TestFieldLengthBoundaries(t *testing.T) {
	for _, n := range []int{2, 3} {
		_, _, in := fixture(t, "bounds", n, 0, nil) // empty message: input ends at the signature

		ringEnd := headerLen + ringLen(n)
		sigEnd := ringEnd + sigLen(n)
		require.Len(t, in, sigEnd, "an empty message means calldata stops at the signature")

		// One byte short of the size byte, of the ring, and of the signature.
		for _, short := range []int{headerLen, ringEnd - 1, sigEnd - 1} {
			_, _, err := submit(in[:short], 10_000_000)
			require.Error(t, err, "n=%d truncated to %d bytes", n, short)
			require.ErrorIs(t, err, ErrInvalidInput)
		}

		// Exactly the signature's last byte completes a verifying call.
		require.True(t, verifies(t, in[:sigEnd]), "n=%d", n)

		// One byte long: the extra byte becomes a message the signature does
		// not cover, so the answer flips to false rather than staying true.
		require.False(t, verifies(t, append(append([]byte{}, in...), 0x00)), "n=%d", n)
	}
}

// Truncation at any offset must yield an error or a false -- never a true,
// never a panic.
func TestTruncationNeverVerifies(t *testing.T) {
	_, _, in := fixture(t, "trunc", 2, 0, []byte("truncate me"))
	full := headerLen + ringLen(2) + sigLen(2)

	for cut := range len(in) {
		out, _, err := submit(in[:cut], 10_000_000)
		if cut < full {
			require.Error(t, err, "cut=%d must not parse", cut)
			require.Nil(t, out)
			continue
		}
		// Past the signature the message is short, so verification fails.
		require.NoError(t, err, "cut=%d", cut)
		require.Equal(t, []byte{0x00}, out, "cut=%d truncated the message", cut)
	}
}

// Trailing garbage is message, and message is bound.
func TestTrailingBytesAreMessage(t *testing.T) {
	_, _, in := fixture(t, "trail", 2, 0, []byte("bound"))
	require.False(t, verifies(t, append(append([]byte{}, in...), 'x')))
}

// --- malformed points ------------------------------------------------------

func TestRefuseAllZeroBody(t *testing.T) {
	for _, n := range []int{2, 3, 5} {
		in := make([]byte, headerLen+ringLen(n)+sigLen(n)+8)
		in[0] = OpVerify
		in[1] = SchemeLSAGSecp256k1
		in[2] = byte(n)
		out, _, err := submit(in, 10_000_000)
		require.NoError(t, err, "n=%d", n)
		require.Equal(t, []byte{0x00}, out, "an all-zero ring and signature must not verify")
	}
}

// All-zero calldata never even reaches the verifier: op 0x00 is not an op.
func TestRefuseAllZeroCalldata(t *testing.T) {
	for _, n := range []int{1, 3, 64, 512} {
		out, _, err := submit(make([]byte, n), 10_000_000)
		require.Error(t, err, "%d zero bytes", n)
		require.Nil(t, out)
	}
}

func TestRefuseInvalidKeyImage(t *testing.T) {
	ring, sig, _ := fixture(t, "badimg", 2, 0, []byte("m"))

	bad := []struct {
		name string
		img  []byte
	}{
		{"all zero", make([]byte, CompressedPubKeySize)},
		{"bad prefix", append([]byte{0x07}, sig.KeyImage[1:]...)},
		{"off curve x", offCurve(t, "badimg-offcurve")},
		{"x equals field order", append([]byte{0x02}, secp256k1.S256().P.FillBytes(make([]byte, 32))...)},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			broken := &LSAGSignature{KeyImage: tc.img, C: sig.C, S: sig.S}
			in := buildVerifyInput(SchemeLSAGSecp256k1, ring, broken.Serialize(), []byte("m"))
			require.False(t, verifies(t, in))
		})
	}
}

func TestRefuseInvalidRingMember(t *testing.T) {
	ring, sig, _ := fixture(t, "badmember", 3, 0, []byte("m"))

	bad := []struct {
		name   string
		member []byte
	}{
		{"all zero", make([]byte, CompressedPubKeySize)},
		{"bad prefix", append([]byte{0x00}, ring[1][1:]...)},
		{"off curve x", offCurve(t, "badmember-offcurve")},
	}
	for _, tc := range bad {
		for pos := range ring {
			t.Run(fmt.Sprintf("%s/member%d", tc.name, pos), func(t *testing.T) {
				broken := append([][]byte{}, ring...)
				broken[pos] = tc.member
				in := buildVerifyInput(SchemeLSAGSecp256k1, broken, sig.Serialize(), []byte("m"))
				require.False(t, verifies(t, in))
			})
		}
	}
}

// --- scalars ---------------------------------------------------------------

// Regression: a scalar of zero, or at or above the group order, makes
// libsecp256k1's constant-time multiply refuse and hand back a nil point.
// The verify loop passed that nil straight to Add, which dereferenced it:
// 233 bytes of calldata and 9000 gas panicked the precompile, and an
// unrecovered panic in a validator is a halt. Every such scalar must now be
// an ordinary false.
func TestRefusePoisonScalarWithoutPanic(t *testing.T) {
	curve := secp256k1.S256()
	_, img := detKey("poison-image")
	ring, _ := detRing(t, "poison", 2)

	zero := big.NewInt(0)
	order := new(big.Int).Set(curve.N)
	overOrder := new(big.Int).Add(curve.N, big.NewInt(1))
	maxWord := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	one := big.NewInt(1)

	poison := []struct {
		name string
		sig  *LSAGSignature
	}{
		{"s zero", &LSAGSignature{KeyImage: img, C: []*big.Int{one, one}, S: []*big.Int{zero, one}}},
		{"s second zero", &LSAGSignature{KeyImage: img, C: []*big.Int{one, one}, S: []*big.Int{one, zero}}},
		{"s at order", &LSAGSignature{KeyImage: img, C: []*big.Int{one, one}, S: []*big.Int{order, one}}},
		{"s over order", &LSAGSignature{KeyImage: img, C: []*big.Int{one, one}, S: []*big.Int{overOrder, one}}},
		{"s all ones", &LSAGSignature{KeyImage: img, C: []*big.Int{one, one}, S: []*big.Int{maxWord, one}}},
		{"c zero", &LSAGSignature{KeyImage: img, C: []*big.Int{zero, one}, S: []*big.Int{one, one}}},
		{"c at order", &LSAGSignature{KeyImage: img, C: []*big.Int{order, one}, S: []*big.Int{one, one}}},
		{"c over order", &LSAGSignature{KeyImage: img, C: []*big.Int{overOrder, one}, S: []*big.Int{one, one}}},
		{"c all ones", &LSAGSignature{KeyImage: img, C: []*big.Int{maxWord, one}, S: []*big.Int{one, one}}},
		{"all zero", &LSAGSignature{KeyImage: img, C: []*big.Int{zero, zero}, S: []*big.Int{zero, zero}}},
	}

	for _, tc := range poison {
		t.Run(tc.name, func(t *testing.T) {
			in := buildVerifyInput(SchemeLSAGSecp256k1, ring, tc.sig.Serialize(), []byte("poison"))
			out, _, err := submit(in, 10_000_000)
			require.NoError(t, err)
			require.Equal(t, []byte{0x00}, out)
		})
	}
}

// The four-term guard in lsagVerify carries two redundant terms: sGx and sHx
// are multiples of the same response, cPx and cIx of the same challenge. That
// redundancy holds only while a failed multiplication is a property of the
// SCALAR alone -- which is what libsecp256k1 documents (overflow or zero) and
// what the pure-Go fallback trivially satisfies, since it never fails at all.
// Pin the assumption: if a backend ever failed on the POINT instead, half the
// guard would stop being covered by the other half.
func TestScalarFailureDependsOnTheScalarAlone(t *testing.T) {
	curve := secp256k1.S256()
	_, pk := detKey("coupling")
	hp := hashToPoint(pk)
	pkX, pkY := secp256k1.DecompressPubkey(pk)

	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	for _, s := range []*big.Int{
		big.NewInt(0), groupOrder(t), new(big.Int).Add(groupOrder(t), big.NewInt(1)), max,
		big.NewInt(1), big.NewInt(2), new(big.Int).Sub(groupOrder(t), big.NewInt(1)),
	} {
		b := s.Bytes()
		base, _ := curve.ScalarBaseMult(b)
		onHash, _ := curve.ScalarMult(hp.X, hp.Y, b)
		onKey, _ := curve.ScalarMult(pkX, pkY, b)
		require.Equal(t, base == nil, onHash == nil, "scalar %s: base vs H(P)", s)
		require.Equal(t, base == nil, onKey == nil, "scalar %s: base vs P", s)
	}
}

// The same poison reaching lsagVerify directly, so the guard is pinned at the
// function that owns it and not only through the precompile.
func TestLsagVerifyRefusesPoisonScalar(t *testing.T) {
	_, img := detKey("poison-direct-image")
	ring, _ := detRing(t, "poison-direct", 2)
	one := big.NewInt(1)

	require.False(t, lsagVerify(ring,
		&LSAGSignature{KeyImage: img, C: []*big.Int{one, one}, S: []*big.Int{big.NewInt(0), one}}, nil))
	require.False(t, lsagVerify(ring,
		&LSAGSignature{KeyImage: img, C: []*big.Int{big.NewInt(0), one}, S: []*big.Int{one, one}}, nil))
}

// --- mutated signatures ----------------------------------------------------

// Flipping any byte of the signature must break it. The sweep covers the key
// image, every challenge and every response, one byte at a time.
func TestBitFlipAnywhereInSignatureIsRefused(t *testing.T) {
	const n = 2
	ring, sig, _ := fixture(t, "flip", n, 0, []byte("flip me"))
	raw := sig.Serialize()

	// c[1..n-1] are carried on the wire but never read by the verifier, so
	// they are excluded here and pinned separately by
	// TestChallengeTailIsUnbound.
	tail := CompressedPubKeySize + ScalarSize // first byte after c[0]
	unread := CompressedPubKeySize + n*ScalarSize

	for i := range raw {
		if i >= tail && i < unread {
			continue
		}
		broken := append([]byte{}, raw...)
		broken[i] ^= 0xFF
		in := buildVerifyInput(SchemeLSAGSecp256k1, ring, broken, []byte("flip me"))
		require.False(t, verifies(t, in), "flipping signature byte %d left it valid", i)
	}
}

// Flipping any byte of any ring member must break it too -- either the member
// stops being a curve point, or it stops being the member that was signed over.
func TestBitFlipAnywhereInRingIsRefused(t *testing.T) {
	ring, sig, _ := fixture(t, "flipring", 2, 0, []byte("m"))
	for member := range ring {
		for i := range ring[member] {
			broken := append([][]byte{}, ring...)
			m := append([]byte{}, ring[member]...)
			m[i] ^= 0xFF
			broken[member] = m
			in := buildVerifyInput(SchemeLSAGSecp256k1, broken, sig.Serialize(), []byte("m"))
			require.False(t, verifies(t, in), "member %d byte %d", member, i)
		}
	}
}

// The ring is an ordered list: the challenge chain is walked in index order,
// so permuting it must invalidate the signature.
func TestRingOrderIsBound(t *testing.T) {
	ring, sig, _ := fixture(t, "order", 3, 0, []byte("m"))

	swapped := [][]byte{ring[1], ring[0], ring[2]}
	require.False(t, verifies(t, buildVerifyInput(SchemeLSAGSecp256k1, swapped, sig.Serialize(), []byte("m"))))

	rotated := [][]byte{ring[2], ring[0], ring[1]}
	require.False(t, verifies(t, buildVerifyInput(SchemeLSAGSecp256k1, rotated, sig.Serialize(), []byte("m"))))
}

// Substituting a decoy for another honest key must break the signature: an
// attacker must not be able to re-point a signature at a ring of their choosing.
func TestRingSubstitutionIsRefused(t *testing.T) {
	ring, sig, _ := fixture(t, "subst", 3, 0, []byte("m"))
	_, outsider := detKey("subst-outsider")

	for pos := range ring {
		broken := append([][]byte{}, ring...)
		broken[pos] = outsider
		require.False(t, verifies(t, buildVerifyInput(SchemeLSAGSecp256k1, broken, sig.Serialize(), []byte("m"))),
			"member %d swapped for an outsider", pos)
	}
}

// Growing or shrinking the ring around an existing signature must be refused.
func TestRingResizeIsRefused(t *testing.T) {
	ring, sig, _ := fixture(t, "resize", 3, 0, []byte("m"))
	_, extra := detKey("resize-extra")

	grown := append(append([][]byte{}, ring...), extra)
	_, _, err := submit(buildVerifyInput(SchemeLSAGSecp256k1, grown, sig.Serialize(), []byte("m")), 10_000_000)
	require.ErrorIs(t, err, ErrInvalidInput, "a 4-member claim over a 3-member signature is short")

	shrunk := ring[:2]
	require.False(t, verifies(t, buildVerifyInput(SchemeLSAGSecp256k1, shrunk, sig.Serialize(), []byte("m"))))
}

func TestMessageIsBound(t *testing.T) {
	ring, sig, in := fixture(t, "msgbind", 2, 0, []byte("original"))
	require.False(t, verifies(t, buildVerifyInput(SchemeLSAGSecp256k1, ring, sig.Serialize(), []byte("originaL"))))
	require.False(t, verifies(t, buildVerifyInput(SchemeLSAGSecp256k1, ring, sig.Serialize(), []byte("origina"))))
	require.False(t, verifies(t, buildVerifyInput(SchemeLSAGSecp256k1, ring, sig.Serialize(), nil)))
	require.True(t, verifies(t, in))
}

// A signature does not transfer between signers of the same ring.
func TestSignatureDoesNotTransferBetweenMembers(t *testing.T) {
	ring, sks := detRing(t, "transfer", 3)
	msg := []byte("m")
	sig := mustSign(t, ring, sks[0], 0, msg, "transfer-seed")

	// Re-point the key image at another member: the image is what links a
	// spend, so a stolen signature carrying a different image must fail.
	other := mustSign(t, ring, sks[1], 1, msg, "transfer-seed-2")
	stolen := &LSAGSignature{KeyImage: other.KeyImage, C: sig.C, S: sig.S}
	require.False(t, verifies(t, buildVerifyInput(SchemeLSAGSecp256k1, ring, stolen.Serialize(), msg)))
}

// --- pinned behaviour that is not a refusal --------------------------------

// The verifier reads c[0] and recomputes the rest, so c[1..n-1] ride the wire
// unread: a valid signature stays valid with 32*(n-1) bytes rewritten. The
// key image, not the signature encoding, is the unique tag. Anything treating
// signature bytes as an identity is wrong; this pins the shape so a change is
// deliberate rather than accidental.
func TestChallengeTailIsUnbound(t *testing.T) {
	const n = 3
	ring, sig, _ := fixture(t, "tail", n, 0, []byte("m"))
	raw := sig.Serialize()

	for i := CompressedPubKeySize + ScalarSize; i < CompressedPubKeySize+n*ScalarSize; i++ {
		broken := append([]byte{}, raw...)
		broken[i] ^= 0xFF
		require.True(t, verifies(t, buildVerifyInput(SchemeLSAGSecp256k1, ring, broken, []byte("m"))),
			"byte %d of the challenge tail is unread, so the answer must not move", i)
	}

	// c[0] is read, so it is bound.
	for i := CompressedPubKeySize; i < CompressedPubKeySize+ScalarSize; i++ {
		broken := append([]byte{}, raw...)
		broken[i] ^= 0xFF
		require.False(t, verifies(t, buildVerifyInput(SchemeLSAGSecp256k1, ring, broken, []byte("m"))),
			"byte %d of c[0] must be bound", i)
	}
}

// A ring may name the same key twice. The precompile does not deduplicate, so
// a caller who reads "ring size 4" as "one of four possible signers" can be
// handed four copies of one key. Pinned, not fixed: rejecting duplicates would
// change which signatures are valid.
func TestDuplicateRingMembersAreAccepted(t *testing.T) {
	sk, pk := detKey("dup/signer")
	_, decoy := detKey("dup/decoy")
	ring := [][]byte{pk, pk, decoy}
	msg := []byte("degenerate ring")

	sig := mustSign(t, ring, sk, 0, msg, "dup-seed")
	require.True(t, verifies(t, buildVerifyInput(SchemeLSAGSecp256k1, ring, sig.Serialize(), msg)),
		"the anonymity set here is 2, not 3")
}

// --- direct calls to guards the precompile cannot reach --------------------

// The size byte is a claim, and verify takes each member from the cursor, so a
// ring larger than what is left runs out instead of reading past it.
// TestRefuseRingLargerThanCalldata reaches this through the precompile; here it
// is pinned on the function, at the two boundaries a ring of two can miss by.
func TestVerifyRefusesRingItCannotFill(t *testing.T) {
	out, err := RingSignaturePrecompile.verify(SchemeLSAGSecp256k1, 2, contract.Read(nil))
	require.ErrorIs(t, err, ErrInvalidInput, "no members at all")
	require.Nil(t, out)

	oneMember := contract.Poisoned(make([]byte, CompressedPubKeySize), 256)
	out, err = RingSignaturePrecompile.verify(SchemeLSAGSecp256k1, 2, contract.Read(oneMember))
	require.ErrorIs(t, err, ErrInvalidInput, "the second member exists only past the declared end")
	require.Nil(t, out)
}

// verify slices the signature to exactly the length parseLSAGSignature needs,
// so its short-data refusal is only reachable directly.
func TestParseRefusesShortSignature(t *testing.T) {
	// Every scalar field is 0x0101..01: small, but inside [1, N-1].
	ones := func(n int) []byte { return bytes.Repeat([]byte{1}, n) }

	for _, n := range []int{2, 3, 8} {
		want := sigLen(n)
		_, err := parseLSAGSignature(ones(want-1), n)
		require.ErrorIs(t, err, ErrInvalidSignature, "n=%d one byte short", n)

		sig, err := parseLSAGSignature(ones(want), n)
		require.NoError(t, err, "n=%d exact", n)
		require.Len(t, sig.C, n)
		require.Len(t, sig.S, n)

		// Extra bytes are ignored, not an error: verify already bounded them.
		_, err = parseLSAGSignature(ones(want+64), n)
		require.NoError(t, err)
	}
	_, err := parseLSAGSignature(nil, 2)
	require.ErrorIs(t, err, ErrInvalidSignature)
}

// secp256k1's group order, written out rather than read from the package
// under test: a bound checked against itself moves with any change to it.
// SEC 2 v2, section 2.4.1.
func groupOrder(t *testing.T) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	require.True(t, ok)
	return n
}

// The boundary the canonicality rule is drawn at must be the group order --
// not the field prime, which is about 2^129 larger and would admit that many
// non-canonical encodings of every scalar.
func TestScalarBoundIsTheGroupOrder(t *testing.T) {
	require.Zero(t, order.Cmp(groupOrder(t)))
	require.NotZero(t, order.Cmp(secp256k1.S256().P), "the field prime is not the group order")
}

// Every scalar on the wire must be a group element in [1, N-1]. Zero has no
// curve multiple; a value at or above N is a second encoding of one below it.
// libsecp256k1 refuses both, the pure-Go fallback reduces them silently, so
// without this rule the same calldata verifies on a CGO_ENABLED=0 build and
// is refused on a cgo one -- two builds of one node, two answers.
func TestParseRefusesNonCanonicalScalar(t *testing.T) {
	const n = 2
	good := bytes.Repeat([]byte{1}, sigLen(n))
	N := groupOrder(t)

	bad := []struct {
		name  string
		value *big.Int
	}{
		{"zero", big.NewInt(0)},
		{"the group order", N},
		{"one above the order", new(big.Int).Add(N, big.NewInt(1))},
		{"the field prime", secp256k1.S256().P},
		{"all ones", new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))},
	}

	// Every scalar slot, challenges and responses alike.
	for slot := range 2 * n {
		at := CompressedPubKeySize + slot*ScalarSize
		for _, tc := range bad {
			t.Run(fmt.Sprintf("%s/slot%d", tc.name, slot), func(t *testing.T) {
				data := append([]byte{}, good...)
				tc.value.FillBytes(data[at : at+ScalarSize])
				_, err := parseLSAGSignature(data, n)
				require.ErrorIs(t, err, ErrInvalidSignature)
			})
		}
	}

	// One below the order is the largest value that is still a scalar.
	data := append([]byte{}, good...)
	new(big.Int).Sub(N, big.NewInt(1)).FillBytes(data[CompressedPubKeySize : CompressedPubKeySize+ScalarSize])
	_, err := parseLSAGSignature(data, n)
	require.NoError(t, err, "N-1 is a scalar")
}

// The same rule seen through the precompile: a response shifted by the group
// order must not verify. Without it the shifted signature is a second valid
// encoding of a signature that already exists -- malleability -- and one that
// only some builds accept.
func TestShiftedResponseIsRefused(t *testing.T) {
	ring, sig, in := fixture(t, "shift", 2, 0, []byte("m"))

	shifted := &LSAGSignature{
		KeyImage: sig.KeyImage,
		C:        sig.C,
		S:        []*big.Int{new(big.Int).Add(sig.S[0], groupOrder(t)), sig.S[1]},
	}
	// Adding N overflows 32 bytes for a full-width response, so Serialize
	// truncates; assert on the value we actually put on the wire instead.
	raw := shifted.Serialize()
	parsed, err := parseLSAGSignature(raw, 2)
	if err == nil {
		require.NotZero(t, parsed.S[0].Cmp(shifted.S[0]),
			"a value that survives 32 bytes must have been refused")
	}
	require.False(t, verifies(t, buildVerifyInput(SchemeLSAGSecp256k1, ring, raw, []byte("m"))))
	require.True(t, verifies(t, in), "the unshifted original still verifies")
}

// An empty ring has no challenge chain to close, so lsagVerify falls out of
// the loop. verify() refuses sizes below two, so only a direct caller gets here.
func TestLsagVerifyRefusesEmptyRing(t *testing.T) {
	_, img := detKey("emptyring")
	sig := &LSAGSignature{
		KeyImage: img,
		C:        []*big.Int{big.NewInt(1)},
		S:        []*big.Int{big.NewInt(1)},
	}
	require.False(t, lsagVerify(nil, sig, nil))
	require.False(t, lsagVerify([][]byte{}, sig, []byte("m")))
}
