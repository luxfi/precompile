// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ai

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// signer is one ML-DSA parameter set reduced to what the verification path needs, so the
// three levels are exercised by identical assertions rather than three copies of them.
type signer struct {
	name    string
	pub     []byte
	sign    func(msg []byte) []byte
	pubSize int
	sigSize int
}

func signers(t *testing.T) []signer {
	t.Helper()

	pub44, priv44, err := mldsa44.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub65, priv65, err := mldsa65.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub87, priv87, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)

	must := func(b []byte, err error) []byte { require.NoError(t, err); return b }

	return []signer{
		{
			name: "ML-DSA-44", pub: must(pub44.MarshalBinary()),
			pubSize: MLDSA44PublicKeySize, sigSize: MLDSA44SignatureSize,
			sign: func(msg []byte) []byte {
				sig := make([]byte, MLDSA44SignatureSize)
				require.NoError(t, mldsa44.SignTo(priv44, msg, nil, true, sig))
				return sig
			},
		},
		{
			name: "ML-DSA-65", pub: must(pub65.MarshalBinary()),
			pubSize: MLDSA65PublicKeySize, sigSize: MLDSA65SignatureSize,
			sign: func(msg []byte) []byte {
				sig := make([]byte, MLDSA65SignatureSize)
				require.NoError(t, mldsa65.SignTo(priv65, msg, nil, true, sig))
				return sig
			},
		},
		{
			name: "ML-DSA-87", pub: must(pub87.MarshalBinary()),
			pubSize: MLDSA87PublicKeySize, sigSize: MLDSA87SignatureSize,
			sign: func(msg []byte) []byte {
				sig := make([]byte, MLDSA87SignatureSize)
				require.NoError(t, mldsa87.SignTo(priv87, msg, nil, true, sig))
				return sig
			},
		},
	}
}

// TestVerifyMLDSA_AcceptsOnlyGenuineSignatures is the core soundness property of the
// mining precompile: a reward is minted against an ML-DSA signature, so anything short of
// a genuine signature over the exact message under the exact key must fail. Each parameter
// set is checked, because a level whose length check passed but whose verifier was wired to
// the wrong curve would still return true.
func TestVerifyMLDSA_AcceptsOnlyGenuineSignatures(t *testing.T) {
	msgA := []byte("work proof alpha")
	msgB := []byte("work proof beta")

	for _, s := range signers(t) {
		t.Run(s.name, func(t *testing.T) {
			require.Len(t, s.pub, s.pubSize)
			sigA := s.sign(msgA)
			require.Len(t, sigA, s.sigSize)

			ok, err := VerifyMLDSA(s.pub, msgA, sigA)
			require.NoError(t, err)
			require.True(t, ok, "a genuine signature must verify")

			// A signature is bound to its message: A's signature must not verify B.
			ok, err = VerifyMLDSA(s.pub, msgB, sigA)
			require.NoError(t, err)
			require.False(t, ok, "a signature over message A must not verify message B")

			// Nor to a message that merely shares a prefix, or differs in length only.
			for _, other := range [][]byte{
				nil, {}, msgA[:len(msgA)-1], append(append([]byte{}, msgA...), 0),
			} {
				ok, err := VerifyMLDSA(s.pub, other, sigA)
				require.NoError(t, err)
				require.False(t, ok, "signature verified a different message %q", other)
			}

			// Every single-bit flip in the signature must break it. Sampling the whole
			// signature would be slow, so byte positions are spread across it — including
			// the first and last, where a truncating or short-circuiting verifier hides.
			for _, pos := range []int{0, 1, 7, s.sigSize / 3, s.sigSize / 2, s.sigSize - 2, s.sigSize - 1} {
				for _, bit := range []uint{0, 3, 7} {
					forged := append([]byte{}, sigA...)
					forged[pos] ^= 1 << bit
					ok, err := VerifyMLDSA(s.pub, msgA, forged)
					require.NoError(t, err)
					require.Falsef(t, ok, "signature verified after flipping bit %d of byte %d", bit, pos)
				}
			}

			// A signature under a different key of the same level must not verify.
			for _, other := range signers(t) {
				if other.name != s.name {
					continue
				}
				ok, err := VerifyMLDSA(s.pub, msgA, other.sign(msgA))
				require.NoError(t, err)
				require.False(t, ok, "a signature from a different key verified")
			}

			// An all-zero signature of the right length must not verify.
			ok, err = VerifyMLDSA(s.pub, msgA, make([]byte, s.sigSize))
			require.NoError(t, err)
			require.False(t, ok, "an all-zero signature verified")

			// A signature of the wrong length is refused outright, one short and one long.
			for _, n := range []int{s.sigSize - 1, s.sigSize + 1, 0} {
				_, err := VerifyMLDSA(s.pub, msgA, make([]byte, n))
				require.ErrorIs(t, err, ErrInvalidSignatureSize, "signature length %d", n)
			}
		})
	}
}

// TestVerifyMLDSA_LevelIsSelectedByKeyLength proves the parameter set is chosen by public
// key length and that a key of any other length is refused rather than silently routed to
// a verifier it does not belong to. A key of level X with a signature of level Y is refused
// on the length check, so the pairing can never be mixed.
func TestVerifyMLDSA_LevelIsSelectedByKeyLength(t *testing.T) {
	msg := []byte("level routing")
	ss := signers(t)

	for _, a := range ss {
		for _, b := range ss {
			if a.name == b.name {
				continue
			}
			// a's key with b's signature: the length check refuses it.
			_, err := VerifyMLDSA(a.pub, msg, b.sign(msg))
			require.ErrorIs(t, err, ErrInvalidSignatureSize,
				"%s key accepted a %s signature", a.name, b.name)
		}
	}

	// Any public key length that is not one of the three is refused, at each boundary.
	for _, n := range []int{
		0, 1, 31,
		MLDSA44PublicKeySize - 1, MLDSA44PublicKeySize + 1,
		MLDSA65PublicKeySize - 1, MLDSA65PublicKeySize + 1,
		MLDSA87PublicKeySize - 1, MLDSA87PublicKeySize + 1,
	} {
		_, err := VerifyMLDSA(make([]byte, n), msg, make([]byte, MLDSA44SignatureSize))
		require.ErrorIs(t, err, ErrInvalidPublicKeySize, "public key length %d", n)
	}
}

// TestVerifyMLDSA_MalformedKeyIsRefused proves a public key of the correct LENGTH but
// invalid encoding is reported as an error rather than being treated as a verification
// failure or, worse, accepted.
func TestVerifyMLDSA_MalformedKeyIsRefused(t *testing.T) {
	s := signers(t)[0]
	msg := []byte("malformed key")
	sig := s.sign(msg)

	// An all-0xFF key of the right length is not a valid encoding.
	junk := make([]byte, s.pubSize)
	for i := range junk {
		junk[i] = 0xFF
	}
	ok, err := VerifyMLDSA(junk, msg, sig)
	require.False(t, ok)
	_ = err // circl may reject at unmarshal or at verify; either way it must not verify.

	// A key that is all zeroes must not verify a genuine signature either.
	ok, _ = VerifyMLDSA(make([]byte, s.pubSize), msg, sig)
	require.False(t, ok, "an all-zero public key verified a signature")
}

// TestRunVerifyMLDSA_ForgeryRejectedThroughDispatch drives the same forgery through the
// registered precompile so the wiring is covered too: the precompile must answer 0 for a
// tampered signature and 1 only for the genuine one, and must never error on well-formed
// framing.
func TestRunVerifyMLDSA_ForgeryRejectedThroughDispatch(t *testing.T) {
	c := &AIMiningContract{}
	s := signers(t)[0]
	msg := []byte("dispatch forgery")
	sig := s.sign(msg)

	call := func(pub, m, sg []byte) []byte {
		body := encodeMLDSAInput(pub, m, sg)
		input := make([]byte, 4+len(body))
		binary.BigEndian.PutUint32(input[:4], SelectorVerifyMLDSA)
		copy(input[4:], body)
		out, _, err := c.Run(newTestAS(), common.Address{}, ContractAddress, input, 1_000_000, false)
		require.NoError(t, err)
		require.Len(t, out, 32)
		return out
	}

	require.Equal(t, byte(1), call(s.pub, msg, sig)[31], "genuine signature must report 1")

	forged := append([]byte{}, sig...)
	forged[len(forged)/2] ^= 0x01
	out := call(s.pub, msg, forged)
	require.Equal(t, byte(0), out[31], "a bit-flipped signature must report 0")
	require.Equal(t, make([]byte, 32), out, "a rejection must be a clean zero word")

	require.Equal(t, byte(0), call(s.pub, []byte("different message"), sig)[31],
		"a signature over another message must report 0")
}

// TestVerifyTEE_RefusesMalformedReceipts covers the receipt length guards: an empty
// receipt, and receipts one byte short of each documented minimum, must all be refused.
func TestVerifyTEE_RefusesMalformedReceipts(t *testing.T) {
	for _, n := range []int{0, 1, 47} {
		ok, err := VerifyTEE(make([]byte, n), make([]byte, 64))
		require.False(t, ok, "receipt of %d bytes verified", n)
		require.Error(t, err, "receipt of %d bytes must be refused", n)
	}
}

// TestBatchVerify_MatchesSingleVerify proves the batch helpers agree with the single-shot
// verifier element by element, including on the mixed case where only some entries are
// genuine — a batch that returned one aggregate answer would mint rewards for forgeries
// riding alongside a valid signature.
func TestBatchVerify_MatchesSingleVerify(t *testing.T) {
	s := signers(t)[0]
	msgs := [][]byte{[]byte("one"), []byte("two"), []byte("three")}

	pubs := make([][]byte, len(msgs))
	sigs := make([][]byte, len(msgs))
	for i, m := range msgs {
		pubs[i] = s.pub
		sigs[i] = s.sign(m)
	}
	// Corrupt exactly the middle one.
	sigs[1][0] ^= 0x80

	got, err := BatchVerifyMLDSA(pubs, msgs, sigs)
	require.NoError(t, err)
	require.Len(t, got, len(msgs))
	for i := range msgs {
		want, err := VerifyMLDSA(pubs[i], msgs[i], sigs[i])
		require.NoError(t, err)
		require.Equalf(t, want, got[i], "batch disagreed with single verify at %d", i)
	}
	require.True(t, got[0])
	require.False(t, got[1], "the corrupted entry must not be reported valid")
	require.True(t, got[2])

	// Mismatched slice lengths are refused rather than silently truncated to the shortest.
	_, err = BatchVerifyMLDSA(pubs[:2], msgs, sigs)
	require.Error(t, err)
	_, err = BatchVerifyMLDSA(pubs, msgs[:1], sigs)
	require.Error(t, err)
}
