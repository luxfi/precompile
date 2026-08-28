// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package p3q

import (
	"encoding/binary"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// katSet groups one parameter set's frozen material with the sizes the
// precompile will hold it to.
type katSet struct {
	name      string
	mode      uint8
	pub       string
	sig       string
	foreign   string
	pkSize    int
	sigSize   int
	msgHexVar string
}

func katSets() []katSet {
	return []katSet{
		{"ML-DSA-44", ModeMLDSA44, katPKHex, katSIGHex, "", MLDSA44PublicKeySize, MLDSA44SignatureSize, katMSGHex},
		{"ML-DSA-65", ModeMLDSA65, kat65PubHex, kat65SigHex, kat65ForeignSigHex, MLDSA65PublicKeySize, MLDSA65SignatureSize, katExtMsgHex},
		{"ML-DSA-87", ModeMLDSA87, kat87PubHex, kat87SigHex, kat87ForeignSigHex, MLDSA87PublicKeySize, MLDSA87SignatureSize, katExtMsgHex},
	}
}

// verdict runs the precompile with ample gas and reports the boolean
// word it produced. P3Q never reverts on a cryptographic outcome, so
// the verdict is the output word, not the error.
func verdict(t *testing.T, input []byte) bool {
	t.Helper()
	out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress,
		input, P3QVerifyPrecompile.RequiredGas(input), true)
	require.NoError(t, err, "a well-funded call must not error")
	require.Len(t, out, 32, "output is always an ABI bool word")
	return out[31] == 1
}

// TestKATEverySetAccepts is the positive known-answer test across all
// three FIPS 204 parameter sets. The pre-existing suite froze only
// ML-DSA-44; 65 is the production target and 87 the Category 5 set,
// and a verifier miswired for either would have gone unseen.
func TestKATEverySetAccepts(t *testing.T) {
	for _, k := range katSets() {
		t.Run(k.name, func(t *testing.T) {
			pk, sig, msg := mustHex(t, k.pub), mustHex(t, k.sig), mustHex(t, k.msgHexVar)
			require.Len(t, pk, k.pkSize, "frozen key must match the declared FIPS 204 size")
			require.Len(t, sig, k.sigSize, "frozen signature must match the declared FIPS 204 size")

			require.True(t, verdict(t, EncodeInput(k.mode, sig, pk, msg)))
			require.NoError(t, Verify(k.mode, pk, sig, msg),
				"the standalone entry point must agree with the precompile")
		})
	}
}

// TestKATRejectsSiblingSlotSignature is the cross-slot replay refusal,
// and the reason PrecompileCtx is a security control rather than a
// label.
//
// Each foreign vector is a genuine, verifying ML-DSA signature — same
// key, same message, same parameter set — that differs from the
// accepted one only in the FIPS 204 context string it was minted
// under: the Pulsar slot's ("lux-evm-precompile-pulsar-v1", 0x012204)
// instead of this slot's. P3Q and Pulsar share a verifier core, so
// without context binding a signature harvested from one slot's
// calldata would be replayable at the other verbatim. Tampered bytes
// cannot demonstrate this; only a real signature under a real rival
// context can.
func TestKATRejectsSiblingSlotSignature(t *testing.T) {
	for _, k := range katSets() {
		if k.foreign == "" {
			continue
		}
		t.Run(k.name, func(t *testing.T) {
			pk, msg := mustHex(t, k.pub), mustHex(t, k.msgHexVar)
			foreign := mustHex(t, k.foreign)
			require.Len(t, foreign, k.sigSize,
				"the foreign vector must be structurally indistinguishable from an accepted one")

			require.False(t, verdict(t, EncodeInput(k.mode, foreign, pk, msg)),
				"a Pulsar-context signature must not verify at the P3Q slot")
			require.Error(t, Verify(k.mode, pk, foreign, msg))

			// The refusal must come from the context, not from some
			// incidental difference: the accepted vector, identical in
			// every structural respect, is taken.
			require.True(t, verdict(t, EncodeInput(k.mode, mustHex(t, k.sig), pk, msg)))
		})
	}
}

// TestKATRejectsBitFlipEverySet sweeps a single-bit flip across each
// frozen signature. Positions are chosen to land in the c-tilde
// challenge, the z vector and the hint region rather than clustering
// at one offset.
func TestKATRejectsBitFlipEverySet(t *testing.T) {
	for _, k := range katSets() {
		t.Run(k.name, func(t *testing.T) {
			pk, msg := mustHex(t, k.pub), mustHex(t, k.msgHexVar)
			for _, pos := range []int{0, 31, 32, k.sigSize / 4, k.sigSize / 2, k.sigSize - 1} {
				sig := mustHex(t, k.sig)
				sig[pos] ^= 0x01
				require.False(t, verdict(t, EncodeInput(k.mode, sig, pk, msg)),
					"bit flip at sig[%d] must reject", pos)
			}
		})
	}
}

// TestKATRejectsCrossSetSubstitution pins parameter-set binding: a
// vector from one set submitted under another set's mode byte must
// never be accepted, whether the sizes happen to line up or not.
func TestKATRejectsCrossSetSubstitution(t *testing.T) {
	sets := katSets()
	for _, have := range sets {
		for _, claim := range sets {
			if have.mode == claim.mode {
				continue
			}
			t.Run(have.name+"_as_"+claim.name, func(t *testing.T) {
				require.False(t, verdict(t, EncodeInput(claim.mode,
					mustHex(t, have.sig), mustHex(t, have.pub), mustHex(t, have.msgHexVar))))
			})
		}
	}
}

// TestKATRejectsForeignKey pins key binding across sets: the frozen
// signature of one set must not verify under another set's public key,
// nor under an all-zero key of the right length.
func TestKATRejectsForeignKey(t *testing.T) {
	for _, k := range katSets() {
		t.Run(k.name, func(t *testing.T) {
			sig, msg := mustHex(t, k.sig), mustHex(t, k.msgHexVar)
			require.False(t, verdict(t, EncodeInput(k.mode, sig, make([]byte, k.pkSize), msg)),
				"an all-zero key must not verify a real signature")

			flipped := mustHex(t, k.pub)
			flipped[0] ^= 0x01 // inside rho, which seeds the A matrix
			require.False(t, verdict(t, EncodeInput(k.mode, sig, flipped, msg)))

			flipped = mustHex(t, k.pub)
			flipped[k.pkSize-1] ^= 0x01 // inside t1
			require.False(t, verdict(t, EncodeInput(k.mode, sig, flipped, msg)))
		})
	}
}

// TestParseRefusesTruncationAtEveryField walks the wire format field
// by field and truncates just past each one, so every incremental
// bounds check in the parser is exercised by an input that reaches it.
//
// The layout is kind || mode || u32 sigLen || sig || u32 pkLen || pk
// || hash32. Each case below is structurally long enough to clear
// MinInputLength and then runs out at a different field.
func TestParseRefusesTruncationAtEveryField(t *testing.T) {
	k := katSets()[0] // ML-DSA-44: smallest blobs
	pk, sig, msg := mustHex(t, k.pub), mustHex(t, k.sig), mustHex(t, k.msgHexVar)
	full := EncodeInput(k.mode, sig, pk, msg)
	require.True(t, verdict(t, full), "the untruncated input is the control")

	be32 := func(v uint32) []byte {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		return b[:]
	}
	head := func() []byte { return []byte{KindPulsar, k.mode} }

	t.Run("fewer than 4 bytes remain for the pubkey length", func(t *testing.T) {
		in := append(head(), be32(uint32(k.sigSize))...)
		in = append(in, sig...)
		in = append(in, 0x00, 0x00, 0x00) // 3 bytes: one short of the length field
		require.GreaterOrEqual(t, len(in), MinInputLength)
		require.False(t, verdict(t, in))
	})

	t.Run("declared pubkey length overruns the buffer", func(t *testing.T) {
		in := append(head(), be32(uint32(k.sigSize))...)
		in = append(in, sig...)
		in = append(in, be32(uint32(k.pkSize))...)
		in = append(in, pk[:k.pkSize-1]...) // one byte short of the key
		in = append(in, msg...)
		require.False(t, verdict(t, in))
	})

	t.Run("declared pubkey length is absurd", func(t *testing.T) {
		in := append(head(), be32(uint32(k.sigSize))...)
		in = append(in, sig...)
		in = append(in, be32(^uint32(0))...) // 4 GiB of key claimed
		in = append(in, pk...)
		in = append(in, msg...)
		require.NotPanics(t, func() { require.False(t, verdict(t, in)) })
	})

	t.Run("message hash truncated", func(t *testing.T) {
		short := full[:len(full)-1]
		require.GreaterOrEqual(t, len(short), MinInputLength)
		require.False(t, verdict(t, short), "31 bytes of hash is not a hash")
	})

	t.Run("message hash absent entirely", func(t *testing.T) {
		in := append(head(), be32(uint32(k.sigSize))...)
		in = append(in, sig...)
		in = append(in, be32(uint32(k.pkSize))...)
		in = append(in, pk...)
		require.False(t, verdict(t, in))
	})

	t.Run("declared signature length overruns the buffer", func(t *testing.T) {
		in := append(head(), be32(^uint32(0))...)
		in = append(in, sig...)
		in = append(in, be32(uint32(k.pkSize))...)
		in = append(in, pk...)
		in = append(in, msg...)
		require.NotPanics(t, func() { require.False(t, verdict(t, in)) })
	})
}

// TestVerifyRejectsWrongHashLength pins the standalone entry point's
// precondition on the digest. P3Q binds a fixed 32-byte hash — that is
// the whole distinction from the variable-length Pulsar slot — so a
// 31- or 33-byte "hash" must be a typed error, never a silent pad or
// truncate that would let two different digests share a signature.
func TestVerifyRejectsWrongHashLength(t *testing.T) {
	k := katSets()[1] // ML-DSA-65
	pk, sig := mustHex(t, k.pub), mustHex(t, k.sig)
	msg := mustHex(t, k.msgHexVar)

	require.NoError(t, Verify(k.mode, pk, sig, msg), "control: the right length verifies")

	for _, n := range []int{0, 1, MessageHashSize - 1, MessageHashSize + 1, 64} {
		require.Error(t, Verify(k.mode, pk, sig, make([]byte, n)),
			"a %d-byte digest must be refused", n)
	}
}

// TestVerifyRejectsUnknownMode pins the standalone entry point's mode
// discrimination over the whole byte range, so no unlisted value can
// be coerced into a neighbouring parameter set.
func TestVerifyRejectsUnknownMode(t *testing.T) {
	k := katSets()[0]
	pk, sig, msg := mustHex(t, k.pub), mustHex(t, k.sig), mustHex(t, k.msgHexVar)
	known := map[uint8]bool{ModeMLDSA44: true, ModeMLDSA65: true, ModeMLDSA87: true}
	for b := 0; b < 256; b++ {
		if known[uint8(b)] {
			continue
		}
		require.ErrorIs(t, Verify(uint8(b), pk, sig, msg), ErrUnsupportedMode,
			"mode 0x%02x must be refused by name", b)
	}
}
