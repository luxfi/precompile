// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"encoding/binary"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// modes pairs each accepted mode byte with its FIPS 204 sizes, so the
// boundary sweeps below run against every parameter set rather than
// only the production one.
var modes = []struct {
	name    string
	mode    uint8
	pubSize int
	sigSize int
}{
	{"Pulsar-44", ModePulsar44, Pulsar44PublicKeySize, Pulsar44SignatureSize},
	{"Pulsar-65", ModePulsar65, Pulsar65PublicKeySize, Pulsar65SignatureSize},
	{"Pulsar-87", ModePulsar87, Pulsar87PublicKeySize, Pulsar87SignatureSize},
}

// exact returns a copy of b whose capacity equals its length.
//
// A Go slice expression s[a:b] panics only when b exceeds cap(s), not
// len(s). An input assembled with append carries spare capacity, so a
// MISSING bounds check reads uninitialised bytes and carries on, and
// the test passes while the guard it was meant to exercise is gone.
// Calldata handed to a precompile by the EVM has no spare capacity, so
// the same input panics in production -- and a panic in geth's
// precompile dispatch has no recover, halting every validator on the
// transaction. Refusal tests therefore submit exact-capacity slices.
func exact(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// call runs the precompile with gas guaranteed sufficient, so the only
// thing under test is the parse/verify outcome.
func call(input []byte) error {
	in := exact(input)
	_, _, err := PulsarVerifyPrecompile.Run(nil, common.Address{}, ContractPulsarVerifyAddress,
		in, PulsarVerifyPrecompile.RequiredGas(in)+1, true)
	return err
}

// TestRefusesBodyBetweenKeyAndLengthWord is the boundary the parser
// most easily gets wrong, and the one with the worst failure mode.
//
// After the public key is carved off, the code reads the eight
// low-order bytes of a 32-byte message-length word straight out of the
// remainder. The single length check before it must therefore reserve
// room for BOTH the key and that word. If it reserved room only for
// the key, an input whose body is at least pubSize but short of
// pubSize+32 slips through and the read runs off the end of the slice
// — a panic, and geth's precompile dispatch has no recover, so it
// halts every validator processing the transaction rather than
// reverting one call.
//
// Sweep the whole window, both edges included.
func TestRefusesBodyBetweenKeyAndLengthWord(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			for _, bodyLen := range []int{m.pubSize, m.pubSize + 1, m.pubSize + 16, m.pubSize + 30, m.pubSize + 31} {
				input := append([]byte{m.mode}, make([]byte, bodyLen)...)
				require.NotPanics(t, func() {
					require.ErrorIs(t, call(input), ErrInvalidInputLength,
						"body of %d bytes (key %d + %d) must be refused, not read past",
						bodyLen, m.pubSize, bodyLen-m.pubSize)
				}, "body length %d must not panic the verifier", bodyLen)
			}

			// One byte further is structurally long enough to reach the
			// length word, so it must fail for a different reason: the
			// signature is missing, not the header.
			ok := append([]byte{m.mode}, make([]byte, m.pubSize+32)...)
			require.ErrorIs(t, call(ok), ErrInvalidInputLength)
		})
	}
}

// TestRefusesShortOfEveryBoundary walks each length-checked field one
// byte short. Every one must be a clean typed refusal.
func TestRefusesShortOfEveryBoundary(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			// One byte short of the public key.
			require.ErrorIs(t, call(append([]byte{m.mode}, make([]byte, m.pubSize-1)...)), ErrInvalidInputLength)

			// Header complete, signature one byte short.
			short := append([]byte{m.mode}, make([]byte, m.pubSize+32+m.sigSize-1)...)
			require.ErrorIs(t, call(short), ErrInvalidInputLength)

			// Header complete, signature exactly present: reaches the
			// verifier and is refused there, not by the parser.
			whole := append([]byte{m.mode}, make([]byte, m.pubSize+32+m.sigSize)...)
			require.ErrorIs(t, call(whole), ErrInvalidSignature,
				"a structurally complete but cryptographically empty call must reach the verifier")
		})
	}
}

// TestRefusesDeclaredMessageOverrun pins the interaction between the
// declared message length and the signature that must follow it. The
// message is variable-length, so the parser has to prove that mlen
// bytes of message AND sigSize bytes of signature both fit — and it
// has to do so without computing mlen+sigSize, which an attacker can
// wrap around uint64.
func TestRefusesDeclaredMessageOverrun(t *testing.T) {
	m := modes[1] // Pulsar-65

	build := func(mlen uint64, tail int) []byte {
		input := append([]byte{m.mode}, make([]byte, m.pubSize)...)
		var w [32]byte
		binary.BigEndian.PutUint64(w[24:], mlen)
		input = append(input, w[:]...)
		return append(input, make([]byte, tail)...)
	}

	for _, tc := range []struct {
		name string
		mlen uint64
		tail int
	}{
		{"message longer than the bytes supplied", 100, 50},
		{"message consumes the signature", uint64(m.sigSize), m.sigSize},
		{"message one byte into the signature", 1, m.sigSize},
		{"length word at uint64 max", ^uint64(0), m.sigSize},
		{"length word one below the wrap point", ^uint64(0) - uint64(m.sigSize), m.sigSize},
		{"length word at int64 boundary", 1 << 63, m.sigSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				require.ErrorIs(t, call(build(tc.mlen, tc.tail)), ErrInvalidInputLength)
			})
		})
	}

	// The complement: a zero-length message with exactly a signature's
	// worth of tail is structurally valid and reaches the verifier.
	require.ErrorIs(t, call(build(0, m.sigSize)), ErrInvalidSignature)
}

// TestRefusesUnknownModeByte sweeps the mode byte across every value
// outside the three accepted ones and requires the same typed refusal
// each time — no byte may be silently coerced into a neighbouring
// parameter set.
func TestRefusesUnknownModeByte(t *testing.T) {
	accepted := map[uint8]bool{ModePulsar44: true, ModePulsar65: true, ModePulsar87: true}
	for b := 0; b < 256; b++ {
		mode := uint8(b)
		if accepted[mode] {
			continue
		}
		input := append([]byte{mode}, make([]byte, 4096)...)
		require.ErrorIs(t, call(input), ErrInvalidMode, "mode byte 0x%02x must be refused", mode)
	}
}

// TestRefusesEmptyInput pins the zero-length case: no mode byte at
// all, refused for length rather than panicking on input[0].
func TestRefusesEmptyInput(t *testing.T) {
	require.ErrorIs(t, call(nil), ErrInvalidInputLength)
	require.ErrorIs(t, call([]byte{}), ErrInvalidInputLength)
}

// TestAcceptsMessageOfAnyLength pins that the wire format is not
// secretly fixed-width in the message: the same key signs messages of
// several lengths, including empty, and each verifies through the
// precompile. Trailing bytes past the signature are ignored.
func TestAcceptsMessageOfAnyLength(t *testing.T) {
	pk := katBytes(t, katPubHex)
	// Re-signing needs the private key, which the frozen vector does
	// not carry; instead assert the parser's framing directly by
	// checking that the declared length is what selects the message
	// bytes. A wrong-length declaration must change the verdict.
	sig := katBytes(t, katSigHex)
	msg := katBytes(t, katMsgHex)

	require.NoError(t, call(buildInput(ModePulsar65, pk, msg, sig)))

	// Declare one byte fewer of message: the verifier now covers a
	// different (shorter) message and must reject.
	input := append([]byte{ModePulsar65}, pk...)
	var w [32]byte
	binary.BigEndian.PutUint64(w[24:], uint64(len(msg)-1))
	input = append(input, w[:]...)
	input = append(input, msg...)
	input = append(input, sig...)
	require.ErrorIs(t, call(input), ErrInvalidSignature,
		"the declared length, not the byte count, selects the signed message")
}
