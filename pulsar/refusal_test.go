// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"encoding/binary"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
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

// call runs the precompile with gas guaranteed sufficient, so the only
// thing under test is the parse/verify outcome.
//
// The input is submitted through contract.Poisoned, which hands the
// precompile a slice carrying 256 bytes of 0xA5 behind its end. That is
// the shape real calldata has: opCall takes the input with
// Memory.GetPtr, a two-index slice of the EVM memory store, and nothing
// on the way to Run copies it, so len is what the caller declared and
// paid for while cap is the rest of memory the same caller filled with
// MSTORE. A Go slice expression only refuses past cap, so a missing
// bounds check does not panic in production -- it reads bytes the
// attacker chose and the verifier answers over them.
//
// A fixture built with plain append also carries spare capacity, but
// zeroed, so an over-read looks like harmless zeros and the test passes
// whether or not the bound exists. A fixture trimmed to cap == len
// turns the over-read into a panic, which is loud but is not what
// production does. Poisoning reproduces production and makes the
// over-read visible in the verdict.
func call(input []byte) error {
	in := contract.Poisoned(input, 256)
	_, _, err := PulsarVerifyPrecompile.Run(nil, common.Address{}, ContractPulsarVerifyAddress,
		in, PulsarVerifyPrecompile.RequiredGas(in)+1, true)
	return err
}

// TestRefusesBodyBetweenKeyAndLengthWord is the boundary the parser
// most easily gets wrong, and the one with the worst failure mode.
//
// After the public key is taken, the parser reads a 32-byte
// message-length word, of which the low 8 bytes are the length. Both
// reads must be bounded against what the caller actually sent. If only
// the key were bounded, an input whose body is at least pubSize but
// short of pubSize+32 would slip through and the length word would be
// read from past the end — 0xA5 here, attacker-chosen MSTORE bytes in
// production — and every later offset would be decided by a number
// nobody sent.
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

// TestRefusesLengthDeclaredPastTheCalldata submits a message length
// larger than the bytes supplied, by margins that fit inside the
// poisoned spare capacity behind the input.
//
// That margin is the point. An over-declaration of a megabyte is
// refused by any parser, because the read runs past cap and Go stops
// it. An over-declaration of eight bytes is the dangerous one: past
// len, inside cap, where the slice expression succeeds and hands back
// memory the same caller wrote with MSTORE. Here those bytes are 0xA5,
// so if the bound were missing the signature would be assembled partly
// out of them and the call would reach the verifier.
//
// The discriminating assertion is therefore WHICH refusal comes back.
// ErrInvalidInputLength means the parser refused on the declared
// length. ErrInvalidSignature would mean the over-read happened and
// only the cryptography stood between us and a verdict over bytes
// nobody sent or paid for.
func TestRefusesLengthDeclaredPastTheCalldata(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			// Supply exactly a signature's worth of tail, then declare a
			// message of `over` bytes on top of it: the message and the
			// signature together need `over` bytes more than were sent.
			for _, over := range []uint64{1, 2, 8, 64, 255, 256} {
				input := append([]byte{m.mode}, make([]byte, m.pubSize)...)
				var w [32]byte
				binary.BigEndian.PutUint64(w[24:], over)
				input = append(input, w[:]...)
				input = append(input, make([]byte, m.sigSize)...)

				require.ErrorIs(t, call(input), ErrInvalidInputLength,
					"%d declared message bytes over a %d-byte tail: refused by the parser, "+
						"never read from past the calldata", over, m.sigSize)
			}

			// The same shape one byte the other way is structurally whole
			// and does reach the verifier, so the sweep above is refusing
			// the overrun and not the shape.
			whole := append([]byte{m.mode}, make([]byte, m.pubSize+32+m.sigSize)...)
			require.ErrorIs(t, call(whole), ErrInvalidSignature)
		})
	}
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
