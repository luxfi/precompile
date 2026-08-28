// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// Offsets of the two length headers inside a frame whose mode is katMode
// (SHA2-128s, 32-byte public key). Named here so the boundary tests read as
// "patch this field" rather than as arithmetic.
const (
	pubKeyLenOffset = ModeByte                                       // 1
	msgLenOffset    = ModeByte + PubKeyLenSize + SLH128PublicKeySize // 35
	katFrameSize    = msgLenOffset + MessageLenSize + 32 + SLHSHA2_128sSignatureSize
)

// patch16 copies frame and overwrites the big-endian uint16 at off.
func patch16(frame []byte, off int, v uint16) []byte {
	out := append([]byte(nil), frame...)
	binary.BigEndian.PutUint16(out[off:off+2], v)
	return out
}

// zeroFrame builds a well-formed, all-zero frame for mode: correct declared
// public key length, zero-length message, all-zero key and signature. Every
// length check passes, so the frame reaches the verifier, which must refuse it.
func zeroFrame(t *testing.T, mode uint8) []byte {
	t.Helper()
	pkSize, sigSize, _, _, err := getModeParams(mode)
	require.NoError(t, err)
	frame := make([]byte, ModeByte+PubKeyLenSize+pkSize+MessageLenSize+sigSize)
	frame[0] = mode
	binary.BigEndian.PutUint16(frame[ModeByte:ModeByte+PubKeyLenSize], uint16(pkSize))
	return frame
}

// TestAddress pins the canonical LP-4200 slot on the interface method, not just
// on the package variable: the module registers Contract.Address(), so a method
// returning some other address would register the precompile at the wrong slot.
func TestAddress(t *testing.T) {
	require.Equal(t, ContractMagnetarVerifyAddress, MagnetarVerifyPrecompile.Address())
	require.Equal(t,
		common.HexToAddress("0x0000000000000000000000000000000000012207"),
		MagnetarVerifyPrecompile.Address())
}

// TestRun_RejectsShortHeader walks the minimum-header boundary one byte at a
// time. Two bytes is one short and must be refused for the header; three bytes
// is exactly the header, so the refusal has to move on to the next field.
func TestRun_RejectsShortHeader(t *testing.T) {
	for _, in := range [][]byte{nil, {}, {ModeSHA2_128s}, {ModeSHA2_128s, 0x00}} {
		out, err := call(t, in)
		require.ErrorIs(t, err, ErrInvalidInputLength, "len=%d", len(in))
		require.ErrorContains(t, err, "need at least 3 bytes", "len=%d", len(in))
		require.Nil(t, out)
	}

	// One byte longer: the header is complete, so the declared public key
	// length (zero) is what fails now.
	out, err := call(t, []byte{ModeSHA2_128s, 0x00, 0x00})
	require.ErrorIs(t, err, ErrInvalidInputLength)
	require.ErrorContains(t, err, "expected pubkey size 32")
	require.Nil(t, out)

	// Both header fields are read before the mode is resolved, so short
	// calldata is refused as short calldata whatever byte sits at offset 0.
	// Resolving the mode first would answer ErrUnsupportedMode for a call that
	// is missing its header -- reporting on a field the caller never supplied.
	for _, mode := range []uint8{ModeSHA2_128s, ModeSHAKE_256f, 0x06, 0x7F, 0xFF} {
		for _, in := range [][]byte{{mode}, {mode, 0x00}} {
			_, err := call(t, in)
			require.ErrorIs(t, err, ErrInvalidInputLength, "mode=0x%02x len=%d", mode, len(in))
			require.ErrorContains(t, err, "need at least 3 bytes", "mode=0x%02x", mode)
		}
	}
}

// TestRun_RejectsUnknownMode sweeps all 256 mode bytes. Exactly the twelve
// FIPS 205 parameter sets may pass the mode check; every other byte must be
// refused as unsupported before any length arithmetic happens.
func TestRun_RejectsUnknownMode(t *testing.T) {
	known := map[uint8]bool{}
	for _, m := range allModes {
		known[m] = true
	}
	require.Len(t, known, 12)

	for b := 0; b < 256; b++ {
		mode := uint8(b)
		_, err := call(t, []byte{mode, 0x00, 0x00})
		if known[mode] {
			require.NotErrorIs(t, err, ErrUnsupportedMode, "mode=0x%02x is a FIPS 205 parameter set", mode)
			continue
		}
		require.ErrorIs(t, err, ErrUnsupportedMode, "mode=0x%02x", mode)
	}
}

// TestRun_RejectsWrongDeclaredPubKeyLen walks the declared public key length
// off the mode's true size in BOTH directions on an otherwise valid frame. The
// frame stays exactly the right total length, so nothing but this one field is
// wrong -- if the equality check were widened to an inequality, or dropped, the
// refusal would change shape or vanish.
func TestRun_RejectsWrongDeclaredPubKeyLen(t *testing.T) {
	frame := katFrame(t)
	for _, declared := range []uint16{0, 1, 31, 33, 48, 64, 0xFFFF} {
		out, err := call(t, patch16(frame, pubKeyLenOffset, declared))
		require.ErrorIs(t, err, ErrInvalidInputLength, "declared=%d", declared)
		require.ErrorContains(t, err, "expected pubkey size 32", "declared=%d", declared)
		require.Nil(t, out)
	}

	// The true size is the only value that gets through.
	out, err := call(t, patch16(frame, pubKeyLenOffset, SLH128PublicKeySize))
	require.NoError(t, err)
	require.Equal(t, word(1), out)
}

// TestRun_MessageLenHeaderBoundary truncates the frame at the byte before and
// the byte at the end of the message-length header. Removing the guard makes
// the shorter case index past the end of the slice, which panics -- inside a
// precompile that halts every validator, so this boundary is load-bearing.
func TestRun_MessageLenHeaderBoundary(t *testing.T) {
	frame := katFrame(t)

	out, err := call(t, frame[:msgLenOffset+MessageLenSize-1])
	require.ErrorIs(t, err, ErrInvalidInputLength)
	require.ErrorContains(t, err, "input too short for message length")
	require.Nil(t, out)

	// One byte longer: the header is readable, so the refusal moves on to the
	// signature tail.
	out, err = call(t, frame[:msgLenOffset+MessageLenSize])
	require.ErrorIs(t, err, ErrInvalidInputLength)
	require.ErrorContains(t, err, "expected exactly")
	require.Nil(t, out)
}

// TestRun_FrameIsExact walks the signature tail one byte short, exact, and one
// byte long. The frame is pinned exactly rather than as a minimum: trailing
// bytes would let one signature be presented under unboundedly many distinct
// calldatas, which is frame malleability even though the verified triple never
// changes.
func TestRun_FrameIsExact(t *testing.T) {
	frame := katFrame(t)
	require.Len(t, frame, katFrameSize)

	out, err := call(t, frame[:len(frame)-1])
	require.ErrorIs(t, err, ErrInvalidInputLength)
	require.ErrorContains(t, err, "expected exactly 7925 bytes, got 7924")
	require.Nil(t, out)

	out, err = call(t, frame)
	require.NoError(t, err)
	require.Equal(t, word(1), out)

	for _, extra := range []int{1, 2, 32} {
		padded := append(append([]byte(nil), frame...), make([]byte, extra)...)
		out, err = call(t, padded)
		require.ErrorIs(t, err, ErrInvalidInputLength, "extra=%d", extra)
		require.ErrorContains(t, err, "expected exactly 7925 bytes", "extra=%d", extra)
		require.Nil(t, out, "a padded frame must not verify", extra)
	}
}

// TestRun_DeclaredLengthCannotReachPastCalldata walks each declared length one
// byte past what the call actually carries, over spare capacity the caller
// filled. A parser that slices instead of bounding does not panic here and does
// not halt a validator: it finds 0xA5 past the end and returns a verdict over
// material nobody declared and nobody paid gas for. Every field the wire format
// declares a length for is exercised -- the public key, the message, and the
// signature the mode fixes.
func TestRun_DeclaredLengthCannotReachPastCalldata(t *testing.T) {
	frame := katFrame(t)

	// A declared 32-byte public key over 31 bytes of calldata.
	shortKey := frame[:ModeByte+PubKeyLenSize+SLH128PublicKeySize-1]
	out, err := call(t, shortKey)
	require.ErrorIs(t, err, ErrInvalidInputLength, "a public key one byte past the calldata")
	require.ErrorContains(t, err, "input too short for message length")
	require.Nil(t, out)

	// The quote reads the message-length header from behind that key, so it has
	// to come up short in the same place. Reading on would price 0xA5A5 bytes
	// of message the caller never supplied.
	_, _, baseGas, _, err := getModeParams(katMode)
	require.NoError(t, err)
	require.Equal(t, baseGas,
		MagnetarVerifyPrecompile.RequiredGas(contract.Poisoned(shortKey, 256)),
		"a short frame is priced at the mode's base, not off bytes past its end")

	// A declared 32-byte message over 31 bytes of calldata.
	out, err = call(t, frame[:msgLenOffset+MessageLenSize+32-1])
	require.ErrorIs(t, err, ErrInvalidInputLength, "a message one byte past the calldata")
	require.Nil(t, out)

	// The signature, whose last byte is the only thing missing.
	out, err = call(t, frame[:len(frame)-1])
	require.ErrorIs(t, err, ErrInvalidInputLength, "a signature one byte past the calldata")
	require.ErrorContains(t, err, "expected exactly 7925 bytes, got 7924")
	require.Nil(t, out)

	// The exact frame still verifies, so the refusals above are about the
	// declared lengths and nothing else.
	out, err = call(t, frame)
	require.NoError(t, err)
	require.Equal(t, word(1), out)
}

// TestRun_TruncatedSignature removes bytes from the signature tail. Each is
// refused on length, never handed to the verifier as a short slice.
func TestRun_TruncatedSignature(t *testing.T) {
	frame := katFrame(t)
	for _, cut := range []int{1, 2, 100, SLHSHA2_128sSignatureSize} {
		out, err := call(t, frame[:len(frame)-cut])
		require.ErrorIs(t, err, ErrInvalidInputLength, "cut=%d", cut)
		require.Nil(t, out)
	}
}

// TestRun_DeclaredMessageLenOverrun declares a message far longer than the
// frame can hold. The offsets Run computes from it must be refused on length
// rather than slicing past the end of the buffer.
func TestRun_DeclaredMessageLenOverrun(t *testing.T) {
	frame := katFrame(t)

	for _, declared := range []uint16{33, 1000, 0x7FFF, 0xFFFE, 0xFFFF} {
		out, err := call(t, patch16(frame, msgLenOffset, declared))
		require.ErrorIs(t, err, ErrInvalidInputLength, "declared=%d", declared)
		require.ErrorContains(t, err, "expected exactly", "declared=%d", declared)
		require.Nil(t, out)
	}

	// The pathological case: a buffer long enough that the message slice alone
	// would be in bounds, so only the signature-tail check stands between the
	// declared length and a read past the end.
	const declared = math.MaxUint16
	long := append(patch16(frame, msgLenOffset, declared),
		make([]byte, msgLenOffset+MessageLenSize+declared-len(frame))...)
	require.Len(t, long, msgLenOffset+MessageLenSize+declared)
	out, err := call(t, long)
	require.ErrorIs(t, err, ErrInvalidInputLength)
	require.Nil(t, out)

	// Shrinking the declared length back to what the frame actually carries
	// restores acceptance, so the refusals above are about this field alone.
	out, err = call(t, patch16(frame, msgLenOffset, 32))
	require.NoError(t, err)
	require.Equal(t, word(1), out)
}

// TestFrameOffsetsCannotOverflow pins the arithmetic that makes Run's offset
// computation panic-free. msgLen is decoded from a uint16 header, so the
// largest frame any mode can describe is bounded well below MaxInt32 -- there
// is no integer overflow on a 32-bit int, let alone a 64-bit one, and the
// exact-length check therefore guarantees every slice expression is in bounds.
// Widening the header to uint32 would break this test, which is the point.
func TestFrameOffsetsCannotOverflow(t *testing.T) {
	for _, mode := range allModes {
		pkSize, sigSize, _, _, err := getModeParams(mode)
		require.NoError(t, err)

		sigEnd := ModeByte + PubKeyLenSize + pkSize + MessageLenSize + math.MaxUint16 + sigSize
		require.Positive(t, sigEnd, "mode=0x%02x", mode)
		require.Less(t, sigEnd, math.MaxInt32, "mode=0x%02x offsets must fit a 32-bit int", mode)

		// Gas is uint64 and cannot wrap either.
		_, _, baseGas, _, err := getModeParams(mode)
		require.NoError(t, err)
		require.Less(t, baseGas+math.MaxUint16*MagnetarVerifyPerByteGas, uint64(math.MaxUint32),
			"mode=0x%02x", mode)
	}
}

// TestRun_AllZeroInput feeds all-zero buffers. Zero is a valid mode byte
// (SHA2-128s), so these are refused by the declared-length checks rather than
// by the mode check, and none of them may panic.
func TestRun_AllZeroInput(t *testing.T) {
	for _, size := range []int{3, 4, 37, 69, katFrameSize - 1, katFrameSize, katFrameSize + 1} {
		out, err := call(t, make([]byte, size))
		require.ErrorIs(t, err, ErrInvalidInputLength, "size=%d", size)
		require.ErrorContains(t, err, "expected pubkey size 32", "size=%d", size)
		require.Nil(t, out)
	}
}

// TestRun_ZeroFrameEveryMode drives the complete Run path -- decode, size
// table, public key parse, verify -- once per FIPS 205 parameter set, without
// signing anything. A well-formed all-zero frame must reach the verifier and
// come back false: a refusal here would mean the mode's declared sizes and the
// frame it accepts disagree.
func TestRun_ZeroFrameEveryMode(t *testing.T) {
	for _, mode := range allModes {
		frame := zeroFrame(t, mode)
		out, err := call(t, frame)
		require.NoError(t, err, "mode=%s", ModeName(mode))
		require.Equal(t, word(0), out, "mode=%s: all-zero signature must not verify", ModeName(mode))
	}
}

// TestRun_NeverPanics sweeps the whole neighbourhood of the header boundaries
// with three fixed byte patterns. A panic inside a precompile is not an error
// return -- geth's dispatch has no recover, so it halts every validator that
// executes the transaction. The sweep is fully deterministic.
func TestRun_NeverPanics(t *testing.T) {
	patterns := []func(i int) byte{
		func(int) byte { return 0x00 },
		func(int) byte { return 0xFF },
		func(i int) byte { return byte(i) },
	}
	modes := append(append([]uint8{}, allModes...), 0x06, 0x0F, 0x16, 0x7F, 0xFF)

	for _, mode := range modes {
		for p, fill := range patterns {
			for n := 0; n <= 80; n++ {
				in := make([]byte, n)
				for i := range in {
					in[i] = fill(i)
				}
				if n > 0 {
					in[0] = mode
				}
				in = contract.Poisoned(in, 256)
				require.NotPanics(t, func() {
					MagnetarVerifyPrecompile.RequiredGas(in)
					_, _, _ = MagnetarVerifyPrecompile.Run(
						nil, common.Address{}, ContractMagnetarVerifyAddress,
						in, MagnetarDefaultGas*100, true,
					)
				}, "mode=0x%02x pattern=%d len=%d", mode, p, n)
			}
		}
	}
}

// TestRun_GasAccounting pins the relationship between supplied gas, the gas
// RequiredGas asks for, and what Run hands back -- on the accepting path, on a
// refusing path, and at the boundary where one wei of gas is missing.
func TestRun_GasAccounting(t *testing.T) {
	frame := contract.Poisoned(katFrame(t), 256)
	need := MagnetarVerifyPrecompile.RequiredGas(frame)
	require.Positive(t, need)

	// Exactly enough: the call succeeds with nothing left over.
	out, remaining, err := MagnetarVerifyPrecompile.Run(
		nil, common.Address{}, ContractMagnetarVerifyAddress, frame, need, true)
	require.NoError(t, err)
	require.Equal(t, word(1), out)
	require.Zero(t, remaining)

	// Surplus is returned untouched.
	out, remaining, err = MagnetarVerifyPrecompile.Run(
		nil, common.Address{}, ContractMagnetarVerifyAddress, frame, need+7, true)
	require.NoError(t, err)
	require.Equal(t, word(1), out)
	require.Equal(t, uint64(7), remaining)

	// One short: out of gas, nothing returned, no gas left.
	out, remaining, err = MagnetarVerifyPrecompile.Run(
		nil, common.Address{}, ContractMagnetarVerifyAddress, frame, need-1, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Nil(t, out)
	require.Zero(t, remaining)

	// Out of gas is decided before the input is looked at.
	_, remaining, err = MagnetarVerifyPrecompile.Run(
		nil, common.Address{}, ContractMagnetarVerifyAddress, nil, 0, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.NotErrorIs(t, err, ErrInvalidInputLength)
	require.Zero(t, remaining)
}

// TestRun_RefusalStillCharges walks EVERY way a frame can be refused and
// asserts the same thing about each: the gas RequiredGas quoted has been
// metered off before the refusal, and only the surplus comes back. A refusal
// that handed back the supplied gas untouched would be free execution -- a
// caller could hammer a validator with malformed calldata at no cost -- and
// each refusal returns its own value, so the property has to be checked on
// each one rather than on a single representative.
func TestRun_RefusalStillCharges(t *testing.T) {
	frame := katFrame(t)

	for _, tc := range []struct {
		name  string
		input []byte
		want  error
	}{
		{"shorter than the header", frame[:2], ErrInvalidInputLength},
		{"unsupported mode", []byte{0xFF, 0x00, 0x20}, ErrUnsupportedMode},
		{"wrong declared pubkey length", patch16(frame, pubKeyLenOffset, 31), ErrInvalidInputLength},
		{"short of the message-length header", frame[:msgLenOffset+1], ErrInvalidInputLength},
		{"frame length not exact", frame[:len(frame)-1], ErrInvalidInputLength},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const surplus = 11
			in := contract.Poisoned(tc.input, 256)
			need := MagnetarVerifyPrecompile.RequiredGas(in)
			require.Positive(t, need)

			out, remaining, err := MagnetarVerifyPrecompile.Run(
				nil, common.Address{}, ContractMagnetarVerifyAddress,
				in, need+surplus, true)
			require.ErrorIs(t, err, tc.want)
			require.Nil(t, out)
			require.Equal(t, uint64(surplus), remaining,
				"a refused frame must still be charged what RequiredGas quoted")
		})
	}
}
