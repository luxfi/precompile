// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import (
	"bytes"
	"crypto/rand"
	"math"
	"testing"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// call runs the precompile with exactly the fee its own schedule quotes.
func call(t testing.TB, input []byte) ([]byte, error) {
	t.Helper()
	gas := MLDSAVerifyPrecompile.RequiredGas(input)
	if gas == math.MaxUint64 {
		gas-- // leave the caller one short so the meter, not the parser, answers
	}
	ret, _, err := MLDSAVerifyPrecompile.Run(
		nil, common.Address{}, ContractMLDSAVerifyAddress, input, gas, true)
	return ret, err
}

// goodFrame returns a frame that verifies, plus its parts.
func goodFrame(t testing.TB, msg []byte) (frame, pk, sig []byte) {
	t.Helper()
	pk, sig, _ = createTestSignature(t, mldsa.MLDSA44, msg)
	return createInputWithMode(ModeMLDSA44, pk, sig, msg), pk, sig
}

// The frame length is exact. One byte short and one byte long are both
// refused; a trailing byte would give one signature two calldata spellings.
func TestRefuse_FrameLengthIsExact(t *testing.T) {
	msg := []byte("exactly this")
	frame, _, _ := goodFrame(t, msg)

	ret, err := call(t, frame)
	require.NoError(t, err)
	require.Equal(t, byte(1), ret[31], "the exact frame is the accepted one")

	_, err = call(t, frame[:len(frame)-1])
	require.ErrorIs(t, err, ErrInvalidInputLength, "one byte short must be refused")

	_, err = call(t, append(append([]byte{}, frame...), 0x00))
	require.ErrorIs(t, err, ErrInvalidInputLength, "one trailing byte must be refused")
}

// The declared message length must agree with the bytes that follow. A
// frame long enough to parse but carrying a different count is refused,
// not silently truncated to whichever of the two is smaller.
func TestRefuse_DeclaredLengthMustMatchPayload(t *testing.T) {
	msg := []byte("sixteen bytes...")
	frame, pk, sig := goodFrame(t, msg)
	sigEnd := ModeByte + MLDSA44PublicKeySize + MessageLenSize + MLDSA44SignatureSize
	require.Equal(t, sigEnd+len(msg), len(frame))

	for _, declared := range []int{0, 1, len(msg) - 1, len(msg) + 1, 255} {
		bad := createInputWithMode(ModeMLDSA44, pk, sig, msg)
		for i := range 8 {
			bad[sigEnd-len(sig)-1-i] = byte(declared >> (i * 8))
		}
		_, err := call(t, bad)
		require.ErrorIsf(t, err, ErrInvalidInputLength,
			"declared %d bytes of message against %d actual and it parsed", declared, len(msg))
	}
}

// The 32-byte message-length word is canonical. Setting any of its high 24
// bytes must not be ignored: truncating them would let 0x00..05 and
// 0xFF..05 both mean "five", so one verification would have many calldatas.
func TestRefuse_MessageLengthWordIsCanonical(t *testing.T) {
	msg := []byte("five!")
	frame, _, _ := goodFrame(t, msg)
	lenAt := ModeByte + MLDSA44PublicKeySize

	ret, err := call(t, frame)
	require.NoError(t, err)
	require.Equal(t, byte(1), ret[31])

	for _, at := range []int{0, 11, 23} {
		bad := append([]byte{}, frame...)
		bad[lenAt+at] = 0x01
		require.Equal(t, uint64(math.MaxUint64), MLDSAVerifyPrecompile.RequiredGas(bad),
			"a length above 2^64 must saturate the fee, not wrap")
		_, err := call(t, bad)
		require.Errorf(t, err, "high length byte %d was ignored", at)
	}
}

// readUint256 saturates rather than truncating, and refuses a word that is
// not 32 bytes wide.
func TestRefuse_ReadUint256Saturates(t *testing.T) {
	word := func(mut func([]byte)) []byte {
		b := make([]byte, 32)
		mut(b)
		return b
	}
	require.Equal(t, uint64(0), readUint256(nil))
	require.Equal(t, uint64(0), readUint256(make([]byte, 31)))
	require.Equal(t, uint64(0), readUint256(make([]byte, 33)))
	require.Equal(t, uint64(0), readUint256(make([]byte, 32)))
	require.Equal(t, uint64(0x0102), readUint256(word(func(b []byte) { b[30], b[31] = 1, 2 })))
	require.Equal(t, uint64(math.MaxUint64),
		readUint256(word(func(b []byte) {
			b[24] = 0xFF
			b[25] = 0xFF
			b[26] = 0xFF
			b[27] = 0xFF
			b[28] = 0xFF
			b[29] = 0xFF
			b[30] = 0xFF
			b[31] = 0xFF
		})))
	for _, hi := range []int{0, 12, 23} {
		require.Equalf(t, uint64(math.MaxUint64),
			readUint256(word(func(b []byte) { b[hi] = 1; b[31] = 5 })),
			"high byte %d truncated instead of saturating", hi)
	}
}

// Empty and one-byte calldata never reach the verifier.
func TestRefuse_TooShortToParse(t *testing.T) {
	for name, in := range map[string][]byte{
		"nil":       nil,
		"empty":     {},
		"mode only": {ModeMLDSA44},
		"mode + 1":  {ModeMLDSA65, 0x00},
	} {
		_, err := call(t, in)
		require.Errorf(t, err, "%s parsed", name)
	}
}

// Unknown mode bytes are refused, including the ones that look like
// neighbours of the real ones.
func TestRefuse_UnknownMode(t *testing.T) {
	for _, mode := range []uint8{0x00, 0x01, 0x11, 0x43, 0x45, 0x64, 0x66, 0x86, 0x88, 0xFF} {
		in := make([]byte, 1+MLDSA65PublicKeySize+MessageLenSize+MLDSA65SignatureSize)
		in[0] = mode
		_, err := call(t, in)
		require.ErrorIsf(t, err, ErrUnsupportedMode, "mode 0x%02x parsed", mode)
	}
}

// A batch reports one verdict per entry, in order, right-aligned in the
// output word. Positional correctness is the property: a batch that
// returned "all valid" or shifted the results by one would still look
// plausible to a length check.
func TestBatch_VerdictsAreOrderedAndPositional(t *testing.T) {
	const n = 5
	valid := map[int]bool{0: true, 2: true, 3: true}

	body := []byte{OpBatchVerify, ModeMLDSA44, 0x00, byte(n)}
	for i := range n {
		msg := []byte{byte('a' + i)}
		pk, sig, _ := createTestSignature(t, mldsa.MLDSA44, msg)
		if !valid[i] {
			sig[0] ^= 0x01
		}
		body = append(body, pk...)
		msgLen := make([]byte, MessageLenSize)
		msgLen[MessageLenSize-1] = byte(len(msg))
		body = append(body, msgLen...)
		body = append(body, sig...)
		body = append(body, msg...)
	}

	ret, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress,
		body, MLDSAVerifyPrecompile.RequiredGas(body), true)
	require.NoError(t, err)
	require.Len(t, ret, 32)

	verdicts := ret[32-n:]
	for i := range n {
		want := byte(0)
		if valid[i] {
			want = 1
		}
		require.Equalf(t, want, verdicts[i], "entry %d verdict", i)
	}
	require.True(t, bytes.Equal(ret[:32-n], make([]byte, 32-n)), "padding must be zero")
}

// A batch wider than one word grows the output to the next 32-byte
// boundary and keeps the verdicts right-aligned within it.
func TestBatch_OutputGrowsPastOneWord(t *testing.T) {
	priv, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA44)
	require.NoError(t, err)
	msg := []byte("w")
	sig, err := priv.SignCtx(rand.Reader, msg, precompileCtx)
	require.NoError(t, err)
	pk := priv.PublicKey.Bytes()

	entry := func(good bool) []byte {
		s := append([]byte{}, sig...)
		if !good {
			s[0] ^= 0x01
		}
		out := append([]byte{}, pk...)
		msgLen := make([]byte, MessageLenSize)
		msgLen[MessageLenSize-1] = byte(len(msg))
		out = append(out, msgLen...)
		out = append(out, s...)
		return append(out, msg...)
	}

	for _, n := range []int{32, 33, 40, 64, 65} {
		body := []byte{OpBatchVerify, ModeMLDSA44, byte(n >> 8), byte(n)}
		for i := range n {
			body = append(body, entry(i%2 == 0)...)
		}
		ret, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress,
			body, MLDSAVerifyPrecompile.RequiredGas(body), true)
		require.NoErrorf(t, err, "batch of %d", n)

		want := ((n + 31) / 32) * 32
		require.Equalf(t, want, len(ret), "batch of %d output width", n)
		verdicts := ret[len(ret)-n:]
		for i := range n {
			expect := byte(0)
			if i%2 == 0 {
				expect = 1
			}
			require.Equalf(t, expect, verdicts[i], "batch of %d, entry %d", n, i)
		}
		require.True(t, bytes.Equal(ret[:len(ret)-n], make([]byte, len(ret)-n)),
			"batch of %d: padding must be zero", n)
	}
}

// A batch entry whose public key is not the declared parameter set is
// refused structurally: the sizes do not line up, so the frame runs out.
func TestBatch_RefusesForeignParameterSet(t *testing.T) {
	msg := []byte("x")
	pk, sig, _ := createTestSignature(t, mldsa.MLDSA65, msg)

	body := []byte{OpBatchVerify, ModeMLDSA44, 0x00, 0x01}
	body = append(body, pk...)
	msgLen := make([]byte, MessageLenSize)
	msgLen[MessageLenSize-1] = byte(len(msg))
	body = append(body, msgLen...)
	body = append(body, sig...)
	body = append(body, msg...)

	_, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress,
		body, MLDSAVerifyPrecompile.RequiredGas(body)+1_000_000, true)
	require.ErrorIs(t, err, ErrInvalidInputLength)
}

// A batch entry may declare any message length it likes; the parser must
// answer with an error, never a panic.
//
// Regression: the entry loop narrowed the declared length to int before
// bounds-checking it. Any value at or above 2^63 became negative, slipped
// past "offset+msgLen > len(input)", and then sliced input[offset:offset-k]
// -- a runtime panic reachable from ordinary calldata. Inside a precompile
// that is not a failed call, it is a dead node, and every validator
// executing the transaction dies the same way.
func TestBatch_DeclaredMessageLengthCannotPanic(t *testing.T) {
	msg := []byte("y")
	pk, sig, _ := createTestSignature(t, mldsa.MLDSA44, msg)

	build := func(msgLenWord []byte) []byte {
		body := []byte{OpBatchVerify, ModeMLDSA44, 0x00, 0x01}
		body = append(body, pk...)
		body = append(body, msgLenWord...)
		body = append(body, sig...)
		return append(body, msg...)
	}

	words := map[string][]byte{}
	// Top bit of the low 64 bits set: int64-negative after narrowing.
	hi := make([]byte, MessageLenSize)
	hi[24] = 0x80
	words["2^63"] = hi
	// All ones in the low 64 bits.
	ones := make([]byte, MessageLenSize)
	for i := 24; i < 32; i++ {
		ones[i] = 0xFF
	}
	words["2^64-1"] = ones
	// A full-width 2^256-1, which saturates.
	all := make([]byte, MessageLenSize)
	for i := range all {
		all[i] = 0xFF
	}
	words["2^256-1"] = all
	// Merely too long for the frame, well inside int range.
	big := make([]byte, MessageLenSize)
	big[28] = 0x01
	words["2^32"] = big

	for name, word := range words {
		in := build(word)
		gas := MLDSAVerifyPrecompile.RequiredGas(in)
		_, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress,
			in, gas+10_000_000, true)
		require.ErrorIsf(t, err, ErrInvalidInputLength,
			"declared length %s must be refused as truncated", name)
	}
}

// An empty batch is still a batch: it names a parameter set and it ends
// where its header says it does. Both were unchecked while a count of zero
// short-circuited straight to a success word, so 0x10 || 0xFF || 0x0000
// returned "verified nothing, fine" for a parameter set that does not
// exist, and any payload could ride along behind it.
func TestBatch_EmptyBatchIsStillChecked(t *testing.T) {
	ret, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress,
		[]byte{OpBatchVerify, ModeMLDSA44, 0x00, 0x00}, 1_000_000, true)
	require.NoError(t, err, "a well-formed empty batch is accepted")
	require.Equal(t, make([]byte, 32), ret)

	_, _, err = MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress,
		[]byte{OpBatchVerify, 0xFF, 0x00, 0x00}, 1_000_000, true)
	require.ErrorIs(t, err, ErrUnsupportedMode, "an empty batch named an unknown parameter set")

	_, _, err = MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress,
		[]byte{OpBatchVerify, ModeMLDSA44, 0x00, 0x00, 0xDE, 0xAD}, 1_000_000, true)
	require.ErrorIs(t, err, ErrInvalidInputLength, "an empty batch carried a trailing payload")
}
