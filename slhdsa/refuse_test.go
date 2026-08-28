// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package slhdsa

import (
	"encoding/binary"
	"testing"

	"github.com/luxfi/crypto/slhdsa"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// allModes is the twelve parameter sets the precompile offers.
var allModes = []uint8{
	ModeSHA2_128s, ModeSHA2_128f, ModeSHA2_192s, ModeSHA2_192f, ModeSHA2_256s, ModeSHA2_256f,
	ModeSHAKE_128s, ModeSHAKE_128f, ModeSHAKE_192s, ModeSHAKE_192f, ModeSHAKE_256s, ModeSHAKE_256f,
}

// katFrame returns a NIST-anchored frame relabelled to carry precompileCtx-
// free material. It is used where a well-shaped frame is needed and the
// verdict does not matter -- building one by signing costs seconds.
func katFrame(t *testing.T) (mode uint8, pk, msg, sig []byte) {
	t.Helper()
	for _, v := range loadACVP(t) {
		if v.TestPassed {
			return acvpMode(t, v.ModeByte), fromHex(t, v.Pk), fromHex(t, v.Message), fromHex(t, v.Signature)
		}
	}
	t.Fatal("no vector")
	return
}

func try(t *testing.T, in []byte) ([]byte, error) {
	t.Helper()
	gas := SLHDSAVerifyPrecompile.RequiredGas(in)
	ret, _, err := SLHDSAVerifyPrecompile.Run(nil, common.Address{},
		ContractSLHDSAVerifyAddress, in, gas, true)
	return ret, err
}

// The frame is exact. One byte short and one byte long are both refused;
// trailing bytes would give one verification many calldata spellings, and
// the ML-DSA precompile next door already pins its frame exactly.
func TestRefuse_FrameLengthIsExact(t *testing.T) {
	mode, pk, msg, sig := katFrame(t)
	in := prepareInputWithMode(mode, pk, msg, sig)

	_, err := try(t, in)
	require.NoError(t, err, "the exact frame is the accepted one")

	_, err = try(t, in[:len(in)-1])
	require.ErrorIs(t, err, ErrInvalidInputLength, "one byte short must be refused")

	_, err = try(t, append(append([]byte{}, in...), 0x00))
	require.ErrorIs(t, err, ErrInvalidInputLength, "one trailing byte must be refused")
}

// The declared public-key length must be the one the mode fixes. Anything
// else is refused rather than used to re-cut the frame.
func TestRefuse_DeclaredPubKeyLengthMustMatchMode(t *testing.T) {
	mode, pk, msg, sig := katFrame(t)
	declared, _, _, _, err := getModeParams(mode)
	require.NoError(t, err)

	for _, wrong := range []int{0, 1, declared - 1, declared + 1, 48, 64, 0xFFFF} {
		in := prepareInputWithMode(mode, pk, msg, sig)
		binary.BigEndian.PutUint16(in[ModeByte:ModeByte+PubKeyLenSize], uint16(wrong))
		_, err := try(t, in)
		require.ErrorIsf(t, err, ErrInvalidInputLength,
			"declared pubkey length %d against mode 0x%02x parsed", wrong, mode)
	}
}

// The declared message length must agree with the payload. Understating it
// leaves trailing bytes; overstating it runs past the end. Both refused.
func TestRefuse_DeclaredMessageLengthMustMatchPayload(t *testing.T) {
	mode, pk, msg, sig := katFrame(t)
	at := ModeByte + PubKeyLenSize + len(pk)

	for _, wrong := range []int{0, 1, len(msg) - 1, len(msg) + 1, 0xFFFF} {
		in := prepareInputWithMode(mode, pk, msg, sig)
		binary.BigEndian.PutUint16(in[at:at+MessageLenSize], uint16(wrong))
		_, err := try(t, in)
		require.ErrorIsf(t, err, ErrInvalidInputLength,
			"declared message length %d against %d actual parsed", wrong, len(msg))
	}
}

// Calldata too short to carry a mode byte and a length field never reaches
// the parser.
func TestRefuse_TooShortToParse(t *testing.T) {
	for name, in := range map[string][]byte{
		"nil":       nil,
		"empty":     {},
		"mode only": {ModeSHA2_128s},
		"mode + 1":  {ModeSHA2_128s, 0x00},
		"no pubkey": {ModeSHA2_128s, 0x00, 0x20},
	} {
		_, err := try(t, in)
		require.Errorf(t, err, "%s parsed", name)
	}
}

// Exactly twelve mode bytes exist. Every other value of the byte is
// refused, including the ones neighbouring the real ones and the ones that
// would fall out of a plausible encoding mistake (0x06, 0x0F, 0x16).
func TestRefuse_ExactlyTwelveModes(t *testing.T) {
	valid := map[uint8]bool{}
	for _, m := range allModes {
		valid[m] = true
		_, _, _, _, err := getModeParams(m)
		require.NoErrorf(t, err, "mode 0x%02x should be known", m)
		require.NotEqual(t, "unknown", ModeName(m))
	}
	require.Len(t, valid, 12)

	for m := range 256 {
		if valid[uint8(m)] {
			continue
		}
		_, _, _, _, err := getModeParams(uint8(m))
		require.ErrorIsf(t, err, ErrUnsupportedMode, "mode 0x%02x is known", m)
		require.Equalf(t, "unknown", ModeName(uint8(m)), "mode 0x%02x is named", m)

		in := []byte{uint8(m), 0x00, 0x20}
		in = append(in, make([]byte, 32+MessageLenSize+SLHSHA2_128sSignatureSize)...)
		_, err = try(t, in)
		require.ErrorIsf(t, err, ErrUnsupportedMode, "mode 0x%02x parsed", m)
	}
}

// All-zero key material of the right shape is refused by the verifier, not
// accepted as a degenerate key.
func TestRefuse_AllZeroMaterial(t *testing.T) {
	for _, mode := range []uint8{ModeSHA2_128s, ModeSHAKE_128s} {
		pubSize, sigSize, _, _, err := getModeParams(mode)
		require.NoError(t, err)

		in := prepareInputWithMode(mode, make([]byte, pubSize), []byte("m"), make([]byte, sigSize))
		ret, err := try(t, in)
		require.NoError(t, err, "an all-zero frame is well-formed, so it gets a verdict")
		require.Equal(t, byte(0), ret[31], "an all-zero signature verified under an all-zero key")
	}
}

// A NIST-valid signature stops verifying as soon as one bit anywhere in
// the frame moves.
func TestRefuse_SingleBitCorruption(t *testing.T) {
	mode, pk, msg, sig := katFrame(t)

	// Sanity: the same material with its own context does verify, so the
	// zeros below are corruption and not a context mismatch.
	pub, err := slhdsa.PublicKeyFromBytes(pk, mustLibMode(t, mode))
	require.NoError(t, err)

	for name, mut := range map[string]func([]byte, []byte, []byte){
		"first signature byte": func(_, _, s []byte) { s[0] ^= 0x01 },
		"last signature byte":  func(_, _, s []byte) { s[len(s)-1] ^= 0x01 },
		"public key":           func(p, _, _ []byte) { p[0] ^= 0x01 },
		"message":              func(_, m, _ []byte) { m[0] ^= 0x01 },
	} {
		p := append([]byte{}, pk...)
		m := append([]byte{}, msg...)
		s := append([]byte{}, sig...)
		mut(p, m, s)
		require.Falsef(t, pub.VerifySignatureCtx(m, s, nil), "%s: still verified", name)

		ret, err := try(t, prepareInputWithMode(mode, p, m, s))
		require.NoErrorf(t, err, "%s", name)
		require.Equalf(t, byte(0), ret[31], "%s: precompile accepted a corrupted frame", name)
	}
}

func mustLibMode(t *testing.T, mode uint8) slhdsa.Mode {
	t.Helper()
	_, _, _, libMode, err := getModeParams(mode)
	require.NoError(t, err)
	return libMode
}

// RequiredGas and Run must read the same frame. If the fee were computed
// from a length the verifier does not use, a caller could buy a large
// verification at a small price. Assert they agree on every well-formed
// frame available.
func TestRefuse_FeeAndParseReadTheSameFrame(t *testing.T) {
	for _, v := range loadACVP(t) {
		mode := acvpMode(t, v.ModeByte)
		pk, msg, sig := fromHex(t, v.Pk), fromHex(t, v.Message), fromHex(t, v.Signature)
		if len(sig) != mustSigSize(t, mode) {
			continue // NIST's wrong-length negative vectors are refused earlier
		}
		in := prepareInputWithMode(mode, pk, msg, sig)

		_, _, baseGas, _, err := getModeParams(mode)
		require.NoError(t, err)
		require.Equalf(t, baseGas+uint64(len(msg))*SLHDSAVerifyPerByteGas,
			SLHDSAVerifyPrecompile.RequiredGas(in),
			"%s tc %d: the quoted fee does not describe the message the verifier hashes",
			v.ParameterSet, v.TcID)

		_, err = try(t, in)
		require.NoErrorf(t, err, "%s tc %d parsed differently than it was priced", v.ParameterSet, v.TcID)
	}
}

func mustSigSize(t *testing.T, mode uint8) int {
	t.Helper()
	_, sigSize, _, _, err := getModeParams(mode)
	require.NoError(t, err)
	return sigSize
}

// A frame can be internally consistent and still declare the wrong
// public-key length: pad the key, shrink the message, and every downstream
// offset still lands where the total says it should. Only the check
// against the mode's own size catches it.
//
// It is load-bearing twice over. RequiredGas quotes a bare base fee the
// moment the declared length disagrees with the mode -- it never reaches
// the per-byte term -- so a Run that accepted the frame anyway would hash
// up to 65535 bytes of message that nobody paid for, and would hand the
// verifier a key of a length the parameter set does not have.
func TestRefuse_SelfConsistentFrameWithWrongPubKeyLength(t *testing.T) {
	const mode = ModeSHA2_128s
	pubSize, sigSize, baseGas, _, err := getModeParams(mode)
	require.NoError(t, err)

	msg := make([]byte, 4096)
	in := prepareInputWithMode(mode, make([]byte, pubSize*2), msg, make([]byte, sigSize))

	// The frame really is self-consistent: total length equals the offsets
	// the declared fields describe.
	require.Equal(t, ModeByte+PubKeyLenSize+pubSize*2+MessageLenSize+len(msg)+sigSize, len(in))
	require.Equal(t, uint16(pubSize*2),
		binary.BigEndian.Uint16(in[ModeByte:ModeByte+PubKeyLenSize]))

	fee := SLHDSAVerifyPrecompile.RequiredGas(in)
	require.Equal(t, baseGas, fee,
		"the fee stops at base once the declared key length disagrees with the mode")
	require.Less(t, fee, baseGas+uint64(len(msg))*SLHDSAVerifyPerByteGas,
		"so accepting this frame would buy unpaid-for hashing")

	_, _, err = SLHDSAVerifyPrecompile.Run(nil, common.Address{},
		ContractSLHDSAVerifyAddress, in, fee, true)
	require.ErrorIs(t, err, ErrInvalidInputLength,
		"a frame declaring a key length the mode does not have was parsed")
}
