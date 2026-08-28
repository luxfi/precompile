// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mlkem

import (
	"crypto/sha256"
	"testing"

	"github.com/luxfi/crypto/mlkem"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// encapFrame builds op || mode || seed(32) || ek for a freshly generated key.
func encapFrame(t testing.TB, mode uint8, seed byte) []byte {
	t.Helper()
	_, _, _, _, kemMode, err := getModeParams(mode)
	require.NoError(t, err)
	pub, _, err := mlkem.GenerateKey(kemMode)
	require.NoError(t, err)

	in := []byte{OpEncapsulate, mode}
	for range SeedSize {
		in = append(in, seed)
	}
	return append(in, pub.Bytes()...)
}

func runEncap(t testing.TB, caller common.Address, in []byte) ([]byte, error) {
	t.Helper()
	out, _, err := MLKEMPrecompile.Run(nil, caller, ContractAddress,
		in, MLKEMPrecompile.RequiredGas(in), true)
	return out, err
}

// The frame is exact: one byte short and one byte long are both refused.
// Trailing bytes would let one encapsulation be requested by many
// distinct calldatas.
func TestRefuse_FrameLengthIsExact(t *testing.T) {
	for _, mode := range []uint8{ModeMLKEM512, ModeMLKEM768, ModeMLKEM1024} {
		in := encapFrame(t, mode, 0x11)
		_, err := runEncap(t, common.Address{}, in)
		require.NoErrorf(t, err, "mode 0x%02x: the exact frame is the accepted one", mode)

		_, err = runEncap(t, common.Address{}, in[:len(in)-1])
		require.ErrorIsf(t, err, ErrInvalidInputLength, "mode 0x%02x: one byte short", mode)

		_, err = runEncap(t, common.Address{}, append(append([]byte{}, in...), 0x00))
		require.ErrorIsf(t, err, ErrInvalidInputLength, "mode 0x%02x: one trailing byte", mode)
	}
}

// Calldata too short to carry an op and a mode is refused before anything
// is parsed.
func TestRefuse_TooShortToParse(t *testing.T) {
	for name, in := range map[string][]byte{
		"nil":       nil,
		"empty":     {},
		"op only":   {OpEncapsulate},
		"no seed":   {OpEncapsulate, ModeMLKEM768},
		"half seed": append([]byte{OpEncapsulate, ModeMLKEM768}, make([]byte, SeedSize/2)...),
	} {
		_, err := runEncap(t, common.Address{}, in)
		require.ErrorIsf(t, err, ErrInvalidInputLength, "%s parsed", name)
	}
}

// Decapsulation is not on chain, and neither is anything else. Only
// OpEncapsulate exists; every other op byte is refused. Decapsulate would
// need the private key in calldata, which every validator can read.
func TestRefuse_OnlyEncapsulateExists(t *testing.T) {
	body := encapFrame(t, ModeMLKEM768, 0x22)
	for op := range 256 {
		if byte(op) == OpEncapsulate {
			continue
		}
		in := append([]byte{}, body...)
		in[0] = byte(op)
		_, err := runEncap(t, common.Address{}, in)
		require.ErrorIsf(t, err, ErrUnsupportedOperation, "op 0x%02x was dispatched", op)
	}
}

// Unknown mode bytes are refused, including the ones adjacent to the three
// that exist.
func TestRefuse_UnknownMode(t *testing.T) {
	body := encapFrame(t, ModeMLKEM768, 0x33)
	for m := range 256 {
		if byte(m) <= ModeMLKEM1024 {
			continue
		}
		in := append([]byte{}, body...)
		in[1] = byte(m)
		_, err := runEncap(t, common.Address{}, in)
		require.ErrorIsf(t, err, ErrUnsupportedMode, "mode 0x%02x was accepted", m)
	}
}

// A key of one parameter set offered under another's mode byte is refused
// on length: the three parameter sets have three distinct key sizes, so
// mode confusion cannot be reached at all.
func TestRefuse_ModeConfusionIsStructural(t *testing.T) {
	modes := []uint8{ModeMLKEM512, ModeMLKEM768, ModeMLKEM1024}

	seen := map[int]uint8{}
	for _, m := range modes {
		pubSize, _, _, _, _, err := getModeParams(m)
		require.NoError(t, err)
		prev, dup := seen[pubSize]
		require.Falsef(t, dup, "modes 0x%02x and 0x%02x share a public-key size", prev, m)
		seen[pubSize] = m
	}

	for _, real := range modes {
		in := encapFrame(t, real, 0x44)
		for _, claimed := range modes {
			if claimed == real {
				continue
			}
			relabelled := append([]byte{}, in...)
			relabelled[1] = claimed
			_, err := runEncap(t, common.Address{}, relabelled)
			require.ErrorIsf(t, err, ErrInvalidInputLength,
				"a 0x%02x key relabelled 0x%02x was encapsulated against", real, claimed)
		}
	}
}

// A key of the right length whose bytes are not a valid encapsulation key
// is refused. FIPS 203 section 7.2 requires the modulus check
// (ByteEncode12(ByteDecode12(ek)) == ek); random bytes fail it, and
// skipping it is how an attacker gets a contract to encapsulate against
// something that is not a key.
func TestRefuse_PublicKeyFailingModulusCheck(t *testing.T) {
	for _, mode := range []uint8{ModeMLKEM512, ModeMLKEM768, ModeMLKEM1024} {
		in := encapFrame(t, mode, 0x55)
		for i := 2 + SeedSize; i < len(in); i++ {
			in[i] = 0xFF // 0xFFF exceeds q-1 = 3328 in every 12-bit lane
		}
		out, err := runEncap(t, common.Address{}, in)
		require.Errorf(t, err, "mode 0x%02x: an out-of-range key was accepted", mode)
		require.Nil(t, out)
	}
}

// Same caller, same calldata, same bytes out -- every validator replays
// this call and must agree. Nothing here may reach for crypto/rand.
func TestBinding_Deterministic(t *testing.T) {
	caller := common.HexToAddress("0x00000000000000000000000000000000000000a1")
	in := encapFrame(t, ModeMLKEM768, 0x66)
	first, err := runEncap(t, caller, in)
	require.NoError(t, err)
	for range 4 {
		again, err := runEncap(t, caller, in)
		require.NoError(t, err)
		require.Equal(t, first, again, "encapsulation must depend on nothing but its inputs")
	}
}

// The caller is bound into the seed. Without that, one contract could
// replay another's calldata and hold the shared secret that contract
// believes is its own.
func TestBinding_CallerSeparatesSeed(t *testing.T) {
	in := encapFrame(t, ModeMLKEM768, 0x77)
	a, err := runEncap(t, common.HexToAddress("0x00000000000000000000000000000000000000a1"), in)
	require.NoError(t, err)
	b, err := runEncap(t, common.HexToAddress("0x00000000000000000000000000000000000000b2"), in)
	require.NoError(t, err)
	require.NotEqual(t, a, b, "two callers shared one encapsulation: the caller is not bound in")
}

// A different raw seed gives a different encapsulation, so the caller
// keeps control of the randomness.
func TestBinding_SeedSeparatesOutput(t *testing.T) {
	base := encapFrame(t, ModeMLKEM768, 0x00)
	other := append([]byte{}, base...)
	other[2] = 0x01

	a, err := runEncap(t, common.Address{}, base)
	require.NoError(t, err)
	b, err := runEncap(t, common.Address{}, other)
	require.NoError(t, err)
	require.NotEqual(t, a, b, "flipping one seed bit left the output unchanged")
}

// deriveSeed is pinned to its construction, recomputed here by hand.
// Dropping the label, dropping the caller, or reordering the two changes
// the derived m -- and changes nothing a round-trip test can see, because
// encapsulation and decapsulation still agree with each other.
func TestBinding_DeriveSeedConstruction(t *testing.T) {
	caller := common.HexToAddress("0x0000000000000000000000000000000000001234")
	var raw [SeedSize]byte
	for i := range raw {
		raw[i] = byte(i)
	}

	h := sha256.New()
	h.Write([]byte("MLKEM_ENCAP_v1"))
	h.Write(caller.Bytes())
	h.Write(raw[:])
	var want [SeedSize]byte
	copy(want[:], h.Sum(nil))

	require.Equal(t, want, deriveSeed(caller, raw))
	require.NotEqual(t, raw, deriveSeed(caller, raw), "the raw seed must not pass through unhashed")
	require.NotEqual(t, deriveSeed(caller, raw),
		deriveSeed(common.HexToAddress("0x0000000000000000000000000000000000001235"), raw),
		"neighbouring callers must not collide")
}

// The reader is a SHA-256 chain over the derived seed: the first 32 bytes
// are the seed itself, and each further 32 come from hashing the block
// before. Encapsulation only draws 32, so the refill path has no
// production caller -- pin it here rather than leave it unexercised.
func TestBinding_ReaderIsASHA256Chain(t *testing.T) {
	var seed [SeedSize]byte
	for i := range seed {
		seed[i] = byte(0xA0 + i)
	}

	want := append([]byte{}, seed[:]...)
	block := seed
	for range 3 {
		block = sha256.Sum256(block[:])
		want = append(want, block[:]...)
	}

	got := make([]byte, len(want))
	n, err := newDeterministicReader(seed).Read(got)
	require.NoError(t, err)
	require.Equal(t, len(want), n)
	require.Equal(t, want, got)

	// Byte-at-a-time reads produce the same stream, so the refill boundary
	// does not depend on how the consumer asks.
	r := newDeterministicReader(seed)
	one := make([]byte, 1)
	for i := range want {
		n, err := r.Read(one)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		require.Equalf(t, want[i], one[0], "byte %d of the stream", i)
	}
}
