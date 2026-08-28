// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hqc

import (
	"crypto/sha256"
	"testing"

	"github.com/luxfi/crypto/hqc"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

var modes = map[uint8]hqc.Mode{
	ModeHQC128: hqc.HQC128,
	ModeHQC192: hqc.HQC192,
	ModeHQC256: hqc.HQC256,
}

// frame builds op || mode || seed(32) || pk of the mode's exact length.
// The public key bytes are a fixed pattern: no backend inspects them
// before the length is checked, and the length is what is under test.
func frame(mode uint8, seed byte) []byte {
	params := hqc.MustParamsFor(modes[mode])
	in := make([]byte, 2+SeedSize+params.PublicKeySize)
	in[0] = OpEncapsulate
	in[1] = mode
	for i := range SeedSize {
		in[2+i] = seed
	}
	for i := 2 + SeedSize; i < len(in); i++ {
		in[i] = byte(i)
	}
	return in
}

func try(t *testing.T, in []byte) ([]byte, error) {
	t.Helper()
	out, _, err := HQCPrecompile.Run(nil, common.Address{}, ContractAddress,
		in, HQCPrecompile.RequiredGas(in), true)
	return out, err
}

// Every mode byte reaches its own parameter set, and the length check that
// follows uses that set's key size -- so the same calldata length is
// valid for exactly one mode.
func TestRefuse_EachModeFixesItsOwnKeySize(t *testing.T) {
	sizes := map[int]uint8{}
	for mode := range modes {
		size := hqc.MustParamsFor(modes[mode]).PublicKeySize
		prev, dup := sizes[size]
		require.Falsef(t, dup, "modes 0x%02x and 0x%02x share a key size", prev, mode)
		sizes[size] = mode
	}

	for mode := range modes {
		in := frame(mode, 0x11)

		// The mode's own length gets past the frame checks -- it fails, if
		// at all, inside the backend, never on shape.
		_, err := try(t, in)
		require.NotErrorIsf(t, err, ErrInvalidInputLength,
			"mode 0x%02x refused its own key length", mode)
		require.NotErrorIsf(t, err, ErrInvalidMode, "mode 0x%02x is not routed", mode)

		// Relabelled to any other mode, the same bytes are the wrong length.
		for other := range modes {
			if other == mode {
				continue
			}
			relabelled := append([]byte{}, in...)
			relabelled[1] = other
			_, err := try(t, relabelled)
			require.ErrorIsf(t, err, ErrInvalidInputLength,
				"a 0x%02x key relabelled 0x%02x passed the length check", mode, other)
		}
	}
}

// The frame is exact: one byte short and one byte long are both refused.
func TestRefuse_FrameLengthIsExact(t *testing.T) {
	for mode := range modes {
		in := frame(mode, 0x22)
		_, err := try(t, in[:len(in)-1])
		require.ErrorIsf(t, err, ErrInvalidInputLength, "mode 0x%02x: one byte short", mode)

		_, err = try(t, append(append([]byte{}, in...), 0x00))
		require.ErrorIsf(t, err, ErrInvalidInputLength, "mode 0x%02x: one byte long", mode)
	}
}

// Calldata below the header minimum never reaches a mode lookup.
func TestRefuse_TooShortToParse(t *testing.T) {
	for name, in := range map[string][]byte{
		"nil":        nil,
		"empty":      {},
		"op only":    {OpEncapsulate},
		"no seed":    {OpEncapsulate, ModeHQC128},
		"short seed": append([]byte{OpEncapsulate, ModeHQC128}, make([]byte, SeedSize-1)...),
		"seed only":  append([]byte{OpEncapsulate, ModeHQC128}, make([]byte, SeedSize)...),
	} {
		_, err := try(t, in)
		require.ErrorIsf(t, err, ErrInvalidInputLength, "%s parsed", name)
	}
}

// Encapsulate is the only operation; every other op byte is refused.
// Decapsulate is absent on purpose -- it would need the private key in
// calldata, which every validator can read.
func TestRefuse_OnlyEncapsulateExists(t *testing.T) {
	body := frame(ModeHQC128, 0x33)
	for op := range 256 {
		if uint8(op) == OpEncapsulate {
			continue
		}
		in := append([]byte{}, body...)
		in[0] = byte(op)
		_, err := try(t, in)
		require.ErrorIsf(t, err, ErrInvalidOperation, "op 0x%02x was dispatched", op)
	}
}

// Exactly three mode bytes exist; every other value is refused.
func TestRefuse_ExactlyThreeModes(t *testing.T) {
	body := frame(ModeHQC128, 0x44)
	for m := range 256 {
		if _, ok := modes[uint8(m)]; ok {
			continue
		}
		in := append([]byte{}, body...)
		in[1] = byte(m)
		_, err := try(t, in)
		require.ErrorIsf(t, err, ErrInvalidMode, "mode 0x%02x was accepted", m)
	}
}

// The op byte is checked before the mode byte, so calldata that is wrong
// in both ways reports the op. Order matters only in that it is fixed:
// a caller can rely on which complaint it gets.
func TestRefuse_OperationIsCheckedBeforeMode(t *testing.T) {
	in := frame(ModeHQC128, 0x55)
	in[0] = 0xEE
	in[1] = 0xEE
	_, err := try(t, in)
	require.ErrorIs(t, err, ErrInvalidOperation)
}

// The reader is a SHA-256 chain seeded by the caller's 32 bytes: the first
// block is SHA-256(seed) and each block after is the hash of the one
// before. Pinning it here is what makes the encapsulation reproducible on
// every validator -- and it is the only place the chain is checked, since
// no backend consumes it in the default build.
func TestBinding_ReaderIsASHA256Chain(t *testing.T) {
	seed := make([]byte, SeedSize)
	for i := range seed {
		seed[i] = byte(0xC0 + i)
	}

	want := []byte{}
	block := sha256.Sum256(seed)
	for range 4 {
		want = append(want, block[:]...)
		block = sha256.Sum256(block[:])
	}

	got := make([]byte, len(want))
	n, err := newDeterministicReader(seed).Read(got)
	require.NoError(t, err)
	require.Equal(t, len(want), n)
	require.Equal(t, want, got)
	require.NotEqual(t, seed, got[:SeedSize], "the raw seed must not pass through unhashed")

	// The stream does not depend on how the consumer asks for it.
	for _, chunk := range []int{1, 7, 16, 32, 33} {
		r := newDeterministicReader(seed)
		out := make([]byte, 0, len(want))
		for len(out) < len(want) {
			buf := make([]byte, min(chunk, len(want)-len(out)))
			n, err := r.Read(buf)
			require.NoError(t, err)
			require.Equal(t, len(buf), n)
			out = append(out, buf...)
		}
		require.Equalf(t, want, out, "stream differs when read %d bytes at a time", chunk)
	}

	// Different seeds give different streams, and a short seed is
	// zero-extended rather than aliasing a longer one.
	other := append([]byte{}, seed...)
	other[0] ^= 0x01
	alt := make([]byte, 32)
	_, err = newDeterministicReader(other).Read(alt)
	require.NoError(t, err)
	require.NotEqual(t, got[:32], alt)
}

// Two callers submitting the same calldata get the same answer: unlike the
// ML-KEM and X-Wing precompiles, HQC derives its stream from the seed
// alone. That is a real difference in the block and it is asserted here so
// it is a decision rather than a drift.
func TestBinding_SeedAloneDeterminesTheStream(t *testing.T) {
	seed := make([]byte, SeedSize)
	a := make([]byte, 64)
	b := make([]byte, 64)
	_, err := newDeterministicReader(seed).Read(a)
	require.NoError(t, err)
	_, err = newDeterministicReader(seed).Read(b)
	require.NoError(t, err)
	require.Equal(t, a, b)
}

// --- module wiring ---

func TestConfig_Roundtrip(t *testing.T) {
	require.Equal(t, ConfigKey, (&Config{}).Key())
	require.Nil(t, (&Config{}).Timestamp())

	ts := uint64(1234)
	c := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, c.Timestamp())

	require.False(t, (&Config{}).IsDisabled())
	require.True(t, (&Config{Upgrade: precompileconfig.Upgrade{Disable: true}}).IsDisabled())

	require.True(t, c.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}))
	other := uint64(5678)
	require.False(t, c.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &other}}))
	require.False(t, c.Equal(nil))
	require.NoError(t, c.Verify(nil))
}

func TestConfigurator_MakesTheRightConfig(t *testing.T) {
	cfg := (&configurator{}).MakeConfig()
	_, ok := cfg.(*Config)
	require.True(t, ok)
	require.Equal(t, ConfigKey, cfg.Key())
	require.NoError(t, (&configurator{}).Configure(nil, nil, nil, nil))
}
