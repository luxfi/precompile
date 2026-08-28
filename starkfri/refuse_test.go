// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package starkfri

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// The default build compiles verify_nocgo.go, which registers nothing. The
// package's default state is therefore "no verifier", and BOTH entry
// points must refuse. A refusal that quietly reported success instead
// would be a forgery oracle for every STARK-FRI proof on the chain, so it
// is the single most important behaviour in this package.

// sfClear empties the verifier slot and restores it afterwards, so these
// tests cannot leak state into the rest of the package.
func sfClear(t *testing.T) {
	t.Helper()
	RegisterVerifier(nil)
	t.Cleanup(func() { RegisterVerifier(nil) })
}

// sfWire serialises the [version][proof_len][proof][pub_len][pub] wire.
func sfWire(version byte, proof, pub []byte) []byte {
	out := make([]byte, 0, 1+4+len(proof)+4+len(pub))
	out = append(out, version)
	out = binary.BigEndian.AppendUint32(out, uint32(len(proof)))
	out = append(out, proof...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(pub)))
	return append(out, pub...)
}

// sfRun submits input to the precompile with gas guaranteed sufficient,
// so the only thing under test is the parse/verify outcome.
//
// The input goes in through contract.Poisoned, which puts 256 bytes of
// 0xA5 behind its end. That is the shape real calldata has: opCall takes
// the input with Memory.GetPtr, a two-index slice of the EVM memory
// store, and nothing on the way to Run copies it — so len is what the
// caller declared and paid for, and cap is the rest of memory, which the
// same caller filled with MSTORE. A slice expression only refuses past
// cap, so a missing bounds check does not panic in production: it reads
// attacker-chosen bytes and the verifier answers over them.
//
// A fixture built with plain append also carries spare capacity, but
// zeroed, so an over-read looks like harmless zeros and the test passes
// whether or not the bound exists. Poisoning makes it visible.
func sfRun(input []byte) error {
	in := contract.Poisoned(input, 256)
	_, _, err := StarkFRIVerifyPrecompile.Run(nil, common.Address{},
		ContractStarkFRIVerifyAddress, in, StarkFRIVerifyPrecompile.RequiredGas(in), true)
	return err
}

// TestSF_SafeRefuseIsTheDefault: with nothing registered, no input of any
// shape may be accepted. This is the property verify_nocgo.go exists to
// provide, asserted rather than assumed.
func TestSF_SafeRefuseIsTheDefault(t *testing.T) {
	sfClear(t)

	proofs := [][]byte{
		sfProof(nil),
		sfProof(bytes.Repeat([]byte{0x00}, 64)),
		sfProof(bytes.Repeat([]byte{0xff}, 4096)),
	}
	pubs := [][]byte{{}, {0xaa}, bytes.Repeat([]byte{0x5a}, 256)}

	for _, proof := range proofs {
		for _, pub := range pubs {
			in := sfWire(VersionV1, proof, pub)

			// In-process entry.
			ok, err := Verify(proof, pub)
			require.False(t, ok, "Verify accepted a proof with no verifier registered")
			require.ErrorIs(t, err, ErrVerifierNotRegistered)

			// Precompile entry. nil error is the ONLY success signal, so
			// the refusal must be a non-nil error.
			require.ErrorIs(t, sfRun(in), ErrVerifierNotRegistered,
				"Run reported success with no verifier registered")
		}
	}
}

// TestSF_VerifyChecksStructureBeforeConsultingTheVerifier pins the
// ordering: a proof without the magic header is rejected on its own bytes.
// If the verifier were consulted first, a caller could distinguish
// "registered" from "not registered", and any future verifier would be
// handed input it never agreed to parse.
func TestSF_VerifyChecksStructureBeforeConsultingTheVerifier(t *testing.T) {
	sfClear(t)

	called := false
	RegisterVerifier(func(byte, []byte, []byte) (bool, error) {
		called = true
		return true, nil
	})

	for _, bad := range [][]byte{
		nil,
		{},
		[]byte("P3Q"),            // one byte short of the header
		[]byte("p3q1"),           // wrong case
		[]byte("XXXX"),           // wrong header
		[]byte("XXXXP3Q1"),       // header not at offset 0
		{0x50, 0x33, 0x51, 0x32}, // "P3Q2"
	} {
		ok, err := Verify(bad, []byte{0x01})
		require.Falsef(t, ok, "accepted proof %q", bad)
		require.ErrorIs(t, err, ErrInvalidProof)
	}
	require.False(t, called,
		"the verifier was consulted for a proof that failed structural validation")

	// Control: a well-formed header does reach it.
	ok, err := Verify(sfProof(nil), []byte{0x01})
	require.NoError(t, err)
	require.True(t, ok)
	require.True(t, called)
}

// TestSF_VerifySurfacesTheVerdict: Verify must relay all three outcomes
// distinctly, never collapsing a failure into a success.
func TestSF_VerifySurfacesTheVerdict(t *testing.T) {
	sfClear(t)
	proof := sfProof([]byte{0x01, 0x02})

	RegisterVerifier(func(byte, []byte, []byte) (bool, error) { return true, nil })
	ok, err := Verify(proof, nil)
	require.NoError(t, err)
	require.True(t, ok)

	RegisterVerifier(func(byte, []byte, []byte) (bool, error) { return false, nil })
	ok, err = Verify(proof, nil)
	require.NoError(t, err, "a well-formed but invalid proof is not an internal error")
	require.False(t, ok)

	boom := errors.New("ffi exploded")
	RegisterVerifier(func(byte, []byte, []byte) (bool, error) { return false, boom })
	ok, err = Verify(proof, nil)
	require.ErrorIs(t, err, boom)
	require.False(t, ok)

	// An internal error must never be reported as a verified proof, even
	// if the callback contradicts itself by returning ok=true with an err.
	RegisterVerifier(func(byte, []byte, []byte) (bool, error) { return true, boom })
	_, err = Verify(proof, nil)
	require.Error(t, err, "an errored verification must not read as success")
}

// TestSF_VerifyPassesTheWireThrough pins that the version and the exact
// proof/public bytes reach the verifier unmodified — a verifier handed
// truncated or reordered input would be checking a different statement.
func TestSF_VerifyPassesTheWireThrough(t *testing.T) {
	sfClear(t)

	proof := sfProof([]byte("body-bytes"))
	pub := []byte("public-inputs")

	var gotVer byte
	var gotProof, gotPub []byte
	RegisterVerifier(func(v byte, p, u []byte) (bool, error) {
		gotVer, gotProof, gotPub = v, bytes.Clone(p), bytes.Clone(u)
		return true, nil
	})

	_, err := Verify(proof, pub)
	require.NoError(t, err)
	require.Equal(t, VersionV1, gotVer)
	require.Equal(t, proof, gotProof)
	require.Equal(t, pub, gotPub)

	// And the same through the precompile, where the bytes are sliced out
	// of a framed input.
	in := sfWire(VersionV1, proof, pub)
	gotProof, gotPub = nil, nil
	_, _, err = StarkFRIVerifyPrecompile.Run(nil, common.Address{},
		ContractStarkFRIVerifyAddress, in, StarkFRIVerifyPrecompile.RequiredGas(in), true)
	require.NoError(t, err)
	require.Equal(t, proof, gotProof, "framing corrupted the proof bytes")
	require.Equal(t, pub, gotPub, "framing corrupted the public inputs")
}

// TestSF_RegistrationSeams pins the two registration verbs against each
// other, including the nil cases neither test covered.
func TestSF_RegistrationSeams(t *testing.T) {
	sfClear(t)

	require.Nil(t, loadVerifier(), "slot must start empty")
	require.False(t, RegisterDefaultVerifier(nil),
		"a nil default must not be installed, and must not claim it was")
	require.Nil(t, loadVerifier(), "a nil default must leave the slot empty")

	RegisterVerifier(func(byte, []byte, []byte) (bool, error) { return true, nil })
	require.NotNil(t, loadVerifier())

	// RegisterVerifier(nil) CLEARS, so the safe-refuse state is reachable
	// again — a verifier cannot be made permanent by accident.
	RegisterVerifier(nil)
	require.Nil(t, loadVerifier())
	_, err := Verify(sfProof(nil), nil)
	require.ErrorIs(t, err, ErrVerifierNotRegistered)

	// RegisterVerifier FORCES, overriding a default already in place.
	require.True(t, RegisterDefaultVerifier(func(byte, []byte, []byte) (bool, error) {
		return false, ErrVerifierNotRegistered
	}))
	RegisterVerifier(func(byte, []byte, []byte) (bool, error) { return true, nil })
	ok, err := Verify(sfProof(nil), nil)
	require.NoError(t, err)
	require.True(t, ok, "RegisterVerifier must override an installed default")
}

// TestSF_WireBoundsAreRefusedNotPanicked walks every length field to its
// extremes. A precompile that panics halts the node; one that reads past
// its input verifies attacker-chosen memory.
func TestSF_WireBoundsAreRefusedNotPanicked(t *testing.T) {
	sfClear(t)
	RegisterVerifier(func(byte, []byte, []byte) (bool, error) { return true, nil })

	proof := sfProof([]byte("body"))
	pub := []byte{0xaa}
	good := sfWire(VersionV1, proof, pub)

	var cases [][]byte
	// Every truncation.
	for n := range len(good) {
		cases = append(cases, bytes.Clone(good[:n]))
	}
	// Overstated and extreme proof lengths.
	for _, n := range []uint32{uint32(len(proof)) + 1, 1 << 16, math.MaxUint32 - 1, math.MaxUint32} {
		c := bytes.Clone(good)
		binary.BigEndian.PutUint32(c[1:5], n)
		cases = append(cases, c)
	}
	// Overstated public-input length.
	for _, n := range []uint32{uint32(len(pub)) + 1, 1 << 20, math.MaxUint32} {
		c := bytes.Clone(good)
		binary.BigEndian.PutUint32(c[5+len(proof):9+len(proof)], n)
		cases = append(cases, c)
	}

	for i, in := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("case %d panicked on %d bytes: %v", i, len(in), r)
				}
			}()
			require.Errorf(t, sfRun(in), "case %d (%d bytes) was ACCEPTED", i, len(in))
		}()
	}

	// Control: the untampered input still verifies, so the sweep above was
	// rejecting the corruption and not something incidental.
	require.NoError(t, sfRun(good))
}

// TestSF_RefusesLengthDeclaredPastTheCalldata over-declares each of the
// two length prefixes by margins that fit inside the poisoned spare
// capacity behind the input.
//
// That margin is the point. An over-declaration of a megabyte is refused
// by any parser, because the read runs past cap and Go stops it. An
// over-declaration of eight bytes is the dangerous one: past len, inside
// cap, where the slice expression succeeds and returns memory the same
// caller wrote with MSTORE. Here those bytes are 0xA5, so the assertion
// is not merely that the call was refused but that the verifier was
// never handed anything — a verdict computed over 0xA5 is a verdict on a
// statement nobody made and nobody paid gas for.
func TestSF_RefusesLengthDeclaredPastTheCalldata(t *testing.T) {
	sfClear(t)
	var saw [][]byte
	RegisterVerifier(func(_ byte, p, u []byte) (bool, error) {
		saw = append(saw, bytes.Clone(p), bytes.Clone(u))
		return true, nil
	})

	proof := sfProof([]byte("body"))
	pub := []byte{0xaa}
	good := sfWire(VersionV1, proof, pub)

	// After the version byte and the proof-length field, this many bytes
	// of calldata remain; declaring one more is already past the end.
	tail := uint32(len(good) - 5)
	for _, over := range []uint32{1, 2, 8, 64, 255, 256} {
		c := bytes.Clone(good)
		binary.BigEndian.PutUint32(c[1:5], tail+over)
		require.ErrorIsf(t, sfRun(c), ErrInvalidInputLength,
			"proof_len declared %d bytes over the %d that remain", over, tail)
	}

	// Same for the public-input length, which is the last field and so
	// backs straight onto the poison.
	for _, over := range []uint32{1, 2, 8, 64, 255, 256} {
		c := bytes.Clone(good)
		binary.BigEndian.PutUint32(c[5+len(proof):9+len(proof)], uint32(len(pub))+over)
		require.ErrorIsf(t, sfRun(c), ErrInvalidInputLength,
			"pub_len declared %d bytes over the %d that remain", over, len(pub))
	}

	require.Empty(t, saw, "the verifier was handed bytes from past the calldata")

	// Control: untampered, the same wire reaches the verifier with exactly
	// the bytes that were sent — so the sweep above refused the
	// over-declaration and not the shape.
	require.NoError(t, sfRun(good))
	require.Equal(t, [][]byte{proof, pub}, saw)
}

// TestSF_GasIsChargedAndProportional: no call is free, price rises with
// size, and the charge is deducted before any verification happens.
func TestSF_GasIsChargedAndProportional(t *testing.T) {
	sfClear(t)
	called := false
	RegisterVerifier(func(byte, []byte, []byte) (bool, error) {
		called = true
		return true, nil
	})

	require.Positive(t, StarkFRIVerifyPrecompile.RequiredGas(nil),
		"even an empty call must cost something")

	prev := StarkFRIVerifyPrecompile.RequiredGas(nil)
	for _, n := range []int{1, 16, 256, 4096} {
		got := StarkFRIVerifyPrecompile.RequiredGas(make([]byte, n))
		require.Greater(t, got, prev, "price must rise with input size")
		prev = got
	}

	proof := sfProof(bytes.Repeat([]byte{1}, 128))
	in := sfWire(VersionV1, proof, []byte{0xaa})
	need := StarkFRIVerifyPrecompile.RequiredGas(in)

	_, rem, err := StarkFRIVerifyPrecompile.Run(nil, common.Address{},
		ContractStarkFRIVerifyAddress, in, need-1, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, rem)
	require.False(t, called, "the verifier ran on an underpaid call")

	_, rem, err = StarkFRIVerifyPrecompile.Run(nil, common.Address{},
		ContractStarkFRIVerifyAddress, in, need+777, true)
	require.NoError(t, err)
	require.Equal(t, uint64(777), rem, "exactly the required gas must be consumed")
	require.True(t, called)
}

// TestSF_ModuleConfig covers the precompileconfig surface the module
// registers, asserting Equal actually discriminates rather than always
// agreeing.
func TestSF_ModuleConfig(t *testing.T) {
	c := &configurator{}
	cfg := c.MakeConfig()
	require.NotNil(t, cfg)
	require.IsType(t, &Config{}, cfg)
	require.NoError(t, c.Configure(nil, cfg, nil, nil))

	ts := uint64(1234)
	a := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, ConfigKey, a.Key())
	require.Equal(t, &ts, a.Timestamp())
	require.False(t, a.IsDisabled())
	require.NoError(t, a.Verify(nil))

	same := uint64(1234)
	require.True(t, a.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &same}}))

	other := uint64(5678)
	require.False(t, a.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &other}}),
		"configs at different timestamps must not compare equal")
	require.False(t, a.Equal(&Config{}), "a nil timestamp must not equal a set one")
	require.False(t, a.Equal(nil), "a nil config must not compare equal")

	disabled := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts, Disable: true}}
	require.True(t, disabled.IsDisabled())
	require.False(t, a.Equal(disabled), "the disable flag is part of identity")

	// The module is registered, at the address the precompile reports.
	m, ok := modules.GetPrecompileModuleByAddress(ContractStarkFRIVerifyAddress)
	require.True(t, ok, "module not registered at its address")
	require.Equal(t, ConfigKey, m.ConfigKey)
	require.Equal(t, StarkFRIVerifyPrecompile, m.Contract)
}
