// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package starkfri

import (
	"bytes"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// sfProofAt returns a proof frame stating the given parameters:
// the "P3Q1" envelope tag, the P3Q-SHA3 profile byte, the 10-byte p3q
// header, then body.
func sfProofAt(logBlowup, numQueries byte, body []byte) []byte {
	out := append([]byte(MagicHeader), 0x10) // ProofSystemId::Sha3
	out = append(out,
		0x01,       // wire version
		0x03,       // log_degree_bound
		logBlowup,  //
		0x01,       // log_arity (binary folding)
		numQueries, //
		0x02,       // log_final_poly
		0x00, 0x00, // flags, reserved
		0x00, 0x00, // public_input_len
	)
	return append(out, body...)
}

// sfProof returns the cheapest frame the floor admits, carrying body.
//
// Fixtures meaning "a proof that clears structural validation" must be
// built with this. A bare MagicHeader followed by arbitrary bytes
// states parameters nobody chose, so whether it clears the floor is an
// accident of those bytes — and under crypto/rand it is not even the
// same accident twice.
func sfProof(body []byte) []byte { return sfProofAt(2, 64, body) }

// TestSF_FloorBoundary walks the whole parameter grid the p3q wire
// admits and pins the verdict at every point: admitted exactly when
// log_blowup * num_queries reaches MinSoundnessBits. One query below
// the line refuses, one query on it passes.
//
// A per-field minimum cannot express this. (log_blowup=1,
// num_queries=64) and (log_blowup=5, num_queries=1) both sit inside
// every range the wire allows and neither is admissible; the boundary
// is a product, so no pair of independent bounds draws it.
func TestSF_FloorBoundary(t *testing.T) {
	sfClear(t)
	var reached int
	RegisterVerifier(func(byte, []byte, []byte) (bool, error) {
		reached++
		return true, nil
	})

	for logBlowup := 1; logBlowup <= 5; logBlowup++ {
		for numQueries := 1; numQueries <= 64; numQueries++ {
			proof := sfProofAt(byte(logBlowup), byte(numQueries), nil)
			want := logBlowup*numQueries >= MinSoundnessBits
			before := reached
			ok, err := Verify(proof, nil)
			require.Equalf(t, want, ok,
				"log_blowup=%d num_queries=%d (%d bits)",
				logBlowup, numQueries, logBlowup*numQueries)
			if want {
				require.NoError(t, err)
				require.Equal(t, before+1, reached, "an admitted proof must reach the verifier")
			} else {
				require.ErrorIs(t, err, ErrInsufficientSoundness)
				require.Equal(t, before, reached,
					"a proof below the floor must not reach the verifier")
			}
		}
	}

	// Rate 1/2 cannot reach the floor at any query count the wire
	// allows, so the whole blowup is unreachable.
	for numQueries := 1; numQueries <= 64; numQueries++ {
		ok, _ := Verify(sfProofAt(1, byte(numQueries), nil), nil)
		require.False(t, ok, "log_blowup=1 num_queries=%d", numQueries)
	}
}

// TestSF_FloorHoldsAtBothEntryPoints: Run and Verify ask the same
// question, so a proof refused by one cannot be admitted by the other.
func TestSF_FloorHoldsAtBothEntryPoints(t *testing.T) {
	sfClear(t)
	called := false
	RegisterVerifier(func(byte, []byte, []byte) (bool, error) {
		called = true
		return true, nil
	})

	weak := sfProofAt(2, 63, nil) // 126 bits — one query short
	at := sfProofAt(2, 64, nil)   // 128 bits — exactly the floor

	_, err := Verify(weak, nil)
	require.ErrorIs(t, err, ErrInsufficientSoundness)
	require.ErrorIs(t, sfRun(sfWire(VersionV1, weak, nil)), ErrInsufficientSoundness)
	require.False(t, called, "a sub-floor proof reached the verifier")

	_, err = Verify(at, nil)
	require.NoError(t, err)
	require.NoError(t, sfRun(sfWire(VersionV1, at, nil)))
	require.True(t, called)
}

// TestSF_FrameTooShortToStateParametersIsRefused: a proof carrying the
// envelope tag but not the header states no parameters at all, so
// there is nothing to hold to the floor. Refusing is the only
// fail-closed answer — reading past the end would decide the policy on
// whatever memory followed.
func TestSF_FrameTooShortToStateParametersIsRefused(t *testing.T) {
	sfClear(t)
	called := false
	RegisterVerifier(func(byte, []byte, []byte) (bool, error) {
		called = true
		return true, nil
	})

	full := sfProof(nil)
	require.Len(t, full, MinProofLength)
	for n := range MinProofLength {
		// Spare capacity behind the truncation holds the bytes that
		// WOULD have cleared the floor, so a missing bound is visible.
		short := full[:n:n]
		short = append(bytes.Clone(short), full[n:]...)[:n]
		ok, err := Verify(short, nil)
		require.False(t, ok, "len=%d", n)
		require.Error(t, err, "len=%d", n)
	}
	require.False(t, called, "a frame too short to state parameters reached the verifier")
	require.NoError(t, sfRunErr(full))
}

// sfRunErr is Verify's error for a proof with no public inputs, so the
// control above reads at the same entry point as the sweep.
func sfRunErr(proof []byte) error {
	_, err := Verify(proof, nil)
	return err
}

// TestSF_FloorRefusalCostsNoVerification pins the ordering that makes
// the floor worth having on this side of the FFI: the refusal is
// decided on the proof's own bytes, before the verifier is looked up,
// so an unregistered node and a registered one answer identically.
func TestSF_FloorRefusalCostsNoVerification(t *testing.T) {
	sfClear(t)
	weak := sfProofAt(1, 1, nil)
	in := sfWire(VersionV1, weak, []byte{0xaa})

	require.ErrorIs(t, sfRun(in), ErrInsufficientSoundness,
		"with no verifier registered, the floor still decides first")

	RegisterVerifier(func(byte, []byte, []byte) (bool, error) {
		t.Fatal("verifier consulted for a proof below the floor")
		return true, nil
	})
	require.ErrorIs(t, sfRun(in), ErrInsufficientSoundness)

	// Gas is a function of calldata length alone, so the refusal is
	// not cheaper for the caller — the saving is the node's work.
	require.Equal(t,
		StarkFRIVerifyPrecompile.RequiredGas(in),
		BaseVerifyGas+uint64(len(in))*PerByteGas)
	_, rem, err := StarkFRIVerifyPrecompile.Run(nil, common.Address{},
		ContractStarkFRIVerifyAddress, in,
		StarkFRIVerifyPrecompile.RequiredGas(in)+42, true)
	require.ErrorIs(t, err, ErrInsufficientSoundness)
	require.Equal(t, uint64(42), rem, "the full gas charge is still taken")
}
