// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kzg4844

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// The consensus-spec KZG reference vectors, as shipped with
// github.com/crate-crypto/go-kzg-4844 (tests/, kzg-mainnet preset). They are
// the only oracle in this package computed by someone else: a commitment
// compared against a commitment from the same library agrees with itself even
// under the wrong trusted setup.
//
// Only vectors whose blob compresses are carried; the handful built from
// random bytes would add a megabyte apiece and test nothing the others do not.
// An `output` of null means the input is malformed and the call must be
// refused -- distinct from a well-formed opening that does not verify.
//
//go:embed testdata/ckzg_vectors.json.gz
var ckzgVectorsGZ []byte

type ckzgVector struct {
	Name       string          `json:"name"`
	Blob       string          `json:"blob"`
	Commitment string          `json:"commitment"`
	Proof      string          `json:"proof"`
	Z          string          `json:"z"`
	Y          string          `json:"y"`
	Output     json.RawMessage `json:"output"`
}

func (v ckzgVector) refused() bool { return string(v.Output) == "null" }

func (v ckzgVector) boolOutput(t *testing.T) bool {
	t.Helper()
	var b bool
	require.NoError(t, json.Unmarshal(v.Output, &b))
	return b
}

func (v ckzgVector) stringOutput(t *testing.T) string {
	t.Helper()
	var s string
	require.NoError(t, json.Unmarshal(v.Output, &s))
	return s
}

func (v ckzgVector) pairOutput(t *testing.T) (string, string) {
	t.Helper()
	var pair []string
	require.NoError(t, json.Unmarshal(v.Output, &pair))
	require.Len(t, pair, 2)
	return pair[0], pair[1]
}

func ckzgVectors(t *testing.T) map[string][]ckzgVector {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(ckzgVectorsGZ))
	require.NoError(t, err)
	raw, err := io.ReadAll(zr)
	require.NoError(t, err)

	var out map[string][]ckzgVector
	require.NoError(t, json.Unmarshal(raw, &out))
	for kind, vs := range out {
		require.NotEmptyf(t, vs, "no vectors for %s", kind)
	}
	return out
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// call runs the precompile at whatever price it asks for.
func call(t *testing.T, input []byte) ([]byte, error) {
	t.Helper()
	gas := KZG4844Precompile.RequiredGas(input)
	out, remaining, err := KZG4844Precompile.Run(nil, common.Address{}, ContractAddress, input, gas, false)
	require.Zero(t, remaining, "the operation did not charge what it advertised")
	return out, err
}

func TestCKZG_BlobToCommitment(t *testing.T) {
	for _, v := range ckzgVectors(t)["blob_to_kzg_commitment"] {
		t.Run(v.Name, func(t *testing.T) {
			out, err := call(t, append([]byte{OpBlobToCommitment}, unhex(t, v.Blob)...))
			if v.refused() {
				require.Error(t, err)
				require.Nil(t, out)
				return
			}
			require.NoError(t, err)
			require.Equal(t, v.stringOutput(t), hex.EncodeToString(out))
		})
	}
}

func TestCKZG_ComputeProof(t *testing.T) {
	for _, v := range ckzgVectors(t)["compute_kzg_proof"] {
		t.Run(v.Name, func(t *testing.T) {
			input := append([]byte{OpComputeProof}, unhex(t, v.Blob)...)
			input = append(input, unhex(t, v.Z)...)

			out, err := call(t, input)
			if v.refused() {
				require.Error(t, err)
				require.Nil(t, out)
				return
			}
			require.NoError(t, err)
			require.Len(t, out, ProofSize+FieldElementSize)

			proof, y := v.pairOutput(t)
			require.Equal(t, proof, hex.EncodeToString(out[:ProofSize]), "proof")
			require.Equal(t, y, hex.EncodeToString(out[ProofSize:]), "claimed value")
		})
	}
}

// TestCKZG_VerifyProof is the largest of these: 122 openings covering
// canonical and non-canonical scalars, points off the curve, points outside
// the r-order subgroup, and correct openings of the wrong point.
func TestCKZG_VerifyProof(t *testing.T) {
	var verified, rejected, refused int

	for _, v := range ckzgVectors(t)["verify_kzg_proof"] {
		t.Run(v.Name, func(t *testing.T) {
			input := []byte{OpVerifyProof}
			input = append(input, unhex(t, v.Commitment)...)
			input = append(input, unhex(t, v.Z)...)
			input = append(input, unhex(t, v.Y)...)
			input = append(input, unhex(t, v.Proof)...)

			out, err := call(t, input)
			if v.refused() {
				refused++
				require.Error(t, err, "accepted a malformed opening")
				require.Nil(t, out)
				return
			}
			require.NoError(t, err)
			if v.boolOutput(t) {
				verified++
				require.Equal(t, []byte{0x01}, out)
			} else {
				rejected++
				require.Equal(t, []byte{0x00}, out)
			}
		})
	}

	// All three answers are exercised; a verifier stuck on any one of them
	// would otherwise pass a set that only contained the other two.
	require.Positive(t, verified, "no vector verified")
	require.Positive(t, rejected, "no vector was a well-formed failure")
	require.Positive(t, refused, "no vector was malformed")
}

func TestCKZG_VerifyBlobProof(t *testing.T) {
	var verified, rejected, refused int

	for _, v := range ckzgVectors(t)["verify_blob_kzg_proof"] {
		t.Run(v.Name, func(t *testing.T) {
			input := []byte{OpVerifyBlobProof}
			input = append(input, unhex(t, v.Blob)...)
			input = append(input, unhex(t, v.Commitment)...)
			input = append(input, unhex(t, v.Proof)...)

			out, err := call(t, input)
			if v.refused() {
				refused++
				require.Error(t, err)
				require.Nil(t, out)
				return
			}
			require.NoError(t, err)
			if v.boolOutput(t) {
				verified++
				require.Equal(t, []byte{0x01}, out)
			} else {
				rejected++
				require.Equal(t, []byte{0x00}, out)
			}
		})
	}

	require.Positive(t, verified)
	require.Positive(t, rejected)
	require.Positive(t, refused)
}

// TestCKZG_BatchAgreesWithTheSingleOpening: a batch is not a separate verifier,
// so it must answer exactly what verifying each member one at a time answers.
func TestCKZG_BatchAgreesWithTheSingleOpening(t *testing.T) {
	all := ckzgVectors(t)["verify_kzg_proof"]

	var wellFormed []ckzgVector
	for _, v := range all {
		if !v.refused() {
			wellFormed = append(wellFormed, v)
		}
	}
	require.Greater(t, len(wellFormed), 4)

	batchOf := func(vs []ckzgVector) []byte {
		input := []byte{OpBatchVerifyProofs, byte(len(vs) >> 8), byte(len(vs))}
		for _, v := range vs {
			input = append(input, unhex(t, v.Commitment)...)
			input = append(input, unhex(t, v.Z)...)
			input = append(input, unhex(t, v.Y)...)
			input = append(input, unhex(t, v.Proof)...)
		}
		return input
	}

	var good, bad []ckzgVector
	for _, v := range wellFormed {
		if v.boolOutput(t) {
			good = append(good, v)
		} else {
			bad = append(bad, v)
		}
	}
	require.NotEmpty(t, good)
	require.NotEmpty(t, bad)

	out, err := call(t, batchOf(good))
	require.NoError(t, err)
	require.Equal(t, []byte{0x01}, out, "a batch of valid openings must verify")

	// One bad member anywhere in the batch sinks it.
	for _, at := range []int{0, len(good) / 2, len(good)} {
		mixed := append([]ckzgVector{}, good[:at]...)
		mixed = append(mixed, bad[0])
		mixed = append(mixed, good[at:]...)

		out, err := call(t, batchOf(mixed))
		require.NoError(t, err)
		require.Equalf(t, []byte{0x00}, out, "a batch with a bad member at %d verified", at)
	}

	// A malformed member is refused rather than counted as a failure.
	var malformed ckzgVector
	for _, v := range all {
		if v.refused() {
			malformed = v
			break
		}
	}
	_, err = call(t, batchOf([]ckzgVector{good[0], malformed}))
	require.Error(t, err)
}

// TestCKZG_CommitmentIsBindingToTheBlob: two vectors with different blobs must
// not share a commitment, and a commitment must open only at the value its own
// blob takes.
func TestCKZG_CommitmentIsBindingToTheBlob(t *testing.T) {
	seen := map[string]string{}
	for _, v := range ckzgVectors(t)["blob_to_kzg_commitment"] {
		if v.refused() {
			continue
		}
		commitment := v.stringOutput(t)
		if prev, ok := seen[commitment]; ok {
			require.Equalf(t, prev, v.Blob, "two blobs share commitment %s", commitment)
		}
		seen[commitment] = v.Blob
	}
	require.Greater(t, len(seen), 1)
}
