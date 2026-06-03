// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// EIP-4844 Known-Answer Tests for the KZG4844 precompile.
//
// Addresses TESTING_GAPS.md §1.9 (HIGH severity):
//   - No EIP-4844 reference KAT vectors
//   - No trusted_setup.json verification
//   - No rejection test for blob field elements >= BLS12-381 scalar modulus
//   - No nil-input test
//
// Vector source:
//   - all_zero_blob   : EIP-4844 / consensus-specs polynomial-commitments.md.
//     The commitment of the zero polynomial is the G1 identity, which
//     serializes to the canonical "compressed infinity" encoding 0xc0 || 0x00*47.
//     This is asserted directly against go-kzg-4844's PointAtInfinity constant
//     (which itself matches the spec's G1_POINT_AT_INFINITY).
//   - single_one_at_index_0 : Hand-constructed input. Expected output is
//     computed at test time via github.com/crate-crypto/go-kzg-4844 v1.1.0
//     using NewContext4096Secure (the official Ethereum KZG ceremony trusted
//     setup). The test asserts that the precompile path returns the SAME bytes
//     as a direct library call. Any divergence indicates the precompile is no
//     longer consensus-compatible with the reference implementation.
//   - modulus_field_element : Blob whose first 32 bytes encode the BLS12-381
//     scalar field modulus r exactly. Per the spec, blob field elements MUST
//     be canonical and strictly less than r. Asserts rejection.
//   - modulus_plus_one      : r + 1; also asserts rejection.
//
// The embedded JSON at testdata/eip4844_vectors.json carries the metadata for
// these vectors. Blob bytes themselves are reconstructed at runtime (a 128 KiB
// all-zero blob need not be embedded).
//
// Together these cover the four sub-items called out in TESTING_GAPS §1.9.

package kzg4844

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"testing"

	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/eip4844_vectors.json
var eip4844VectorsJSON []byte

// blsModulusBytes is the BLS12-381 scalar field modulus r in big-endian.
// Identical to gokzg4844.BlsModulus; kept as a local literal so the test
// remains a true KAT independent of the helper package's constants.
var blsModulusBytes = [32]byte{
	0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
	0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
	0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
}

// TestKZG4844_VectorsManifestParses ensures the embedded testdata stays
// well-formed JSON. Catches accidental corruption of the manifest.
func TestKZG4844_VectorsManifestParses(t *testing.T) {
	require.NotEmpty(t, eip4844VectorsJSON, "embedded eip4844_vectors.json must be non-empty")
	var manifest map[string]any
	require.NoError(t, json.Unmarshal(eip4844VectorsJSON, &manifest))
	meta, ok := manifest["_meta"].(map[string]any)
	require.True(t, ok, "manifest must contain _meta object")
	vecs, ok := meta["vectors"].([]any)
	require.True(t, ok, "_meta.vectors must be an array")
	require.GreaterOrEqual(t, len(vecs), 4, "manifest must document at least 4 vectors")
}

// TestKZG4844_TrustedSetupInitialized verifies the precompile's bundled
// trusted setup is the one shipped by go-kzg-4844's NewContext4096Secure
// (the official Ethereum KZG ceremony). We assert that committing to a
// known input via the precompile equals committing via a fresh secure
// context. If the trusted setup were swapped or corrupted, these would
// diverge.
func TestKZG4844_TrustedSetupInitialized(t *testing.T) {
	require.NotNil(t, kzgContext, "global kzgContext must be initialized by init()")

	freshCtx, err := gokzg4844.NewContext4096Secure()
	require.NoError(t, err, "secure context must initialize")

	// Use a small deterministic blob (a "1" in the first field element slot).
	blob := make([]byte, BlobSize)
	blob[31] = 0x01

	var goBlob gokzg4844.Blob
	copy(goBlob[:], blob)

	freshCommit, err := freshCtx.BlobToKZGCommitment(&goBlob, 0)
	require.NoError(t, err)

	input := make([]byte, 1+BlobSize)
	input[0] = OpBlobToCommitment
	copy(input[1:], blob)

	precompileCommit, _, err := KZG4844Precompile.Run(
		nil, common.Address{}, ContractAddress, input, GasBlobToCommitment, false,
	)
	require.NoError(t, err)
	require.Equal(t, freshCommit[:], precompileCommit,
		"precompile and freshly-initialized secure context must produce identical commitments")
}

// TestBlobToCommitment_AgainstEIP4844Vectors runs the KAT vectors.
func TestBlobToCommitment_AgainstEIP4844Vectors(t *testing.T) {
	t.Run("all_zero_blob/commitment_is_point_at_infinity", func(t *testing.T) {
		blob := make([]byte, BlobSize) // implicit zero
		input := make([]byte, 1+BlobSize)
		input[0] = OpBlobToCommitment
		copy(input[1:], blob)

		got, _, err := KZG4844Precompile.Run(
			nil, common.Address{}, ContractAddress, input, GasBlobToCommitment, false,
		)
		require.NoError(t, err)
		require.Len(t, got, CommitmentSize)

		// Spec: commitment of the zero polynomial is the G1 identity, which
		// serializes (BLS12-381 compressed form) to 0xc0 || 0x00 * 47.
		expected := gokzg4844.PointAtInfinity
		require.True(t, bytes.Equal(got, expected[:]),
			"all-zero blob must commit to G1 point at infinity (0xc0 || 0x00*47); got %x", got)
	})

	t.Run("single_one_at_index_0/matches_reference_library", func(t *testing.T) {
		blob := make([]byte, BlobSize)
		blob[31] = 0x01 // first field element = 1, rest = 0

		// Reference: direct go-kzg-4844 call.
		var goBlob gokzg4844.Blob
		copy(goBlob[:], blob)
		refCtx, err := gokzg4844.NewContext4096Secure()
		require.NoError(t, err)
		refCommit, err := refCtx.BlobToKZGCommitment(&goBlob, 0)
		require.NoError(t, err)

		// Precompile.
		input := make([]byte, 1+BlobSize)
		input[0] = OpBlobToCommitment
		copy(input[1:], blob)
		got, _, err := KZG4844Precompile.Run(
			nil, common.Address{}, ContractAddress, input, GasBlobToCommitment, false,
		)
		require.NoError(t, err)
		require.Equal(t, refCommit[:], got,
			"precompile commitment must equal reference library commitment for blob{[31]=1, rest=0}")

		// Precompile result must NOT be the point at infinity for this non-zero input.
		require.False(t, bytes.Equal(got, gokzg4844.PointAtInfinity[:]),
			"commitment of non-zero blob must not equal point at infinity")
	})
}

// TestBlobToCommitment_RejectsOversizedFieldElement verifies that blob field
// elements >= BLS12-381 scalar modulus are rejected (not silently reduced).
//
// This is consensus-critical: silent reduction would let two blobs with
// different bit patterns produce the same commitment.
func TestBlobToCommitment_RejectsOversizedFieldElement(t *testing.T) {
	cases := []struct {
		name      string
		buildBlob func() []byte
	}{
		{
			name: "field_element_equals_modulus",
			buildBlob: func() []byte {
				blob := make([]byte, BlobSize)
				copy(blob[:32], blsModulusBytes[:]) // first field element = r exactly
				return blob
			},
		},
		{
			name: "field_element_equals_modulus_plus_one",
			buildBlob: func() []byte {
				blob := make([]byte, BlobSize)
				// r + 1 in big-endian. r ends in ...0x00000001, so r+1 ends in ...0x00000002.
				rPlus1 := blsModulusBytes
				rPlus1[31] = 0x02
				copy(blob[:32], rPlus1[:])
				return blob
			},
		},
		{
			name: "field_element_is_all_0xFF",
			buildBlob: func() []byte {
				blob := make([]byte, BlobSize)
				for i := 0; i < 32; i++ {
					blob[i] = 0xFF // way above modulus
				}
				return blob
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			blob := tc.buildBlob()
			input := make([]byte, 1+BlobSize)
			input[0] = OpBlobToCommitment
			copy(input[1:], blob)

			_, _, err := KZG4844Precompile.Run(
				nil, common.Address{}, ContractAddress, input, GasBlobToCommitment, false,
			)
			require.Error(t, err,
				"blob with non-canonical field element must be rejected, not silently accepted")
		})
	}
}

// TestBlobToCommitment_RejectsNilBlob asserts the precompile cleanly
// rejects nil input rather than panicking or returning a zero commitment.
func TestBlobToCommitment_RejectsNilBlob(t *testing.T) {
	// nil input
	_, _, err := KZG4844Precompile.Run(
		nil, common.Address{}, ContractAddress, nil, 1_000_000, false,
	)
	require.Error(t, err, "nil input must be rejected")

	// op byte only, no blob payload
	input := []byte{OpBlobToCommitment}
	_, _, err = KZG4844Precompile.Run(
		nil, common.Address{}, ContractAddress, input, GasBlobToCommitment, false,
	)
	require.Error(t, err, "op byte with no payload must be rejected")
}

// TestBlobToCommitment_RejectsShortBlob asserts off-by-one short blobs are rejected.
func TestBlobToCommitment_RejectsShortBlob(t *testing.T) {
	// One byte short of a full blob.
	input := make([]byte, 1+BlobSize-1)
	input[0] = OpBlobToCommitment
	_, _, err := KZG4844Precompile.Run(
		nil, common.Address{}, ContractAddress, input, GasBlobToCommitment, false,
	)
	require.Error(t, err, "blob one byte short of BlobSize must be rejected")

	// Half a blob.
	input = make([]byte, 1+BlobSize/2)
	input[0] = OpBlobToCommitment
	_, _, err = KZG4844Precompile.Run(
		nil, common.Address{}, ContractAddress, input, GasBlobToCommitment, false,
	)
	require.Error(t, err, "half-sized blob must be rejected")
}

// TestComputeKZGProof_KnownAnswer verifies proof computation is deterministic
// and matches the reference library byte-for-byte for a known input.
func TestComputeKZGProof_KnownAnswer(t *testing.T) {
	blob := make([]byte, BlobSize)
	blob[31] = 0x01 // poly(X) = 1 at x=0 (Lagrange basis interpretation)

	// Evaluation point z = 0x42 (small canonical scalar).
	z := make([]byte, FieldElementSize)
	z[31] = 0x42

	// Reference computation.
	var goBlob gokzg4844.Blob
	copy(goBlob[:], blob)
	var goZ gokzg4844.Scalar
	copy(goZ[:], z)

	refCtx, err := gokzg4844.NewContext4096Secure()
	require.NoError(t, err)
	refProof, refY, err := refCtx.ComputeKZGProof(&goBlob, goZ, 0)
	require.NoError(t, err)

	// Precompile.
	input := make([]byte, 1+BlobSize+FieldElementSize)
	input[0] = OpComputeProof
	copy(input[1:], blob)
	copy(input[1+BlobSize:], z)

	result, _, err := KZG4844Precompile.Run(
		nil, common.Address{}, ContractAddress, input, GasComputeProof, false,
	)
	require.NoError(t, err)
	require.Equal(t, ProofSize+FieldElementSize, len(result))

	gotProof := result[:ProofSize]
	gotY := result[ProofSize:]
	require.Equal(t, refProof[:], gotProof,
		"precompile proof bytes must match reference library proof bytes")
	require.Equal(t, refY[:], gotY,
		"precompile y bytes must match reference library y bytes")
}

// TestVerifyKZGProof_ValidRejectsTampered asserts a round-trip:
// commit -> prove -> verify (true), then mutate -> verify (false).
// Distinct from TestKZG4844_VerifyProof_Invalid in that it walks the
// tamper space across multiple components (commitment, z, y, proof).
func TestVerifyKZGProof_ValidRejectsTampered(t *testing.T) {
	blob := make([]byte, BlobSize)
	blob[31] = 0x01

	// 1. Commit.
	cInput := make([]byte, 1+BlobSize)
	cInput[0] = OpBlobToCommitment
	copy(cInput[1:], blob)
	commitment, _, err := KZG4844Precompile.Run(
		nil, common.Address{}, ContractAddress, cInput, GasBlobToCommitment, false,
	)
	require.NoError(t, err)

	// 2. Prove at z=0x42.
	z := make([]byte, FieldElementSize)
	z[31] = 0x42
	pInput := make([]byte, 1+BlobSize+FieldElementSize)
	pInput[0] = OpComputeProof
	copy(pInput[1:], blob)
	copy(pInput[1+BlobSize:], z)
	proofRes, _, err := KZG4844Precompile.Run(
		nil, common.Address{}, ContractAddress, pInput, GasComputeProof, false,
	)
	require.NoError(t, err)
	proof := proofRes[:ProofSize]
	y := proofRes[ProofSize:]

	buildVerifyInput := func(c, zb, yb, pb []byte) []byte {
		in := make([]byte, 1+CommitmentSize+FieldElementSize+FieldElementSize+ProofSize)
		in[0] = OpVerifyProof
		off := 1
		off += copy(in[off:], c)
		off += copy(in[off:], zb)
		off += copy(in[off:], yb)
		copy(in[off:], pb)
		return in
	}

	// 3. Valid path returns 0x01.
	validIn := buildVerifyInput(commitment, z, y, proof)
	res, _, err := KZG4844Precompile.Run(
		nil, common.Address{}, ContractAddress, validIn, GasVerifyProof, false,
	)
	require.NoError(t, err)
	require.Equal(t, []byte{0x01}, res, "untampered proof must verify")

	// 4. Tamper each component independently and confirm rejection.
	for _, tamper := range []struct {
		name  string
		mutFn func() []byte
	}{
		{"flip_commitment_byte", func() []byte {
			c := append([]byte{}, commitment...)
			c[5] ^= 0x01
			return buildVerifyInput(c, z, y, proof)
		}},
		{"flip_z_byte", func() []byte {
			z2 := append([]byte{}, z...)
			z2[31] ^= 0x01
			return buildVerifyInput(commitment, z2, y, proof)
		}},
		{"flip_y_byte", func() []byte {
			y2 := append([]byte{}, y...)
			y2[31] ^= 0x01
			return buildVerifyInput(commitment, z, y2, proof)
		}},
		{"flip_proof_byte", func() []byte {
			p := append([]byte{}, proof...)
			p[5] ^= 0x01
			return buildVerifyInput(commitment, z, y, p)
		}},
	} {
		tamper := tamper
		t.Run(tamper.name, func(t *testing.T) {
			in := tamper.mutFn()
			out, _, err := KZG4844Precompile.Run(
				nil, common.Address{}, ContractAddress, in, GasVerifyProof, false,
			)
			// Either return 0x00 (clean reject) or an error from BLS12-381
			// decompression. Both indicate the tampered proof was not
			// accepted as valid; what we MUST NOT see is a 0x01 result.
			if err == nil {
				require.Equal(t, []byte{0x00}, out,
					"tampered (%s) proof must NOT verify as 0x01", tamper.name)
			}
		})
	}
}
