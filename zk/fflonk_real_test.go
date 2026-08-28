// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/luxfi/crypto/kzg4844"
	"github.com/luxfi/geth/common"
)

// makeBlob builds a KZG blob whose first len(vals) field elements are the given
// small (canonical) values.
func makeBlob(vals ...uint64) *kzg4844.Blob {
	var blob kzg4844.Blob
	for i, v := range vals {
		binary.BigEndian.PutUint64(blob[i*32+24:i*32+32], v)
	}
	return &blob
}

// buildValidFflonkProof produces a proof whose two openings genuinely verify
// against the KZG trusted setup for the given verifying key and public inputs.
func buildValidFflonkProof(t *testing.T, vk *VerifyingKey, publicInputs []*big.Int, numEvals int) []byte {
	t.Helper()
	if numEvals < 8 {
		t.Fatalf("numEvals must be >= 8")
	}
	blob1 := makeBlob(3, 5, 7)
	blob2 := makeBlob(11, 13, 17)
	c1, err := kzg4844.BlobToCommitment(blob1)
	if err != nil {
		t.Fatalf("commit1: %v", err)
	}
	c2, err := kzg4844.BlobToCommitment(blob2)
	if err != nil {
		t.Fatalf("commit2: %v", err)
	}

	// Auxiliary (non-claim) evaluations, bound into the opening point.
	bound := make([]*big.Int, numEvals-2)
	for i := range bound {
		bound[i] = big.NewInt(int64(1000 + i))
	}

	z := computeFflonkOpeningPoint(vk, c1[:], c2[:], publicInputs, bound)
	var zpt kzg4844.Point
	copy(zpt[:], padScalar32(z))

	w1, claim1, err := kzg4844.ComputeProof(blob1, zpt)
	if err != nil {
		t.Fatalf("prove1: %v", err)
	}
	w2, claim2, err := kzg4844.ComputeProof(blob2, zpt)
	if err != nil {
		t.Fatalf("prove2: %v", err)
	}

	proof := make([]byte, 0, 192+numEvals*32)
	proof = append(proof, c1[:]...)
	proof = append(proof, c2[:]...)
	proof = append(proof, w1[:]...)
	proof = append(proof, w2[:]...)
	proof = append(proof, claim1[:]...) // evaluations[0] = C1 opening
	proof = append(proof, claim2[:]...) // evaluations[1] = C2 opening
	for _, b := range bound {
		proof = append(proof, padScalar32(b)...)
	}
	return proof
}

func fflonkTestVK() *VerifyingKey {
	return &VerifyingKey{ProofSystem: ProofSystemFflonk, Hash: [32]byte{0x0F, 0xF1, 0x07}}
}

// TestFflonkVerifyValid: a genuine pair of KZG openings verifies.
func TestFflonkVerifyValid(t *testing.T) {
	zv := NewZKVerifier()
	vk := fflonkTestVK()
	pub := []*big.Int{big.NewInt(7), big.NewInt(42)}
	proof := buildValidFflonkProof(t, vk, pub, 8)

	if !zv.fflonkVerify(vk, proof, pub).OK() {
		t.Fatal("a valid fflonk proof must verify")
	}
}

// TestFflonkVerifyTamperedClaim: corrupting a claim value breaks the pairing.
func TestFflonkVerifyTamperedClaim(t *testing.T) {
	zv := NewZKVerifier()
	vk := fflonkTestVK()
	pub := []*big.Int{big.NewInt(7)}
	proof := buildValidFflonkProof(t, vk, pub, 8)

	proof[192] ^= 0x01 // flip a bit in evaluations[0] (the C1 opening value)
	if zv.fflonkVerify(vk, proof, pub).OK() {
		t.Fatal("tampered claim must be REJECTED")
	}
}

// TestFflonkVerifyTamperedProofPoint: corrupting an opening proof point fails.
func TestFflonkVerifyTamperedProofPoint(t *testing.T) {
	zv := NewZKVerifier()
	vk := fflonkTestVK()
	pub := []*big.Int{big.NewInt(7)}
	proof := buildValidFflonkProof(t, vk, pub, 8)

	proof[96] ^= 0x01 // flip a bit in W1 (BLS12-381 G1 point)
	if zv.fflonkVerify(vk, proof, pub).OK() {
		t.Fatal("tampered opening-proof point must be REJECTED")
	}
}

// TestFflonkVerifyTamperedBoundEval: a bound (non-claim) evaluation feeds the
// Fiat-Shamir point, so tampering it shifts z and both openings fail.
func TestFflonkVerifyTamperedBoundEval(t *testing.T) {
	zv := NewZKVerifier()
	vk := fflonkTestVK()
	pub := []*big.Int{big.NewInt(7)}
	proof := buildValidFflonkProof(t, vk, pub, 8)

	proof[192+3*32] ^= 0x01 // flip a bit in evaluations[3] (a bound eval)
	if zv.fflonkVerify(vk, proof, pub).OK() {
		t.Fatal("tampered bound evaluation must be REJECTED")
	}
}

// TestFflonkVerifyWrongPublicInputs: verifying with different public inputs
// changes z and rejects the proof.
func TestFflonkVerifyWrongPublicInputs(t *testing.T) {
	zv := NewZKVerifier()
	vk := fflonkTestVK()
	proof := buildValidFflonkProof(t, vk, []*big.Int{big.NewInt(7)}, 8)

	if zv.fflonkVerify(vk, proof, []*big.Int{big.NewInt(8)}).OK() {
		t.Fatal("verification under different public inputs must be REJECTED")
	}
}

// TestFflonkVerifyOffCurvePoint: a commitment that is not a valid G1 point is
// rejected before any pairing.
func TestFflonkVerifyOffCurvePoint(t *testing.T) {
	zv := NewZKVerifier()
	vk := fflonkTestVK()
	pub := []*big.Int{big.NewInt(7)}
	proof := buildValidFflonkProof(t, vk, pub, 8)

	for i := 0; i < 48; i++ {
		proof[i] = 0xFF // C1 is no longer a valid compressed G1 point
	}
	if zv.fflonkVerify(vk, proof, pub).OK() {
		t.Fatal("off-curve / invalid G1 commitment must be REJECTED")
	}
}

// TestFflonkVerifyNonCanonicalScalar: an evaluation >= the scalar field order
// is rejected.
func TestFflonkVerifyNonCanonicalScalar(t *testing.T) {
	zv := NewZKVerifier()
	vk := fflonkTestVK()
	pub := []*big.Int{big.NewInt(7)}
	proof := buildValidFflonkProof(t, vk, pub, 8)

	copy(proof[192:224], padScalar32(blsScalarField())) // evaluations[0] = r
	if zv.fflonkVerify(vk, proof, pub).OK() {
		t.Fatal("non-canonical scalar evaluation must be REJECTED")
	}
}

// TestFflonkVerifyShortProof: an undersized proof is rejected.
func TestFflonkVerifyShortProof(t *testing.T) {
	zv := NewZKVerifier()
	if zv.fflonkVerify(fflonkTestVK(), make([]byte, 100), nil).OK() {
		t.Fatal("short proof must be REJECTED")
	}
}

// TestValidG1Point checks the BLS12-381 G1 point validator directly.
func TestValidG1Point(t *testing.T) {
	// A real commitment is a valid, non-infinity G1 point.
	c, err := kzg4844.BlobToCommitment(makeBlob(1, 2, 3))
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if !validG1Point(c[:]) {
		t.Error("a genuine KZG commitment must be a valid G1 point")
	}
	// Infinity (all zeros) is rejected.
	if validG1Point(make([]byte, 48)) {
		t.Error("point at infinity must be rejected")
	}
	// Garbage / off-curve bytes are rejected.
	bad := make([]byte, 48)
	for i := range bad {
		bad[i] = 0xFF
	}
	if validG1Point(bad) {
		t.Error("off-curve bytes must be rejected")
	}
	// Wrong length is rejected.
	if validG1Point(make([]byte, 32)) {
		t.Error("wrong-length point must be rejected")
	}
}

// TestVerifyFflonkEndToEnd exercises the public VerifyFflonk entry: a valid
// proof reports Valid, a tampered proof does not.
func TestVerifyFflonkEndToEnd(t *testing.T) {
	zv := NewZKVerifier()
	g1 := make([]byte, 64)
	g2 := make([]byte, 128)
	keyID, err := zv.RegisterVerifyingKey(common.Address{}, ProofSystemFflonk, CircuitTransfer, g1, g2, g2, g2, [][]byte{g1})
	if err != nil {
		t.Fatalf("register vk: %v", err)
	}
	vk := zv.VerifyingKeys[keyID]
	pub := []*big.Int{big.NewInt(99)}
	proof := buildValidFflonkProof(t, vk, pub, 8)

	res, err := zv.VerifyFflonk(keyID, proof, pub)
	if err != nil {
		t.Fatalf("VerifyFflonk: %v", err)
	}
	if !res.Valid {
		t.Fatal("valid proof must report Valid via VerifyFflonk")
	}

	tampered := make([]byte, len(proof))
	copy(tampered, proof)
	tampered[192] ^= 0x01
	res, err = zv.VerifyFflonk(keyID, tampered, pub)
	if err != nil {
		t.Fatalf("VerifyFflonk(tampered): %v", err)
	}
	if res.Valid {
		t.Fatal("tampered proof must NOT report Valid via VerifyFflonk")
	}
}
