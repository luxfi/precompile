package aivmbridge

import (
	"testing"

	"github.com/luxfi/crypto/poi"
)

// buildOpening makes a small proof-of-inference transcript and returns the wire-encoded opening of
// its first matmul. With fabricate=true that matmul's output has one entry flipped (a claimed
// result never produced by A·B).
func buildOpening(fabricate bool) []byte {
	s := uint64(0x1234)
	rnd := func(rows, cols int) poi.Mat {
		d := make([]int64, rows*cols)
		for i := range d {
			s = s*6364136223846793005 + 1442695040888963407
			d[i] = int64((s>>33)%127) - 63
		}
		return poi.NewMat(rows, cols, d)
	}
	tr := poi.NewTranscript()
	a, b := rnd(4, 16), rnd(16, 8)
	if fabricate {
		c := poi.ExactMatmul(a, b)
		c.Data[3]++ // fabricate one output entry
		tr.CommitClaimed(a, b, c)
	} else {
		tr.Matmul(a, b)
	}
	tr.Matmul(rnd(2, 4), rnd(4, 3)) // a second matmul so the tree has a real proof path
	root := tr.Root()
	return poi.EncodeOpening(root, []byte("beacon:precompile"), tr.Open(0))
}

// An honest opening verifies natively: included AND Freivalds-OK → verdict 0b11.
func TestPrecompile_VerifyComputeProof_Honest(t *testing.T) {
	ret, rem, err := verifyComputeProof(buildOpening(false), 50_000_000)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ret[31] != resultIncluded|resultFreivaldsOK {
		t.Fatalf("honest verdict = %d, want %d (included|ok)", ret[31], resultIncluded|resultFreivaldsOK)
	}
	if rem >= 50_000_000 {
		t.Fatal("gas must be consumed")
	}
}

// A fabricated output is caught natively: included but NOT Freivalds-OK → verdict 0b01 (= fraud).
func TestPrecompile_VerifyComputeProof_Fraud(t *testing.T) {
	ret, _, err := verifyComputeProof(buildOpening(true), 50_000_000)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ret[31] != resultIncluded {
		t.Fatalf("fraud verdict = %d, want %d (included, not ok)", ret[31], resultIncluded)
	}
}

// Below the base, the op is out of gas (bounds griefing on a malformed/huge frame).
func TestPrecompile_VerifyComputeProof_OOG(t *testing.T) {
	if _, _, err := verifyComputeProof(buildOpening(false), GasVerifyComputeProofBase-1); err == nil {
		t.Fatal("must be out of gas below the base")
	}
}

// RequiredGas (the EVM's pre-charge) matches what Run actually consumes.
func TestPrecompile_GasAccountingConsistent(t *testing.T) {
	in := buildOpening(false)
	want := computeProofRequiredGas(in)
	if want <= GasVerifyComputeProofBase {
		t.Fatal("a real opening must cost more than the base")
	}
	_, rem, err := verifyComputeProof(in, want)
	if err != nil {
		t.Fatalf("verify at RequiredGas budget: %v", err)
	}
	if rem != 0 {
		t.Fatalf("Run consumed %d less than RequiredGas estimated (rem=%d) — accounting drift", want-rem, rem)
	}
}

// A garbage frame decodes-errs and consumes only the base (no panic, no over-charge).
func TestPrecompile_VerifyComputeProof_Garbage(t *testing.T) {
	_, rem, err := verifyComputeProof([]byte{1, 2, 3, 4, 5}, 1_000_000)
	if err == nil {
		t.Fatal("garbage frame must error")
	}
	if rem != 1_000_000-GasVerifyComputeProofBase {
		t.Fatalf("garbage frame must consume exactly the base, rem=%d", rem)
	}
}
