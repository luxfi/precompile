// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

const testGas = 100_000

func TestRequiredGas(t *testing.T) {
	if gas := Ed25519VerifyPrecompile.RequiredGas(nil); gas != GasEd25519Verify {
		t.Errorf("expected gas %d, got %d", GasEd25519Verify, gas)
	}
}

func TestValidSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	message := sha256.Sum256([]byte("test message for MIGA mint claim"))
	sig := ed25519.Sign(priv, message[:])

	input := make([]byte, 0, InputLength)
	input = append(input, message[:]...)
	input = append(input, sig...)
	input = append(input, pub...)

	result, remainingGas, err := Ed25519VerifyPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
	if err != nil {
		t.Fatal(err)
	}
	if remainingGas != testGas-GasEd25519Verify {
		t.Errorf("expected remaining gas %d, got %d", testGas-GasEd25519Verify, remainingGas)
	}
	if len(result) != 32 || result[31] != 1 {
		t.Error("expected valid signature to return success")
	}
}

func TestInvalidSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	message := sha256.Sum256([]byte("test message"))
	fakeSig := make([]byte, SignatureSize)

	input := make([]byte, 0, InputLength)
	input = append(input, message[:]...)
	input = append(input, fakeSig...)
	input = append(input, pub...)

	result, _, err := Ed25519VerifyPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected invalid signature to return nil")
	}
}

func TestWrongPublicKey(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	message := sha256.Sum256([]byte("test message"))
	sig := ed25519.Sign(priv1, message[:])

	input := make([]byte, 0, InputLength)
	input = append(input, message[:]...)
	input = append(input, sig...)
	input = append(input, pub2...)

	result, _, err := Ed25519VerifyPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected wrong key verification to return nil")
	}
}

func TestInvalidInputLength(t *testing.T) {
	// Too short
	result, _, err := Ed25519VerifyPrecompile.Run(nil, ContractAddress, ContractAddress, []byte{1, 2, 3}, testGas, true)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected short input to return nil")
	}

	// Too long
	result, _, err = Ed25519VerifyPrecompile.Run(nil, ContractAddress, ContractAddress, make([]byte, 200), testGas, true)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected long input to return nil")
	}
}

func TestOutOfGas(t *testing.T) {
	_, _, err := Ed25519VerifyPrecompile.Run(nil, ContractAddress, ContractAddress, make([]byte, 128), GasEd25519Verify-1, true)
	if err == nil {
		t.Error("expected out of gas error")
	}
}

func TestVerifyConvenience(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("hello world")
	sig := ed25519.Sign(priv, message)

	if !VerifyRaw(message, sig, pub) {
		t.Error("VerifyRaw should return true for valid signature")
	}

	if VerifyRaw(message, make([]byte, 64), pub) {
		t.Error("VerifyRaw should return false for invalid signature")
	}
}

func BenchmarkVerify(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	message := sha256.Sum256([]byte("benchmark message"))
	sig := ed25519.Sign(priv, message[:])

	input := make([]byte, 0, InputLength)
	input = append(input, message[:]...)
	input = append(input, sig...)
	input = append(input, pub...)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Ed25519VerifyPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true) //nolint:errcheck
	}
}
