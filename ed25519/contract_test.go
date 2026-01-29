// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/luxfi/geth/common"
)

func TestAddress(t *testing.T) {
	c := &Contract{}
	expected := common.HexToAddress(Ed25519VerifyAddress)
	if c.Address() != expected {
		t.Errorf("expected address %s, got %s", expected.Hex(), c.Address().Hex())
	}
}

func TestRequiredGas(t *testing.T) {
	c := &Contract{}
	if gas := c.RequiredGas(nil); gas != Ed25519VerifyGas {
		t.Errorf("expected gas %d, got %d", Ed25519VerifyGas, gas)
	}
}

func TestValidSignature(t *testing.T) {
	c := &Contract{}

	// Generate a test key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Sign a message hash
	message := sha256.Sum256([]byte("test message for MIGA mint claim"))
	sig := ed25519.Sign(priv, message[:])

	// Build input: hash(32) + signature(64) + pubkey(32) = 128 bytes
	input := make([]byte, 0, InputLength)
	input = append(input, message[:]...)
	input = append(input, sig...)
	input = append(input, pub...)

	result, err := c.Run(input)
	if err != nil {
		t.Fatal(err)
	}

	// Check success (last byte = 1)
	if len(result) != 32 || result[31] != 1 {
		t.Error("expected valid signature to return success")
	}
}

func TestInvalidSignature(t *testing.T) {
	c := &Contract{}

	// Generate a key pair
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	message := sha256.Sum256([]byte("test message"))
	fakeSig := make([]byte, SignatureSize) // zero signature = invalid

	input := make([]byte, 0, InputLength)
	input = append(input, message[:]...)
	input = append(input, fakeSig...)
	input = append(input, pub...)

	result, err := c.Run(input)
	if err != nil {
		t.Fatal(err)
	}

	// Should return nil (failure)
	if result != nil {
		t.Error("expected invalid signature to return nil")
	}
}

func TestWrongPublicKey(t *testing.T) {
	c := &Contract{}

	// Generate two key pairs
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	// Sign with key 1, verify with key 2
	message := sha256.Sum256([]byte("test message"))
	sig := ed25519.Sign(priv1, message[:])

	input := make([]byte, 0, InputLength)
	input = append(input, message[:]...)
	input = append(input, sig...)
	input = append(input, pub2...)

	result, err := c.Run(input)
	if err != nil {
		t.Fatal(err)
	}

	if result != nil {
		t.Error("expected wrong key verification to return nil")
	}
}

func TestInvalidInputLength(t *testing.T) {
	c := &Contract{}

	// Too short
	result, err := c.Run([]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected short input to return nil")
	}

	// Too long
	result, err = c.Run(make([]byte, 200))
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected long input to return nil")
	}
}

func TestName(t *testing.T) {
	c := &Contract{}
	if name := c.Name(); name != "ED25519_VERIFY" {
		t.Errorf("expected name ED25519_VERIFY, got %s", name)
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

// BenchmarkVerify measures Ed25519 verification performance
func BenchmarkVerify(b *testing.B) {
	c := &Contract{}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	message := sha256.Sum256([]byte("benchmark message"))
	sig := ed25519.Sign(priv, message[:])

	input := make([]byte, 0, InputLength)
	input = append(input, message[:]...)
	input = append(input, sig...)
	input = append(input, pub...)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Run(input) //nolint:errcheck
	}
}
