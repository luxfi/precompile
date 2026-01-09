// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mlkem

import (
	"bytes"
	"testing"

	"github.com/luxfi/crypto/mlkem"
	"github.com/luxfi/geth/common"
)

// mockAccessibleState implements contract.AccessibleState for testing
type mockAccessibleState struct{}

func (m *mockAccessibleState) GetStateDB() interface{}      { return nil }
func (m *mockAccessibleState) GetBlockContext() interface{} { return nil }

func TestMLKEMPrecompileAddress(t *testing.T) {
	expected := common.HexToAddress("0x0200000000000000000000000000000000000007")
	if MLKEMPrecompile.Address() != expected {
		t.Errorf("expected address %s, got %s", expected.Hex(), MLKEMPrecompile.Address().Hex())
	}
}

func TestRequiredGas(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected uint64
	}{
		{"empty input", []byte{}, MLKEM768EncapsulateGas},
		{"only op byte", []byte{OpEncapsulate}, MLKEM768EncapsulateGas},
		{"encapsulate 512", []byte{OpEncapsulate, ModeMLKEM512}, MLKEM512EncapsulateGas},
		{"encapsulate 768", []byte{OpEncapsulate, ModeMLKEM768}, MLKEM768EncapsulateGas},
		{"encapsulate 1024", []byte{OpEncapsulate, ModeMLKEM1024}, MLKEM1024EncapsulateGas},
		{"decapsulate 512", []byte{OpDecapsulate, ModeMLKEM512}, MLKEM512DecapsulateGas},
		{"decapsulate 768", []byte{OpDecapsulate, ModeMLKEM768}, MLKEM768DecapsulateGas},
		{"decapsulate 1024", []byte{OpDecapsulate, ModeMLKEM1024}, MLKEM1024DecapsulateGas},
		{"invalid mode", []byte{OpEncapsulate, 0xFF}, MLKEM768EncapsulateGas},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gas := MLKEMPrecompile.RequiredGas(tt.input)
			if gas != tt.expected {
				t.Errorf("expected gas %d, got %d", tt.expected, gas)
			}
		})
	}
}

func TestEncapsulateDecapsulate(t *testing.T) {
	modes := []struct {
		name      string
		mode      uint8
		mlkemMode mlkem.Mode
	}{
		{"ML-KEM-512", ModeMLKEM512, mlkem.MLKEM512},
		{"ML-KEM-768", ModeMLKEM768, mlkem.MLKEM768},
		{"ML-KEM-1024", ModeMLKEM1024, mlkem.MLKEM1024},
	}

	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			// Generate key pair
			pk, sk, err := mlkem.GenerateKey(m.mlkemMode)
			if err != nil {
				t.Fatalf("failed to generate key pair: %v", err)
			}

			// Build encapsulate input
			encInput := make([]byte, 2+len(pk.Bytes()))
			encInput[0] = OpEncapsulate
			encInput[1] = m.mode
			copy(encInput[2:], pk.Bytes())

			// Run encapsulate
			result, remainingGas, err := MLKEMPrecompile.Run(
				nil, // accessibleState not used
				common.Address{},
				ContractAddress,
				encInput,
				1_000_000, // suppliedGas
				false,     // readOnly
			)
			if err != nil {
				t.Fatalf("encapsulate failed: %v", err)
			}
			if remainingGas == 0 {
				t.Error("expected remaining gas > 0")
			}

			// Parse result: ciphertext || sharedSecret
			ctSize := mlkem.GetCiphertextSize(m.mlkemMode)
			if len(result) != ctSize+32 {
				t.Fatalf("expected result length %d, got %d", ctSize+32, len(result))
			}

			ciphertext := result[:ctSize]
			sharedSecret1 := result[ctSize:]

			// Build decapsulate input
			decInput := make([]byte, 2+len(sk.Bytes())+len(ciphertext))
			decInput[0] = OpDecapsulate
			decInput[1] = m.mode
			copy(decInput[2:], sk.Bytes())
			copy(decInput[2+len(sk.Bytes()):], ciphertext)

			// Run decapsulate
			sharedSecret2, remainingGas, err := MLKEMPrecompile.Run(
				nil,
				common.Address{},
				ContractAddress,
				decInput,
				1_000_000,
				false,
			)
			if err != nil {
				t.Fatalf("decapsulate failed: %v", err)
			}
			if remainingGas == 0 {
				t.Error("expected remaining gas > 0")
			}

			// Verify shared secrets match
			if !bytes.Equal(sharedSecret1, sharedSecret2) {
				t.Error("shared secrets do not match")
			}
		})
	}
}

func TestInvalidInputs(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"only op", []byte{OpEncapsulate}},
		{"invalid op", []byte{0xFF, ModeMLKEM768}},
		{"encapsulate no key", []byte{OpEncapsulate, ModeMLKEM768}},
		{"encapsulate wrong size", []byte{OpEncapsulate, ModeMLKEM768, 0x01, 0x02, 0x03}},
		{"decapsulate no data", []byte{OpDecapsulate, ModeMLKEM768}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := MLKEMPrecompile.Run(
				nil,
				common.Address{},
				ContractAddress,
				tt.input,
				1_000_000,
				false,
			)
			if err == nil {
				t.Error("expected error for invalid input")
			}
		})
	}
}

func TestOutOfGas(t *testing.T) {
	// Generate a valid key for testing
	pk, _, err := mlkem.GenerateKey(mlkem.MLKEM768)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	input := make([]byte, 2+len(pk.Bytes()))
	input[0] = OpEncapsulate
	input[1] = ModeMLKEM768
	copy(input[2:], pk.Bytes())

	// Run with insufficient gas
	_, _, err = MLKEMPrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		100, // Very low gas
		false,
	)
	if err == nil || err.Error() != "out of gas" {
		t.Errorf("expected 'out of gas' error, got: %v", err)
	}
}

func BenchmarkEncapsulate(b *testing.B) {
	modes := []struct {
		name      string
		mode      uint8
		mlkemMode mlkem.Mode
	}{
		{"ML-KEM-512", ModeMLKEM512, mlkem.MLKEM512},
		{"ML-KEM-768", ModeMLKEM768, mlkem.MLKEM768},
		{"ML-KEM-1024", ModeMLKEM1024, mlkem.MLKEM1024},
	}

	for _, m := range modes {
		pk, _, _ := mlkem.GenerateKey(m.mlkemMode)
		input := make([]byte, 2+len(pk.Bytes()))
		input[0] = OpEncapsulate
		input[1] = m.mode
		copy(input[2:], pk.Bytes())

		b.Run(m.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				MLKEMPrecompile.Run(nil, common.Address{}, ContractAddress, input, 1_000_000, false)
			}
		})
	}
}

func BenchmarkDecapsulate(b *testing.B) {
	modes := []struct {
		name      string
		mode      uint8
		mlkemMode mlkem.Mode
	}{
		{"ML-KEM-512", ModeMLKEM512, mlkem.MLKEM512},
		{"ML-KEM-768", ModeMLKEM768, mlkem.MLKEM768},
		{"ML-KEM-1024", ModeMLKEM1024, mlkem.MLKEM1024},
	}

	for _, m := range modes {
		pk, sk, _ := mlkem.GenerateKey(m.mlkemMode)
		ct, _, _ := pk.Encapsulate()

		input := make([]byte, 2+len(sk.Bytes())+len(ct))
		input[0] = OpDecapsulate
		input[1] = m.mode
		copy(input[2:], sk.Bytes())
		copy(input[2+len(sk.Bytes()):], ct)

		b.Run(m.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				MLKEMPrecompile.Run(nil, common.Address{}, ContractAddress, input, 1_000_000, false)
			}
		})
	}
}
