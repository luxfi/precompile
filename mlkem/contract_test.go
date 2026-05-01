// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mlkem

import (
	"testing"

	"github.com/luxfi/crypto/mlkem"
	"github.com/luxfi/geth/common"
)

func TestMLKEMPrecompileAddress(t *testing.T) {
	expected := common.HexToAddress("0x0000000000000000000000000000000000012201")
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
		{"invalid mode", []byte{OpEncapsulate, 0xFF}, MLKEM768EncapsulateGas},
		{"decapsulate rejected", []byte{0x02, ModeMLKEM768}, MLKEM768EncapsulateGas},
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

func TestEncapsulate(t *testing.T) {
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
			pk, _, err := mlkem.GenerateKey(m.mlkemMode)
			if err != nil {
				t.Fatalf("failed to generate key pair: %v", err)
			}

			encInput := make([]byte, 2+SeedSize+len(pk.Bytes()))
			encInput[0] = OpEncapsulate
			encInput[1] = m.mode
			copy(encInput[2+SeedSize:], pk.Bytes())

			result, remainingGas, err := MLKEMPrecompile.Run(
				nil,
				common.Address{},
				ContractAddress,
				encInput,
				1_000_000,
				false,
			)
			if err != nil {
				t.Fatalf("encapsulate failed: %v", err)
			}
			if remainingGas == 0 {
				t.Error("expected remaining gas > 0")
			}

			ctSize := mlkem.GetCiphertextSize(m.mlkemMode)
			if len(result) != ctSize+32 {
				t.Fatalf("expected result length %d, got %d", ctSize+32, len(result))
			}
		})
	}
}

func TestDecapsulateRejected(t *testing.T) {
	// Verify that the old OpDecapsulate (0x02) is rejected
	pk, _, err := mlkem.GenerateKey(mlkem.MLKEM768)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	input := make([]byte, 2+SeedSize+len(pk.Bytes()))
	input[0] = 0x02 // Old OpDecapsulate
	input[1] = ModeMLKEM768
	copy(input[2+SeedSize:], pk.Bytes())

	_, _, err = MLKEMPrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		1_000_000,
		false,
	)
	if err == nil {
		t.Error("expected error for decapsulate operation")
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
	pk, _, err := mlkem.GenerateKey(mlkem.MLKEM768)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	input := make([]byte, 2+SeedSize+len(pk.Bytes()))
	input[0] = OpEncapsulate
	input[1] = ModeMLKEM768
	copy(input[2+SeedSize:], pk.Bytes())

	_, _, err = MLKEMPrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		100,
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
		input := make([]byte, 2+SeedSize+len(pk.Bytes()))
		input[0] = OpEncapsulate
		input[1] = m.mode
		copy(input[2+SeedSize:], pk.Bytes())

		b.Run(m.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				MLKEMPrecompile.Run(nil, common.Address{}, ContractAddress, input, 1_000_000, false)
			}
		})
	}
}
