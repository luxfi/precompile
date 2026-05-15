// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hqc

import (
	"errors"
	"testing"

	"github.com/luxfi/crypto/hqc"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// TestPrecompile_Address pins the canonical LP-4200 slot.
func TestPrecompile_Address(t *testing.T) {
	want := common.HexToAddress("0x0000000000000000000000000000000000012208")
	if ContractAddress != want {
		t.Errorf("ContractAddress = %s, want %s", ContractAddress.Hex(), want.Hex())
	}
}

// TestRun_GasZero asserts the universal gas-exhaustion floor: zero
// supplied gas surfaces contract.ErrOutOfGas regardless of input shape.
func TestRun_GasZero(t *testing.T) {
	in := make([]byte, 2+SeedSize+2249) // shaped like a valid HQC-128 encap input
	in[0] = 0x01
	in[1] = 0x00
	_, _, err := HQCPrecompile.Run(nil, common.Address{}, ContractAddress, in, 0, true)
	if !errors.Is(err, contract.ErrOutOfGas) {
		t.Errorf("zero gas should surface ErrOutOfGas, got %v", err)
	}
}

// TestRun_ShortInput refuses input below the minimum header length.
func TestRun_ShortInput(t *testing.T) {
	_, _, err := HQCPrecompile.Run(nil, common.Address{}, ContractAddress,
		[]byte{0x01, 0x00, 0x00}, // op + mode + 1 byte (need 32 seed)
		1_000_000, true)
	if !errors.Is(err, ErrInvalidInputLength) {
		t.Errorf("short input should surface ErrInvalidInputLength, got %v", err)
	}
}

// TestRun_InvalidOperation rejects unknown op bytes.
func TestRun_InvalidOperation(t *testing.T) {
	in := make([]byte, 2+SeedSize+2249)
	in[0] = 0x99 // not 0x01 Encapsulate
	in[1] = 0x00
	_, _, err := HQCPrecompile.Run(nil, common.Address{}, ContractAddress,
		in, 1_000_000, true)
	if !errors.Is(err, ErrInvalidOperation) {
		t.Errorf("bad op byte: want ErrInvalidOperation, got %v", err)
	}
}

// TestRun_InvalidMode rejects unknown mode bytes.
func TestRun_InvalidMode(t *testing.T) {
	in := make([]byte, 2+SeedSize+2249)
	in[0] = 0x01
	in[1] = 0x99 // not 0x00/0x01/0x02
	_, _, err := HQCPrecompile.Run(nil, common.Address{}, ContractAddress,
		in, 1_000_000, true)
	if !errors.Is(err, ErrInvalidMode) {
		t.Errorf("bad mode byte: want ErrInvalidMode, got %v", err)
	}
}

// TestRun_WrongPubkeyLen — input has correct op + mode + seed but a
// pubkey of the wrong length for that mode.
func TestRun_WrongPubkeyLen(t *testing.T) {
	in := make([]byte, 2+SeedSize+100) // HQC-128 wants 2249 B pubkey, gave 100
	in[0] = 0x01
	in[1] = 0x00
	_, _, err := HQCPrecompile.Run(nil, common.Address{}, ContractAddress,
		in, 1_000_000, true)
	if !errors.Is(err, ErrInvalidInputLength) {
		t.Errorf("wrong pubkey len: want ErrInvalidInputLength, got %v", err)
	}
}

// TestRun_BackendStubSurfacesError — under the default no-backend
// build, Encapsulate returns hqc.ErrBackendNotWired. The precompile
// must propagate it as-is rather than swallowing into a generic error.
func TestRun_BackendStubSurfacesError(t *testing.T) {
	in := make([]byte, 2+SeedSize+2249)
	in[0] = 0x01
	in[1] = 0x00 // HQC-128
	// pkBytes left zero — backend stub returns ErrBackendNotWired before
	// any structural validation, which is the expected behaviour on a
	// host without a wired HQC backend (cgo PQClean or CIRCL HQC).
	_, _, err := HQCPrecompile.Run(nil, common.Address{}, ContractAddress,
		in, 1_000_000, true)
	if !errors.Is(err, hqc.ErrBackendNotWired) {
		t.Errorf("backend-not-wired path: want hqc.ErrBackendNotWired, got %v", err)
	}
}
