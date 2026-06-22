// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// gas_test.go — gas accounting. Asserts the flat submit gas, the depth-scaled verify
// gas, OOG semantics (charged gas burned, returns (nil,0,err)), and that RequiredGas
// matches what Run actually charges. Gas never depends on any A-Chain observation.

package aivmbridge

import (
	"testing"

	"github.com/luxfi/geth/common"
)

func TestGas_SubmitFlat(t *testing.T) {
	input := encodeSubmit(h32(0x11), h32(0x22), 1, 1, feeWord(5), [32]byte{})
	if g := BridgePrecompile.RequiredGas(input); g != GasSubmitInferenceIntent {
		t.Fatalf("submit gas = %d, want %d", g, GasSubmitInferenceIntent)
	}
}

func TestGas_VerifyScalesWithDepth(t *testing.T) {
	// Build proofs of differing depth and assert RequiredGas tracks verifyGas(depth).
	for _, nLeaves := range []int{1, 2, 4, 8, 16} {
		leaves := make([][32]byte, nLeaves)
		for i := range leaves {
			leaves[i] = h32(byte(i + 1))
		}
		tree := buildMerkleTree(leaves)
		p := tree.proof(0)
		// A minimal well-formed receipt so the frame parses in RequiredGas.
		r := AInferenceReceipt{Version: ReceiptVersion, Status: StatusPending}
		input := encodeVerify(EncodeReceipt(r), encodeProof(p))
		want := verifyGas(len(p.Path))
		if g := BridgePrecompile.RequiredGas(input); g != want {
			t.Fatalf("nLeaves=%d depth=%d: gas = %d, want %d", nLeaves, len(p.Path), g, want)
		}
	}
}

func TestGas_SubmitOutOfGas(t *testing.T) {
	installSpy(t, h32(0xA0))
	st := newMockState(common.HexToHash("0x01"))
	input := encodeSubmit(h32(0x11), h32(0x22), 1, 1, feeWord(5), [32]byte{})
	// One gas short.
	_, rem, err := BridgePrecompile.Run(st, common.Address{0x1}, ContractAddress, input, GasSubmitInferenceIntent-1, false)
	if err == nil {
		t.Fatal("expected OOG error")
	}
	if rem != 0 {
		t.Fatalf("OOG remaining gas = %d, want 0", rem)
	}
}

func TestGas_VerifyOutOfGas(t *testing.T) {
	f := newVerifyFixture(t)
	input := encodeVerify(EncodeReceipt(f.receipt), encodeProof(f.proof))
	full := BridgePrecompile.RequiredGas(input)
	// One gas short of the full metered amount: must OOG with (nil,0,err).
	_, rem, err := BridgePrecompile.Run(f.st, f.caller, ContractAddress, input, full-1, false)
	if err == nil {
		t.Fatal("expected OOG error")
	}
	if rem != 0 {
		t.Fatalf("OOG remaining gas = %d, want 0", rem)
	}
}

func TestGas_VerifyBelowBaseOutOfGas(t *testing.T) {
	f := newVerifyFixture(t)
	input := encodeVerify(EncodeReceipt(f.receipt), encodeProof(f.proof))
	// Below even the base: immediate OOG before any decode.
	_, rem, err := BridgePrecompile.Run(f.st, f.caller, ContractAddress, input, GasVerifyInferenceReceiptBase-1, false)
	if err == nil {
		t.Fatal("expected OOG error")
	}
	if rem != 0 {
		t.Fatalf("remaining gas = %d, want 0", rem)
	}
}

func TestGas_RequiredGasMatchesCharged(t *testing.T) {
	// Submit: RequiredGas must equal what Run consumes (supplied - remaining).
	installSpy(t, h32(0xA0))
	st := newMockState(common.HexToHash("0x55"))
	in := encodeSubmit(h32(0x11), h32(0x22), 1, 1, feeWord(5), [32]byte{})
	g := BridgePrecompile.RequiredGas(in)
	_, rem, err := BridgePrecompile.Run(st, common.Address{0x1}, ContractAddress, in, g+777, false)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if g+777-rem != g {
		t.Fatalf("charged %d, RequiredGas %d", g+777-rem, g)
	}

	// Verify: same invariant.
	f := newVerifyFixture(t)
	vin := encodeVerify(EncodeReceipt(f.receipt), encodeProof(f.proof))
	vg := BridgePrecompile.RequiredGas(vin)
	_, vrem, verr := BridgePrecompile.Run(f.st, f.caller, ContractAddress, vin, vg+555, false)
	if verr != nil {
		t.Fatalf("verify run: %v", verr)
	}
	if vg+555-vrem != vg {
		t.Fatalf("verify charged %d, RequiredGas %d", vg+555-vrem, vg)
	}
}
