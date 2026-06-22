// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// install_test.go — InstallAChainClient discipline: install-once (no late swap /
// TOCTOU against in-flight Run), and the install-time sanity checks (non-nil,
// non-empty brand, non-zero AChainID). A misconfigured plugin must fail loudly at
// boot, never silently re-resolve a live client mid-flight.

package aivmbridge

import (
	"context"
	"sync"
	"testing"

	"github.com/luxfi/geth/common"
)

func TestInstall_OnceOnly(t *testing.T) {
	resetAChainClientForTest()
	t.Cleanup(resetAChainClientForTest)

	c1 := NewNativeAChainClient("Lux Inference", h32(0xA0), nil)
	if err := InstallAChainClient(c1); err != nil {
		t.Fatalf("first install: %v", err)
	}
	// Second install MUST error (install-once; no late re-resolution race).
	c2 := NewNativeAChainClient("Other", h32(0xB0), nil)
	if err := InstallAChainClient(c2); err == nil {
		t.Fatal("second install should error (install-once)")
	}
	// The live client must still be c1 (the swap was rejected, not applied).
	if got := currentAChainClient().AChainID(); got != c1.AChainID() {
		t.Fatalf("live client changed after rejected install: got AChainID %x", got)
	}
}

func TestInstall_RejectsNil(t *testing.T) {
	resetAChainClientForTest()
	t.Cleanup(resetAChainClientForTest)
	if err := InstallAChainClient(nil); err == nil {
		t.Fatal("nil client should be rejected")
	}
}

func TestInstall_RejectsEmptyBrand(t *testing.T) {
	resetAChainClientForTest()
	t.Cleanup(resetAChainClientForTest)
	if err := InstallAChainClient(&emptyBrandClient{}); err == nil {
		t.Fatal("empty-brand client should be rejected")
	}
}

func TestInstall_RejectsZeroAChainID(t *testing.T) {
	resetAChainClientForTest()
	t.Cleanup(resetAChainClientForTest)
	// A native client with a zero A-Chain id (unscoped rail) must be rejected.
	if err := InstallAChainClient(NewNativeAChainClient("Lux Inference", [32]byte{}, nil)); err == nil {
		t.Fatal("zero-AChainID client should be rejected (cross-rail aliasing risk)")
	}
}

func TestInstall_DefaultIsUnavailable(t *testing.T) {
	resetAChainClientForTest()
	c := currentAChainClient()
	if _, err := c.SubmitInferenceIntent(context.Background(), nil, InferenceIntent{}); err != ErrAChainUnavailable {
		t.Fatalf("default client submit err = %v, want ErrAChainUnavailable", err)
	}
}

// TestInstall_ConcurrentRunReadsRaceFree drives many concurrent Run() calls (each
// reading currentAChainClient via the atomic.Pointer) against a single published
// client. Under -race this proves the publish/read seam is race-free (the spec's
// "atomic publish so concurrent Run reads are race-free" claim). Each goroutine
// submits a DISTINCT intent (varied tx hash) so the writes don't collide.
func TestInstall_ConcurrentRunReadsRaceFree(t *testing.T) {
	installNative(t, h32(0xA0), nil)

	const goroutines = 32
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make([]error, goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			st := newMockState(common.BytesToHash([]byte{byte(g), byte(g >> 8), 0xAB}))
			caller := common.BytesToAddress([]byte{byte(g + 1)})
			in := encodeSubmit(h32(0x11), h32(0x22), 1, 1, feeWord(uint64(g)+1), [32]byte{})
			gas := BridgePrecompile.RequiredGas(in)
			_, _, err := BridgePrecompile.Run(st, caller, ContractAddress, in, gas, false)
			errs[g] = err
		}(g)
	}
	wg.Wait()
	for g, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", g, err)
		}
	}
}

// emptyBrandClient reports an empty Brand() — must trip the install sanity check.
type emptyBrandClient struct{}

func (emptyBrandClient) Brand() string      { return "" }
func (emptyBrandClient) AChainID() [32]byte { return h32(0xA0) }
func (emptyBrandClient) SubmitInferenceIntent(context.Context, IntentStore, InferenceIntent) ([32]byte, error) {
	return [32]byte{}, nil
}
func (emptyBrandClient) VerifyInferenceReceipt(context.Context, ReceiptVerifierState, AInferenceReceipt, AInferenceProof) (VerifiedAInferenceReceipt, error) {
	return VerifiedAInferenceReceipt{}, nil
}
