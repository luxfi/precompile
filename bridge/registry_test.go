// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

package bridge

import (
	"testing"

	"github.com/luxfi/geth/common"
)

// There is one StateDB fake in this package: regStateDB, in registrar_test.go.
// The previous second fake answered GetState/SetState and panicked on the other
// sixteen methods, so any test that reached past the storage surface died
// instead of failing — and no test could grow past it.

func TestStaticRegistry_GetAndAll(t *testing.T) {
	r := NewStatic(DefaultSeed())

	c, ok := r.Get(96369)
	if !ok || c.Name != "lux" {
		t.Fatalf("expected lux at 96369, got %+v ok=%v", c, ok)
	}

	if _, ok := r.Get(99999); ok {
		t.Fatal("expected unknown id to miss")
	}

	all := r.All()
	if len(all) != len(DefaultSeed()) {
		t.Fatalf("All() length mismatch: %d vs %d", len(all), len(DefaultSeed()))
	}
}

func TestStaticRegistry_AllReturnsCopy(t *testing.T) {
	r := NewStatic(DefaultSeed())
	a := r.All()
	a[0].Name = "mutated"
	b := r.All()
	if b[0].Name == "mutated" {
		t.Fatal("All() must return a defensive copy")
	}
}

func TestStateRegistry_RoundTrip(t *testing.T) {
	state := newRegState()
	addr := common.HexToAddress("0x0000000000000000000000000000000000000440")

	seed := DefaultSeed()
	n, err := SeedRegistry(state, addr, seed)
	if err != nil {
		t.Fatalf("SeedRegistry: %v", err)
	}
	if n != len(seed) {
		t.Fatalf("expected to write %d rows, got %d", len(seed), n)
	}

	r := NewStateRegistry(state, addr)

	c, ok := r.Get(200200)
	if !ok || c.Name != "zoo" {
		t.Fatalf("expected zoo at 200200, got %+v ok=%v", c, ok)
	}

	c, ok = r.Get(900001)
	if !ok || c.EVM {
		t.Fatalf("expected solana virtual chain (EVM=false), got %+v ok=%v", c, ok)
	}

	all := r.All()
	if len(all) != len(seed) {
		t.Fatalf("All() length mismatch: %d vs %d", len(all), len(seed))
	}
}

func TestStateRegistry_SeedIsIdempotent(t *testing.T) {
	state := newRegState()
	addr := common.HexToAddress("0x0000000000000000000000000000000000000440")

	if _, err := SeedRegistry(state, addr, DefaultSeed()); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	n, err := SeedRegistry(state, addr, []Chain{{ID: 1, Name: "ignored", EVM: true}})
	if err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if n != 0 {
		t.Fatalf("second seed must be no-op, wrote %d rows", n)
	}
}

func TestStateRegistry_RejectsLongName(t *testing.T) {
	state := newRegState()
	addr := common.HexToAddress("0x0000000000000000000000000000000000000440")

	long := Chain{ID: 7, Name: "this-name-is-definitely-more-than-thirty-two-bytes", EVM: true}
	_, err := SeedRegistry(state, addr, []Chain{long})
	if err != ErrChainNameTooLong {
		t.Fatalf("expected ErrChainNameTooLong, got %v", err)
	}
}
