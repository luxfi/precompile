// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

package bridge

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
)

// memStateDB is a minimal contract.StateDB implementation backed by a map.
// It implements only the surface SeedRegistry and stateRegistry exercise.
type memStateDB struct {
	store map[common.Address]map[common.Hash]common.Hash
}

func newMemStateDB() *memStateDB {
	return &memStateDB{store: make(map[common.Address]map[common.Hash]common.Hash)}
}

func (m *memStateDB) GetState(a common.Address, k common.Hash) common.Hash {
	s := m.store[a]
	if s == nil {
		return common.Hash{}
	}
	return s[k]
}

func (m *memStateDB) SetState(a common.Address, k, v common.Hash) common.Hash {
	s := m.store[a]
	if s == nil {
		s = make(map[common.Hash]common.Hash)
		m.store[a] = s
	}
	prev := s[k]
	s[k] = v
	return prev
}

// Unused surface — implemented to satisfy the interface, panics if exercised.
func (*memStateDB) SetNonce(common.Address, uint64, tracing.NonceChangeReason) {
	panic("not implemented")
}
func (*memStateDB) GetNonce(common.Address) uint64 { panic("not implemented") }
func (*memStateDB) GetBalance(common.Address) *uint256.Int {
	panic("not implemented")
}
func (*memStateDB) AddBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int {
	panic("not implemented")
}
func (*memStateDB) SubBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int {
	panic("not implemented")
}
func (*memStateDB) GetBalanceMultiCoin(common.Address, common.Hash) *big.Int {
	panic("not implemented")
}
func (*memStateDB) AddBalanceMultiCoin(common.Address, common.Hash, *big.Int) {
	panic("not implemented")
}
func (*memStateDB) SubBalanceMultiCoin(common.Address, common.Hash, *big.Int) {
	panic("not implemented")
}
func (*memStateDB) CreateAccount(common.Address)  { panic("not implemented") }
func (*memStateDB) Exist(common.Address) bool     { panic("not implemented") }
func (*memStateDB) AddLog(*ethtypes.Log)          { panic("not implemented") }
func (*memStateDB) Logs() []*ethtypes.Log         { panic("not implemented") }
func (*memStateDB) GetPredicateStorageSlots(common.Address, int) ([]byte, bool) {
	panic("not implemented")
}
func (*memStateDB) TxHash() common.Hash    { panic("not implemented") }
func (*memStateDB) Snapshot() int          { panic("not implemented") }
func (*memStateDB) RevertToSnapshot(int)   { panic("not implemented") }

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
	state := newMemStateDB()
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
	state := newMemStateDB()
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
	state := newMemStateDB()
	addr := common.HexToAddress("0x0000000000000000000000000000000000000440")

	long := Chain{ID: 7, Name: "this-name-is-definitely-more-than-thirty-two-bytes", EVM: true}
	_, err := SeedRegistry(state, addr, []Chain{long})
	if err != ErrChainNameTooLong {
		t.Fatalf("expected ErrChainNameTooLong, got %v", err)
	}
}

func TestGateway_RegistryDriven(t *testing.T) {
	// A gateway built over an ad-hoc registry only supports the ids in it.
	r := NewStatic([]Chain{
		{ID: 42, Name: "answer", EVM: true},
	})
	gw := NewBridgeGatewayWithRegistry(r)

	if !gw.Supports(42) {
		t.Fatal("expected 42 to be supported")
	}
	if gw.Supports(96369) {
		t.Fatal("expected 96369 to be unsupported (not in registry)")
	}
}
