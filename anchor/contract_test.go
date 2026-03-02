// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package anchor

import (
	"context"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	luxcrypto "github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
)

// --- mock StateDB ---

type mockStateDB struct {
	storage map[common.Address]map[common.Hash]common.Hash
}

func newMockStateDB() *mockStateDB {
	return &mockStateDB{storage: make(map[common.Address]map[common.Hash]common.Hash)}
}

func (m *mockStateDB) GetState(addr common.Address, key common.Hash) common.Hash {
	if s, ok := m.storage[addr]; ok {
		return s[key]
	}
	return common.Hash{}
}

func (m *mockStateDB) SetState(addr common.Address, key, value common.Hash) common.Hash {
	if m.storage[addr] == nil {
		m.storage[addr] = make(map[common.Hash]common.Hash)
	}
	prev := m.storage[addr][key]
	m.storage[addr][key] = value
	return prev
}

// Stubs to satisfy contract.StateDB interface.
func (m *mockStateDB) SetNonce(common.Address, uint64, tracing.NonceChangeReason)                 {}
func (m *mockStateDB) GetNonce(common.Address) uint64                                              { return 0 }
func (m *mockStateDB) GetBalance(common.Address) *uint256.Int                                      { return new(uint256.Int) }
func (m *mockStateDB) AddBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int { return uint256.Int{} }
func (m *mockStateDB) SubBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int { return uint256.Int{} }
func (m *mockStateDB) GetBalanceMultiCoin(common.Address, common.Hash) *big.Int                    { return big.NewInt(0) }
func (m *mockStateDB) AddBalanceMultiCoin(common.Address, common.Hash, *big.Int)                   {}
func (m *mockStateDB) SubBalanceMultiCoin(common.Address, common.Hash, *big.Int)                   {}
func (m *mockStateDB) CreateAccount(common.Address)                                                {}
func (m *mockStateDB) Exist(common.Address) bool                                                   { return false }
func (m *mockStateDB) AddLog(*ethtypes.Log)                                                        {}
func (m *mockStateDB) Logs() []*ethtypes.Log                                                       { return nil }
func (m *mockStateDB) GetPredicateStorageSlots(common.Address, int) ([]byte, bool)                 { return nil, false }
func (m *mockStateDB) TxHash() common.Hash                                                         { return common.Hash{} }
func (m *mockStateDB) Snapshot() int                                                               { return 0 }
func (m *mockStateDB) RevertToSnapshot(int)                                                        {}

// --- mock AccessibleState ---

type mockAccessibleState struct {
	db *mockStateDB
}

func (m *mockAccessibleState) GetStateDB() contract.StateDB                             { return m.db }
func (m *mockAccessibleState) GetBlockContext() contract.BlockContext                    { return nil }
func (m *mockAccessibleState) GetConsensusContext() context.Context                     { return context.Background() }
func (m *mockAccessibleState) GetChainConfig() precompileconfig.ChainConfig             { return nil }
func (m *mockAccessibleState) GetPrecompileEnv() contract.PrecompileEnvironment         { return nil }

// --- helpers ---

func makeSubmitInput(appID common.Hash, height uint64, root common.Hash) []byte {
	input := make([]byte, 4+96)
	copy(input[:4], selectorSubmit)
	copy(input[4:36], appID[:])
	binary.BigEndian.PutUint64(input[60:68], height)
	copy(input[68:100], root[:])
	return input
}

func makeGetInput(appID common.Hash, height uint64) []byte {
	input := make([]byte, 4+64)
	copy(input[:4], selectorGet)
	copy(input[4:36], appID[:])
	binary.BigEndian.PutUint64(input[60:68], height)
	return input
}

func makeGetLatestInput(appID common.Hash) []byte {
	input := make([]byte, 4+32)
	copy(input[:4], selectorGetLatest)
	copy(input[4:36], appID[:])
	return input
}

func makeListInput(appID common.Hash, from, to uint64) []byte {
	input := make([]byte, 4+96)
	copy(input[:4], selectorList)
	copy(input[4:36], appID[:])
	binary.BigEndian.PutUint64(input[60:68], from)
	binary.BigEndian.PutUint64(input[92:100], to)
	return input
}

func testAppID() common.Hash {
	return common.BytesToHash(luxcrypto.Keccak256([]byte("test-app")))
}

func testRoot(n byte) common.Hash {
	var h common.Hash
	for i := range h {
		h[i] = n
	}
	return h
}

// --- tests ---

func TestSubmitAndGet(t *testing.T) {
	p := AnchorPrecompile
	state := &mockAccessibleState{db: newMockStateDB()}
	appID := testAppID()
	root := testRoot(0xAA)

	input := makeSubmitInput(appID, 1, root)
	ret, gas, err := p.Run(state, common.Address{}, ContractAddress, input, 100_000, false)
	if err != nil {
		t.Fatalf("submit failed: %v", err)
	}
	if gas != 100_000-GasSubmit {
		t.Fatalf("expected remaining gas %d, got %d", 100_000-GasSubmit, gas)
	}
	retHeight := binary.BigEndian.Uint64(ret[24:32])
	if retHeight != 1 {
		t.Fatalf("expected returned height 1, got %d", retHeight)
	}

	getInput := makeGetInput(appID, 1)
	ret, _, err = p.Run(state, common.Address{}, ContractAddress, getInput, 100_000, true)
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	var gotRoot common.Hash
	copy(gotRoot[:], ret)
	if gotRoot != root {
		t.Fatalf("expected root %x, got %x", root, gotRoot)
	}
}

func TestGetLatest(t *testing.T) {
	p := AnchorPrecompile
	state := &mockAccessibleState{db: newMockStateDB()}
	appID := testAppID()

	for _, h := range []uint64{1, 5, 10} {
		input := makeSubmitInput(appID, h, testRoot(byte(h)))
		_, _, err := p.Run(state, common.Address{}, ContractAddress, input, 100_000, false)
		if err != nil {
			t.Fatalf("submit height %d failed: %v", h, err)
		}
	}

	input := makeGetLatestInput(appID)
	ret, _, err := p.Run(state, common.Address{}, ContractAddress, input, 100_000, true)
	if err != nil {
		t.Fatalf("getLatest failed: %v", err)
	}
	latest := binary.BigEndian.Uint64(ret[24:32])
	if latest != 10 {
		t.Fatalf("expected latest=10, got %d", latest)
	}
}

func TestHeightMonotonicity(t *testing.T) {
	p := AnchorPrecompile
	state := &mockAccessibleState{db: newMockStateDB()}
	appID := testAppID()

	input := makeSubmitInput(appID, 5, testRoot(0x55))
	_, _, err := p.Run(state, common.Address{}, ContractAddress, input, 100_000, false)
	if err != nil {
		t.Fatalf("submit height 5 failed: %v", err)
	}

	// Lower height should fail
	input = makeSubmitInput(appID, 3, testRoot(0x33))
	_, _, err = p.Run(state, common.Address{}, ContractAddress, input, 100_000, false)
	if err != ErrHeightNotMonotonic {
		t.Fatalf("expected ErrHeightNotMonotonic, got %v", err)
	}

	// Same height should fail
	input = makeSubmitInput(appID, 5, testRoot(0x55))
	_, _, err = p.Run(state, common.Address{}, ContractAddress, input, 100_000, false)
	if err != ErrHeightNotMonotonic {
		t.Fatalf("expected ErrHeightNotMonotonic for same height, got %v", err)
	}

	// Higher height should succeed
	input = makeSubmitInput(appID, 6, testRoot(0x66))
	_, _, err = p.Run(state, common.Address{}, ContractAddress, input, 100_000, false)
	if err != nil {
		t.Fatalf("submit height 6 failed: %v", err)
	}
}

func TestReadOnlySubmitReverts(t *testing.T) {
	p := AnchorPrecompile
	state := &mockAccessibleState{db: newMockStateDB()}
	input := makeSubmitInput(testAppID(), 1, testRoot(0x01))
	_, _, err := p.Run(state, common.Address{}, ContractAddress, input, 100_000, true)
	if err != ErrReadOnlySubmit {
		t.Fatalf("expected ErrReadOnlySubmit, got %v", err)
	}
}

func TestGetNonexistent(t *testing.T) {
	p := AnchorPrecompile
	state := &mockAccessibleState{db: newMockStateDB()}
	input := makeGetInput(testAppID(), 999)
	_, _, err := p.Run(state, common.Address{}, ContractAddress, input, 100_000, true)
	if err != ErrAnchorNotFound {
		t.Fatalf("expected ErrAnchorNotFound, got %v", err)
	}
}

func TestList(t *testing.T) {
	p := AnchorPrecompile
	state := &mockAccessibleState{db: newMockStateDB()}
	appID := testAppID()

	for h := uint64(1); h <= 5; h++ {
		input := makeSubmitInput(appID, h, testRoot(byte(h)))
		_, _, err := p.Run(state, common.Address{}, ContractAddress, input, 100_000, false)
		if err != nil {
			t.Fatalf("submit height %d failed: %v", h, err)
		}
	}

	// List [2, 5) = 3 entries
	input := makeListInput(appID, 2, 5)
	ret, gas, err := p.Run(state, common.Address{}, ContractAddress, input, 100_000, true)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}

	expectedGas := uint64(100_000) - GasListBase - 3*GasListPerItem
	if gas != expectedGas {
		t.Fatalf("expected remaining gas %d, got %d", expectedGas, gas)
	}

	for i := uint64(0); i < 3; i++ {
		var gotRoot common.Hash
		copy(gotRoot[:], ret[64+i*32:64+(i+1)*32])
		expected := testRoot(byte(i + 2))
		if gotRoot != expected {
			t.Fatalf("list[%d]: expected %x, got %x", i, expected, gotRoot)
		}
	}
}

func TestOutOfGas(t *testing.T) {
	p := AnchorPrecompile
	state := &mockAccessibleState{db: newMockStateDB()}
	input := makeSubmitInput(testAppID(), 1, testRoot(0x01))
	_, _, err := p.Run(state, common.Address{}, ContractAddress, input, 100, false)
	if err != contract.ErrOutOfGas {
		t.Fatalf("expected ErrOutOfGas, got %v", err)
	}
}

func TestInvalidSelector(t *testing.T) {
	p := AnchorPrecompile
	state := &mockAccessibleState{db: newMockStateDB()}
	input := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00}
	_, _, err := p.Run(state, common.Address{}, ContractAddress, input, 100_000, false)
	if err != ErrInvalidSelector {
		t.Fatalf("expected ErrInvalidSelector, got %v", err)
	}
}

func TestMultipleAppIDs(t *testing.T) {
	p := AnchorPrecompile
	state := &mockAccessibleState{db: newMockStateDB()}
	app1 := common.BytesToHash(luxcrypto.Keccak256([]byte("app-1")))
	app2 := common.BytesToHash(luxcrypto.Keccak256([]byte("app-2")))

	input := makeSubmitInput(app1, 10, testRoot(0xAA))
	_, _, err := p.Run(state, common.Address{}, ContractAddress, input, 100_000, false)
	if err != nil {
		t.Fatalf("app1 submit failed: %v", err)
	}

	input = makeSubmitInput(app2, 1, testRoot(0xBB))
	_, _, err = p.Run(state, common.Address{}, ContractAddress, input, 100_000, false)
	if err != nil {
		t.Fatalf("app2 submit failed: %v", err)
	}

	input = makeGetLatestInput(app1)
	ret, _, _ := p.Run(state, common.Address{}, ContractAddress, input, 100_000, true)
	if binary.BigEndian.Uint64(ret[24:32]) != 10 {
		t.Fatal("app1 latest should be 10")
	}

	input = makeGetLatestInput(app2)
	ret, _, _ = p.Run(state, common.Address{}, ContractAddress, input, 100_000, true)
	if binary.BigEndian.Uint64(ret[24:32]) != 1 {
		t.Fatal("app2 latest should be 1")
	}
}

func TestStorageKeyDeterminism(t *testing.T) {
	appID := testAppID()
	h := uint64(42)

	k1 := rootKey(appID, h)
	k2 := rootKey(appID, h)
	if k1 != k2 {
		t.Fatal("rootKey not deterministic")
	}

	l1 := latestKey(appID)
	l2 := latestKey(appID)
	if l1 != l2 {
		t.Fatal("latestKey not deterministic")
	}

	if k1 == l1 {
		t.Fatal("rootKey and latestKey collide")
	}
}
