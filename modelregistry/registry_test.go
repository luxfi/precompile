// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package modelregistry

import (
	"bytes"
	"context"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
)

// --- minimal map-backed StateDB mock (only GetState/SetState are exercised) ---------

type mockState struct{ m map[common.Hash]common.Hash }

func newMockState() *mockState { return &mockState{m: map[common.Hash]common.Hash{}} }

func (s *mockState) GetState(_ common.Address, k common.Hash) common.Hash { return s.m[k] }
func (s *mockState) SetState(_ common.Address, k, v common.Hash) common.Hash {
	old := s.m[k]
	s.m[k] = v
	return old
}

func (s *mockState) SetNonce(common.Address, uint64, tracing.NonceChangeReason) {}
func (s *mockState) GetNonce(common.Address) uint64                             { return 0 }
func (s *mockState) GetBalance(common.Address) *uint256.Int                     { return uint256.NewInt(0) }
func (s *mockState) AddBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int {
	return uint256.Int{}
}
func (s *mockState) SubBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int {
	return uint256.Int{}
}
func (s *mockState) GetBalanceMultiCoin(common.Address, common.Hash) *big.Int    { return big.NewInt(0) }
func (s *mockState) AddBalanceMultiCoin(common.Address, common.Hash, *big.Int)   {}
func (s *mockState) SubBalanceMultiCoin(common.Address, common.Hash, *big.Int)   {}
func (s *mockState) CreateAccount(common.Address)                                {}
func (s *mockState) Exist(common.Address) bool                                   { return false }
func (s *mockState) AddLog(*ethtypes.Log)                                        {}
func (s *mockState) Logs() []*ethtypes.Log                                       { return nil }
func (s *mockState) GetPredicateStorageSlots(common.Address, int) ([]byte, bool) { return nil, false }
func (s *mockState) TxHash() common.Hash                                         { return common.Hash{} }
func (s *mockState) Snapshot() int                                               { return 0 }
func (s *mockState) RevertToSnapshot(int)                                        {}

type mockAccessible struct{ s contract.StateDB }

func (a mockAccessible) GetStateDB() contract.StateDB                     { return a.s }
func (a mockAccessible) GetBlockContext() contract.BlockContext           { return nil }
func (a mockAccessible) GetConsensusContext() context.Context             { return nil }
func (a mockAccessible) GetChainConfig() precompileconfig.ChainConfig     { return nil }
func (a mockAccessible) GetPrecompileEnv() contract.PrecompileEnvironment { return nil }

// --- helpers -----------------------------------------------------------------------

func sel(s uint32) []byte  { b := make([]byte, 4); binary.BigEndian.PutUint32(b, s); return b }
func word(b []byte) []byte { out := make([]byte, 32); copy(out[32-len(b):], b); return out }
func u256(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return word(b) }

func adoptInput(name, weight common.Hash, version uint64) []byte {
	return bytes.Join([][]byte{sel(SelectorAdopt), name[:], u256(version), weight[:]}, nil)
}
func getApprovedInput(name common.Hash) []byte { return append(sel(SelectorGetApproved), name[:]...) }
func isAdminInput(a common.Address) []byte     { return append(sel(SelectorIsAdmin), word(a.Bytes())...) }
func setAdminInput(a common.Address, on bool) []byte {
	en := make([]byte, 32)
	if on {
		en[31] = 1
	}
	return bytes.Join([][]byte{sel(SelectorSetAdmin), word(a.Bytes()), en}, nil)
}

// --- tests -------------------------------------------------------------------------

func TestModelRegistryAdoptAndRead(t *testing.T) {
	admin := common.HexToAddress("0x00000000000000000000000000000000000000A1")
	st := newMockState()
	// Configure seeds the admin (the genesis governance set).
	if err := (&configurator{}).Configure(nil, &Config{Admins: []common.Address{admin}}, st, nil); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	acc := mockAccessible{s: st}

	name := common.HexToHash("0x0001") // "Beluga-LLM"
	weight := common.HexToHash("0xABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890AB")

	// Non-admin cannot adopt.
	stranger := common.HexToAddress("0x00000000000000000000000000000000000000BB")
	if _, _, err := ModelRegistryPrecompile.Run(acc, stranger, ContractAddress, adoptInput(name, weight, 1), GasAdopt, false); err == nil {
		t.Fatal("expected non-admin adopt to fail")
	}

	// Admin adopts v3.
	if _, _, err := ModelRegistryPrecompile.Run(acc, admin, ContractAddress, adoptInput(name, weight, 3), GasAdopt, false); err != nil {
		t.Fatalf("admin adopt: %v", err)
	}

	// Read back via the precompile ABI.
	ret, _, err := ModelRegistryPrecompile.Run(acc, stranger, ContractAddress, getApprovedInput(name), GasGetApproved, true)
	if err != nil {
		t.Fatalf("getApproved: %v", err)
	}
	if len(ret) != 64 {
		t.Fatalf("getApproved len %d, want 64", len(ret))
	}
	gotVer := binary.BigEndian.Uint64(ret[24:32])
	gotWeight := common.BytesToHash(ret[32:64])
	if gotVer != 3 || gotWeight != weight {
		t.Fatalf("getApproved = (v%d, %s), want (v3, %s)", gotVer, gotWeight, weight)
	}

	// And the Go helper agrees.
	v, w := GetApproved(st, name)
	if v != 3 || w != weight {
		t.Fatalf("GetApproved helper = (v%d, %s)", v, w)
	}
}

func TestModelRegistryGovernance(t *testing.T) {
	admin := common.HexToAddress("0x00000000000000000000000000000000000000A1")
	st := newMockState()
	_ = (&configurator{}).Configure(nil, &Config{Admins: []common.Address{admin}}, st, nil)
	acc := mockAccessible{s: st}

	newAdmin := common.HexToAddress("0x00000000000000000000000000000000000000A2")

	// newAdmin starts as non-admin.
	r, _, _ := ModelRegistryPrecompile.Run(acc, admin, ContractAddress, isAdminInput(newAdmin), GasIsAdmin, true)
	if r[31] != 0 {
		t.Fatal("newAdmin should not be admin yet")
	}
	// Admin promotes newAdmin.
	if _, _, err := ModelRegistryPrecompile.Run(acc, admin, ContractAddress, setAdminInput(newAdmin, true), GasSetAdmin, false); err != nil {
		t.Fatalf("setAdmin: %v", err)
	}
	// newAdmin can now adopt.
	name := common.HexToHash("0x07")
	if _, _, err := ModelRegistryPrecompile.Run(acc, newAdmin, ContractAddress, adoptInput(name, common.HexToHash("0x99"), 1), GasAdopt, false); err != nil {
		t.Fatalf("newAdmin adopt: %v", err)
	}
	// Read-only adopt is rejected.
	if _, _, err := ModelRegistryPrecompile.Run(acc, admin, ContractAddress, adoptInput(name, common.HexToHash("0x99"), 2), GasAdopt, true); err == nil {
		t.Fatal("expected read-only adopt to fail")
	}
}
