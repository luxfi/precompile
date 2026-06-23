// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// harness_test.go — the shared test harness for the A-Chain inference bridge: a
// minimal in-memory StateDB, an AccessibleState + AtomicState mock, a real keccak
// merkle tree (so proofs are genuine, not faked), and small builders. No network, no
// aivm — the bridge's whole contract is that it never needs them.

package aivmbridge

import (
	"context"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/ids"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/luxfi/vm/chains/atomic"
)

// memStateDB is a minimal contract.StateDB backed by an in-memory slot map. Only the
// state-slot + tx-hash + log methods are exercised by the bridge; the balance / nonce
// surface is present to satisfy the interface and is unused (the bridge touches NO
// balances — that is part of its safety contract, and the harness proves it by leaving
// the balance ledger inert).
type memStateDB struct {
	slots  map[common.Address]map[common.Hash]common.Hash
	logs   []*ethtypes.Log
	txHash common.Hash
}

func newMemStateDB() *memStateDB {
	return &memStateDB{slots: make(map[common.Address]map[common.Hash]common.Hash)}
}

func (m *memStateDB) GetState(addr common.Address, key common.Hash) common.Hash {
	if s, ok := m.slots[addr]; ok {
		return s[key]
	}
	return common.Hash{}
}

// SetState returns the prior value (contract.StateDB semantics).
func (m *memStateDB) SetState(addr common.Address, key common.Hash, value common.Hash) common.Hash {
	if _, ok := m.slots[addr]; !ok {
		m.slots[addr] = make(map[common.Hash]common.Hash)
	}
	prev := m.slots[addr][key]
	m.slots[addr][key] = value
	return prev
}

func (m *memStateDB) TxHash() common.Hash { return m.txHash }

func (m *memStateDB) AddLog(l *ethtypes.Log) { m.logs = append(m.logs, l) }
func (m *memStateDB) Logs() []*ethtypes.Log  { return m.logs }

// --- unused balance/nonce/account surface (interface satisfaction only) -------

func (m *memStateDB) SetNonce(common.Address, uint64, tracing.NonceChangeReason) {}
func (m *memStateDB) GetNonce(common.Address) uint64                             { return 0 }
func (m *memStateDB) GetBalance(common.Address) *uint256.Int                     { return uint256.NewInt(0) }
func (m *memStateDB) AddBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int {
	return uint256.Int{}
}
func (m *memStateDB) SubBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int {
	return uint256.Int{}
}
func (m *memStateDB) GetBalanceMultiCoin(common.Address, common.Hash) *big.Int  { return big.NewInt(0) }
func (m *memStateDB) AddBalanceMultiCoin(common.Address, common.Hash, *big.Int) {}
func (m *memStateDB) SubBalanceMultiCoin(common.Address, common.Hash, *big.Int) {}
func (m *memStateDB) CreateAccount(common.Address)                              {}
func (m *memStateDB) Exist(common.Address) bool                                 { return true }
func (m *memStateDB) GetPredicateStorageSlots(common.Address, int) ([]byte, bool) {
	return nil, false
}
func (m *memStateDB) Snapshot() int        { return 0 }
func (m *memStateDB) RevertToSnapshot(int) {}

var _ contract.StateDB = (*memStateDB)(nil)

// --- block context ------------------------------------------------------------

type mockBlockCtx struct {
	number    *big.Int
	timestamp uint64
}

func (m *mockBlockCtx) Number() *big.Int  { return m.number }
func (m *mockBlockCtx) Timestamp() uint64 { return m.timestamp }
func (m *mockBlockCtx) GetPredicateResults(common.Hash, common.Address) []byte {
	return nil
}

// --- accessible + atomic state ------------------------------------------------

// mockState implements BOTH contract.AccessibleState and contract.AtomicState so the
// bridge's `accessibleState.(contract.AtomicState)` assertion succeeds and reaches the
// chain identity it binds into the deterministic intent id. (The ErrNoAtomicState
// revert is exercised separately via accessibleOnly, which hides the AtomicState
// methods so the assertion fails.)
type mockState struct {
	db          *memStateDB
	blockNumber uint64
	readOnly    bool

	networkID uint32
	chainID   ids.ID
	cChainID  ids.ID
	txID      ids.ID
	callIndex uint32
}

func (m *mockState) GetStateDB() contract.StateDB { return m.db }
func (m *mockState) GetBlockContext() contract.BlockContext {
	return &mockBlockCtx{number: new(big.Int).SetUint64(m.blockNumber)}
}
func (m *mockState) GetConsensusContext() context.Context         { return context.Background() }
func (m *mockState) GetChainConfig() precompileconfig.ChainConfig { return nil }
func (m *mockState) GetPrecompileEnv() contract.PrecompileEnvironment {
	return &mockEnv{ro: m.readOnly}
}

// AtomicState — only reached when atomicAbsent is false.
func (m *mockState) AtomicMemory() atomic.SharedMemory    { return nil }
func (m *mockState) NetworkID() uint32                    { return m.networkID }
func (m *mockState) ChainID() ids.ID                      { return m.chainID }
func (m *mockState) CChainID() ids.ID                     { return m.cChainID }
func (m *mockState) GovernanceController() common.Address { return common.Address{} } // no DEX governance in this mock (fail-closed)
func (m *mockState) DChainID() ids.ID                     { return ids.Empty }
func (m *mockState) TxID() ids.ID                         { return m.txID }
func (m *mockState) CallIndex() uint32                    { return m.callIndex }

type mockEnv struct{ ro bool }

func (e *mockEnv) ReadOnly() bool { return e.ro }

// accessibleOnly wraps a mockState but HIDES the AtomicState methods, so the bridge's
// type assertion to contract.AtomicState fails (exercises ErrNoAtomicState). It embeds
// only the AccessibleState surface.
type accessibleOnly struct {
	db          *memStateDB
	blockNumber uint64
	readOnly    bool
}

func (m *accessibleOnly) GetStateDB() contract.StateDB { return m.db }
func (m *accessibleOnly) GetBlockContext() contract.BlockContext {
	return &mockBlockCtx{number: new(big.Int).SetUint64(m.blockNumber)}
}
func (m *accessibleOnly) GetConsensusContext() context.Context         { return context.Background() }
func (m *accessibleOnly) GetChainConfig() precompileconfig.ChainConfig { return nil }
func (m *accessibleOnly) GetPrecompileEnv() contract.PrecompileEnvironment {
	return &mockEnv{ro: m.readOnly}
}

var (
	_ contract.AccessibleState = (*mockState)(nil)
	_ contract.AtomicState     = (*mockState)(nil)
	_ contract.AccessibleState = (*accessibleOnly)(nil)
)

// newMockState builds the default atomic-capable state with fixed chain identity.
func newMockState(txHash common.Hash) *mockState {
	db := newMemStateDB()
	db.txHash = txHash
	return &mockState{
		db:          db,
		blockNumber: 100,
		networkID:   1,
		chainID:     ids.ID{0xCC},
		cChainID:    ids.ID{0xCC},
		txID:        ids.ID{0x7A},
		callIndex:   0,
	}
}

// --- real keccak merkle tree (genuine proofs, not faked) ----------------------

// merkleTree builds a binary keccak merkle tree using the SAME construction as
// production (proof.go + chains/aivm/quorum_merkle.go): each supplied leaf value (a
// receipt_hash) is first LEAF-HASHED (leafHash = keccak(value)) so a leaf preimage (32
// bytes) can never be confused with an internal node preimage (64 bytes), then nodes are
// combined with hashPair; an odd node duplicates itself (the canonical "promote last"
// rule). It yields the root and an inclusion proof (path + index) for any leaf, matching
// the C verify (which leaf-hashes receipt_hash) and the A producer byte-for-byte.
//
// NOTE: callers pass the RAW receipt_hash (e.g. ReceiptHash(rcpt)); buildMerkleTree
// applies the leaf hash internally so a test tree equals the real committed tree.
type merkleTree struct {
	levels [][][32]byte // levels[0] = leaf-hashed leaves, last = root
}

func buildMerkleTree(rawLeaves [][32]byte) *merkleTree {
	if len(rawLeaves) == 0 {
		return &merkleTree{levels: [][][32]byte{{[32]byte{}}}}
	}
	// Leaf-hash every supplied value so the tree matches production (A commits the
	// receipt_root over leafHash(receipt_hash); C folds from leafHash(receipt_hash)).
	leaves := make([][32]byte, len(rawLeaves))
	for i, lh := range rawLeaves {
		leaves[i] = leafHash(lh)
	}
	levels := [][][32]byte{append([][32]byte(nil), leaves...)}
	cur := leaves
	for len(cur) > 1 {
		var next [][32]byte
		for i := 0; i < len(cur); i += 2 {
			left := cur[i]
			right := left // odd node duplicates itself
			if i+1 < len(cur) {
				right = cur[i+1]
			}
			next = append(next, hashPair(left, right))
		}
		levels = append(levels, next)
		cur = next
	}
	return &merkleTree{levels: levels}
}

func (mt *merkleTree) root() [32]byte {
	top := mt.levels[len(mt.levels)-1]
	return top[0]
}

// proof returns the inclusion proof for the leaf at index i, in the bit-order
// VerifyMerkle expects (bit k of index selects left/right at level k).
func (mt *merkleTree) proof(i int) AInferenceProof {
	var path [][32]byte
	idx := i
	for lvl := 0; lvl < len(mt.levels)-1; lvl++ {
		nodes := mt.levels[lvl]
		var sib [32]byte
		if idx%2 == 0 {
			if idx+1 < len(nodes) {
				sib = nodes[idx+1]
			} else {
				sib = nodes[idx] // duplicated
			}
		} else {
			sib = nodes[idx-1]
		}
		path = append(path, sib)
		idx /= 2
	}
	return AInferenceProof{ReceiptRoot: mt.root(), Path: path, Index: uint64(i)}
}

// --- calldata builders --------------------------------------------------------

func encodeSubmit(modelSpec, prompt [32]byte, n, threshold uint16, fee [32]byte, routing [32]byte) []byte {
	in := make([]byte, 4+submitIntentArgsLen)
	putU32(in[0:4], SelectorSubmitInferenceIntent)
	copy(in[4:36], modelSpec[:])
	copy(in[36:68], prompt[:])
	in[68+30] = byte(n >> 8) // word [64:96], low 2 bytes at [94:96] -> offset 4+64=68 .. +30
	in[68+31] = byte(n)
	in[100+30] = byte(threshold >> 8) // word [96:128] -> offset 4+96=100
	in[100+31] = byte(threshold)
	copy(in[132:164], fee[:]) // word [128:160] -> offset 4+128=132
	copy(in[164:196], routing[:])
	return in
}

func encodeVerify(receipt []byte, proof []byte) []byte {
	out := make([]byte, 4+4+len(receipt)+len(proof))
	putU32(out[0:4], SelectorVerifyInferenceReceipt)
	out[4] = byte(len(receipt) >> 8)
	out[5] = byte(len(receipt))
	out[6] = byte(len(proof) >> 8)
	out[7] = byte(len(proof))
	copy(out[8:], receipt)
	copy(out[8+len(receipt):], proof)
	return out
}

func encodeProof(p AInferenceProof) []byte {
	out := make([]byte, 32+8+2+len(p.Path)*32)
	copy(out[0:32], p.ReceiptRoot[:])
	putU64(out[32:40], p.Index)
	out[40] = byte(len(p.Path) >> 8)
	out[41] = byte(len(p.Path))
	for i, n := range p.Path {
		copy(out[42+i*32:42+i*32+32], n[:])
	}
	return out
}

func putU32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

// --- common test fixtures -----------------------------------------------------

func h32(b byte) [32]byte {
	var x [32]byte
	for i := range x {
		x[i] = b
	}
	return x
}

// keccak is the test's independent keccak256 (luxfi/crypto, the same the package uses)
// used by the wire-spec cross-check to recompute hashes from hand-assembled preimages.
func keccak(b []byte) [32]byte {
	var out [32]byte
	copy(out[:], crypto.Keccak256(b))
	return out
}

func feeWord(v uint64) [32]byte {
	var x [32]byte
	putU64(x[24:32], v)
	return x
}

// installNative installs a staged native client with a fixed A-Chain id and resets it
// when the test ends. Returns the a-chain id it bound.
func installNative(t *testing.T, achainID [32]byte, notify ZAPNotifier) {
	t.Helper()
	resetAChainClientForTest()
	if err := InstallAChainClient(NewNativeAChainClient("Lux Inference", achainID, notify)); err != nil {
		t.Fatalf("InstallAChainClient: %v", err)
	}
	t.Cleanup(resetAChainClientForTest)
}
