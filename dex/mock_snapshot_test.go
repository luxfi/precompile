// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/precompile/contract"
)

// mock_snapshot_test.go gives the test harness the EXACT atomicity boundary
// production has: the EVM wraps every CALL to a precompile in StateDB.Snapshot()
// and, when the precompile returns a non-nil error, StateDB.RevertToSnapshot()
// rolls back EVERY state write the precompile made — the ERC-20 transferFrom of
// the order lock, the seam-reserve/escrow ledger writes, the vault value move —
// all of it, because they are all StateDB writes covered by the one snapshot. See
// geth/core/vm/evm.go (Snapshot at the top of Call, RevertToSnapshot on err).
// (Recovered from the deleted swap_sync_snapshot_test.go: it is generic mock-EVM
// snapshot infra — no matcher dependency — that the KEEP settle/atomicity tests use.)
//
// The MockStateDB the unit tests run over stubbed Snapshot/RevertToSnapshot as
// no-ops, so a direct h.c.Run(...) could not OBSERVE the rollback — a returned
// error left partial writes in the mock. This file implements a REAL snapshot on
// the mock (a full clone of every mutable map) and an EVM-faithful Run helper
// that takes the snapshot before dispatch and reverts on error, exactly as the
// production EVM does. The atomicity tests drive through it so they prove the
// REAL production property (both-or-neither under the EVM snapshot), not a
// hand-rolled in-precompile undo.

// mockSnapshot is a deep copy of every mutable field of a MockStateDB at the
// instant a snapshot is taken. Reverting restores these maps wholesale. The test
// scale (a handful of accounts/assets) makes a full clone trivially cheap and
// unambiguously correct — there is no partial-snapshot hazard.
type mockSnapshot struct {
	states        map[common.Address]map[common.Hash]common.Hash
	balances      map[common.Address]*uint256.Int
	exists        map[common.Address]bool
	tokenBalances map[common.Address]map[common.Address]*big.Int
	logs          []*ethtypes.Log
}

// snapshotStack is the LIFO of taken snapshots for one MockStateDB. The Snapshot()
// id is the stack length at capture; RevertToSnapshot(id) restores the state as of
// that capture and truncates the stack to it (matching the geth journal's revert-
// to-a-revision semantics closely enough for the test's single-frame use).
var snapshotStacks = map[*MockStateDB][]mockSnapshot{}

// cloneStates deep-copies the per-account storage map.
func cloneStates(in map[common.Address]map[common.Hash]common.Hash) map[common.Address]map[common.Hash]common.Hash {
	out := make(map[common.Address]map[common.Hash]common.Hash, len(in))
	for addr, kv := range in {
		m := make(map[common.Hash]common.Hash, len(kv))
		for k, v := range kv {
			m[k] = v
		}
		out[addr] = m
	}
	return out
}

// cloneBalances deep-copies the native-balance map (uint256 values are copied, not
// aliased, so a later AddBalance/SubBalance cannot mutate the snapshot).
func cloneBalances(in map[common.Address]*uint256.Int) map[common.Address]*uint256.Int {
	out := make(map[common.Address]*uint256.Int, len(in))
	for addr, v := range in {
		out[addr] = new(uint256.Int).Set(v)
	}
	return out
}

// cloneExists copies the account-existence set.
func cloneExists(in map[common.Address]bool) map[common.Address]bool {
	out := make(map[common.Address]bool, len(in))
	for addr, v := range in {
		out[addr] = v
	}
	return out
}

// cloneTokenBalances deep-copies the (token -> holder -> balance) ERC-20 ledger,
// copying each big.Int value so a later transferFrom cannot mutate the snapshot.
func cloneTokenBalances(in map[common.Address]map[common.Address]*big.Int) map[common.Address]map[common.Address]*big.Int {
	out := make(map[common.Address]map[common.Address]*big.Int, len(in))
	for token, holders := range in {
		m := make(map[common.Address]*big.Int, len(holders))
		for holder, v := range holders {
			m[holder] = new(big.Int).Set(v)
		}
		out[token] = m
	}
	return out
}

// takeMockSnapshot clones every mutable field of m, pushes it on m's stack, and
// returns the snapshot id (the pre-push stack length).
func takeMockSnapshot(m *MockStateDB) int {
	snap := mockSnapshot{
		states:        cloneStates(m.states),
		balances:      cloneBalances(m.balances),
		exists:        cloneExists(m.exists),
		tokenBalances: cloneTokenBalances(m.tokenBalances),
		logs:          append([]*ethtypes.Log(nil), m.logs...),
	}
	id := len(snapshotStacks[m])
	snapshotStacks[m] = append(snapshotStacks[m], snap)
	return id
}

// revertMockToSnapshot restores m's state to the snapshot with the given id and
// truncates the stack to it. An out-of-range id is a no-op (defensive — a real
// EVM never reverts to an id it did not hand out).
func revertMockToSnapshot(m *MockStateDB, id int) {
	stack := snapshotStacks[m]
	if id < 0 || id >= len(stack) {
		return
	}
	snap := stack[id]
	m.states = cloneStates(snap.states)
	m.balances = cloneBalances(snap.balances)
	m.exists = cloneExists(snap.exists)
	m.tokenBalances = cloneTokenBalances(snap.tokenBalances)
	m.logs = append([]*ethtypes.Log(nil), snap.logs...)
	snapshotStacks[m] = stack[:id]
}

// runWithEVMSnapshot dispatches a precompile call through the EXACT atomicity
// boundary the production EVM gives a precompile CALL: it snapshots the StateDB
// before dispatch, runs the contract, and on a non-nil error reverts the snapshot
// — so a failed swap rolls back BOTH the C-surface (ERC-20/native balances) AND
// the D-surface (dexcore book/ledger) together, both-or-neither. On success the
// snapshot is simply dropped (the writes stand). This mirrors
// geth/core/vm/evm.go's Call: `snapshot := Snapshot(); … ; if err != nil {
// RevertToSnapshot(snapshot) }`. Tests that assert the atomic-revert invariant
// drive through this helper instead of calling Run directly, so they observe the
// real production rollback rather than the mock's partial writes.
func runWithEVMSnapshot(
	c *SettleContract,
	state *nativeAtomicState,
	caller common.Address,
	addr common.Address,
	input []byte,
	gas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	m := state.stateDB
	snapshot := state.GetStateDB().(contract.StateDB).Snapshot()
	out, gasLeft, err := c.Run(state, caller, addr, input, gas, readOnly)
	if err != nil {
		_ = m // m is the concrete mock the wrapper snapshots; revert via the wrapper id
		state.GetStateDB().(contract.StateDB).RevertToSnapshot(snapshot)
	}
	return out, gasLeft, err
}
