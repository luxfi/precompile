// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dead

import (
	"context"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

// ─── test harness ─────────────────────────────────────────────────────────────

type mockBlockContext struct{}

func (mockBlockContext) Number() *big.Int  { return big.NewInt(1) }
func (mockBlockContext) Timestamp() uint64 { return 1 }
func (mockBlockContext) GetPredicateResults(common.Hash, common.Address) []byte {
	return nil
}

type mockEnv struct{ readOnly bool }

func (m mockEnv) ReadOnly() bool { return m.readOnly }

type mockAccessibleState struct {
	stateDB  contract.StateDB
	readOnly bool
}

func (m *mockAccessibleState) GetStateDB() contract.StateDB { return m.stateDB }
func (m *mockAccessibleState) GetBlockContext() contract.BlockContext {
	return mockBlockContext{}
}
func (m *mockAccessibleState) GetConsensusContext() context.Context { return context.Background() }
func (m *mockAccessibleState) GetChainConfig() precompileconfig.ChainConfig {
	return nil
}
func (m *mockAccessibleState) GetPrecompileEnv() contract.PrecompileEnvironment {
	return mockEnv{readOnly: m.readOnly}
}

func newState() (*MockStateDB, *mockAccessibleState) {
	db := NewMockStateDB()
	return db, &mockAccessibleState{stateDB: db}
}

// selectorCall builds calldata for a 4-byte selector with a single 32-byte word.
func selectorCall(sel [4]byte, word common.Hash) []byte {
	return append(sel[:], word.Bytes()...)
}

func addrWord(a common.Address) common.Hash {
	var h common.Hash
	copy(h[12:], a.Bytes())
	return h
}

// ─── admin provisioning ───────────────────────────────────────────────────────

// An unset admin slot is the genesis state of every chain that activates this
// precompile. If the empty slot admits the caller, then the first transaction
// after genesis takes ownership of all three dead addresses. Nobody is admin
// until an admin is provisioned through Configure.
func TestUnsetAdminSlotAdmitsNobody(t *testing.T) {
	db, _ := newState()

	for _, caller := range []common.Address{
		common.HexToAddress("0x1111111111111111111111111111111111111111"),
		common.HexToAddress("0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"),
		DefaultDAOTreasury,
		{}, // the zero address itself
	} {
		require.False(t, DeadPrecompile.isAdmin(db, caller),
			"caller %s was admitted while the admin slot was unset", caller)
	}
}

// The end-to-end shape of the same property: an arbitrary account must not be
// able to seize the administrator role by being the first to ask for it.
func TestAdminCannotBeSeizedThroughRun(t *testing.T) {
	db, state := newState()
	attacker := common.HexToAddress("0xBAdC0ffee0DDF00D000000000000000000000001")

	_, _, err := DeadPrecompile.Run(state, attacker, DeadAddress,
		selectorCall(SelectorSetAdmin, addrWord(attacker)), 1_000_000, false)
	require.ErrorIs(t, err, ErrUnauthorized)

	require.Equal(t, common.Address{}, DeadPrecompile.getAdminInternal(db),
		"attacker installed itself as admin")
}

// A provisioned admin is honoured, and only that admin.
func TestProvisionedAdminIsHonoured(t *testing.T) {
	db, state := newState()
	admin := common.HexToAddress("0x1234567890123456789012345678901234567890")
	stranger := common.HexToAddress("0x9999999999999999999999999999999999999999")

	cfg := &Config{key: ConfigKeyDead, AdminAddress: &admin}
	require.NoError(t, (&configurator{key: ConfigKeyDead}).Configure(nil, cfg, db, mockBlockContext{}))
	require.Equal(t, admin, DeadPrecompile.getAdminInternal(db))

	require.True(t, DeadPrecompile.isAdmin(db, admin))
	require.False(t, DeadPrecompile.isAdmin(db, stranger))

	// The stranger cannot redirect the treasury.
	_, _, err := DeadPrecompile.Run(state, stranger, DeadAddress,
		selectorCall(SelectorSetTreasury, addrWord(stranger)), 1_000_000, false)
	require.ErrorIs(t, err, ErrUnauthorized)

	// The admin can.
	newTreasury := common.HexToAddress("0xAbcAbcAbcAbcAbcAbcAbcAbcAbcAbcAbcAbcAbc1")
	_, _, err = DeadPrecompile.Run(state, admin, DeadAddress,
		selectorCall(SelectorSetTreasury, addrWord(newTreasury)), 1_000_000, false)
	require.NoError(t, err)
	require.Equal(t, newTreasury, DeadPrecompile.getTreasuryInternal(db))
}

// Configure must refuse to provision the zero address, which would leave the
// slot indistinguishable from "unprovisioned".
func TestConfigureRefusesZeroAdmin(t *testing.T) {
	db, _ := newState()
	zero := common.Address{}
	cfg := &Config{key: ConfigKeyDead, AdminAddress: &zero}
	require.Error(t, (&configurator{key: ConfigKeyDead}).Configure(nil, cfg, db, mockBlockContext{}))
}

// ─── receive accounting ───────────────────────────────────────────────────────

// The burned share must stay burned. Splitting the address's whole balance on
// every call re-splits the share that was already burned, so repeated calls
// migrate it to the treasury a fraction at a time until nothing is left.
func TestReceiveDoesNotResplitAlreadyBurnedFunds(t *testing.T) {
	db, _ := newState()
	treasury := common.HexToAddress("0xABCDEF1234567890123456789012345678901234")
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	DeadPrecompile.setStateAddress(db, TreasurySlot, treasury)
	DeadPrecompile.setStateUint64(db, BurnBPSSlot, 5000) // 50/50
	DeadPrecompile.setStateBool(db, EnabledSlot, true)

	db.AddBalance(DeadAddress, uint256.NewInt(1000), tracing.BalanceChangeTransfer)

	_, _, err := DeadPrecompile.handleReceive(db, caller, DeadAddress, GasBase, false)
	require.NoError(t, err)

	burnedAfterFirst := db.GetBalance(DeadAddress)
	treasuryAfterFirst := db.GetBalance(treasury)
	require.Equal(t, uint64(500), burnedAfterFirst.Uint64())
	require.Equal(t, uint64(500), treasuryAfterFirst.Uint64())

	// Nine more calls with no new funds arriving. Each is a no-op.
	for i := range 9 {
		_, _, err := DeadPrecompile.handleReceive(db, caller, DeadAddress, GasBase, false)
		require.NoError(t, err, "call %d", i+2)
	}

	require.Equal(t, burnedAfterFirst.Uint64(), db.GetBalance(DeadAddress).Uint64(),
		"burned funds drained by repeated calls")
	require.Equal(t, treasuryAfterFirst.Uint64(), db.GetBalance(treasury).Uint64(),
		"treasury grew without any new funds arriving")
}

// Funds that arrive after a split are themselves split, exactly once.
func TestReceiveSplitsOnlyNewFunds(t *testing.T) {
	db, _ := newState()
	treasury := common.HexToAddress("0xABCDEF1234567890123456789012345678901234")
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	DeadPrecompile.setStateAddress(db, TreasurySlot, treasury)
	DeadPrecompile.setStateUint64(db, BurnBPSSlot, 5000)
	DeadPrecompile.setStateBool(db, EnabledSlot, true)

	for round := 1; round <= 3; round++ {
		db.AddBalance(DeadAddress, uint256.NewInt(1000), tracing.BalanceChangeTransfer)

		// Two calls per round; the second must be a no-op.
		for range 2 {
			_, _, err := DeadPrecompile.handleReceive(db, caller, DeadAddress, GasBase, false)
			require.NoError(t, err)
		}

		want := uint64(500 * round)
		require.Equal(t, want, db.GetBalance(treasury).Uint64(), "round %d treasury", round)
		require.Equal(t, want, db.GetBalance(DeadAddress).Uint64(), "round %d burned", round)
	}
}

// A 100%-burn configuration must move nothing, however often it is called.
func TestFullBurnMovesNothing(t *testing.T) {
	db, _ := newState()
	treasury := common.HexToAddress("0xABCDEF1234567890123456789012345678901234")
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	DeadPrecompile.setStateAddress(db, TreasurySlot, treasury)
	DeadPrecompile.setStateUint64(db, BurnBPSSlot, BasisPoints) // 100% burn
	DeadPrecompile.setStateBool(db, EnabledSlot, true)
	db.AddBalance(DeadAddress, uint256.NewInt(1000), tracing.BalanceChangeTransfer)

	for range 5 {
		_, _, err := DeadPrecompile.handleReceive(db, caller, DeadAddress, GasBase, false)
		require.NoError(t, err)
	}

	require.True(t, db.GetBalance(treasury).IsZero(), "treasury received part of a full burn")
	require.Equal(t, uint64(1000), db.GetBalance(DeadAddress).Uint64())
}

// Read-only execution must not move funds, and must not record progress either —
// otherwise the split it declined to perform is lost when the call is replayed
// in a writable context.
func TestReadOnlyReceiveLeavesStateUntouched(t *testing.T) {
	db, _ := newState()
	treasury := common.HexToAddress("0xABCDEF1234567890123456789012345678901234")
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	DeadPrecompile.setStateAddress(db, TreasurySlot, treasury)
	DeadPrecompile.setStateUint64(db, BurnBPSSlot, 5000)
	DeadPrecompile.setStateBool(db, EnabledSlot, true)
	db.AddBalance(DeadAddress, uint256.NewInt(1000), tracing.BalanceChangeTransfer)

	_, _, err := DeadPrecompile.handleReceive(db, caller, DeadAddress, GasBase, true)
	require.NoError(t, err)
	require.True(t, db.GetBalance(treasury).IsZero(), "read-only call moved funds")
	require.Equal(t, uint64(1000), db.GetBalance(DeadAddress).Uint64())

	// The pending split is still pending, and a writable call performs it.
	_, _, err = DeadPrecompile.handleReceive(db, caller, DeadAddress, GasBase, false)
	require.NoError(t, err)
	require.Equal(t, uint64(500), db.GetBalance(treasury).Uint64())
}

// ─── gas ──────────────────────────────────────────────────────────────────────

// Every reachable path charges. An input too short to carry a selector is still
// a call, and returning the full supplied gas makes it free to repeat.
func TestMalformedInputIsNotFree(t *testing.T) {
	_, state := newState()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	for _, input := range [][]byte{{0x01}, {0x01, 0x02}, {0x01, 0x02, 0x03}} {
		_, remaining, err := DeadPrecompile.Run(state, caller, DeadAddress, input, 1_000_000, false)
		require.Error(t, err)
		require.Less(t, remaining, uint64(1_000_000),
			"a %d-byte input was refused without charging gas", len(input))
	}
}

// Running out of gas must consume everything supplied rather than refunding it.
func TestInsufficientGasConsumesSupply(t *testing.T) {
	_, state := newState()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	_, remaining, err := DeadPrecompile.Run(state, caller, DeadAddress, nil, GasBase-1, false)
	require.ErrorIs(t, err, ErrInsufficientGas)
	require.Zero(t, remaining)
}

// ─── storage layout ───────────────────────────────────────────────────────────

// The four slots are hand-chosen constants, not digests. They were once
// commented as keccak256 of "dead.admin" and friends, which invites a
// maintainer to regenerate them from the strings; doing so would relocate every
// slot and orphan the stored admin, leaving the precompile reading an empty
// word where its owner used to be. Pin both facts: the values, and that they
// are not those digests.
func TestStorageSlotsArePinnedAndDistinct(t *testing.T) {
	slots := map[string]common.Hash{
		"admin":    AdminSlot,
		"treasury": TreasurySlot,
		"burnBPS":  BurnBPSSlot,
		"enabled":  EnabledSlot,
		"burned":   BurnedSlot,
	}

	seen := make(map[common.Hash]string, len(slots))
	for name, slot := range slots {
		require.NotEqual(t, common.Hash{}, slot, "%s slot is the zero word", name)
		if prev, dup := seen[slot]; dup {
			t.Fatalf("slots %q and %q collide on %s", prev, name, slot)
		}
		seen[slot] = name
	}

	// None of them is keccak256 of the string the old comments named.
	for name, slot := range map[string]common.Hash{
		"dead.admin":    AdminSlot,
		"dead.treasury": TreasurySlot,
		"dead.burnBPS":  BurnBPSSlot,
		"dead.enabled":  EnabledSlot,
	} {
		h := sha3.NewLegacyKeccak256()
		h.Write([]byte(name))
		var digest common.Hash
		copy(digest[:], h.Sum(nil))
		require.NotEqual(t, digest, slot,
			"%s now equals keccak256(%q) — the storage layout moved", name, name)
	}
}

// The burned-progress slot is per dead address: each address keeps its own
// balance, so one address's progress must not mask another's pending funds.
func TestBurnedProgressIsPerAddress(t *testing.T) {
	db, _ := newState()
	treasury := common.HexToAddress("0xABCDEF1234567890123456789012345678901234")
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	DeadPrecompile.setStateAddress(db, TreasurySlot, treasury)
	DeadPrecompile.setStateUint64(db, BurnBPSSlot, 5000)
	DeadPrecompile.setStateBool(db, EnabledSlot, true)

	for _, a := range AllDeadAddresses {
		db.AddBalance(a, uint256.NewInt(1000), tracing.BalanceChangeTransfer)
	}
	for _, a := range AllDeadAddresses {
		_, _, err := DeadPrecompile.handleReceive(db, caller, a, GasBase, false)
		require.NoError(t, err)
	}

	for _, a := range AllDeadAddresses {
		require.Equal(t, uint64(500), db.GetBalance(a).Uint64(), "address %s", a)
	}
	require.Equal(t, uint64(1500), db.GetBalance(treasury).Uint64())
}

// ─── disabled ─────────────────────────────────────────────────────────────────

// A disabled precompile moves nothing.
func TestDisabledReceiveMovesNothing(t *testing.T) {
	db, _ := newState()
	treasury := common.HexToAddress("0xABCDEF1234567890123456789012345678901234")
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	DeadPrecompile.setStateAddress(db, TreasurySlot, treasury)
	DeadPrecompile.setStateUint64(db, BurnBPSSlot, 5000)
	DeadPrecompile.setStateBool(db, EnabledSlot, false)
	db.AddBalance(DeadAddress, uint256.NewInt(1000), tracing.BalanceChangeTransfer)

	_, _, err := DeadPrecompile.handleReceive(db, caller, DeadAddress, GasBase, false)
	require.ErrorIs(t, err, ErrDisabled)
	require.True(t, db.GetBalance(treasury).IsZero())
	require.Equal(t, uint64(1000), db.GetBalance(DeadAddress).Uint64())
}
