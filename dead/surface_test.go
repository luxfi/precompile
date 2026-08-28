// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dead

import (
	"encoding/binary"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// provisioned returns a state with `admin` installed as administrator.
func provisioned(t *testing.T, admin common.Address) (*MockStateDB, *mockAccessibleState) {
	t.Helper()
	db, state := newState()
	cfg := &Config{key: ConfigKeyDead, AdminAddress: &admin}
	require.NoError(t, (&configurator{key: ConfigKeyDead}).Configure(nil, cfg, db, mockBlockContext{}))
	return db, state
}

func uintWord(v uint64) common.Hash {
	var h common.Hash
	binary.BigEndian.PutUint64(h[24:], v)
	return h
}

// ─── burn ratio ───────────────────────────────────────────────────────────────

func TestSetBurnRatioRoundTrips(t *testing.T) {
	admin := common.HexToAddress("0x1234567890123456789012345678901234567890")
	db, state := provisioned(t, admin)

	for _, bps := range []uint64{0, 1, 5000, 9999, BasisPoints} {
		_, _, err := DeadPrecompile.Run(state, admin, DeadAddress,
			selectorCall(SelectorSetBurnRatio, uintWord(bps)), 1_000_000, false)
		require.NoError(t, err, "bps=%d", bps)
		require.Equal(t, bps, DeadPrecompile.getBurnRatioInternal(db), "bps=%d", bps)

		// The getter reports the same thing over the wire.
		out, _, err := DeadPrecompile.Run(state, admin, DeadAddress,
			SelectorGetBurnRatio[:], 1_000_000, false)
		require.NoError(t, err)
		require.Len(t, out, 32)
		require.Equal(t, bps, binary.BigEndian.Uint64(out[24:]))
	}
}

// A ratio above 100% would make the treasury share underflow, so it is refused.
func TestSetBurnRatioRefusesAboveFullScale(t *testing.T) {
	admin := common.HexToAddress("0x1234567890123456789012345678901234567890")
	db, state := provisioned(t, admin)

	for _, bps := range []uint64{BasisPoints + 1, 20_000, ^uint64(0)} {
		_, _, err := DeadPrecompile.Run(state, admin, DeadAddress,
			selectorCall(SelectorSetBurnRatio, uintWord(bps)), 1_000_000, false)
		require.ErrorIs(t, err, ErrInvalidRatio, "bps=%d", bps)
	}
	// Unchanged — still the default.
	require.Equal(t, DefaultBurnBPS, DeadPrecompile.getBurnRatioInternal(db))
}

// The split never mints: burn + treasury == value, for every ratio.
func TestSplitConservesValue(t *testing.T) {
	values := []*uint256.Int{
		uint256.NewInt(0), uint256.NewInt(1), uint256.NewInt(3),
		uint256.NewInt(1000), uint256.NewInt(1e18),
		new(uint256.Int).SetAllOne(),
	}
	for _, bps := range []uint64{0, 1, 3333, 5000, 9999, BasisPoints} {
		for _, v := range values {
			burn, treasury := CalculateSplitUint256(v, bps)
			sum := new(uint256.Int).Add(burn, treasury)
			require.Equal(t, 0, sum.Cmp(v),
				"bps=%d value=%s: burn %s + treasury %s != value", bps, v, burn, treasury)
			require.False(t, burn.Gt(v), "burn exceeds value")
			require.False(t, treasury.Gt(v), "treasury exceeds value")
		}
	}
}

// Integer division truncates the burn, so the remainder must land in the
// treasury rather than vanishing — the caller's side never gains from rounding.
func TestSplitRoundsRemainderToTreasury(t *testing.T) {
	burn, treasury := CalculateSplitUint256(uint256.NewInt(1), 5000)
	require.Equal(t, uint64(0), burn.Uint64())
	require.Equal(t, uint64(1), treasury.Uint64())

	burn, treasury = CalculateSplitUint256(uint256.NewInt(3), 5000)
	require.Equal(t, uint64(1), burn.Uint64())
	require.Equal(t, uint64(2), treasury.Uint64())
}

func TestSplitOfZeroIsZero(t *testing.T) {
	burn, treasury := CalculateSplitUint256(uint256.NewInt(0), 5000)
	require.True(t, burn.IsZero())
	require.True(t, treasury.IsZero())
}

// ─── enabled flag ─────────────────────────────────────────────────────────────

func TestSetEnabledRoundTrips(t *testing.T) {
	admin := common.HexToAddress("0x1234567890123456789012345678901234567890")
	db, state := provisioned(t, admin)

	for _, want := range []bool{false, true, false} {
		word := common.Hash{}
		if want {
			word[31] = 1
		}
		_, _, err := DeadPrecompile.Run(state, admin, DeadAddress,
			selectorCall(SelectorSetEnabled, word), 1_000_000, false)
		require.NoError(t, err)
		require.Equal(t, want, DeadPrecompile.isEnabledInternal(db))

		out, _, err := DeadPrecompile.Run(state, admin, DeadAddress,
			SelectorIsEnabled[:], 1_000_000, false)
		require.NoError(t, err)
		require.Len(t, out, 32)
		require.Equal(t, want, out[31] != 0)
	}
}

// ─── admin-only surface ───────────────────────────────────────────────────────

// Every mutating selector refuses a non-admin, refuses read-only execution, and
// refuses arguments too short to hold a word — and none of them leaves a trace.
func TestMutatingSelectorsRefuseConsistently(t *testing.T) {
	admin := common.HexToAddress("0x1234567890123456789012345678901234567890")
	stranger := common.HexToAddress("0x9999999999999999999999999999999999999999")

	mutators := map[string][4]byte{
		"setAdmin":     SelectorSetAdmin,
		"setTreasury":  SelectorSetTreasury,
		"setBurnRatio": SelectorSetBurnRatio,
		"setEnabled":   SelectorSetEnabled,
	}

	for name, sel := range mutators {
		t.Run(name+"/non-admin", func(t *testing.T) {
			_, state := provisioned(t, admin)
			_, _, err := DeadPrecompile.Run(state, stranger, DeadAddress,
				selectorCall(sel, uintWord(1)), 1_000_000, false)
			require.ErrorIs(t, err, ErrUnauthorized)
		})

		t.Run(name+"/read-only", func(t *testing.T) {
			_, state := provisioned(t, admin)
			_, _, err := DeadPrecompile.Run(state, admin, DeadAddress,
				selectorCall(sel, uintWord(1)), 1_000_000, true)
			require.ErrorIs(t, err, ErrUnauthorized)
		})

		t.Run(name+"/short-args", func(t *testing.T) {
			_, state := provisioned(t, admin)
			_, _, err := DeadPrecompile.Run(state, admin, DeadAddress,
				append(sel[:], 0x01), 1_000_000, false)
			require.ErrorIs(t, err, ErrInvalidInput)
		})

		t.Run(name+"/insufficient-gas", func(t *testing.T) {
			_, state := provisioned(t, admin)
			_, remaining, err := DeadPrecompile.Run(state, admin, DeadAddress,
				selectorCall(sel, uintWord(1)), GasAdminWrite-1, false)
			require.ErrorIs(t, err, ErrInsufficientGas)
			require.Zero(t, remaining)
		})
	}
}

// setAdmin and setTreasury both refuse the zero address, which would otherwise
// be indistinguishable from an unset slot.
func TestAddressSettersRefuseZero(t *testing.T) {
	admin := common.HexToAddress("0x1234567890123456789012345678901234567890")
	db, state := provisioned(t, admin)

	for _, sel := range [][4]byte{SelectorSetAdmin, SelectorSetTreasury} {
		_, _, err := DeadPrecompile.Run(state, admin, DeadAddress,
			selectorCall(sel, common.Hash{}), 1_000_000, false)
		require.ErrorIs(t, err, ErrInvalidAddress)
	}
	require.Equal(t, admin, DeadPrecompile.getAdminInternal(db))
}

// Handing the role on works, and the old admin loses it.
func TestAdminHandover(t *testing.T) {
	admin := common.HexToAddress("0x1234567890123456789012345678901234567890")
	successor := common.HexToAddress("0x5555555555555555555555555555555555555555")
	db, state := provisioned(t, admin)

	_, _, err := DeadPrecompile.Run(state, admin, DeadAddress,
		selectorCall(SelectorSetAdmin, addrWord(successor)), 1_000_000, false)
	require.NoError(t, err)
	require.Equal(t, successor, DeadPrecompile.getAdminInternal(db))

	// The former admin is now a stranger.
	_, _, err = DeadPrecompile.Run(state, admin, DeadAddress,
		selectorCall(SelectorSetTreasury, addrWord(admin)), 1_000_000, false)
	require.ErrorIs(t, err, ErrUnauthorized)
}

// ─── view surface ─────────────────────────────────────────────────────────────

func TestViewSelectorsReportState(t *testing.T) {
	admin := common.HexToAddress("0x1234567890123456789012345678901234567890")
	db, state := provisioned(t, admin)

	out, _, err := DeadPrecompile.Run(state, admin, DeadAddress, SelectorGetAdmin[:], 1_000_000, false)
	require.NoError(t, err)
	require.Equal(t, admin, common.BytesToAddress(out[12:]))

	// Treasury falls back to the default until one is set.
	out, _, err = DeadPrecompile.Run(state, admin, DeadAddress, SelectorGetTreasury[:], 1_000_000, false)
	require.NoError(t, err)
	require.Equal(t, DefaultDAOTreasury, common.BytesToAddress(out[12:]))

	newTreasury := common.HexToAddress("0xAbcAbcAbcAbcAbcAbcAbcAbcAbcAbcAbcAbcAbc1")
	_, _, err = DeadPrecompile.Run(state, admin, DeadAddress,
		selectorCall(SelectorSetTreasury, addrWord(newTreasury)), 1_000_000, false)
	require.NoError(t, err)
	out, _, err = DeadPrecompile.Run(state, admin, DeadAddress, SelectorGetTreasury[:], 1_000_000, false)
	require.NoError(t, err)
	require.Equal(t, newTreasury, common.BytesToAddress(out[12:]))
	require.Equal(t, newTreasury, DeadPrecompile.getTreasuryInternal(db))
}

// getSplit answers the same numbers the receive path would apply.
func TestGetSplitMatchesReceive(t *testing.T) {
	admin := common.HexToAddress("0x1234567890123456789012345678901234567890")
	_, state := provisioned(t, admin)

	_, _, err := DeadPrecompile.Run(state, admin, DeadAddress,
		selectorCall(SelectorSetBurnRatio, uintWord(7000)), 1_000_000, false)
	require.NoError(t, err)

	out, _, err := DeadPrecompile.Run(state, admin, DeadAddress,
		selectorCall(SelectorGetSplit, uintWord(1000)), 1_000_000, false)
	require.NoError(t, err)
	require.Len(t, out, 64)

	burn := new(uint256.Int).SetBytes(out[:32])
	treasury := new(uint256.Int).SetBytes(out[32:])
	require.Equal(t, uint64(700), burn.Uint64())
	require.Equal(t, uint64(300), treasury.Uint64())

	wantBurn, wantTreasury := CalculateSplitUint256(uint256.NewInt(1000), 7000)
	require.Equal(t, 0, wantBurn.Cmp(burn))
	require.Equal(t, 0, wantTreasury.Cmp(treasury))
}

func TestGetSplitRefusesShortArgs(t *testing.T) {
	admin := common.HexToAddress("0x1234567890123456789012345678901234567890")
	_, state := provisioned(t, admin)
	_, _, err := DeadPrecompile.Run(state, admin, DeadAddress,
		append(SelectorGetSplit[:], 0x01), 1_000_000, false)
	require.ErrorIs(t, err, ErrInvalidInput)
}

// Views are readable in read-only execution — they change nothing.
func TestViewSelectorsWorkReadOnly(t *testing.T) {
	admin := common.HexToAddress("0x1234567890123456789012345678901234567890")
	_, state := provisioned(t, admin)

	for _, sel := range [][4]byte{SelectorGetAdmin, SelectorGetTreasury, SelectorGetBurnRatio, SelectorIsEnabled} {
		_, _, err := DeadPrecompile.Run(state, admin, DeadAddress, sel[:], 1_000_000, true)
		require.NoError(t, err)
	}
}

// Every view refuses below its read price, consuming the supply rather than
// refunding it.
func TestViewSelectorsChargeReadGas(t *testing.T) {
	admin := common.HexToAddress("0x1234567890123456789012345678901234567890")
	_, state := provisioned(t, admin)

	for _, sel := range [][4]byte{SelectorGetAdmin, SelectorGetTreasury, SelectorGetBurnRatio, SelectorIsEnabled} {
		_, remaining, err := DeadPrecompile.Run(state, admin, DeadAddress, sel[:], GasAdminRead-1, false)
		require.ErrorIs(t, err, ErrInsufficientGas)
		require.Zero(t, remaining)
	}

	_, remaining, err := DeadPrecompile.Run(state, admin, DeadAddress,
		selectorCall(SelectorGetSplit, uintWord(1)), GasAdminRead-1, false)
	require.ErrorIs(t, err, ErrInsufficientGas)
	require.Zero(t, remaining)
}

// An unrecognised selector is treated as a receive, so it must obey the same
// accounting as one — in particular it must not be a second way to re-split.
func TestUnknownSelectorBehavesAsReceive(t *testing.T) {
	admin := common.HexToAddress("0x1234567890123456789012345678901234567890")
	db, state := provisioned(t, admin)
	treasury := common.HexToAddress("0xABCDEF1234567890123456789012345678901234")

	DeadPrecompile.setStateAddress(db, TreasurySlot, treasury)
	DeadPrecompile.setStateUint64(db, BurnBPSSlot, 5000)
	DeadPrecompile.setStateBool(db, EnabledSlot, true)
	db.AddBalance(DeadAddress, uint256.NewInt(1000), tracing.BalanceChangeTransfer)

	unknown := []byte{0xde, 0xad, 0xbe, 0xef}
	for range 5 {
		_, _, err := DeadPrecompile.Run(state, admin, DeadAddress, unknown, 1_000_000, false)
		require.NoError(t, err)
	}
	require.Equal(t, uint64(500), db.GetBalance(treasury).Uint64())
	require.Equal(t, uint64(500), db.GetBalance(DeadAddress).Uint64())
}

// ─── config plumbing ──────────────────────────────────────────────────────────

func TestConfigContract(t *testing.T) {
	c := &configurator{key: ConfigKeyDead}
	cfg, ok := c.MakeConfig().(*Config)
	require.True(t, ok)
	require.Equal(t, ConfigKeyDead, cfg.Key())
	require.Nil(t, cfg.Timestamp())
	require.False(t, cfg.IsDisabled())
	require.NoError(t, cfg.Verify(nil))

	// Equal compares the key and the upgrade, and rejects a foreign type.
	require.True(t, cfg.Equal(&Config{key: ConfigKeyDead}))
	require.False(t, cfg.Equal(&Config{key: ConfigKeyZero}))
	require.False(t, cfg.Equal(nil))
	require.False(t, cfg.Equal(otherConfig{}))
}

// Configure refuses a config of the wrong concrete type rather than silently
// provisioning nothing.
func TestConfigureRejectsForeignConfig(t *testing.T) {
	db, _ := newState()
	require.Error(t, (&configurator{key: ConfigKeyDead}).Configure(nil, otherConfig{}, db, mockBlockContext{}))
}

// A config naming no admin provisions none, and leaves the precompile ownerless.
func TestConfigureWithoutAdminProvisionsNobody(t *testing.T) {
	db, _ := newState()
	cfg := &Config{key: ConfigKeyDead}
	require.NoError(t, (&configurator{key: ConfigKeyDead}).Configure(nil, cfg, db, mockBlockContext{}))
	require.Equal(t, common.Address{}, DeadPrecompile.getAdminInternal(db))
	require.False(t, DeadPrecompile.isAdmin(db, common.HexToAddress("0x1")))
}

// All three dead addresses register, at distinct addresses, sharing one contract.
func TestAllThreeModulesRegistered(t *testing.T) {
	seen := map[common.Address]string{}
	for _, m := range []struct {
		mod  interface{ }
		addr common.Address
		key  string
	}{
		{nil, ModuleZero.Address, ModuleZero.ConfigKey},
		{nil, ModuleDead.Address, ModuleDead.ConfigKey},
		{nil, ModuleFull.Address, ModuleFull.ConfigKey},
	} {
		require.NotContains(t, seen, m.addr, "duplicate address %s", m.addr)
		seen[m.addr] = m.key
	}
	require.Len(t, seen, 3)
	require.Contains(t, seen, ZeroAddress)
	require.Contains(t, seen, DeadAddress)
	require.Contains(t, seen, DeadFullAddress)

	require.Same(t, DeadPrecompile, ModuleZero.Contract)
	require.Same(t, DeadPrecompile, ModuleDead.Contract)
	require.Same(t, DeadPrecompile, ModuleFull.Contract)

	// None of them is AlwaysOn: the precompile is inert unless a chain enables it.
	require.False(t, ModuleZero.AlwaysOn)
	require.False(t, ModuleDead.AlwaysOn)
	require.False(t, ModuleFull.AlwaysOn)
}

// otherConfig is a foreign precompileconfig.Config used to exercise type checks.
type otherConfig struct{}

func (otherConfig) Key() string                                  { return "other" }
func (otherConfig) Timestamp() *uint64                           { return nil }
func (otherConfig) IsDisabled() bool                             { return false }
func (otherConfig) Equal(precompileconfig.Config) bool           { return false }
func (otherConfig) Verify(precompileconfig.ChainConfig) error    { return nil }
