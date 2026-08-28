// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package modelregistry

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

var (
	govA     = common.HexToAddress("0x00000000000000000000000000000000000000A1")
	govB     = common.HexToAddress("0x00000000000000000000000000000000000000A2")
	govC     = common.HexToAddress("0x00000000000000000000000000000000000000A3")
	outsider = common.HexToAddress("0x00000000000000000000000000000000000000BB")

	beluga   = common.HexToHash("0x0000000000000000000000000000000000000000000000000042424265677561")
	weightV1 = common.HexToHash("0xABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890")
	weightV2 = common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
)

const selectorUnknown uint32 = 0xDEADBEEF

func ptr64(v uint64) *uint64 { return &v }

// countingState is the mock StateDB plus a write counter. Reading state back is
// not enough to prove a refused call wrote nothing — a write of the identical
// value is invisible to a read. The counter proves SetState was never reached.
type countingState struct {
	*mockState
	writes int
}

var _ contract.StateDB = (*countingState)(nil)

func (c *countingState) SetState(addr common.Address, k, v common.Hash) common.Hash {
	c.writes++
	return c.mockState.SetState(addr, k, v)
}

func (c *countingState) snap() map[common.Hash]common.Hash {
	out := make(map[common.Hash]common.Hash, len(c.m))
	for k, v := range c.m {
		out[k] = v
	}
	return out
}

// seeded builds a registry whose genesis governance set is admins.
func seeded(t *testing.T, admins ...common.Address) (*countingState, mockAccessible) {
	t.Helper()
	st := &countingState{mockState: newMockState()}
	require.NoError(t, (&configurator{}).Configure(nil, &Config{Admins: admins}, st, nil))
	st.writes = 0 // genesis seeding is not what the caller under test is doing
	return st, mockAccessible{s: st}
}

// run executes input, paying exactly what RequiredGas asks.
func run(acc mockAccessible, caller common.Address, in []byte, readOnly bool) ([]byte, error) {
	ret, _, err := ModelRegistryPrecompile.Run(
		acc, caller, ContractAddress, in, ModelRegistryPrecompile.RequiredGas(in), readOnly)
	return ret, err
}

// refuses asserts input is rejected AND that the rejection was inert: no write
// attempted, and the whole state map byte-identical afterwards.
func refuses(t *testing.T, st *countingState, acc mockAccessible, caller common.Address, in []byte, readOnly bool) error {
	t.Helper()
	before := st.snap()
	st.writes = 0
	_, err := run(acc, caller, in, readOnly)
	require.Error(t, err)
	require.Zero(t, st.writes, "refused call reached SetState")
	require.Equal(t, before, st.snap(), "refused call mutated state")
	return err
}

// adopted reads the registry through the precompile ABI, which is what a
// contract on-chain sees.
func adopted(t *testing.T, acc mockAccessible, name common.Hash) (common.Hash, common.Hash) {
	t.Helper()
	ret, err := run(acc, outsider, getApprovedInput(name), true)
	require.NoError(t, err)
	require.Len(t, ret, 64)
	return common.BytesToHash(ret[0:32]), common.BytesToHash(ret[32:64])
}

func isAdminABI(t *testing.T, acc mockAccessible, a common.Address) bool {
	t.Helper()
	ret, err := run(acc, outsider, isAdminInput(a), true)
	require.NoError(t, err)
	require.Len(t, ret, 32)
	return ret[31] == 1
}

// truncate returns a call whose selector is intact but whose body is one byte
// short of the minimum the handler needs.
func truncate(selector uint32, bodyLen int) []byte {
	return append(sel(selector), make([]byte, bodyLen)...)
}

// ---------------------------------------------------------------------------
// module wiring
// ---------------------------------------------------------------------------

func TestModuleRegistration(t *testing.T) {
	byKey, ok := modules.GetPrecompileModule(ConfigKey)
	require.True(t, ok, "package init did not register the module under its config key")
	require.Equal(t, ContractAddress, byKey.Address)

	byAddr, ok := modules.GetPrecompileModuleByAddress(ContractAddress)
	require.True(t, ok, "module is not reachable by address")
	require.Equal(t, ConfigKey, byAddr.ConfigKey)

	// Genesis JSON routes by config key; the address routes EVM calls. Both must
	// land on this package's contract or the precompile is unreachable.
	require.Same(t, ModelRegistryPrecompile, byAddr.Contract)
	require.Equal(t, ConfigKey, Module.Configurator.MakeConfig().Key())

	// The address is consensus: every chain config, Solidity binding and
	// off-chain reader already names it. Slot 0x02 of the AI reserved range
	// 0x0300…0000..00FF is MODEL_REGISTRY; moving it would leave callers
	// talking to an empty account rather than to a precompile.
	require.Equal(t,
		common.HexToAddress("0x0300000000000000000000000000000000000002"),
		ContractAddress)

	// The config key is the genesis/upgrade JSON key. Renaming it does not
	// fail — the host simply never finds a config for this module, so the
	// precompile silently never activates.
	require.Equal(t, "modelRegistryConfig", ConfigKey)

	// So are the selectors. Distinctness matters as much as the values: two
	// selectors sharing a number would make the second method unreachable,
	// because Run dispatches on the first matching arm.
	selectors := map[string]uint32{
		"adopt":       SelectorAdopt,
		"getApproved": SelectorGetApproved,
		"isAdmin":     SelectorIsAdmin,
		"setAdmin":    SelectorSetAdmin,
	}
	require.Equal(t, map[string]uint32{
		"adopt":       0x01000000,
		"getApproved": 0x02000000,
		"isAdmin":     0x03000000,
		"setAdmin":    0x04000000,
	}, selectors)

	seen := map[uint32]string{}
	for name, s := range selectors {
		prev, dup := seen[s]
		require.False(t, dup, "%s and %s share selector %#x", prev, name, s)
		seen[s] = name
	}
	require.NotContains(t, seen, selectorUnknown, "the test's unknown selector is a real method")
}

func TestMakeConfigIsFreshAndEmpty(t *testing.T) {
	c := (&configurator{}).MakeConfig()
	require.NotNil(t, c)

	cfg, ok := c.(*Config)
	require.True(t, ok, "MakeConfig must produce the type Configure asserts on")
	require.Empty(t, cfg.Admins, "a fresh config must seed no governance")
	require.Nil(t, cfg.Timestamp())
	require.False(t, cfg.IsDisabled())
	require.NoError(t, cfg.Verify(nil))
	require.Equal(t, ConfigKey, cfg.Key())

	// The host unmarshals genesis JSON into whatever MakeConfig hands back. If
	// it returned a shared value, one chain's admin set would leak into another.
	other := (&configurator{}).MakeConfig()
	require.NotSame(t, cfg, other)
	cfg.Admins = append(cfg.Admins, govA)
	require.Empty(t, other.(*Config).Admins)
}

func TestConfigMirrorsUpgrade(t *testing.T) {
	for _, tc := range []struct {
		name string
		up   precompileconfig.Upgrade
	}{
		{"unscheduled", precompileconfig.Upgrade{}},
		{"scheduled", precompileconfig.Upgrade{BlockTimestamp: ptr64(1_700_000_000)}},
		{"disabled", precompileconfig.Upgrade{BlockTimestamp: ptr64(9), Disable: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{Upgrade: tc.up, Admins: []common.Address{govA}}
			require.Equal(t, ConfigKey, c.Key())
			require.Equal(t, tc.up.Timestamp(), c.Timestamp())
			require.Equal(t, tc.up.Disable, c.IsDisabled())
			// Verify gates genesis JSON; this config carries nothing to reject.
			require.NoError(t, c.Verify(nil))
		})
	}

	// Timestamp aliases the upgrade's pointer rather than copying a snapshot.
	c := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ptr64(5)}}
	require.Equal(t, uint64(5), *c.Timestamp())
}

// ---------------------------------------------------------------------------
// Config.Equal
// ---------------------------------------------------------------------------

// foreignConfig is an unrelated Config implementation. Equal must reject it on
// type, never by reading fields it does not have.
type foreignConfig struct{}

func (foreignConfig) Key() string                               { return "foreign" }
func (foreignConfig) Timestamp() *uint64                        { return nil }
func (foreignConfig) IsDisabled() bool                          { return false }
func (foreignConfig) Verify(precompileconfig.ChainConfig) error { return nil }
func (foreignConfig) Equal(precompileconfig.Config) bool        { return false }

var _ precompileconfig.Config = foreignConfig{}

func TestConfigEqual(t *testing.T) {
	up := func(ts *uint64, disable bool) precompileconfig.Upgrade {
		return precompileconfig.Upgrade{BlockTimestamp: ts, Disable: disable}
	}

	for _, tc := range []struct {
		name string
		a, b *Config
		want bool
	}{
		{"zero values", &Config{}, &Config{}, true},
		{"nil vs empty admin slice", &Config{}, &Config{Admins: []common.Address{}}, true},
		{"same everything",
			&Config{Upgrade: up(ptr64(7), true), Admins: []common.Address{govA, govB}},
			&Config{Upgrade: up(ptr64(7), true), Admins: []common.Address{govA, govB}}, true},

		// Upgrade half.
		{"timestamp differs",
			&Config{Upgrade: up(ptr64(7), false)}, &Config{Upgrade: up(ptr64(8), false)}, false},
		{"timestamp set vs unscheduled",
			&Config{Upgrade: up(ptr64(7), false)}, &Config{Upgrade: up(nil, false)}, false},
		{"disable differs",
			&Config{Upgrade: up(ptr64(7), true)}, &Config{Upgrade: up(ptr64(7), false)}, false},

		// Admins half.
		{"admin count differs (none vs one)",
			&Config{}, &Config{Admins: []common.Address{govA}}, false},
		{"admin count differs (one vs two)",
			&Config{Admins: []common.Address{govA}},
			&Config{Admins: []common.Address{govA, govB}}, false},
		{"same length, different member",
			&Config{Admins: []common.Address{govA}},
			&Config{Admins: []common.Address{govB}}, false},
		{"same length, one member swapped",
			&Config{Admins: []common.Address{govA, govB}},
			&Config{Admins: []common.Address{govA, govC}}, false},
		// Order is part of the config document: two genesis files listing the
		// same admins in different orders are different files, and Equal is how
		// the host detects a config it has not already applied.
		{"same members, different order",
			&Config{Admins: []common.Address{govA, govB}},
			&Config{Admins: []common.Address{govB, govA}}, false},

		// Both halves differ at once.
		{"upgrade and admins both differ",
			&Config{Upgrade: up(ptr64(1), false), Admins: []common.Address{govA}},
			&Config{Upgrade: up(ptr64(2), true), Admins: []common.Address{govB}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.a.Equal(tc.b))
			require.Equal(t, tc.want, tc.b.Equal(tc.a), "Equal must be symmetric")
		})
	}

	full := &Config{Upgrade: up(ptr64(7), true), Admins: []common.Address{govA}}
	require.True(t, full.Equal(full), "Equal must be reflexive")
	require.False(t, full.Equal(nil), "a nil config is not equal to a real one")
	require.False(t, full.Equal(foreignConfig{}), "a foreign Config type is never equal")
}

// TestConfigEqualComparesEveryField fails the day a field is added to Config
// without teaching Equal about it — the classic way an upgrade check goes blind.
func TestConfigEqualComparesEveryField(t *testing.T) {
	base := Config{
		Upgrade: precompileconfig.Upgrade{BlockTimestamp: ptr64(7)},
		Admins:  []common.Address{govA},
	}
	mutate := map[string]func(*Config){
		"Upgrade": func(c *Config) { c.Upgrade.BlockTimestamp = ptr64(8) },
		"Admins":  func(c *Config) { c.Admins = []common.Address{govB} },
	}

	rt := reflect.TypeOf(base)
	require.Equal(t, len(mutate), rt.NumField(),
		"Config's field set changed; extend Equal and this table")

	for i := range rt.NumField() {
		name := rt.Field(i).Name
		change, known := mutate[name]
		require.True(t, known, "no mutation covers field %s", name)

		t.Run(name, func(t *testing.T) {
			other := base
			change(&other)
			require.False(t, base.Equal(&other), "Equal ignores %s", name)
			require.False(t, other.Equal(&base), "Equal ignores %s", name)
		})
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestConfigureSeedsGenesisAdmins(t *testing.T) {
	for _, tc := range []struct {
		name   string
		admins []common.Address
	}{
		{"no admins", nil},
		{"empty slice", []common.Address{}},
		{"one admin", []common.Address{govA}},
		{"several admins", []common.Address{govA, govB, govC}},
		{"duplicate entries", []common.Address{govA, govA}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &countingState{mockState: newMockState()}
			require.NoError(t, (&configurator{}).Configure(nil, &Config{Admins: tc.admins}, st, nil))
			acc := mockAccessible{s: st}

			for _, a := range tc.admins {
				require.True(t, IsAdmin(st, a), "%s was listed at genesis but is not admin", a)
				require.True(t, isAdminABI(t, acc, a), "ABI disagrees with the Go helper for %s", a)
			}
			// Seeding is not "everyone is admin".
			require.False(t, IsAdmin(st, outsider))
			require.False(t, isAdminABI(t, acc, outsider))

			if len(tc.admins) == 0 {
				require.Zero(t, st.writes, "an empty governance set must touch no state")
			} else {
				require.NotZero(t, st.writes)
				// The seeding is real governance, not just a flag: a seeded
				// admin can actually adopt.
				_, err := run(acc, tc.admins[0], adoptInput(beluga, weightV1, 1), false)
				require.NoError(t, err)
			}
		})
	}
}

func TestConfigureRejectsForeignConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  precompileconfig.Config
	}{
		{"nil config", nil},
		{"foreign type", foreignConfig{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &countingState{mockState: newMockState()}
			err := (&configurator{}).Configure(nil, tc.cfg, st, nil)
			require.ErrorContains(t, err, "unexpected config type")
			require.Zero(t, st.writes, "a rejected config must not seed anything")
			require.Empty(t, st.m)
		})
	}
}

// ---------------------------------------------------------------------------
// access control
// ---------------------------------------------------------------------------

func TestNonAdminCannotAdopt(t *testing.T) {
	st, acc := seeded(t, govA)

	// Nothing adopted yet.
	ver, weight := adopted(t, acc, beluga)
	require.Equal(t, common.Hash{}, ver)
	require.Equal(t, common.Hash{}, weight)

	err := refuses(t, st, acc, outsider, adoptInput(beluga, weightV1, 1), false)
	require.ErrorContains(t, err, "not an admin")

	// State is still empty when read back through the ABI.
	ver, weight = adopted(t, acc, beluga)
	require.Equal(t, common.Hash{}, ver, "a refused adopt published a version")
	require.Equal(t, common.Hash{}, weight, "a refused adopt published weights")

	// And a refused caller cannot overwrite an existing adoption either.
	_, err = run(acc, govA, adoptInput(beluga, weightV1, 1), false)
	require.NoError(t, err)
	err = refuses(t, st, acc, outsider, adoptInput(beluga, weightV2, 99), false)
	require.ErrorContains(t, err, "not an admin")
	ver, weight = adopted(t, acc, beluga)
	require.Equal(t, uint64(1), binary.BigEndian.Uint64(ver[24:32]))
	require.Equal(t, weightV1, weight, "a refused adopt replaced the live weights")
}

func TestNonAdminCannotSetAdmin(t *testing.T) {
	st, acc := seeded(t, govA)

	err := refuses(t, st, acc, outsider, setAdminInput(outsider, true), false)
	require.ErrorContains(t, err, "not an admin")
	require.False(t, IsAdmin(st, outsider), "an outsider promoted itself")

	// Nor can an outsider strip a real admin.
	err = refuses(t, st, acc, outsider, setAdminInput(govA, false), false)
	require.ErrorContains(t, err, "not an admin")
	require.True(t, IsAdmin(st, govA), "an outsider demoted a genesis admin")
}

// TestAuthorizationPrecedesParsing pins the order of the checks in Run:
// read-only, then admin, then body length. A caller who is not allowed to write
// must be turned away before the body is even looked at, so no malformed-input
// path can ever run ahead of the authorization check.
func TestAuthorizationPrecedesParsing(t *testing.T) {
	st, acc := seeded(t, govA)

	for _, tc := range []struct {
		name     string
		caller   common.Address
		in       []byte
		readOnly bool
		want     string
	}{
		{"adopt, outsider, short body", outsider, truncate(SelectorAdopt, 95), false, "not an admin"},
		{"setAdmin, outsider, short body", outsider, truncate(SelectorSetAdmin, 63), false, "not an admin"},
		{"adopt, admin, read-only, short body", govA, truncate(SelectorAdopt, 95), true, "read-only"},
		{"setAdmin, admin, read-only, short body", govA, truncate(SelectorSetAdmin, 63), true, "read-only"},
		{"adopt, outsider, read-only", outsider, adoptInput(beluga, weightV1, 1), true, "read-only"},
		{"setAdmin, outsider, read-only", outsider, setAdminInput(outsider, true), true, "read-only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := refuses(t, st, acc, tc.caller, tc.in, tc.readOnly)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestAdminAdoptsAndPromotes(t *testing.T) {
	st, acc := seeded(t, govA)

	// govB is not admin yet, so it cannot adopt.
	require.False(t, isAdminABI(t, acc, govB))
	err := refuses(t, st, acc, govB, adoptInput(beluga, weightV1, 1), false)
	require.ErrorContains(t, err, "not an admin")

	// govA promotes govB.
	ret, err := run(acc, govA, setAdminInput(govB, true), false)
	require.NoError(t, err)
	require.Equal(t, boolWord(true), ret)
	require.True(t, IsAdmin(st, govB))
	require.True(t, isAdminABI(t, acc, govB))

	// The promotion is real: govB can now adopt, and the adoption is visible.
	ret, err = run(acc, govB, adoptInput(beluga, weightV2, 42), false)
	require.NoError(t, err)
	require.Equal(t, boolWord(true), ret)

	ver, weight := adopted(t, acc, beluga)
	require.Equal(t, uint64(42), binary.BigEndian.Uint64(ver[24:32]))
	require.Equal(t, weightV2, weight)

	// Promotion does not spill onto anyone else.
	require.False(t, IsAdmin(st, govC))
	require.False(t, IsAdmin(st, outsider))

	// A newly promoted admin can promote in turn: the privilege is not
	// special-cased to the genesis set.
	_, err = run(acc, govB, setAdminInput(govC, true), false)
	require.NoError(t, err)
	require.True(t, IsAdmin(st, govC))
}

func TestSetAdminDemotes(t *testing.T) {
	st, acc := seeded(t, govA, govB)
	require.True(t, IsAdmin(st, govB))

	ret, err := run(acc, govA, setAdminInput(govB, false), false)
	require.NoError(t, err)
	require.Equal(t, boolWord(true), ret)

	// Demotion clears the slot rather than leaving a stale non-zero value.
	require.Equal(t, common.Hash{}, st.GetState(ContractAddress, adminKey(govB)))
	require.False(t, IsAdmin(st, govB))
	require.False(t, isAdminABI(t, acc, govB))

	// A demoted admin is refused on both privileged entry points.
	err = refuses(t, st, acc, govB, adoptInput(beluga, weightV1, 1), false)
	require.ErrorContains(t, err, "not an admin")
	err = refuses(t, st, acc, govB, setAdminInput(govB, true), false)
	require.ErrorContains(t, err, "not an admin")

	// Demotion is not contagious.
	require.True(t, IsAdmin(st, govA))

	// A re-promotion restores the privilege, so demotion is a toggle and not a
	// one-way burn of the address.
	_, err = run(acc, govA, setAdminInput(govB, true), false)
	require.NoError(t, err)
	require.True(t, IsAdmin(st, govB))
}

// TestSoleAdminCanDemoteItself records that governance has no floor: the last
// admin may remove itself, after which nothing can ever adopt or re-admit an
// admin again, because both paths require an existing admin. Configure only
// runs at activation, so there is no way back.
func TestSoleAdminCanDemoteItself(t *testing.T) {
	st, acc := seeded(t, govA)

	_, err := run(acc, govA, setAdminInput(govA, false), false)
	require.NoError(t, err)
	require.False(t, IsAdmin(st, govA))

	err = refuses(t, st, acc, govA, setAdminInput(govA, true), false)
	require.ErrorContains(t, err, "not an admin")
	err = refuses(t, st, acc, govA, adoptInput(beluga, weightV1, 1), false)
	require.ErrorContains(t, err, "not an admin")
}

// ---------------------------------------------------------------------------
// read-only
// ---------------------------------------------------------------------------

func TestReadOnlyRefusesWritesAndAllowsReads(t *testing.T) {
	st, acc := seeded(t, govA)
	_, err := run(acc, govA, adoptInput(beluga, weightV1, 3), false)
	require.NoError(t, err)

	// Writes: refused even for a genesis admin, and inert.
	err = refuses(t, st, acc, govA, adoptInput(beluga, weightV2, 9), true)
	require.ErrorContains(t, err, "read-only")
	err = refuses(t, st, acc, govA, setAdminInput(govB, true), true)
	require.ErrorContains(t, err, "read-only")
	err = refuses(t, st, acc, govA, setAdminInput(govA, false), true)
	require.ErrorContains(t, err, "read-only")

	// Nothing moved.
	require.True(t, IsAdmin(st, govA))
	require.False(t, IsAdmin(st, govB))
	ver, weight := adopted(t, acc, beluga)
	require.Equal(t, uint64(3), binary.BigEndian.Uint64(ver[24:32]))
	require.Equal(t, weightV1, weight)

	// Reads still answer under read-only — that is the whole point of eth_call.
	require.True(t, isAdminABI(t, acc, govA))
	require.False(t, isAdminABI(t, acc, govB))
}

// ---------------------------------------------------------------------------
// Run: refusals
// ---------------------------------------------------------------------------

func TestRunRefusalsAreInert(t *testing.T) {
	st, acc := seeded(t, govA)
	// Give the state something to lose.
	_, err := run(acc, govA, adoptInput(beluga, weightV1, 5), false)
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		in   []byte
		want string
	}{
		{"nil input", nil, "input too short"},
		{"one byte", []byte{0x01}, "input too short"},
		{"two bytes", []byte{0x01, 0x00}, "input too short"},
		{"three bytes", []byte{0x01, 0x00, 0x00}, "input too short"},
		{"unknown selector", sel(selectorUnknown), "unknown selector"},
		{"unknown selector with body", append(sel(selectorUnknown), make([]byte, 96)...), "unknown selector"},
		{"adopt body one byte short", truncate(SelectorAdopt, 95), "adopt: input too short"},
		{"getApproved body one byte short", truncate(SelectorGetApproved, 31), "getApproved: input too short"},
		{"isAdmin body one byte short", truncate(SelectorIsAdmin, 31), "isAdmin: input too short"},
		{"setAdmin body one byte short", truncate(SelectorSetAdmin, 63), "setAdmin: input too short"},
		{"adopt with no body", sel(SelectorAdopt), "adopt: input too short"},
		{"getApproved with no body", sel(SelectorGetApproved), "getApproved: input too short"},
		{"isAdmin with no body", sel(SelectorIsAdmin), "isAdmin: input too short"},
		{"setAdmin with no body", sel(SelectorSetAdmin), "setAdmin: input too short"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Caller is an admin under a writable call, so the only thing that
			// can reject these is the decoding itself.
			err := refuses(t, st, acc, govA, tc.in, false)
			require.ErrorContains(t, err, tc.want)
		})
	}

	// The live adoption survived every one of them.
	ver, weight := adopted(t, acc, beluga)
	require.Equal(t, uint64(5), binary.BigEndian.Uint64(ver[24:32]))
	require.Equal(t, weightV1, weight)
	require.True(t, IsAdmin(st, govA))
}

// TestRunAcceptsMinimumBodies is the other half of the length checks: one byte
// less is refused, exactly enough is accepted. Without this, a handler that
// demanded one byte too many would still pass the refusal table.
func TestRunAcceptsMinimumBodies(t *testing.T) {
	_, acc := seeded(t, govA)

	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"adopt", truncate(SelectorAdopt, 96)},
		{"getApproved", truncate(SelectorGetApproved, 32)},
		{"isAdmin", truncate(SelectorIsAdmin, 32)},
		{"setAdmin", truncate(SelectorSetAdmin, 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := run(acc, govA, tc.in, false)
			require.NoError(t, err)
		})
	}

	// Trailing bytes past the minimum are ignored, not rejected.
	_, err := run(acc, govA, append(adoptInput(beluga, weightV1, 1), make([]byte, 33)...), false)
	require.NoError(t, err)
	ver, weight := adopted(t, acc, beluga)
	require.Equal(t, uint64(1), binary.BigEndian.Uint64(ver[24:32]))
	require.Equal(t, weightV1, weight)
}

// ---------------------------------------------------------------------------
// gas
// ---------------------------------------------------------------------------

func TestRequiredGasPricesBySelector(t *testing.T) {
	gasOf := ModelRegistryPrecompile.RequiredGas

	adopt := gasOf(adoptInput(beluga, weightV1, 1))
	setAdmin := gasOf(setAdminInput(govB, true))
	getApproved := gasOf(getApprovedInput(beluga))
	isAdmin := gasOf(isAdminInput(govA))

	// Relative shape, not literals: nothing is free; a read of two slots costs
	// more than a read of one; a write costs more than a read; a two-slot write
	// costs more than a one-slot write.
	require.Positive(t, isAdmin)
	require.Greater(t, getApproved, isAdmin)
	require.Greater(t, setAdmin, getApproved)
	require.Greater(t, adopt, setAdmin)

	// Price follows the selector alone — same selector, different body, same
	// price — so a caller cannot buy a discount by varying arguments.
	require.Equal(t, adopt, gasOf(adoptInput(weightV2, beluga, 1<<40)))
	require.Equal(t, setAdmin, gasOf(setAdminInput(outsider, false)))
	require.Equal(t, isAdmin, gasOf(isAdminInput(outsider)))
	require.Equal(t, getApproved, gasOf(getApprovedInput(weightV1)))

	// Nor by truncating the body: the price is fixed before the body is read.
	require.Equal(t, adopt, gasOf(truncate(SelectorAdopt, 0)))
	require.Equal(t, setAdmin, gasOf(truncate(SelectorSetAdmin, 1)))

	// Undecodable input falls to the module's default price. It is never free —
	// probing the precompile costs gas — and never priced as a write.
	for _, in := range [][]byte{nil, {}, {0x01}, {0x01, 0x02, 0x03}, sel(selectorUnknown)} {
		def := gasOf(in)
		require.Equal(t, getApproved, def, "default price drifted from the read price")
		require.Positive(t, def)
		require.Less(t, def, setAdmin)
	}

	// RequiredGas is pure: it may not consult state, so repeating a call after
	// the registry has changed must return the same number.
	st, acc := seeded(t, govA)
	in := adoptInput(beluga, weightV1, 1)
	_, err := run(acc, govA, in, false)
	require.NoError(t, err)
	require.NotEmpty(t, st.m)
	require.Equal(t, adopt, gasOf(in))
}

// TestRunDebitsExactlyRequiredGas pins the accounting: one gas short refuses and
// consumes everything; anything at or above the price leaves the surplus.
func TestRunDebitsExactlyRequiredGas(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"adopt", adoptInput(beluga, weightV1, 1)},
		{"getApproved", getApprovedInput(beluga)},
		{"isAdmin", isAdminInput(govA)},
		{"setAdmin", setAdminInput(govB, true)},
		{"unknown selector", sel(selectorUnknown)},
		{"short input", []byte{0x01}},
		{"truncated adopt body", truncate(SelectorAdopt, 95)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			need := ModelRegistryPrecompile.RequiredGas(tc.in)
			require.Positive(t, need)

			// One gas short: refused, no gas returned, nothing written.
			st, acc := seeded(t, govA)
			before := st.snap()
			ret, remaining, err := ModelRegistryPrecompile.Run(
				acc, govA, ContractAddress, tc.in, need-1, false)
			require.ErrorContains(t, err, "out of gas")
			require.Nil(t, ret)
			require.Zero(t, remaining)
			require.Zero(t, st.writes, "an out-of-gas call still wrote state")
			require.Equal(t, before, st.snap())

			// Exactly the price: the call is decided on its merits and the whole
			// supply is consumed.
			_, acc = seeded(t, govA)
			_, remaining, _ = ModelRegistryPrecompile.Run(
				acc, govA, ContractAddress, tc.in, need, false)
			require.Zero(t, remaining)

			// Surplus is returned untouched, whether the call succeeds or is
			// refused after the gas check.
			_, acc = seeded(t, govA)
			_, remaining, _ = ModelRegistryPrecompile.Run(
				acc, govA, ContractAddress, tc.in, need+1234, false)
			require.Equal(t, uint64(1234), remaining)
		})
	}
}

// ---------------------------------------------------------------------------
// storage layout
// ---------------------------------------------------------------------------

// TestStateKeysAreStable pins the storage layout. These slots are consensus:
// a live chain's governance set and adopted models sit at exactly these
// addresses, so changing the hash, a domain prefix, or the argument order
// relocates every existing entry to a slot nothing reads. That failure is
// silent — the registry would come back from the upgrade with no admins and no
// adopted model, and no error anywhere. Change these values only as a
// deliberate, migrated hard fork.
func TestStateKeysAreStable(t *testing.T) {
	require.Equal(t,
		common.HexToHash("0x1b008afa4aa1ed15a87c1c0a6811b61d26d57c311d618395d3892b1ee4ebc119"),
		adminKey(govA))
	require.Equal(t,
		common.HexToHash("0x4d8cb13131d6a12dff452503f667e4dd4d65433ae656738a58f24cba0579729d"),
		verKey(beluga))
	require.Equal(t,
		common.HexToHash("0xb0c71026c4b8bc2ef8f1ab3b0beda93d82b007d628336ceb8463aceaf62603fc"),
		weightKey(beluga))

	// The three domains are separated: the same bytes read as an address and as
	// a model name never land in the same slot, so adopting a model can never
	// mint an admin and promoting an admin can never publish weights.
	asName := common.BytesToHash(govA.Bytes())
	slots := []common.Hash{adminKey(govA), verKey(asName), weightKey(asName)}
	for i := range slots {
		for j := i + 1; j < len(slots); j++ {
			require.NotEqual(t, slots[i], slots[j], "storage domains %d and %d collide", i, j)
		}
	}

	// Distinct subjects get distinct slots.
	require.NotEqual(t, adminKey(govA), adminKey(govB))
	require.NotEqual(t, verKey(beluga), verKey(weightV1))
	require.NotEqual(t, weightKey(beluga), weightKey(weightV1))

	// enabledHash is a non-zero word, which is the whole test IsAdmin applies.
	require.NotEqual(t, common.Hash{}, enabledHash)
}

func TestAdoptIsPerModelName(t *testing.T) {
	_, acc := seeded(t, govA)
	other := common.HexToHash("0x02")

	_, err := run(acc, govA, adoptInput(beluga, weightV1, 1), false)
	require.NoError(t, err)
	_, err = run(acc, govA, adoptInput(other, weightV2, 2), false)
	require.NoError(t, err)

	ver, weight := adopted(t, acc, beluga)
	require.Equal(t, uint64(1), binary.BigEndian.Uint64(ver[24:32]))
	require.Equal(t, weightV1, weight)

	ver, weight = adopted(t, acc, other)
	require.Equal(t, uint64(2), binary.BigEndian.Uint64(ver[24:32]))
	require.Equal(t, weightV2, weight)

	// An unadopted name reads as empty, which is how a caller tells "no brain
	// chosen yet" from "this one".
	ver, weight = adopted(t, acc, common.HexToHash("0x03"))
	require.Equal(t, common.Hash{}, ver)
	require.Equal(t, common.Hash{}, weight)

	// The admin flag and the model slots cannot collide: adopting a model whose
	// name is an admin address must not confer or revoke adminship.
	nameOfAdmin := common.BytesToHash(govA.Bytes())
	_, err = run(acc, govA, adoptInput(nameOfAdmin, weightV2, 7), false)
	require.NoError(t, err)
	require.True(t, IsAdmin(acc.s, govA))
	require.False(t, IsAdmin(acc.s, govB))
}

// TestGetApprovedNarrowsTheVersionWord records that the two read paths disagree
// above 2^64: the ABI returns the full 32-byte word that was adopted, while the
// Go helper reports only its low 64 bits.
func TestGetApprovedNarrowsTheVersionWord(t *testing.T) {
	st, acc := seeded(t, govA)

	// A version word whose value does not fit in 64 bits.
	hiVersion := common.HexToHash("0x0000000000000000000000000000000000000001000000000000000000000000")
	in := append(append(sel(SelectorAdopt), beluga[:]...), append(hiVersion[:], weightV1[:]...)...)
	_, err := run(acc, govA, in, false)
	require.NoError(t, err)

	ver, weight := adopted(t, acc, beluga)
	require.Equal(t, hiVersion, ver, "the ABI must return the exact word that was adopted")
	require.Equal(t, weightV1, weight)

	v, w := GetApproved(st, beluga)
	require.Equal(t, weightV1, w)
	require.Zero(t, v, "GetApproved reports the low 64 bits only; callers must not "+
		"treat it as the full adopted version")

	// Inside 64 bits the two paths agree, which is the supported range.
	_, err = run(acc, govA, adoptInput(beluga, weightV2, 1<<40), false)
	require.NoError(t, err)
	v, w = GetApproved(st, beluga)
	require.Equal(t, uint64(1)<<40, v)
	require.Equal(t, weightV2, w)
}

// TestSetAdminTreatsAnyNonZeroWordAsTrue pins the bool decoding: Solidity sends
// 0 or 1, but the handler accepts any non-zero word as "enable" rather than
// rejecting a non-canonical encoding.
func TestSetAdminTreatsAnyNonZeroWordAsTrue(t *testing.T) {
	st, acc := seeded(t, govA)

	enable := make([]byte, 32)
	enable[0] = 0x02 // non-canonical true, high byte set
	in := append(append(sel(SelectorSetAdmin), word(govB.Bytes())...), enable...)
	_, err := run(acc, govA, in, false)
	require.NoError(t, err)
	require.True(t, IsAdmin(st, govB))

	// The address is decoded from the low 20 bytes; the 12 padding bytes are
	// ignored rather than rejected.
	padded := append(append(sel(SelectorIsAdmin), make([]byte, 12)...), govB.Bytes()...)
	padded[4] = 0xFF
	ret, err := run(acc, outsider, padded, true)
	require.NoError(t, err)
	require.Equal(t, byte(1), ret[31])
}
