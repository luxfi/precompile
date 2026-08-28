// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"reflect"
	"strings"
	"testing"

	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// TestConfig_ConstructorsCarryTheirUpgrade proves the two constructors differ in exactly
// the field that names them, and that neither invents a schedule of its own.
func TestConfig_ConstructorsCarryTheirUpgrade(t *testing.T) {
	ts := uint64(1_700_000_000)

	enable := NewConfig(&ts)
	require.Equal(t, &ts, enable.Timestamp())
	require.False(t, enable.IsDisabled(), "NewConfig must schedule an activation")

	disable := NewDisableConfig(&ts)
	require.Equal(t, &ts, disable.Timestamp())
	require.True(t, disable.IsDisabled(), "NewDisableConfig must schedule a deactivation")

	// Same instant, opposite intent: the two are not equal.
	require.False(t, enable.Equal(disable))
	require.False(t, disable.Equal(enable))

	// An unscheduled config has no timestamp, so it is never enabled.
	require.Nil(t, NewConfig(nil).Timestamp())
}

// TestConfig_KeyMatchesTheModule proves the config answers to the key the module is
// registered under. If they drifted, an upgrade.json entry would parse and then never be
// found — the precompile would silently never activate.
func TestConfig_KeyMatchesTheModule(t *testing.T) {
	require.Equal(t, ConfigKey, (&Config{}).Key())
	require.Equal(t, Module.ConfigKey, (&Config{}).Key())
	require.Equal(t, ConfigKey, (&configurator{}).MakeConfig().Key())
}

// TestConfig_MakeConfigIsFreshEachTime proves MakeConfig hands back a distinct zero value.
// A shared instance would let one upgrade entry's fields leak into the next as the chain
// config is unmarshalled.
func TestConfig_MakeConfigIsFreshEachTime(t *testing.T) {
	c := &configurator{}

	first, ok := c.MakeConfig().(*Config)
	require.True(t, ok, "MakeConfig must produce the type Configure asserts on")
	require.Equal(t, Config{}, *first, "MakeConfig must not pre-populate anything")

	first.NetworkKeyPath = "/tmp/leaked"
	second, ok := c.MakeConfig().(*Config)
	require.True(t, ok)
	require.Empty(t, second.NetworkKeyPath, "MakeConfig must not share state between calls")
	require.NotSame(t, first, second)
}

// TestConfig_VerifyAcceptsEveryWellFormedShape pins that Verify imposes no extra
// requirements: the activation constraint lives in Configure, where the chain's gas limit
// is actually known, and duplicating it here would be a second place to keep in step.
func TestConfig_VerifyAcceptsEveryWellFormedShape(t *testing.T) {
	ts := uint64(1)
	for _, c := range []*Config{
		{},
		NewConfig(nil),
		NewConfig(&ts),
		NewDisableConfig(&ts),
		{NetworkKeyPath: "/keys/net", CoprocessorEndpoint: "https://f-chain"},
	} {
		require.NoError(t, c.Verify(nil))
	}
}

// TestConfig_EqualComparesEveryField mutates one field at a time and asserts equality
// breaks in both directions. The reflection guard fails the day a field is added without
// Equal being taught about it — the way an upgrade comparison silently goes blind.
func TestConfig_EqualComparesEveryField(t *testing.T) {
	ts := uint64(42)
	base := func() *Config {
		return &Config{
			Upgrade:             precompileconfig.Upgrade{BlockTimestamp: &ts},
			NetworkKeyPath:      "/keys/net",
			CoprocessorEndpoint: "https://f-chain",
		}
	}

	require.True(t, base().Equal(base()), "identical configs must compare equal")

	mutations := map[string]func(*Config){
		"NetworkKeyPath":      func(c *Config) { c.NetworkKeyPath = "/keys/other" },
		"CoprocessorEndpoint": func(c *Config) { c.CoprocessorEndpoint = "https://elsewhere" },
		"Upgrade.Disable":     func(c *Config) { c.Disable = true },
		"Upgrade.BlockTimestamp": func(c *Config) {
			other := ts + 1
			c.BlockTimestamp = &other
		},
		"Upgrade.BlockTimestamp unset": func(c *Config) { c.BlockTimestamp = nil },
	}

	// Every field of Config and of the Upgrade it embeds must be represented above, or
	// Equal has a dimension nothing tests. Counting distinct field names rather than
	// mutations lets one field carry several mutations (a timestamp can change or be
	// unset) without loosening the guard.
	covered := map[string]bool{}
	for name := range mutations {
		covered[strings.Fields(name)[0]] = true
	}
	own := reflect.TypeOf(Config{}).NumField() - 1 // minus the embedded Upgrade
	require.Equal(t, own+reflect.TypeOf(precompileconfig.Upgrade{}).NumField(), len(covered),
		"Config or Upgrade gained a field; extend the mutation table and check Equal covers it")

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := base()
			mutate(changed)
			require.False(t, base().Equal(changed), "%s must break equality", name)
			require.False(t, changed.Equal(base()), "%s must break equality both ways", name)

			// Applying the same mutation to both sides restores equality, proving Equal
			// reacted to the difference and not merely to the mutation happening.
			both := base()
			mutate(both)
			require.True(t, both.Equal(changed))
		})
	}

	// Timestamps compare by value, not pointer identity.
	a, b := base(), base()
	sameInstant := ts
	b.BlockTimestamp = &sameInstant
	require.True(t, a.Equal(b), "equal instants held in different pointers must compare equal")
}

// TestConfig_EqualRejectsForeignConfigs proves a config of another type is never equal,
// however identical its upgrade schedule.
func TestConfig_EqualRejectsForeignConfigs(t *testing.T) {
	ts := uint64(7)
	c := NewConfig(&ts)

	require.False(t, c.Equal(nil), "an untyped nil is not a *Config")
	require.False(t, c.Equal(foreignConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}),
		"only the type separates two configs with identical schedules")
}

// foreignConfig is a different precompile's config carrying the same upgrade.
type foreignConfig struct {
	precompileconfig.Upgrade
}

func (foreignConfig) Key() string                               { return "notFHE" }
func (foreignConfig) Verify(precompileconfig.ChainConfig) error { return nil }
func (foreignConfig) Equal(cfg precompileconfig.Config) bool    { return false }
func (f foreignConfig) Timestamp() *uint64                      { return f.Upgrade.Timestamp() }
func (f foreignConfig) IsDisabled() bool                        { return f.Upgrade.Disable }

var _ precompileconfig.Config = foreignConfig{}

// TestModule_RegistersTheSingletonAtItsOwnAddress proves init actually registered the
// module, that the registered contract is the singleton the package exports, and that the
// address is not one of the sibling addresses declared alongside it.
func TestModule_RegistersTheSingletonAtItsOwnAddress(t *testing.T) {
	require.Equal(t, ContractAddress, Module.Address)
	require.Same(t, FHEPrecompile, Module.Contract)
	require.NotNil(t, Module.Configurator)

	for name, addr := range map[string]interface{ Hex() string }{
		"ACL":           ACLContractAddress,
		"InputVerifier": InputVerifierAddress,
		"Gateway":       GatewayContractAddress,
	} {
		require.NotEqualf(t, ContractAddress.Hex(), addr.Hex(),
			"the %s address must not collide with the precompile's own", name)
	}
}

// TestDoSAuditRow_PredicateAtTheBudgetBoundary pins the audit predicate itself rather than
// the numbers in the table: a row is safe exactly while (gasLimit / gasPerOp) x perOpMs
// stays inside the per-block compute budget, and it flips at the boundary.
func TestDoSAuditRow_PredicateAtTheBudgetBoundary(t *testing.T) {
	// One op per block, costing exactly the budget: safe. One millisecond more: not.
	row := DoSAuditRow{GasPerOp: 1_000, PerOpMs: BlockComputeBudgetMs}
	require.True(t, row.IsSafeAtGasLimit(1_000), "exactly the budget is within it")
	require.False(t, row.IsSafeAtGasLimit(2_000), "two ops at the full budget exceed it")

	// Cheaper ops fit more per block, so raising the gas limit can flip a row unsafe.
	cheap := DoSAuditRow{GasPerOp: 100, PerOpMs: 1}
	require.True(t, cheap.IsSafeAtGasLimit(100*BlockComputeBudgetMs))
	require.False(t, cheap.IsSafeAtGasLimit(100*BlockComputeBudgetMs+100))

	// An unconfigured row (no gas declared) is EXCLUDED from the audit rather than failing
	// it — the predicate has no opinion where there is no price. That is fail-open: a row
	// added to the table without a gas figure passes silently.
	require.True(t, DoSAuditRow{}.IsSafeAtGasLimit(1),
		"a row with no declared gas is excluded from the audit")

	// Every row actually in the table does declare a price, so none of them is riding
	// that exclusion today.
	for _, r := range DoSAuditTable {
		require.NotZerof(t, r.GasPerOp, "%s has no declared gas and would skip the audit", r.Precompile)
	}
}
