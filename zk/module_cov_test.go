// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"encoding/json"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helpers (all prefixed mod)
// ---------------------------------------------------------------------------

// modOther is a second, unrelated Config implementation. Equal must reject it
// even when its upgrade window is identical.
type modOther struct {
	Upgrade precompileconfig.Upgrade
}

func (c *modOther) Key() string                               { return "modOtherConfig" }
func (c *modOther) Timestamp() *uint64                        { return c.Upgrade.Timestamp() }
func (c *modOther) IsDisabled() bool                          { return c.Upgrade.Disable }
func (c *modOther) Verify(precompileconfig.ChainConfig) error { return nil }
func (c *modOther) Equal(precompileconfig.Config) bool        { return false }

var _ precompileconfig.Config = (*modOther)(nil)

// modAt builds a Config enabled at the given timestamp.
func modAt(ts uint64) *Config {
	return &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
}

// modDisabled builds a Config enabled at the given timestamp and switched off.
func modDisabled(ts uint64) *Config {
	c := modAt(ts)
	c.Upgrade.Disable = true
	return c
}

// ---------------------------------------------------------------------------
// registration
// ---------------------------------------------------------------------------

func TestMod_ModuleIsRegisteredAtItsAddress(t *testing.T) {
	got, ok := modules.GetPrecompileModuleByAddress(ZKVerifyContractAddress)
	require.True(t, ok, "init must have registered the module at 0x0900…00")
	require.Equal(t, ConfigKey, got.ConfigKey)
	require.Equal(t, ZKVerifyContractAddress, got.Address)
	require.Same(t, ZKVerifyPrecompile, got.Contract, "the registered contract is the package singleton")
	require.NotNil(t, got.Configurator)
	require.False(t, got.AlwaysOn, "the ZK precompile activates from a config, not unconditionally")

	// Lookup by key agrees with lookup by address.
	byKey, ok := modules.GetPrecompileModule(ConfigKey)
	require.True(t, ok)
	require.Equal(t, got.Address, byKey.Address)
	require.Same(t, got.Contract, byKey.Contract)

	// The declared package var is what was registered.
	require.Equal(t, Module.ConfigKey, got.ConfigKey)
	require.Equal(t, Module.Address, got.Address)

	// And it sits inside the reserved precompile space, which is why
	// RegisterModule accepted it.
	require.True(t, modules.ReservedAddress(ZKVerifyContractAddress))

	// Nothing else claimed the same address or key.
	count := 0
	for _, m := range modules.RegisteredModules() {
		if m.Address == ZKVerifyContractAddress || m.ConfigKey == ConfigKey {
			count++
		}
	}
	require.Equal(t, 1, count)
}

func TestMod_AddressesAreDistinctAndInRange(t *testing.T) {
	// Every declared address must be unique, or two features would answer at
	// the same call target.
	declared := map[string]string{
		"zkVerify":     ZKVerifyContractAddress.Hex(),
		"groth16":      Groth16ContractAddress.Hex(),
		"plonk":        PlonkContractAddress.Hex(),
		"fflonk":       FflonkContractAddress.Hex(),
		"halo2":        Halo2ContractAddress.Hex(),
		"kzg":          KZGContractAddress.Hex(),
		"ipa":          IPAContractAddress.Hex(),
		"privacyPool":  PrivacyPoolContractAddress.Hex(),
		"nullifier":    NullifierContractAddress.Hex(),
		"commitment":   CommitmentContractAddress.Hex(),
		"rangeProof":   RangeProofContractAddress.Hex(),
		"rollupVerify": RollupVerifyContractAddress.Hex(),
		"stateRoot":    StateRootContractAddress.Hex(),
		"batchProof":   BatchProofContractAddress.Hex(),
	}
	seen := map[string]string{}
	for name, hex := range declared {
		prev, dup := seen[hex]
		require.Falsef(t, dup, "%s and %s share address %s", prev, name, hex)
		seen[hex] = name
	}
	require.Len(t, seen, len(declared))

	// Only the entry point is registered; the other addresses are documentary
	// and answer nothing, so a call to one of them is not a ZK call.
	for name, hex := range declared {
		if name == "zkVerify" {
			continue
		}
		require.NotEqual(t, ZKVerifyContractAddress.Hex(), hex)
		_, ok := modules.GetPrecompileModuleByAddress(common.HexToAddress(hex))
		require.Falsef(t, ok, "%s is declared but not registered", name)
	}
}

// ---------------------------------------------------------------------------
// configurator
// ---------------------------------------------------------------------------

func TestMod_MakeConfigHandsBackAFreshUsableConfig(t *testing.T) {
	c := &configurator{}

	got := c.MakeConfig()
	require.NotNil(t, got)
	require.IsType(t, &Config{}, got)

	// Zero-valued: never enabled, not disabled.
	require.Nil(t, got.Timestamp(), "a fresh config names no activation time")
	require.False(t, got.IsDisabled())
	require.Equal(t, ConfigKey, got.Key())

	// Fresh each call, so two chains being configured cannot share state.
	other := c.MakeConfig()
	require.NotSame(t, got, other)
	got.(*Config).Upgrade.Disable = true
	require.False(t, other.IsDisabled())

	// The registered configurator behaves the same as a bare one.
	m, ok := modules.GetPrecompileModuleByAddress(ZKVerifyContractAddress)
	require.True(t, ok)
	require.IsType(t, &Config{}, m.MakeConfig())
}

func TestMod_ConfigureTouchesNothing(t *testing.T) {
	c := &configurator{}

	// The precompile keeps no state, so Configure must succeed without
	// reading or writing any of its arguments. Handing it nothing proves it.
	require.NoError(t, c.Configure(nil, nil, nil, nil))
	require.NoError(t, c.Configure(nil, c.MakeConfig(), nil, nil))
	require.NoError(t, c.Configure(nil, modAt(7), nil, nil))
	require.NoError(t, c.Configure(nil, &modOther{}, nil, nil),
		"Configure does not inspect the config, so even a foreign one passes")

	// Same through the registered module.
	m, ok := modules.GetPrecompileModuleByAddress(ZKVerifyContractAddress)
	require.True(t, ok)
	require.NoError(t, m.Configure(nil, m.MakeConfig(), nil, nil))
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

func TestMod_ConfigKeyIsTheRegistrationKey(t *testing.T) {
	require.Equal(t, ConfigKey, (&Config{}).Key())
	require.Equal(t, ConfigKey, modAt(9).Key())
	require.Equal(t, ConfigKey, modDisabled(9).Key())

	// The key a config reports is the key it is registered under, which is how
	// a chain config finds this precompile.
	m, ok := modules.GetPrecompileModule((&Config{}).Key())
	require.True(t, ok)
	require.Equal(t, ZKVerifyContractAddress, m.Address)
}

func TestMod_TimestampAndIsDisabledMirrorTheUpgrade(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cfg      *Config
		wantTS   *uint64
		disabled bool
	}{
		{"zero value is never enabled", &Config{}, nil, false},
		{"genesis", modAt(0), func() *uint64 { v := uint64(0); return &v }(), false},
		{"future", modAt(1 << 40), func() *uint64 { v := uint64(1 << 40); return &v }(), false},
		{"disabled at genesis", modDisabled(0), func() *uint64 { v := uint64(0); return &v }(), true},
		{"disabled later", modDisabled(99), func() *uint64 { v := uint64(99); return &v }(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.wantTS, tc.cfg.Timestamp())
			require.Equal(t, tc.disabled, tc.cfg.IsDisabled())

			// Not a copy: the config forwards the embedded upgrade's own
			// answers, so mutating the upgrade is visible through the config.
			require.Equal(t, tc.cfg.Upgrade.Timestamp(), tc.cfg.Timestamp())
			require.Equal(t, tc.cfg.Upgrade.IsDisabled(), tc.cfg.IsDisabled())
		})
	}

	// A nil timestamp and a zero timestamp are different states: never
	// enabled versus enabled from genesis.
	require.Nil(t, (&Config{}).Timestamp())
	require.NotNil(t, modAt(0).Timestamp())

	c := modAt(5)
	*c.Upgrade.BlockTimestamp = 6
	require.EqualValues(t, 6, *c.Timestamp())
	c.Upgrade.Disable = true
	require.True(t, c.IsDisabled())
}

func TestMod_Equal(t *testing.T) {
	ts5a, ts5b := modAt(5), modAt(5)

	for _, tc := range []struct {
		name  string
		a     *Config
		b     precompileconfig.Config
		equal bool
	}{
		{"same zero value", &Config{}, &Config{}, true},
		{"itself", ts5a, ts5a, true},
		{"same timestamp, different pointers", ts5a, ts5b, true},
		{"same disabled state", modDisabled(5), modDisabled(5), true},

		{"different timestamp", modAt(5), modAt(6), false},
		{"timestamp against none", modAt(5), &Config{}, false},
		{"none against timestamp", &Config{}, modAt(5), false},
		{"genesis against never", modAt(0), &Config{}, false},
		{"same timestamp, different disable flag", modAt(5), modDisabled(5), false},
		{"disable flag alone", &Config{Upgrade: precompileconfig.Upgrade{Disable: true}}, &Config{}, false},

		{"a different config type", &Config{}, &modOther{}, false},
		{"a different config type with the same upgrade", modAt(5), &modOther{Upgrade: precompileconfig.Upgrade{BlockTimestamp: func() *uint64 { v := uint64(5); return &v }()}}, false},
		{"a nil interface", &Config{}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.equal, tc.a.Equal(tc.b))
		})
	}

	// Symmetric wherever both sides are *Config.
	for _, pair := range [][2]*Config{
		{modAt(5), modAt(6)},
		{modAt(5), modAt(5)},
		{&Config{}, modAt(0)},
		{modAt(5), modDisabled(5)},
	} {
		require.Equal(t, pair[0].Equal(pair[1]), pair[1].Equal(pair[0]), "Equal must be symmetric")
	}

	// Every timestamp is distinguishable from every other.
	for i := range uint64(8) {
		for j := range uint64(8) {
			require.Equalf(t, i == j, modAt(i).Equal(modAt(j)), "%d vs %d", i, j)
		}
	}
}

func TestMod_EqualPanicsOnATypedNilConfig(t *testing.T) {
	// An untyped nil misses the type assertion and is refused. A typed
	// (*Config)(nil) passes the assertion and is then dereferenced, so the
	// two spellings of "no config" behave completely differently.
	require.False(t, (&Config{}).Equal(nil))
	require.Panics(t, func() { (&Config{}).Equal((*Config)(nil)) })
}

func TestMod_VerifyAcceptsEveryConfig(t *testing.T) {
	// Verify is called on startup and a returned error is fatal. This
	// precompile takes no parameters, so nothing can be misconfigured and it
	// accepts unconditionally, including with no chain config to inspect.
	for _, cfg := range []*Config{
		{},
		modAt(0),
		modAt(1 << 40),
		modDisabled(0),
	} {
		require.NoError(t, cfg.Verify(nil))
	}

	// Verified configs stay usable: Verify has no side effect.
	c := modAt(5)
	before := *c.Upgrade.BlockTimestamp
	require.NoError(t, c.Verify(nil))
	require.Equal(t, before, *c.Upgrade.BlockTimestamp)
	require.True(t, c.Equal(modAt(5)))
}

func TestMod_ConfigRoundTripsThroughJSON(t *testing.T) {
	// The config is what a chain's genesis or upgrade file decodes into, so
	// the json tags are load-bearing.
	cfg := (&configurator{}).MakeConfig()
	require.NoError(t, json.Unmarshal([]byte(`{"upgrade":{"blockTimestamp":7}}`), cfg))
	require.NotNil(t, cfg.Timestamp())
	require.EqualValues(t, 7, *cfg.Timestamp())
	require.False(t, cfg.IsDisabled())
	require.Equal(t, ConfigKey, cfg.Key())
	require.True(t, cfg.Equal(modAt(7)))

	off := (&configurator{}).MakeConfig()
	require.NoError(t, json.Unmarshal([]byte(`{"upgrade":{"blockTimestamp":7,"disable":true}}`), off))
	require.True(t, off.IsDisabled())
	require.False(t, cfg.Equal(off), "the same window with the disable flag set is a different config")

	// An empty document leaves a config that never activates.
	empty := (&configurator{}).MakeConfig()
	require.NoError(t, json.Unmarshal([]byte(`{}`), empty))
	require.Nil(t, empty.Timestamp())
	require.False(t, empty.IsDisabled())

	// And it re-encodes to something that decodes back to itself.
	encoded, err := json.Marshal(cfg)
	require.NoError(t, err)
	decoded := (&configurator{}).MakeConfig()
	require.NoError(t, json.Unmarshal(encoded, decoded))
	require.True(t, cfg.Equal(decoded))
}

// ---------------------------------------------------------------------------
// what is wired to the EVM, and what is not
// ---------------------------------------------------------------------------

func TestMod_OnlyTheZKVerifyContractIsReachableFromTheEVM(t *testing.T) {
	// A type reaches the EVM only by satisfying StatefulPrecompiledContract
	// and being registered. zkVerifyPrecompile does both.
	var registered any = ZKVerifyPrecompile
	_, ok := registered.(contract.StatefulPrecompiledContract)
	require.True(t, ok)

	// The three RequiredGas methods on STARKVerifier, Poseidon2Scheme and
	// PedersenScheme are not precompile gas functions: none of those types has
	// a Run method, so none can be registered, and none is. They are library
	// pricing helpers with no caller in this module.
	for _, orphan := range []struct {
		name string
		v    any
	}{
		{"STARKVerifier", &STARKVerifier{}},
		{"Poseidon2Scheme", NewPoseidon2Scheme()},
		{"PedersenScheme", NewPedersenScheme()},
	} {
		_, isContract := orphan.v.(contract.StatefulPrecompiledContract)
		require.Falsef(t, isContract, "%s must not silently become a precompile", orphan.name)
	}

	// Go's type checker makes the stronger statement: a type switch on
	// m.Contract with those three cases does not compile ("impossible type
	// switch case ... missing method Run"), so no module in any binary can
	// hold one. What remains to check is that this package registered exactly
	// one contract, and that it is the one with a Run method.
	registeredHere := 0
	for _, m := range modules.RegisteredModules() {
		if m.ConfigKey == ConfigKey {
			registeredHere++
			require.Same(t, ZKVerifyPrecompile, m.Contract)
		}
	}
	require.Equal(t, 1, registeredHere, "one config key, one contract, one address")
}
