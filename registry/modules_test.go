// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// The invariants that keep this package honest: it must actually link the
// precompiles it claims to link, and every answer it gives must be derived from
// the addresses those precompiles registered — never from a second table.
package registry_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/registry"
	"github.com/stretchr/testify/require"
)

// TestImportingRegistryRegistersPrecompiles is the reason a host writes
// `import _ "github.com/luxfi/precompile/registry"`. This test package imports
// registry and nothing else that registers, so if the blank imports inside
// registry.go were dropped the count would collapse.
func TestImportingRegistryRegistersPrecompiles(t *testing.T) {
	got := modules.RegisteredModules()
	require.Greater(t, len(got), 40,
		"importing registry must pull in the precompile set; got %d", len(got))
}

// TestEveryRegisteredAddressIsReserved — the module gate refuses an address
// outside reservedRanges, so a registration that got through proves the address
// is admissible. Restated here over the full linked set so a range narrowed in
// modules/ cannot orphan a live precompile.
func TestEveryRegisteredAddressIsReserved(t *testing.T) {
	var bad []string
	for _, m := range modules.RegisteredModules() {
		if !modules.ReservedAddress(m.Address) {
			bad = append(bad, fmt.Sprintf("%s at %s", m.ConfigKey, m.Address.Hex()))
		}
	}
	sort.Strings(bad)
	require.Empty(t, bad, "registered outside every reserved range:\n  %s", strings.Join(bad, "\n  "))
}

// TestNoAddressOrKeyCollisionsAcrossTheWholeLinkedSet is the property
// RegisterModule enforces one call at a time, restated over the whole set that
// a production binary actually links. Two precompiles at one address is a
// consensus split; two at one config key silently drops one from upgrade.json.
func TestNoAddressOrKeyCollisionsAcrossTheWholeLinkedSet(t *testing.T) {
	byAddr := map[common.Address]string{}
	byKey := map[string]common.Address{}
	for _, m := range modules.RegisteredModules() {
		if prev, dup := byAddr[m.Address]; dup {
			t.Fatalf("address %s claimed by %q and %q", m.Address.Hex(), prev, m.ConfigKey)
		}
		byAddr[m.Address] = m.ConfigKey

		if prev, dup := byKey[m.ConfigKey]; dup {
			t.Fatalf("config key %q claimed by %s and %s", m.ConfigKey, prev.Hex(), m.Address.Hex())
		}
		byKey[m.ConfigKey] = m.Address
	}
	require.Equal(t, len(byAddr), len(byKey))
}

// TestRegisteredModulesIsSortedAcrossTheWholeLinkedSet — the host relies on
// this ordering per block. Checking it on synthetic modules in the modules
// package is necessary; checking it on the real linked set is what matters.
func TestRegisteredModulesIsSortedAcrossTheWholeLinkedSet(t *testing.T) {
	got := modules.RegisteredModules()
	require.NotEmpty(t, got)
	for i := 1; i < len(got); i++ {
		require.Negative(t, bytesCompare(got[i-1].Address, got[i].Address),
			"registry out of order at %d: %s then %s", i, got[i-1].Address.Hex(), got[i].Address.Hex())
	}
}

func bytesCompare(a, b common.Address) int {
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}

// TestEveryRegisteredModuleIsUsable — a registered module with a nil Contract
// is an address the EVM will dispatch to and then nil-panic on. A nil
// Configurator on a module that is not AlwaysOn cannot be activated by config.
func TestEveryRegisteredModuleIsUsable(t *testing.T) {
	for _, m := range modules.RegisteredModules() {
		require.NotEmpty(t, m.ConfigKey, "%s registered with no config key", m.Address.Hex())
		require.NotNil(t, m.Contract, "%s (%s) registered with a nil Contract", m.ConfigKey, m.Address.Hex())
		if !m.AlwaysOn {
			require.NotNil(t, m.Configurator,
				"%s (%s) has no Configurator and is not AlwaysOn, so nothing can activate it",
				m.ConfigKey, m.Address.Hex())
		}
	}
}

// TestConfiguratorsMakeTheirOwnConfig — MakeConfig is how the host unmarshals
// upgrade.json into a precompile's config. Returning nil, or a config whose
// Key() disagrees with the module's ConfigKey, routes an operator's upgrade
// entry to the wrong precompile or to none.
func TestConfiguratorsMakeTheirOwnConfig(t *testing.T) {
	var bad []string
	for _, m := range modules.RegisteredModules() {
		if m.Configurator == nil {
			continue
		}
		cfg := m.MakeConfig()
		if cfg == nil {
			bad = append(bad, fmt.Sprintf("%s: MakeConfig returned nil", m.ConfigKey))
			continue
		}
		if got := cfg.Key(); got != m.ConfigKey {
			bad = append(bad, fmt.Sprintf(
				"%s at %s: MakeConfig().Key() is %q", m.ConfigKey, m.Address.Hex(), got))
		}
	}
	sort.Strings(bad)
	require.Empty(t, bad, "%d config-key mismatches:\n  %s", len(bad), strings.Join(bad, "\n  "))
}

// TestInFamilyAgreesWithTheRegistry — the derivation must not invent or drop
// members. Every family member is registered, and every registered PCII address
// whose page names a known family is in that family.
func TestInFamilyAgreesWithTheRegistry(t *testing.T) {
	families := []string{"PQ", "EVM", "Privacy", "Threshold", "Bridge", "AI", "DEX"}

	inSomeFamily := map[common.Address]bool{}
	for _, f := range families {
		members, ok := registry.InFamily(f)
		require.True(t, ok)
		for _, m := range members {
			got, found := modules.GetPrecompileModuleByAddress(m.Address)
			require.True(t, found, "%s is in family %s but not registered", m.Address.Hex(), f)
			require.Equal(t, got.ConfigKey, m.ConfigKey)
			inSomeFamily[m.Address] = true
		}
	}

	pageToFamily := map[uint8]string{}
	for _, f := range families {
		p, ok := registry.FamilyPage(f)
		require.True(t, ok)
		pageToFamily[p] = f
	}

	var missed []string
	for _, m := range modules.RegisteredModules() {
		a := m.Address
		// PCII addresses have 18 leading zero bytes.
		pcii := true
		for _, b := range a[:common.AddressLength-2] {
			if b != 0 {
				pcii = false
				break
			}
		}
		if !pcii {
			continue
		}
		page := a[common.AddressLength-2] >> 4
		if _, known := pageToFamily[page]; !known {
			continue
		}
		if !inSomeFamily[a] {
			missed = append(missed, fmt.Sprintf("%s at %s (page %d)", m.ConfigKey, a.Hex(), page))
		}
	}
	sort.Strings(missed)
	require.Empty(t, missed, "%d registered precompiles missing from their family:\n  %s",
		len(missed), strings.Join(missed, "\n  "))
}
