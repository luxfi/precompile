// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"strings"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/precompileconfig"
)

// TestDexConfigure_NoProtocolFeeController_RejectsActivation verifies that
// Configure() refuses to activate the DEX precompile when the upgrade.json
// dexConfig omits protocolFeeController (or sets it to the zero address).
//
// Regression: before this guard, omitting the field defaulted to the Foundry
// Anvil account #0 (0xf39Fd6...92266) whose private key is in every Foundry
// installation. That left PauseDEX / ResumeDEX / FreezePool callable by any
// caller — a chain-wide AMM compromise at activation.
func TestDexConfigure_NoProtocolFeeController_RejectsActivation(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
	}{
		{
			name: "zero-address protocolFeeController",
			cfg: &Config{
				ProtocolFeeController: common.Address{},
			},
		},
		{
			name: "no protocolFeeController field at all",
			cfg:  &Config{},
		},
	}

	cfgr := &configurator{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := cfgr.Configure(nil, tc.cfg, nil, nil)
			if !errors.Is(err, ErrDEXNoProtocolFeeController) {
				t.Fatalf("expected ErrDEXNoProtocolFeeController, got: %v", err)
			}
		})
	}
}

// TestDexConfigure_AnvilDefault_RejectsActivation verifies that any of the
// well-known Foundry/Anvil deterministic dev accounts is rejected as the
// protocolFeeController. These addresses' private keys are public knowledge,
// so configuring one as the chain's AMM admin would be a chain-wide
// compromise. The blocklist lives in dex/module.go::compromisedDevControllers
// and must catch each of them.
func TestDexConfigure_AnvilDefault_RejectsActivation(t *testing.T) {
	anvilAccounts := []string{
		"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", // anvil #0
		"0x70997970C51812dc3A010C7d01b50e0d17dc79C8", // anvil #1
		"0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", // anvil #2
		"0x90F79bf6EB2c4f870365E785982E1f101E93b906", // anvil #3
		"0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65", // anvil #4
		"0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc", // anvil #5
		"0x976EA74026E726554dB657fA54763abd0C3a0aa9", // anvil #6
		"0x14dC79964da2C08b23698B3D3cc7Ca32193d9955", // anvil #7
		"0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f", // anvil #8
		"0xa0Ee7A142d267C1f36714E4a8F75612F20a79720", // anvil #9
	}

	cfgr := &configurator{}
	for _, addr := range anvilAccounts {
		t.Run(addr, func(t *testing.T) {
			cfg := &Config{
				ProtocolFeeController: common.HexToAddress(addr),
			}
			err := cfgr.Configure(nil, cfg, nil, nil)
			if !errors.Is(err, ErrDEXCompromisedController) {
				t.Fatalf("expected ErrDEXCompromisedController for %s, got: %v", addr, err)
			}
			// The error message should include the offending address so
			// operators can see exactly what they put in upgrade.json.
			if !strings.Contains(err.Error(), addr) && !strings.Contains(err.Error(), strings.ToLower(addr)) {
				// Address.Hex() uses checksum casing, accept either.
				expectedChecksum := common.HexToAddress(addr).Hex()
				if !strings.Contains(err.Error(), expectedChecksum) {
					t.Errorf("error should include the offending address; got: %v", err)
				}
			}
		})
	}
}

// TestDexConfigure_RealAddress_ActivatesCleanly verifies that a real (non-
// dev-key) protocolFeeController activates the precompile without error.
// We use the LUX_MNEMONIC-derived treasury 0x9011E888...4714 as the canonical
// transitional placeholder (KMS-controlled, not publicly known).
func TestDexConfigure_RealAddress_ActivatesCleanly(t *testing.T) {
	cfgr := &configurator{}

	// Reset singleton state to be hermetic — Configure() mutates the
	// singleton PoolManager's protocolFeeController. Save+restore.
	origController := DEXPrecompile.poolManager.protocolFeeController
	t.Cleanup(func() {
		DEXPrecompile.poolManager.protocolFeeController = origController
	})

	realAddr := common.HexToAddress("0x9011E888251AB053B7bD1cdB598Db4f9DEd94714")
	cfg := &Config{ProtocolFeeController: realAddr}

	if err := cfgr.Configure(nil, cfg, nil, nil); err != nil {
		t.Fatalf("Configure with real address should succeed, got: %v", err)
	}
	if DEXPrecompile.poolManager.protocolFeeController != realAddr {
		t.Fatalf(
			"singleton controller not updated: got %s, want %s",
			DEXPrecompile.poolManager.protocolFeeController.Hex(), realAddr.Hex(),
		)
	}
}

// TestDexAdmin_OnlyConfiguredController verifies that admin functions
// (PauseDEX, ResumeDEX, PausePool, ResumePool, FreezePool) refuse unauthorized
// callers — only the address configured as protocolFeeController is allowed.
// This complements the activation-time guard: even if a real controller is
// configured, a random EVM caller cannot exercise the admin surface.
func TestDexAdmin_OnlyConfiguredController(t *testing.T) {
	configured := common.HexToAddress("0x9011E888251AB053B7bD1cdB598Db4f9DEd94714")
	random := common.HexToAddress("0xBADBADBADBADBADBADBADBADBADBADBADBADBADB")

	pm := NewPoolManager(&mockEngine{})
	pm.protocolFeeController = configured
	stateDB := NewMockStateDB()

	// Initialize a pool so freeze/pause-pool have a target.
	keyAB, poolID, _, _ := initTwoPoolsPF(t, pm, stateDB)
	_ = keyAB

	// Each admin call by `random` must return ErrUnauthorized.
	cases := []struct {
		name string
		fn   func() error
	}{
		{"PauseDEX", func() error { return pm.PauseDEX(stateDB, random) }},
		{"ResumeDEX", func() error { return pm.ResumeDEX(stateDB, random) }},
		{"PausePool", func() error { return pm.PausePool(stateDB, random, poolID) }},
		{"ResumePool", func() error { return pm.ResumePool(stateDB, random, poolID) }},
		{"FreezePool", func() error { return pm.FreezePool(stateDB, random, poolID) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fn(); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("expected ErrUnauthorized for random caller on %s, got: %v", tc.name, err)
			}
		})
	}

	// And the configured controller can pause/resume successfully.
	if err := pm.PauseDEX(stateDB, configured); err != nil {
		t.Fatalf("configured controller PauseDEX should succeed, got: %v", err)
	}
	if err := pm.ResumeDEX(stateDB, configured); err != nil {
		t.Fatalf("configured controller ResumeDEX should succeed, got: %v", err)
	}
}

// TestDexConfig_MakeConfigReturnsConfig verifies the configurator returns the
// canonical Config type, so JSON unmarshalling produces a struct whose
// ProtocolFeeController field is populated from `protocolFeeController` in
// upgrade.json (the field the operator must set).
func TestDexConfig_MakeConfigReturnsConfig(t *testing.T) {
	cfg := (&configurator{}).MakeConfig()
	if _, ok := cfg.(*Config); !ok {
		t.Fatalf("MakeConfig should return *Config, got %T", cfg)
	}
	// Confirm the interface compliance is preserved.
	var _ precompileconfig.Config = (*Config)(nil)
}
