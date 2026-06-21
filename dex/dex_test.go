// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/modules"
)

// 0x9010 is REMOVED as a callable precompile (no Run, not registered, no forward).
// 0x9999 is the SOLE canonical DEX precompile and takes NO per-net config: its
// settlement-governance authority (protocolFeeController) is the built-in
// DefaultDAOTreasury, fixed across every network. There is therefore no
// activation-time controller config to misconfigure — the compromised-dev-key class
// of footgun is structurally eliminated. These tests pin that new model.

var lxPoolAddr9010 = common.HexToAddress(LXPoolAddress)

// anvilDevAccounts are the well-known Foundry/Anvil deterministic dev accounts whose
// private keys are public knowledge. The 0x9999 built-in controller must never be one
// of them (settle_module.go DefaultDAOTreasury).
var anvilDevAccounts = []common.Address{
	common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), // anvil #0
	common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"), // anvil #1
	common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"), // anvil #2
	common.HexToAddress("0x90F79bf6EB2c4f870365E785982E1f101E93b906"), // anvil #3
	common.HexToAddress("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"), // anvil #4
	common.HexToAddress("0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc"), // anvil #5
	common.HexToAddress("0x976EA74026E726554dB657fA54763abd0C3a0aa9"), // anvil #6
	common.HexToAddress("0x14dC79964da2C08b23698B3D3cc7Ca32193d9955"), // anvil #7
	common.HexToAddress("0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f"), // anvil #8
	common.HexToAddress("0xa0Ee7A142d267C1f36714E4a8F75612F20a79720"), // anvil #9
}

// TestDex9010_NotRegistered asserts 0x9010 is NOT a registered precompile — it has no
// module, so the EVM never dispatches it and eth_getCode(0x9010) is 0x. 0x9999 IS
// registered and is the sole DEX money path.
func TestDex9010_NotRegistered(t *testing.T) {
	if _, ok := modules.GetPrecompileModuleByAddress(lxPoolAddr9010); ok {
		t.Fatal("0x9010 must NOT be a registered precompile — it is removed; 0x9999 is the sole DEX precompile")
	}
	if _, ok := modules.GetPrecompileModuleByAddress(poolManagerAddr9999); !ok {
		t.Fatal("0x9999 must be the registered DEX precompile")
	}
}

// TestDex9999_DefaultControllerNotCompromised asserts the built-in 0x9999 settlement
// governance authority (DefaultDAOTreasury) is NOT one of the publicly-known dev keys.
// Because 0x9999 has no per-net controller config, this built-in value is the only
// admin and it must be safe by construction.
func TestDex9999_DefaultControllerNotCompromised(t *testing.T) {
	for _, bad := range anvilDevAccounts {
		if DefaultDAOTreasury == bad {
			t.Fatalf("0x9999 DefaultDAOTreasury must not be a publicly-known dev key: %s", bad.Hex())
		}
	}
	if DefaultDAOTreasury == (common.Address{}) {
		t.Fatal("0x9999 DefaultDAOTreasury must not be the zero address")
	}
	// The singleton 0x9999 contract must carry the built-in treasury as its authority.
	if SettlePrecompile.protocolFeeController != DefaultDAOTreasury {
		t.Fatalf("0x9999 protocolFeeController must be the built-in DefaultDAOTreasury, got %s",
			SettlePrecompile.protocolFeeController.Hex())
	}
}

// TestDexAdmin_OnlyConfiguredController verifies that the shared PoolManager admin
// functions (PauseDEX, ResumeDEX, PausePool, ResumePool, FreezePool) refuse
// unauthorized callers — only the configured protocolFeeController is allowed. This is
// the authorization gate 0x9999's halt/governance selectors rely on.
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
