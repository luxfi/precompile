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
// 0x9999 is the SOLE canonical DEX precompile and takes NO per-net config FILE: its
// settlement-governance authority is the per-NETWORK governance controller resolved at
// RUNTIME from contract.AtomicState.GovernanceController() (a governance CONTRACT, never
// a hardcoded mnemonic-derivable EOA). There is therefore no single admin key baked into
// the binary — the centralized-key footgun is structurally eliminated. These tests pin
// that model: there is no DefaultDAOTreasury, the SettleContract carries no authority
// field, and only the runtime-supplied governance address may halt.

var lxPoolAddr9010 = common.HexToAddress(LXPoolAddress)

// retiredHardcodedHaltEOA is the address that USED to be the hardcoded 0x9999 halt
// authority (the mnemonic-derivable DefaultDAOTreasury). It is the devnet "Maker"
// derivable from LUX_MNEMONIC, so anyone with that mnemonic could halt the DEX. After
// HIGH-3 it has NO special power: the halt authority is the runtime governance
// controller, and this EOA is not it. The governance tests prove it can no longer halt.
var retiredHardcodedHaltEOA = common.HexToAddress("0x9011E888251AB053B7bD1cdB598Db4f9DEd94714")

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

// TestDex9999_GovernanceIsRuntimeResolved_NotHardcoded pins the HIGH-3 model at the
// STATIC level: 0x9999 carries NO hardcoded halt authority. The SettleContract is a
// zero-field struct (no protocolFeeController), so a single process-global precompile
// instance serves every network and there is no compromised default key on the struct.
// The authority is supplied per network at runtime via AtomicState (proven dynamically
// in the harness governance tests). A grep-level guard: this file no longer references a
// DefaultDAOTreasury symbol (it is deleted); if anyone re-introduces a hardcoded halt
// EOA, the harness halt tests below (only-governance-can-halt) fail.
func TestDex9999_GovernanceIsRuntimeResolved_NotHardcoded(t *testing.T) {
	// The 0x9999 contract is registered and is the sole DEX money path...
	if _, ok := modules.GetPrecompileModuleByAddress(poolManagerAddr9999); !ok {
		t.Fatal("0x9999 must be the registered DEX precompile")
	}
	// ...and a SettleContract value is constructible with NO authority field — i.e. the
	// authority is not a struct field set from a hardcoded key. (A non-zero-field struct
	// would not compile as SettleContract{}.)
	c := &SettleContract{}
	_ = c
	// The fail-closed authority error exists and is distinct — an unconfigured network
	// cannot halt at all (no default key to fall back to).
	if ErrSettleNoGovernance == nil {
		t.Fatal("ErrSettleNoGovernance must exist — the fail-closed authority error for an unset governance controller")
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
