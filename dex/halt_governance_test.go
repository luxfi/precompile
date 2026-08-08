// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// halt_governance_test.go is the HIGH-3 TDD proof: the 0x9999 emergency-halt authority
// is the per-NETWORK DEX governance controller resolved at runtime from
// contract.AtomicState.GovernanceController() — a governance CONTRACT, NEVER a single
// hardcoded mnemonic-derivable EOA. It proves, through the production Run dispatch:
//
//  1. ONLY the configured governance controller may halt (global / asset / market), and
//     the halt actually BITES (a subsequent swap reverts with the right halt error).
//  2. The RETIRED hardcoded EOA (0x9011…94714, the old DefaultDAOTreasury, derivable
//     from the dev mnemonic) CANNOT halt — it is unauthorized like any other caller.
//  3. An arbitrary EOA CANNOT halt.
//  4. When NO governance controller is configured (the zero address), NOBODY can halt:
//     the gate is fail-closed (ErrSettleNoGovernance), so an unset network can be neither
//     censored nor DoS'd through this authority. There is no default key to abuse.
//  5. The SAME gate guards pot seeding (seedSeamReserve): the retired EOA cannot seed.
//  6. Conservation is preserved: governance can halt/unhalt but mints nothing (the
//     unhalt restores trading; TestDecomplect_DAOControllerCannotMintOrMoveUserFunds in
//     settle_decomplect_test.go proves no mint/move).

// haltGlobal builds and runs setHaltGlobal(on) from `caller`, returning the dispatch err.
func haltGlobal(h *settleHarness, caller common.Address, on bool) error {
	data := make([]byte, 32)
	if on {
		data[31] = 1
	}
	_, _, err := h.c.Run(h.state, caller, poolManagerAddr9999,
		prependSelector(SelectorSetHaltGlobal, data), 5_000_000, false)
	return err
}

// haltAsset builds and runs setHaltAsset(assetID, on) from `caller`.
func haltAsset(h *settleHarness, caller common.Address, assetID [32]byte, on bool) error {
	data := make([]byte, 64)
	copy(data[0:32], assetID[:])
	if on {
		data[63] = 1
	}
	_, _, err := h.c.Run(h.state, caller, poolManagerAddr9999,
		prependSelector(SelectorSetHaltAsset, data), 5_000_000, false)
	return err
}

// haltMarket builds and runs setHaltMarket(marketID, on) from `caller`.
func haltMarket(h *settleHarness, caller common.Address, marketID [32]byte, on bool) error {
	data := make([]byte, 64)
	copy(data[0:32], marketID[:])
	if on {
		data[63] = 1
	}
	_, _, err := h.c.Run(h.state, caller, poolManagerAddr9999,
		prependSelector(SelectorSetHaltMarket, data), 5_000_000, false)
	return err
}

// TestHIGH3_OnlyGovernanceCanHalt_RetiredEOACannot is the central HIGH-3 proof.
func TestHIGH3_OnlyGovernanceCanHalt_RetiredEOACannot(t *testing.T) {
	h := newSettleHarness(t)
	gov := h.operator() // the runtime-resolved governance controller (testGovernance)

	// Sanity: the test governance address is NOT the retired hardcoded EOA, and the
	// retired EOA is a real-looking address (so "it cannot halt" is a meaningful claim).
	if gov == retiredHardcodedHaltEOA {
		t.Fatal("test setup error: governance must differ from the retired hardcoded EOA")
	}
	arbitrary := common.HexToAddress("0xBADBADBADBADBADBADBADBADBADBADBADBADBADB")

	// (2)+(3): the retired EOA and an arbitrary EOA are BOTH unauthorized to halt.
	if err := haltGlobal(h, retiredHardcodedHaltEOA, true); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("retired 0x9011 EOA must NOT be able to setHaltGlobal — got %v, want ErrUnauthorized", err)
	}
	if err := haltAsset(h, retiredHardcodedHaltEOA, h.inAssetID(), true); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("retired 0x9011 EOA must NOT be able to setHaltAsset — got %v, want ErrUnauthorized", err)
	}
	if err := haltGlobal(h, arbitrary, true); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("arbitrary EOA must NOT be able to setHaltGlobal — got %v, want ErrUnauthorized", err)
	}

	// Confirm none of those rejected calls actually halted anything (the gate ran before
	// any state write; a reverted halt write rolls back with the revert).
	if checkHalt(newPoolStateAdapter(h.state), h.key, h.params) != nil {
		t.Fatal("an unauthorized halt attempt wrote halt state (do-not-ship)")
	}

	// (1): the configured governance controller CAN halt globally.
	if err := haltGlobal(h, gov, true); err != nil {
		t.Fatalf("governance controller must be able to setHaltGlobal, got: %v", err)
	}
	if got := checkHalt(newPoolStateAdapter(h.state), h.key, h.params); !errors.Is(got, ErrDEXHalted) {
		t.Fatalf("global halt did not bite: checkHalt = %v, want ErrDEXHalted", got)
	}
	// And governance can lift it (no mint, just unhalt).
	if err := haltGlobal(h, gov, false); err != nil {
		t.Fatalf("governance controller must be able to clear the global halt, got: %v", err)
	}
	if got := checkHalt(newPoolStateAdapter(h.state), h.key, h.params); got != nil {
		t.Fatalf("global halt not cleared: checkHalt = %v, want nil", got)
	}

	// (1) asset-scoped: governance halts the input asset; checkHalt reports ErrAssetHalted.
	if err := haltAsset(h, gov, h.inAssetID(), true); err != nil {
		t.Fatalf("governance setHaltAsset(in) failed: %v", err)
	}
	if got := checkHalt(newPoolStateAdapter(h.state), h.key, h.params); !errors.Is(got, ErrAssetHalted) {
		t.Fatalf("asset halt did not bite: checkHalt = %v, want ErrAssetHalted", got)
	}
	if err := haltAsset(h, gov, h.inAssetID(), false); err != nil {
		t.Fatalf("governance clear setHaltAsset(in) failed: %v", err)
	}

	// (1) market-scoped: governance halts this pool; checkHalt reports ErrMarketHalted.
	poolID := h.key.ID()
	if err := haltMarket(h, gov, poolID, true); err != nil {
		t.Fatalf("governance setHaltMarket failed: %v", err)
	}
	if got := checkHalt(newPoolStateAdapter(h.state), h.key, h.params); !errors.Is(got, ErrMarketHalted) {
		t.Fatalf("market halt did not bite: checkHalt = %v, want ErrMarketHalted", got)
	}
}

// TestHIGH3_FailClosed_NoGovernanceConfigured_NobodyCanHalt proves the maximally-
// decentralized default: a network with NO governance controller (zero address) has NO
// halt authority at all — not the retired EOA, not even a would-be admin. Every halt
// attempt is fail-closed (ErrSettleNoGovernance). This is strictly safer than a default
// key: an unset network can be neither censored nor DoS'd through this authority.
func TestHIGH3_FailClosed_NoGovernanceConfigured_NobodyCanHalt(t *testing.T) {
	h := newSettleHarness(t)
	h.state.governance = common.Address{} // network configured NO governance controller

	for _, caller := range []common.Address{
		retiredHardcodedHaltEOA,
		h.caller,
		common.HexToAddress("0x60F0000000000000000000000000000000000A11"), // even the would-be gov addr
	} {
		if err := haltGlobal(h, caller, true); !errors.Is(err, ErrSettleNoGovernance) {
			t.Fatalf("with no governance configured, setHaltGlobal by %s must be fail-closed — got %v, want ErrSettleNoGovernance",
				caller.Hex(), err)
		}
		if err := haltAsset(h, caller, h.inAssetID(), true); !errors.Is(err, ErrSettleNoGovernance) {
			t.Fatalf("with no governance configured, setHaltAsset by %s must be fail-closed — got %v, want ErrSettleNoGovernance",
				caller.Hex(), err)
		}
	}
	// Nothing was halted: the swap path is unaffected (no fail-OPEN, no fail-into-halt).
	if got := checkHalt(newPoolStateAdapter(h.state), h.key, h.params); got != nil {
		t.Fatalf("fail-closed authority must not have written halt state: checkHalt = %v", got)
	}
}

// TestHIGH3_RetiredEOACannotSeedPots proves the SAME governance gate guards the operator
// pot-seeding selectors (seedSeamReserve), so the retired EOA cannot seed/credit either.
// (TestDecomplect_DAOControllerCannotMintOrMoveUserFunds already proves the AUTHORIZED
// controller cannot mint; here we prove the retired EOA is not even authorized to attempt it.)
func TestHIGH3_RetiredEOACannotSeedPots(t *testing.T) {
	h := newSettleHarness(t)

	// seedSeamReserve(address(0), 1_000_000) by the retired EOA: unauthorized, before any
	// value accounting. The gate is the governance controller, not a hardcoded key.
	data := make([]byte, 64)
	new(big.Int).SetUint64(1_000_000).FillBytes(data[32:64])
	if _, _, err := h.c.Run(h.state, retiredHardcodedHaltEOA, poolManagerAddr9999,
		prependSelector(SelectorSeedSeamReserve, data), 5_000_000, false); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("retired 0x9011 EOA must NOT be able to seedSeamReserve — got %v, want ErrUnauthorized", err)
	}

	// The configured governance controller IS authorized to attempt the seed (it then
	// fails ErrSeedUndelivered because no value was delivered — proving authorization is
	// distinct from the conservation guarantee, which still holds).
	if _, _, err := h.c.Run(h.state, h.operator(), poolManagerAddr9999,
		prependSelector(SelectorSeedSeamReserve, data), 5_000_000, false); !errors.Is(err, ErrSeedUndelivered) {
		t.Fatalf("governance controller seed with no value must reach the conservation check (ErrSeedUndelivered), got: %v", err)
	}
}

// TestHIGH3_HaltBitesARealSwap is the end-to-end proof that governance-set halt actually
// stops a real swap on the money path: governance halts the market, a real swap (a Phase-A
// order — the canonical settle-only money path) reverts with the halt error before any
// input is locked, governance lifts it, and the swap then proceeds. This closes the loop —
// "governance halts" means "the money path actually stops", and only governance can do it.
func TestHIGH3_HaltBitesARealSwap(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(1000)
	gov := h.operator()
	poolID := h.key.ID()

	// Governance halts THIS market.
	if err := haltMarket(h, gov, poolID, true); err != nil {
		t.Fatalf("governance setHaltMarket: %v", err)
	}

	// A real swap (Phase-A order) now reverts with the market-halt error — checkHalt gates
	// the money path BEFORE any input is locked (no strand on a halted swap).
	if _, err := h.runSwap(t, h.crossCalldata(), false); !errors.Is(err, ErrMarketHalted) {
		t.Fatalf("halted market must refuse a swap with ErrMarketHalted, got: %v", err)
	}

	// Only governance can lift it (the retired EOA cannot).
	if err := haltMarket(h, retiredHardcodedHaltEOA, poolID, false); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("retired EOA must NOT be able to clear the market halt, got: %v", err)
	}
	if err := haltMarket(h, gov, poolID, false); err != nil {
		t.Fatalf("governance must be able to clear the market halt, got: %v", err)
	}

	// With the halt lifted, the same swap proceeds (creates its C->D order).
	out, err := h.runSwap(t, h.crossCalldata(), false)
	if err != nil {
		t.Fatalf("after governance lifted the halt, the swap must succeed, got: %v", err)
	}
	if len(out) != 32 {
		t.Fatal("swap after unhalt must return a 32-byte order id")
	}
}
