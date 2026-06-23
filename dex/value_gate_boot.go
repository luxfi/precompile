// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"sync/atomic"
)

// value_gate_boot.go is the SINGLE production activation path for the synchronous native-
// value router, plus the fail-closed gate state it flips. The gate (valueSwapsEnabled) is
// decorative unless something actually turns it on AFTER proving the consensus engine
// delivers quorum finality — otherwise a node could enable value trading on a single-
// validator or degraded engine where a proposer self-finalizes a fabricated fill. This file
// is that proof-gated switch: EnableValueSwaps(true) is reachable in production ONLY through
// EnableValueSwapsViaQuorumGate, which first asks the live engine to certify quorum finality
// and STAYS DISABLED (returning the error) if it cannot.
//
// DEPENDENCY INVERSION (no upward import): the precompile owns the PORT it needs (the
// ValueDEXQuorumGate — "can this engine finalize value with a quorum?"), and the consensus
// engine SATISFIES it (consensus/engine/chain.Transitive has exactly
// RequireQuorumFinalityForValueDEX). The EVM-plugin boot — which already composes both —
// passes the live engine here. The precompile never imports consensus, so there is no
// cycle and no leak of the consensus package into the value path. This mirrors how the
// boot wires the local D-Chain client (InstallDChainClient) and the asset resolver
// (InstallAssetResolver): the precompile names the capability, the host injects it.

// valueSwapsEnabled is the FAIL-CLOSED activation gate for the synchronous on-chain value
// router. It defaults to false (the zero value): a node does NOT move real value through the
// synchronous swap path until EnableValueSwapsViaQuorumGate certifies quorum finality and
// flips it on. Every sync swap checks ValueSwapsEnabled() first and reverts when off, so the
// safe default is "value swaps disabled" — never trade real value over an unverified engine.
var valueSwapsEnabled atomic.Bool

// EnableValueSwaps sets the node's synchronous-value-router switch. It is NOT a public
// production entrypoint — the ONLY production caller is EnableValueSwapsViaQuorumGate (below),
// which flips it on solely after the consensus engine certifies quorum finality. Tests toggle
// it directly to exercise the on/off branches.
func EnableValueSwaps(on bool) { valueSwapsEnabled.Store(on) }

// ValueSwapsEnabled reports whether the synchronous value router is active. The sync swap
// handler consults it before moving any value (fail-closed: off => revert).
func ValueSwapsEnabled() bool { return valueSwapsEnabled.Load() }

// ErrValueSwapsNotEnabled is returned when a synchronous value swap is attempted on a node
// whose value router is disabled — the fail-closed default. It requires a quorum-finality
// consensus engine to be certified (EnableValueSwapsViaQuorumGate) before value can move.
var ErrValueSwapsNotEnabled = errors.New("dex: native-value swaps are not enabled on this node (requires quorum-finality consensus)")

// ValueDEXQuorumGate is the consensus-side gate the value-DEX activation path consults
// before enabling real-value trading. It is satisfied structurally by
// consensus/engine/chain.Transitive (its RequireQuorumFinalityForValueDEX method): the
// engine reads its OWN live finality regime (Mode()) and returns nil only when it is in
// quorum-finality mode (K>1, verified α-of-K cert path, stake-weighted supermajority, and
// — on a strict-PQ chain — a PQ witness). On any weaker regime it returns a non-nil error
// and value-DEX must NOT activate.
type ValueDEXQuorumGate interface {
	// RequireQuorumFinalityForValueDEX returns nil iff real-value DEX may activate on this
	// engine (dexNativeValueEnabled == true requires quorum-finality mode). A non-nil error
	// means the engine cannot guarantee quorum finality and value-DEX must stay disabled.
	RequireQuorumFinalityForValueDEX(dexNativeValueEnabled bool) error
}

// ErrNilQuorumGate is returned when EnableValueSwapsViaQuorumGate is called with no engine
// gate. FAIL-CLOSED: without a live engine to certify quorum finality, value swaps stay
// disabled — the activation path never enables value trading "on faith".
var ErrNilQuorumGate = errors.New("dex: cannot enable value swaps without a consensus quorum gate (fail-closed)")

// EnableValueSwapsViaQuorumGate is the ONE production way to turn on the synchronous
// native-value router. It is the precompile-side half of the launch rule; the engine-side
// half is RequireQuorumFinalityForValueDEX.
//
// Semantics (fail-closed throughout):
//   - gate == nil                       -> value swaps stay OFF; returns ErrNilQuorumGate.
//   - gate.RequireQuorumFinalityForValueDEX(true) != nil -> value swaps stay OFF; returns
//     that error (the engine is single-validator / degraded / not stake-weighted / missing
//     the strict-PQ witness — any regime weaker than verified quorum finality).
//   - gate certifies quorum finality (nil) -> EnableValueSwaps(true); returns nil.
//
// CRUCIALLY it ASKS the gate FIRST and only enables on success: there is no path that flips
// the switch before the engine certifies quorum finality. The EVM plugin calls this exactly
// once at boot with the live engine. If it returns an error, the node runs with value swaps
// disabled (every sync swap reverts ErrValueSwapsNotEnabled) — the safe default — rather
// than activating value trading over an engine that cannot witness quorum finality.
func EnableValueSwapsViaQuorumGate(gate ValueDEXQuorumGate) error {
	if gate == nil {
		EnableValueSwaps(false) // belt-and-suspenders: ensure OFF
		return ErrNilQuorumGate
	}
	// Ask the engine to certify quorum finality for real-value DEX. dexNativeValueEnabled =
	// true means "we WANT value at stake" — the gate then demands quorum-finality mode.
	if err := gate.RequireQuorumFinalityForValueDEX(true); err != nil {
		EnableValueSwaps(false) // stay closed on any non-quorum-finality regime
		return err
	}
	// Only here — after the engine certified quorum finality — does value trading turn on.
	EnableValueSwaps(true)
	return nil
}
