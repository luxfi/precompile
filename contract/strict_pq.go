// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package contract

import "errors"

// ErrClassicalForbiddenInPQ is returned by classical pairing-based or
// discrete-log precompiles when the active chain reports a strict
// post-quantum profile. The precompile is still registered at its
// stable address so the registry numbering does not move, but the
// contract refuses to execute.
//
// Non-Lux chains that integrate Lux precompiles for cross-chain
// verification do NOT implement StrictPQReporter and therefore see
// the classical primitives execute normally.
var ErrClassicalForbiddenInPQ = errors.New("contract: classical pairing-based primitive forbidden under strict-PQ chain profile")

// StrictPQReporter is the feature-detection interface a ChainConfig
// may implement to opt in to strict-PQ enforcement. ChainConfig
// implementations that do NOT implement this interface are treated
// as classical-permissive (the default for compatibility with
// existing non-Lux chains that integrate Lux precompiles).
type StrictPQReporter interface {
	IsStrictPQ(time uint64) bool
}

// RefuseUnderStrictPQ returns ErrClassicalForbiddenInPQ when the
// active chain profile reports strict-PQ, else nil. Classical
// precompiles (KZG, Groth16, PLONK, fflonk, Halo2, BN254-Pedersen,
// BabyJubJub, Pallas/Vesta) MUST call this at the top of their Run()
// before doing any work.
func RefuseUnderStrictPQ(state AccessibleState) error {
	// Permissive when state, chain config, or block context is not
	// wired. The test invocation pattern routinely passes nil for
	// state; only a chain that wires StrictPQReporter into its
	// ChainConfig actually triggers the gate.
	if state == nil {
		return nil
	}
	cfg := state.GetChainConfig()
	if cfg == nil {
		return nil
	}
	r, ok := cfg.(StrictPQReporter)
	if !ok {
		return nil
	}
	bc := state.GetBlockContext()
	var ts uint64
	if bc != nil {
		ts = bc.Timestamp()
	}
	if r.IsStrictPQ(ts) {
		return ErrClassicalForbiddenInPQ
	}
	return nil
}
