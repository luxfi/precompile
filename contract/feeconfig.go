// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package contract

import "errors"

// ErrFHEUnsafeGasLimit is returned when a compute-heavy precompile
// (currently only FHE) is being activated on a chain whose effective
// block gas limit cannot afford the per-op wall-clock budget. The
// configurator surfaces it during luxd boot so the misconfiguration
// is loud rather than silently bricking the chain at the activation
// block.
//
// Recovery is operator-side: raise the chain's gasLimit (via
// feeConfigManagerConfig admin) before re-running the upgrade, or
// remove the precompile from upgrade.json.
var ErrFHEUnsafeGasLimit = errors.New("contract: chain gasLimit too small for safe FHE operation under measured per-op wall-clock budget")

// FeeConfigReporter is the feature-detection interface a ChainConfig
// may implement to expose its effective block gas limit at the
// timestamp the precompile is being activated. Compute-heavy
// precompiles probe this interface in their Configure() activation
// gate; if absent (e.g. non-Lux integrators), the precompile is
// permissive.
//
// The reporter takes a timestamp because the chain's effective fee
// config can change over time (feeConfigManagerConfig admin can
// raise the gasLimit post-genesis), so the activation decision
// must be made against the value at the activation block.
type FeeConfigReporter interface {
	// EffectiveGasLimit returns the block gas limit currently in
	// force at the given block timestamp. Returns 0 when the
	// reporter has no opinion.
	EffectiveGasLimit(time uint64) uint64
}

// RequireGasLimit returns ErrFHEUnsafeGasLimit when the active chain
// reports a FeeConfigReporter AND the reported effective gas limit
// is less than minGasLimit. Used by FHE module.Configure to refuse
// activation on chains that cannot afford the precompile's per-op
// wall-clock budget.
//
// Permissive when the ChainConfig does not implement
// FeeConfigReporter (the default for non-Lux chains that integrate
// Lux precompiles for cross-chain verification — they're expected
// to know what they're doing).
//
// blockContext provides the activation timestamp. nil blockContext
// is treated as time=0 (chain genesis) and the chain's
// genesis-time gasLimit governs.
func RequireGasLimit(chainConfig any, blockContext ConfigurationBlockContext, minGasLimit uint64) error {
	if chainConfig == nil {
		return nil
	}
	r, ok := chainConfig.(FeeConfigReporter)
	if !ok {
		return nil
	}
	var ts uint64
	if blockContext != nil {
		ts = blockContext.Timestamp()
	}
	got := r.EffectiveGasLimit(ts)
	if got == 0 {
		// Reporter abstained — treat as permissive.
		return nil
	}
	if got < minGasLimit {
		return ErrFHEUnsafeGasLimit
	}
	return nil
}
