// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package contract

import (
	"testing"

	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// feeReportingChainConfig is a ChainConfig that also implements
// FeeConfigReporter.
type feeReportingChainConfig struct {
	*MockChainConfig
	// limit returned at any time before flipAt; postLimit returned at
	// flipAt and later. Models feeConfigManagerConfig raising the
	// gasLimit post-genesis.
	limit     uint64
	postLimit uint64
	flipAt    uint64
}

func newFeeReportingChainConfig(limit, postLimit, flipAt uint64) *feeReportingChainConfig {
	return &feeReportingChainConfig{
		MockChainConfig: NewMockChainConfig(0),
		limit:           limit,
		postLimit:       postLimit,
		flipAt:          flipAt,
	}
}

func (f *feeReportingChainConfig) EffectiveGasLimit(time uint64) uint64 {
	if time >= f.flipAt {
		return f.postLimit
	}
	return f.limit
}

// TestRequireGasLimit_NoReporter verifies that ChainConfigs that do
// not implement FeeConfigReporter are treated as permissive (the
// default for non-Lux chains that integrate Lux precompiles).
func TestRequireGasLimit_NoReporter(t *testing.T) {
	cfg := NewMockChainConfig(0) // no FeeConfigReporter
	bc := NewMockBlockContext(1, 1000)
	require.NoError(t, RequireGasLimit(cfg, bc, 1<<30))
}

// TestRequireGasLimit_NilChainConfig verifies permissive behavior.
func TestRequireGasLimit_NilChainConfig(t *testing.T) {
	bc := NewMockBlockContext(1, 1000)
	require.NoError(t, RequireGasLimit(nil, bc, 1<<30))
}

// TestRequireGasLimit_ReporterAbove verifies that a reporter whose
// limit exceeds the threshold is permissive.
func TestRequireGasLimit_ReporterAbove(t *testing.T) {
	cfg := newFeeReportingChainConfig(20_000_000, 20_000_000, 0)
	bc := NewMockBlockContext(1, 1000)
	require.NoError(t, RequireGasLimit(cfg, bc, 12_000_000))
}

// TestRequireGasLimit_ReporterAtThreshold verifies inclusive lower bound:
// a reporter at exactly the threshold passes (min is the floor, not exclusive).
func TestRequireGasLimit_ReporterAtThreshold(t *testing.T) {
	cfg := newFeeReportingChainConfig(12_000_000, 12_000_000, 0)
	bc := NewMockBlockContext(1, 1000)
	require.NoError(t, RequireGasLimit(cfg, bc, 12_000_000))
}

// TestRequireGasLimit_ReporterBelow verifies that a reporter whose
// limit is below the threshold refuses with ErrFHEUnsafeGasLimit.
func TestRequireGasLimit_ReporterBelow(t *testing.T) {
	cfg := newFeeReportingChainConfig(8_000_000, 8_000_000, 0)
	bc := NewMockBlockContext(1, 1000)
	err := RequireGasLimit(cfg, bc, 12_000_000)
	require.ErrorIs(t, err, ErrFHEUnsafeGasLimit)
}

// TestRequireGasLimit_ReporterAbstains verifies that EffectiveGasLimit
// returning 0 (reporter has no opinion) is treated as permissive.
func TestRequireGasLimit_ReporterAbstains(t *testing.T) {
	cfg := newFeeReportingChainConfig(0, 0, 0)
	bc := NewMockBlockContext(1, 1000)
	require.NoError(t, RequireGasLimit(cfg, bc, 12_000_000))
}

// TestRequireGasLimit_TimeAware verifies that the reporter is queried
// at the activation block timestamp — models feeConfigManagerConfig
// raising the gasLimit post-genesis.
func TestRequireGasLimit_TimeAware(t *testing.T) {
	// Mainnet shape: genesis 12M, fee-manager raises to 20M at t=900000000.
	cfg := newFeeReportingChainConfig(12_000_000, 20_000_000, 900_000_000)

	// Before the flip: refuses because 12M < 15M threshold.
	bcEarly := NewMockBlockContext(1, 500_000_000)
	require.ErrorIs(t, RequireGasLimit(cfg, bcEarly, 15_000_000), ErrFHEUnsafeGasLimit)

	// After the flip: passes because 20M >= 15M threshold.
	bcLate := NewMockBlockContext(1, 1_000_000_000)
	require.NoError(t, RequireGasLimit(cfg, bcLate, 15_000_000))
}

// TestRequireGasLimit_NilBlockContext verifies that nil blockContext
// is treated as time=0 (chain genesis) and the genesis-time gasLimit
// is the one evaluated.
func TestRequireGasLimit_NilBlockContext(t *testing.T) {
	cfg := newFeeReportingChainConfig(12_000_000, 20_000_000, 900_000_000)
	require.ErrorIs(t, RequireGasLimit(cfg, nil, 15_000_000), ErrFHEUnsafeGasLimit)
}

// TestFeeConfigReporter_InterfaceShape is a compile-time check that
// the test reporter type satisfies both ChainConfig and
// FeeConfigReporter.
func TestFeeConfigReporter_InterfaceShape(t *testing.T) {
	var _ FeeConfigReporter = (*feeReportingChainConfig)(nil)
	var _ precompileconfig.ChainConfig = (*feeReportingChainConfig)(nil)
}
