// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// feeReportingChainConfig is a ChainConfig that also implements
// contract.FeeConfigReporter for activation-gate tests.
type feeReportingChainConfig struct {
	limit uint64
}

func (f *feeReportingChainConfig) EffectiveGasLimit(time uint64) uint64 {
	return f.limit
}

// stubBlockContext is a minimal contract.ConfigurationBlockContext
// — Configure does not call any other method on it.
type stubBlockContext struct {
	number    *big.Int
	timestamp uint64
}

func (s *stubBlockContext) Number() *big.Int  { return s.number }
func (s *stubBlockContext) Timestamp() uint64 { return s.timestamp }

// TestConfigure_RefusesAtMainnetGasLimit proves the activation gate
// refuses when the chain reports the real mainnet C-Chain gas limit
// (12_000_000). With current TFHE perf (78 s/mul) and GasMul=936M, the
// chain cannot host even one Mul per block, so the gate fires.
func TestConfigure_RefusesAtMainnetGasLimit(t *testing.T) {
	cfg := &Config{}
	chainCfg := &feeReportingChainConfig{limit: MainnetCChainGasLimit}
	bc := &stubBlockContext{number: big.NewInt(0), timestamp: 0}

	c := &configurator{}
	err := c.Configure(chainCfg, cfg, nil, bc)
	require.Error(t, err, "Configure must refuse at mainnet gasLimit")
	require.True(t, errors.Is(err, contract.ErrFHEUnsafeGasLimit),
		"refusal must be the typed contract.ErrFHEUnsafeGasLimit, got %v", err)
}

// TestConfigure_RefusesAtPostFeeManagerGasLimit proves the gate also
// refuses at the 20M post-feeConfigManagerConfig gasLimit.
func TestConfigure_RefusesAtPostFeeManagerGasLimit(t *testing.T) {
	cfg := &Config{}
	chainCfg := &feeReportingChainConfig{limit: PostFeeManagerGasLimit}
	bc := &stubBlockContext{number: big.NewInt(0), timestamp: 0}

	c := &configurator{}
	err := c.Configure(chainCfg, cfg, nil, bc)
	require.ErrorIs(t, err, contract.ErrFHEUnsafeGasLimit,
		"Configure must refuse at 20M post-fee-manager gasLimit")
}

// TestConfigure_RefusesAt30MReferenceGasLimit proves the gate refuses
// even at the pre-2026 30M reference gasLimit. Documents that a chain
// would need a gas limit on the order of 1 B to safely host this
// precompile at current TFHE perf.
func TestConfigure_RefusesAt30MReferenceGasLimit(t *testing.T) {
	cfg := &Config{}
	chainCfg := &feeReportingChainConfig{limit: ReferenceGasLimit30M}
	bc := &stubBlockContext{number: big.NewInt(0), timestamp: 0}

	c := &configurator{}
	err := c.Configure(chainCfg, cfg, nil, bc)
	require.ErrorIs(t, err, contract.ErrFHEUnsafeGasLimit,
		"Configure must refuse at 30M reference gasLimit")
}

// TestConfigure_PermitsAtSufficientGasLimit proves the gate is not
// permanently sealed: when the chain reports a gasLimit at or above
// GasMul × MinSafeGasMulRatio, Configure succeeds.
//
// This is the recovery path for operators once gasLimit is raised via
// feeConfigManagerConfig admin OR once a faster TFHE evaluator lands.
func TestConfigure_PermitsAtSufficientGasLimit(t *testing.T) {
	cfg := &Config{}
	chainCfg := &feeReportingChainConfig{limit: GasMul * MinSafeGasMulRatio}
	bc := &stubBlockContext{number: big.NewInt(0), timestamp: 0}

	c := &configurator{}
	require.NoError(t, c.Configure(chainCfg, cfg, nil, bc),
		"Configure must permit activation at gasLimit >= GasMul × MinSafeGasMulRatio")
}

// TestConfigure_PermissiveWithoutFeeConfigReporter proves cross-chain
// compatibility: a ChainConfig that doesn't implement FeeConfigReporter
// (e.g. a non-Lux chain integrating Lux precompiles) is permissive,
// matching the StrictPQ pattern.
func TestConfigure_PermissiveWithoutFeeConfigReporter(t *testing.T) {
	cfg := &Config{}
	var chainCfg nonReportingChainConfig // does NOT implement FeeConfigReporter
	bc := &stubBlockContext{number: big.NewInt(0), timestamp: 0}

	c := &configurator{}
	require.NoError(t, c.Configure(&chainCfg, cfg, nil, bc),
		"Configure must be permissive on non-Lux chains lacking FeeConfigReporter")
}

// TestConfigure_PermissiveOnNilChainConfig proves Configure does not
// crash or accidentally engage the gate when chainConfig is nil.
func TestConfigure_PermissiveOnNilChainConfig(t *testing.T) {
	cfg := &Config{}
	bc := &stubBlockContext{number: big.NewInt(0), timestamp: 0}

	c := &configurator{}
	require.NoError(t, c.Configure(nil, cfg, nil, bc),
		"Configure must accept nil chainConfig for back-compat")
}

// TestConfigure_RejectsWrongConfigType preserves the existing typed
// rejection. Important: the activation gate must come AFTER the type
// assertion so a malformed upgrade.json surfaces the structural error
// rather than the budget refusal.
func TestConfigure_RejectsWrongConfigType(t *testing.T) {
	bc := &stubBlockContext{number: big.NewInt(0), timestamp: 0}
	c := &configurator{}
	// Pass nil config — must be rejected with type mismatch, not gate refusal.
	err := c.Configure(nil, nil, nil, bc)
	require.Error(t, err)
}

// nonReportingChainConfig is a ChainConfig that does NOT implement
// FeeConfigReporter, modeling a non-Lux integrator.
type nonReportingChainConfig struct{}
