// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package contract

import (
	"testing"

	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// strictPQChainConfig is a ChainConfig that also implements StrictPQReporter.
type strictPQChainConfig struct {
	*MockChainConfig
	strictPQTime uint64
}

func newStrictPQChainConfig(strictPQTime uint64) *strictPQChainConfig {
	return &strictPQChainConfig{
		MockChainConfig: NewMockChainConfig(0),
		strictPQTime:    strictPQTime,
	}
}

func (s *strictPQChainConfig) IsStrictPQ(time uint64) bool {
	return time >= s.strictPQTime
}

// TestRefuseUnderStrictPQ_NoReporter verifies that ChainConfigs that
// do not implement StrictPQReporter are treated as classical-permissive.
// This is the default for non-Lux chains that integrate Lux precompiles.
func TestRefuseUnderStrictPQ_NoReporter(t *testing.T) {
	state := NewMockAccessibleState(NewMockStateDB(), NewMockBlockContext(1, 1000))
	// chainConfig is the plain MockChainConfig — no StrictPQReporter.
	require.NoError(t, RefuseUnderStrictPQ(state))
}

// TestRefuseUnderStrictPQ_ReporterFalse verifies that when the chain
// implements StrictPQReporter but reports false at the current
// timestamp, classical precompiles are allowed.
func TestRefuseUnderStrictPQ_ReporterFalse(t *testing.T) {
	state := NewMockAccessibleState(NewMockStateDB(), NewMockBlockContext(1, 500))
	state.chainConfig = newStrictPQChainConfig(1000) // strict-PQ starts at 1000
	require.NoError(t, RefuseUnderStrictPQ(state))
}

// TestRefuseUnderStrictPQ_ReporterTrue verifies that when the chain
// implements StrictPQReporter and reports true at the current
// timestamp, classical precompiles are refused.
func TestRefuseUnderStrictPQ_ReporterTrue(t *testing.T) {
	state := NewMockAccessibleState(NewMockStateDB(), NewMockBlockContext(1, 1500))
	state.chainConfig = newStrictPQChainConfig(1000)
	err := RefuseUnderStrictPQ(state)
	require.ErrorIs(t, err, ErrClassicalForbiddenInPQ)
}

// TestStrictPQReporter_InterfaceShape ensures the interface contract
// stays stable. A trivial compile-time check that a struct
// implementing IsStrictPQ satisfies the interface.
func TestStrictPQReporter_InterfaceShape(t *testing.T) {
	var _ StrictPQReporter = (*strictPQChainConfig)(nil)
	// Also ensure ChainConfig is still satisfied — the gate must not
	// require strict-PQ chains to be a different ChainConfig type.
	var _ precompileconfig.ChainConfig = (*strictPQChainConfig)(nil)
}
