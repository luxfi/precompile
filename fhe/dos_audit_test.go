// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDoSAuditTable_QuasarEditionMainnetSafety walks every row in the
// cross-precompile DoS audit table and asserts the row's declared
// SafeAt12M matches the value computed from the row's gas + wall-clock
// budget at gasLimit=12M (real C-Chain mainnet from
// ~/work/lux/genesis/configs/mainnet/cchain.json).
//
// This is the regression guard against silent gas-cost drift. If a
// precompile's gas is later lowered such that it no longer fits the
// 12M-mainnet budget, this test surfaces the divergence loudly.
func TestDoSAuditTable_QuasarEditionMainnetSafety(t *testing.T) {
	for _, row := range DoSAuditTable {
		got := row.IsSafeAtGasLimit(MainnetCChainGasLimit)
		require.Equal(t, row.SafeAt12M, got,
			"%s: declared SafeAt12M=%v but computed %v "+
				"(GasPerOp=%d, PerOpMs=%d, maxOpsPerBlock=%d, wall-clock-ms=%d, budget=%d)",
			row.Precompile, row.SafeAt12M, got,
			row.GasPerOp, row.PerOpMs,
			MainnetCChainGasLimit/row.GasPerOp,
			(MainnetCChainGasLimit/row.GasPerOp)*row.PerOpMs,
			BlockComputeBudgetMs)
		require.True(t, got,
			"row %q must remain DoS-safe at 12M mainnet gasLimit; "+
				"audit drift detected", row.Precompile)
	}
}

// TestDoSAuditTable_PostFeeManagerSafety verifies the 20M
// post-feeConfigManagerConfig gasLimit also keeps every row within
// the per-block compute budget.
func TestDoSAuditTable_PostFeeManagerSafety(t *testing.T) {
	for _, row := range DoSAuditTable {
		require.True(t, row.IsSafeAtGasLimit(PostFeeManagerGasLimit),
			"row %q must remain DoS-safe at 20M post-fee-manager gasLimit",
			row.Precompile)
	}
}

// TestDoSAuditTable_FHEActivationStillRefuses pins the inverse: the
// FHE rows look "safe" only because GasMul ≥ MainnetCChainGasLimit
// (their per-op gas exceeds the entire block budget), which means
// zero ops fit per block. The activation gate must still refuse
// rather than ship an unusable precompile silently.
//
// This is the regression that catches someone "fixing" the audit by
// lowering GasMul to make ops actually fit — that would make the row
// genuinely unsafe at 12M, and this test would flag the regression
// before the chain stalled.
func TestDoSAuditTable_FHEActivationStillRefuses(t *testing.T) {
	// The activation gate refuses when gasLimit < GasMul × MinSafeGasMulRatio.
	gateThreshold := GasMul * MinSafeGasMulRatio
	require.Greater(t, gateThreshold, MainnetCChainGasLimit,
		"FHE activation gate must refuse at 12M mainnet; "+
			"otherwise a single Mul that fits in a block stalls the chain "+
			"for %d ms wall-clock", WallClockMsMulUint8)
	require.Greater(t, gateThreshold, PostFeeManagerGasLimit,
		"FHE activation gate must refuse at 20M post-fee-manager")
	require.Greater(t, gateThreshold, ReferenceGasLimit30M,
		"FHE activation gate must refuse at 30M reference")
}

// TestDoSAuditTable_RowGasMatchesDeclaration cross-checks the rows
// against the actual constants. If GasMul is changed in contract.go
// without updating the audit table, this test fails.
func TestDoSAuditTable_RowGasMatchesDeclaration(t *testing.T) {
	rowsByName := map[string]DoSAuditRow{}
	for _, r := range DoSAuditTable {
		rowsByName[r.Precompile] = r
	}

	require.Equal(t, GasAdd, rowsByName["fhe/add-uint8"].GasPerOp,
		"fhe/add-uint8 row gas must equal the GasAdd constant")
	require.Equal(t, GasMul, rowsByName["fhe/mul-uint8"].GasPerOp,
		"fhe/mul-uint8 row gas must equal the GasMul constant")
	require.Equal(t, WallClockMsAddUint8, rowsByName["fhe/add-uint8"].PerOpMs,
		"fhe/add-uint8 row wall-clock ms must equal the measured constant")
	require.Equal(t, WallClockMsMulUint8, rowsByName["fhe/mul-uint8"].PerOpMs,
		"fhe/mul-uint8 row wall-clock ms must equal the measured constant")
}
