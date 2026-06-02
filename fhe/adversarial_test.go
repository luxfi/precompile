// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Adversarial regression tests targeting Red team findings.
// Every test here MUST fail on vulnerable code and pass on fixed code.

package fhe

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// ============================================================================
// Finding 8: FHE gas repricing (HIGH) — re-derivation at REAL mainnet limits
// Red demonstrated that FHE multiply was underpriced relative to its
// computational cost, enabling gas-based DoS attacks where an attacker
// submits many FHE multiplications to stall the block.
//
// The fix ensures gas costs reflect actual compute time MEASURED on
// commodity validator hardware (Apple M1 Max, the high-end ARM commodity
// range) and SIZED so that the per-block FHE-precompile wall-clock budget
// (BlockComputeBudgetMs = 1000 ms = half a 2 s block target) is never
// exceeded at the real C-Chain mainnet gas limit (12_000_000 — not the
// 30_000_000 used in the pre-2026 reference test).
//
// The Mul wall-clock (78 s/op) so vastly exceeds the per-block budget
// that ANY non-zero number of muls per block stalls the chain. The gas
// floor is therefore sized to require gasLimit ≥ GasMul, and the FHE
// module Configure activation gate refuses activation under any chain
// whose gasLimit is below GasMul × MinSafeGasMulRatio.
// ============================================================================

// TestFHEMulGasCost_ReflectsComputeTime proves that FHE multiply gas cost
// is high enough to reflect its measured wall-clock cost.
//
// Bound: GasMul must reflect at least the WallClockMsMulUint8 × 12_000
// derivation. Anything less is a known-vulnerable repricing.
func TestFHEMulGasCost_ReflectsComputeTime(t *testing.T) {
	// Per fhe/contract.go: GasMul = WallClockMsMulUint8 × 12_000.
	// Anything below this is underpriced at the 12M block limit.
	minSafeGasMul := WallClockMsMulUint8 * 12_000
	require.GreaterOrEqual(t, GasMul, minSafeGasMul,
		"FHE multiply gas must reflect measured wall-clock × 12_000 gas/ms calibration; "+
			"got GasMul=%d, need >= %d", GasMul, minSafeGasMul)
}

// TestFHEAddGasCost_LessThanMul proves addition is cheaper than multiplication.
func TestFHEAddGasCost_LessThanMul(t *testing.T) {
	require.Less(t, GasAdd, GasMul,
		"FHE add gas must be less than FHE multiply gas (O(n) vs O(n^2))")
}

// TestFHEDivGasCost_ReflectsComputeTime proves division gas is substantial.
func TestFHEDivGasCost_ReflectsComputeTime(t *testing.T) {
	// Division uses binary long division with bootstrapping.
	// While cheaper than schoolbook multiplication (O(n) vs O(n^2)),
	// it is still computationally expensive and must be priced
	// accordingly. With the bench-derived sizing it is ~0.7x mul.
	require.GreaterOrEqual(t, GasDiv, GasMul*70/100,
		"FHE div gas must be at least 0.7x mul gas (binary long div)")
}

// TestFHERemGasCost_ReflectsComputeTime proves remainder gas matches div.
func TestFHERemGasCost_ReflectsComputeTime(t *testing.T) {
	require.Equal(t, GasDiv, GasRem,
		"FHE rem gas must equal div gas (same algorithm)")
}

// TestFHEMulGasCost_MostExpensiveArithmetic proves multiply is the most
// expensive arithmetic operation, reflecting O(n^2) bootstrapping cost.
func TestFHEMulGasCost_MostExpensiveArithmetic(t *testing.T) {
	require.Greater(t, GasMul, GasDiv,
		"FHE multiply must cost more than division (O(n^2) vs O(n) bootstrapping)")
	require.Greater(t, GasMul, GasAdd,
		"FHE multiply must cost more than addition")
	require.Greater(t, GasMul, GasSub,
		"FHE multiply must cost more than subtraction")
}

// TestFHEGasCost_AllOperations_AboveFloor proves all operations have a
// minimum gas floor to prevent spam.
func TestFHEGasCost_AllOperations_AboveFloor(t *testing.T) {
	const minFloor = uint64(10_000) // Minimum gas for any FHE operation

	ops := map[string]uint64{
		"Encrypt":        GasEncrypt,
		"DecryptRequest": GasDecryptRequest,
		"Add":            GasAdd,
		"Sub":            GasSub,
		"Mul":            GasMul,
		"Div":            GasDiv,
		"Rem":            GasRem,
		"And":            GasAnd,
		"Or":             GasOr,
		"Xor":            GasXor,
		"Not":            GasNot,
		"Shl":            GasShl,
		"Shr":            GasShr,
		"Rotl":           GasRotl,
		"Rotr":           GasRotr,
		"Eq":             GasEq,
		"Ne":             GasNe,
		"Gt":             GasGt,
		"Ge":             GasGe,
		"Lt":             GasLt,
		"Le":             GasLe,
		"Min":            GasMin,
		"Max":            GasMax,
		"Select":         GasSelect,
		"Neg":            GasNeg,
		"Rand":           GasRand,
		"Cast":           GasCast,
		"Require":        GasRequire,
	}

	for name, gas := range ops {
		require.GreaterOrEqual(t, gas, minFloor,
			"FHE %s gas (%d) must be >= minimum floor (%d) to prevent spam",
			name, gas, minFloor)
	}
}

// TestFHEGasCost_RelativeOrdering proves that gas costs reflect
// computational complexity ordering.
func TestFHEGasCost_RelativeOrdering(t *testing.T) {
	// Complexity ordering: bitwise < comparison < add/sub < mul
	// Not all are strict, but multiplication must exceed addition
	// and division must be at most multiplication.

	// Bitwise operations are cheapest (no full bootstrap per word).
	require.LessOrEqual(t, GasNot, GasAdd,
		"NOT must cost <= ADD")
	require.LessOrEqual(t, GasAnd, GasAdd,
		"AND must cost <= ADD")

	// Add/Sub are equal (same algorithm)
	require.Equal(t, GasAdd, GasSub,
		"ADD and SUB must have equal gas (same algorithm)")

	// Mul > Add (quadratic vs linear)
	require.Greater(t, GasMul, GasAdd,
		"MUL must cost more than ADD")

	// Mul > Div (schoolbook O(n^2) vs binary long division)
	require.Greater(t, GasMul, GasDiv,
		"MUL must cost more than DIV (O(n^2) bootstrapping)")

	// Min/Max involve comparison + selection (2x compare cost).
	require.Greater(t, GasMin, GasEq,
		"MIN must cost more than a single comparison")
	require.Greater(t, GasMax, GasEq,
		"MAX must cost more than a single comparison")
}

// ============================================================================
// Block-gas-budget DoS resistance at REAL mainnet limits
//
// These tests are the centerpiece of the CLOSE FHE Mul DoS audit. They
// assert that at each canonical gas limit on the C-Chain timeline, the
// product (per-mul wall-clock) × (max muls per block at that gas limit)
// stays under the per-block FHE compute budget (BlockComputeBudgetMs).
//
// All three tests share the same predicate:
//
//	maxMulsPerBlock := gasLimit / GasMul
//	totalWallClockMs := maxMulsPerBlock * WallClockMsMulUint8
//	REQUIRE: totalWallClockMs <= BlockComputeBudgetMs
//
// The tests differ only in the gasLimit they target.
// ============================================================================

// assertDoSResistanceAtGasLimit is the shared predicate.
func assertDoSResistanceAtGasLimit(t *testing.T, gasLimit uint64, label string) {
	t.Helper()
	maxMulsPerBlock := gasLimit / GasMul
	totalWallClockMs := maxMulsPerBlock * WallClockMsMulUint8
	require.LessOrEqual(t, totalWallClockMs, BlockComputeBudgetMs,
		"%s: gasLimit=%d, GasMul=%d → max %d muls/block × %d ms/mul = %d ms wall-clock > %d ms budget",
		label, gasLimit, GasMul, maxMulsPerBlock, WallClockMsMulUint8,
		totalWallClockMs, BlockComputeBudgetMs)
	t.Logf("%s: gasLimit=%d, GasMul=%d, max muls/block=%d, wall-clock=%d ms (budget %d ms)",
		label, gasLimit, GasMul, maxMulsPerBlock, totalWallClockMs, BlockComputeBudgetMs)
}

// TestFHEGasCost_Mul_DoSResistance_30M_Reference is the legacy 30M-gasLimit
// reference benchmark (the pre-2026 audit assumed this gas limit). Retained
// as a comparator — proves that even at 30M the per-block FHE budget is
// preserved.
func TestFHEGasCost_Mul_DoSResistance_30M_Reference(t *testing.T) {
	assertDoSResistanceAtGasLimit(t, ReferenceGasLimit30M, "30M-reference")
}

// TestFHEGasCost_Mul_DoSResistance_12M_Mainnet is the centerpiece of the
// CLOSE FHE Mul DoS audit. It pins the predicate at the REAL mainnet
// C-Chain gas limit (12_000_000) from
// ~/work/lux/genesis/configs/mainnet/cchain.json line 16.
//
// On vulnerable code (GasMul=750_000 at gasLimit=12M):
//
//	maxMulsPerBlock = 16
//	totalWallClockMs = 16 × 78_000 = 1_248_000 ms = 20.8 minutes
//	REQUIRE: 1_248_000 <= 1_000 → FAILS by 1248x
//
// On the fixed code (GasMul = 936_000_000 at gasLimit=12M):
//
//	maxMulsPerBlock = 0
//	totalWallClockMs = 0
//	REQUIRE: 0 <= 1_000 → PASSES
//
// The price of correctness is that 0 muls per tx fit at this gas limit —
// the precompile is mathematically blocked from running, which is the
// activation gate's job to surface explicitly during luxd boot.
func TestFHEGasCost_Mul_DoSResistance_12M_Mainnet(t *testing.T) {
	assertDoSResistanceAtGasLimit(t, MainnetCChainGasLimit, "12M-mainnet")
}

// TestFHEGasCost_Mul_DoSResistance_20M_PostFeeManager exercises the
// post-feeConfigManagerConfig gasLimit raise (20M) from
// ~/work/lux/genesis/configs/mainnet/upgrade.json line 9. Same predicate.
func TestFHEGasCost_Mul_DoSResistance_20M_PostFeeManager(t *testing.T) {
	assertDoSResistanceAtGasLimit(t, PostFeeManagerGasLimit, "20M-postFeeManager")
}

// TestFHEGasCost_Add_DoSResistance_12M_Mainnet asserts that GasAdd, when
// summed at the maximum per-block multiplicity, also stays within budget.
// Add is much faster than Mul (15 s vs 78 s) so even with the lower
// per-op gas cost the predicate holds.
func TestFHEGasCost_Add_DoSResistance_12M_Mainnet(t *testing.T) {
	maxAddsPerBlock := MainnetCChainGasLimit / GasAdd
	totalWallClockMs := maxAddsPerBlock * WallClockMsAddUint8
	require.LessOrEqual(t, totalWallClockMs, BlockComputeBudgetMs,
		"12M-mainnet-add: max %d adds/block × %d ms/add = %d ms > %d ms budget",
		maxAddsPerBlock, WallClockMsAddUint8, totalWallClockMs, BlockComputeBudgetMs)
	t.Logf("12M-mainnet-add: max adds/block=%d, wall-clock=%d ms", maxAddsPerBlock, totalWallClockMs)
}

// TestFHEGasCost_GasMul_MeetsActivationGateThreshold proves that the
// derived GasMul value satisfies the gate's MinSafeGasMulRatio when
// gasLimit ≥ MainnetCChainGasLimit × MinSafeGasMulRatio. (Equivalently,
// the gate refuses at exactly the gas limits we need it to refuse at.)
func TestFHEGasCost_GasMul_MeetsActivationGateThreshold(t *testing.T) {
	// The gate refuses if gasLimit < GasMul × MinSafeGasMulRatio.
	// At MainnetCChainGasLimit (12M): MUST refuse (since GasMul=936M > 12M).
	require.Greater(t, GasMul*MinSafeGasMulRatio, MainnetCChainGasLimit,
		"Activation gate must refuse at mainnet gasLimit (the precompile is "+
			"currently too expensive to safely ship at 12M block-gas-limit)")

	// At ReferenceGasLimit30M (30M): MUST still refuse.
	require.Greater(t, GasMul*MinSafeGasMulRatio, ReferenceGasLimit30M,
		"Activation gate must refuse at 30M reference gasLimit too")

	// At PostFeeManagerGasLimit (20M): MUST refuse.
	require.Greater(t, GasMul*MinSafeGasMulRatio, PostFeeManagerGasLimit,
		"Activation gate must refuse at 20M post-fee-manager gasLimit")

	// Only when gasLimit reaches GasMul itself does the gate let activation
	// proceed. Document the value so operators know what they need.
	t.Logf("Activation requires gasLimit >= %d (current Lux mainnet: %d, "+
		"post-fee-manager: %d). To unblock: raise gasLimit via feeConfigManagerConfig "+
		"OR reduce GasMul by reducing WallClockMsMulUint8 (requires faster TFHE evaluator).",
		GasMul*MinSafeGasMulRatio, MainnetCChainGasLimit, PostFeeManagerGasLimit)
}
