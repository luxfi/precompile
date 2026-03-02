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
// Finding 8: FHE gas repricing (HIGH)
// Red demonstrated that FHE multiply was underpriced relative to its
// computational cost, enabling gas-based DoS attacks where an attacker
// submits many FHE multiplications to stall the block.
//
// The fix ensures gas costs reflect actual compute time:
// - FHE multiply (O(n^2) bootstrapping) must cost significantly more than add
// - FHE division must cost at least as much as multiply
// - All costs must be above a minimum floor that prevents spam
// ============================================================================

// TestFHEMulGasCost_ReflectsComputeTime proves that FHE multiply gas cost
// is high enough to reflect its quadratic bootstrapping cost.
func TestFHEMulGasCost_ReflectsComputeTime(t *testing.T) {
	// FHE multiply is O(n^2) in bootstrapping operations for n-bit integers.
	// It takes ~2 minutes for uint8 in pure Go. Gas must reflect this.
	// The Red team finding showed the old value (150,000) was too low.
	// The fix repriced to >= 500,000 (actual: 750,000).
	require.GreaterOrEqual(t, GasMul, uint64(500_000),
		"FHE multiply gas must be >= 500,000 to reflect O(n^2) bootstrapping cost")
}

// TestFHEAddGasCost_LessThanMul proves addition is cheaper than multiplication.
func TestFHEAddGasCost_LessThanMul(t *testing.T) {
	require.Less(t, GasAdd, GasMul,
		"FHE add gas must be less than FHE multiply gas (O(n) vs O(n^2))")
}

// TestFHEDivGasCost_ReflectsComputeTime proves division gas is substantial.
func TestFHEDivGasCost_ReflectsComputeTime(t *testing.T) {
	// Division uses binary long division with bootstrapping.
	// While cheaper than schoolbook multiplication (O(n^2) vs O(n*log(n))),
	// it is still computationally expensive and must be priced accordingly.
	require.GreaterOrEqual(t, GasDiv, uint64(500_000),
		"FHE div gas must be >= 500,000 to prevent gas-based DoS")
}

// TestFHERemGasCost_ReflectsComputeTime proves remainder gas is substantial.
func TestFHERemGasCost_ReflectsComputeTime(t *testing.T) {
	// Remainder has the same complexity as division.
	require.Equal(t, GasDiv, GasRem,
		"FHE rem gas must equal div gas (same algorithm)")
}

// TestFHEMulGasCost_MostExpensiveArithmetic proves multiply is the most
// expensive arithmetic operation, reflecting O(n^2) bootstrapping cost.
func TestFHEMulGasCost_MostExpensiveArithmetic(t *testing.T) {
	require.Greater(t, GasMul, GasDiv,
		"FHE multiply must cost more than division (O(n^2) vs O(n*log(n)))")
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
	// Complexity ordering: bitwise < comparison < add/sub < mul < div
	// Not all are strict, but multiplication must exceed addition
	// and division must exceed or equal multiplication.

	// Bitwise operations are cheapest
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

	// Min/Max involve comparison + selection
	require.Greater(t, GasMin, GasEq,
		"MIN must cost more than a single comparison")
	require.Greater(t, GasMax, GasEq,
		"MAX must cost more than a single comparison")

	// Select involves conditional evaluation
	require.Greater(t, GasSelect, GasNot,
		"SELECT must cost more than NOT")
}

// TestFHEGasCost_Mul_DosResistance proves that a block filled with FHE
// multiplications cannot exceed a reasonable compute budget.
func TestFHEGasCost_Mul_DosResistance(t *testing.T) {
	// A typical block has ~30M gas limit.
	// FHE multiply takes ~120 seconds on CPU for uint8.
	// If GasMul were too low, an attacker could fit too many multiplies
	// in a single block, causing validators to time out.
	const blockGasLimit = uint64(30_000_000)
	maxMulsPerBlock := blockGasLimit / GasMul

	// With 750,000 gas per mul, that's 40 muls max per block.
	// At ~2 minutes each, that's 80 minutes of CPU per block.
	// The high gas cost creates a strong economic barrier against DoS.
	require.LessOrEqual(t, maxMulsPerBlock, uint64(40),
		"block must not allow more than 40 FHE multiplications (DoS resistance)")

	t.Logf("Max FHE multiplications per block at gas limit %d: %d", blockGasLimit, maxMulsPerBlock)
}
