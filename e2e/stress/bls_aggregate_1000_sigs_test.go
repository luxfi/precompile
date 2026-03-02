//go:build stress

// bls_aggregate_1000_sigs_test benchmarks BLS12-381 operations at scale:
// - 1000 G1 additions (simulating signature aggregation)
// - G1Mul throughput
// - G2 operations
package stress

import (
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	bls "github.com/luxfi/precompile/bls12381"
	"github.com/luxfi/precompile/e2e/harness"
	"github.com/stretchr/testify/require"
)

func encodeG1(p bls12381.G1Affine) []byte {
	out := make([]byte, 128)
	xBytes := p.X.Bytes()
	yBytes := p.Y.Bytes()
	// EIP-2537: 64-byte padded (16 zero prefix + 48 byte value)
	copy(out[16:64], xBytes[:])
	copy(out[80:128], yBytes[:])
	return out
}

func BenchmarkBLS12381_G1Add_1000(b *testing.B) {
	// Generate a valid G1 point (generator * 2)
	var g bls12381.G1Affine
	g.X.SetOne()
	g.Y.SetString("2") // simplified; real test needs on-curve point
	// Use the actual generator
	_, _, g1Gen, _ := bls12381.Generators()

	p1 := encodeG1(g1Gen)

	// G1Add input: 2 * 128 bytes = 256 bytes
	input := make([]byte, 256)
	copy(input[0:128], p1)
	copy(input[128:256], p1)

	var totalGas uint64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 1000; j++ {
			_, gas, err := harness.Call(
				bls.G1AddModule.Contract,
				bls.G1AddAddress,
				input,
				true,
			)
			if err != nil {
				b.Fatalf("G1Add failed at iteration %d: %v", j, err)
			}
			totalGas += gas
		}
	}
	b.ReportMetric(float64(totalGas)/float64(b.N), "gas/1000ops")
	b.ReportMetric(float64(b.N)*1000/b.Elapsed().Seconds(), "ops/sec")
}

func BenchmarkBLS12381_G1Mul(b *testing.B) {
	_, _, g1Gen, _ := bls12381.Generators()
	p1 := encodeG1(g1Gen)

	// G1Mul input: point(128) + scalar(32) = 160 bytes
	scalar := harness.PadLeft(big.NewInt(42).Bytes(), 32)
	input := make([]byte, 160)
	copy(input[0:128], p1)
	copy(input[128:160], scalar)

	var totalGas uint64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, gas, err := harness.Call(
			bls.G1MulModule.Contract,
			bls.G1MulAddress,
			input,
			true,
		)
		if err != nil {
			b.Fatalf("G1Mul failed: %v", err)
		}
		totalGas += gas
	}
	b.ReportMetric(float64(totalGas)/float64(b.N), "gas/op")
}

func TestBLS12381_G1Add_Correctness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	_, _, g1Gen, _ := bls12381.Generators()

	// Build a proper on-curve generator point
	p := encodeG1(g1Gen)

	input := make([]byte, 256)
	copy(input[0:128], p)
	copy(input[128:256], p)

	out, gas, err := harness.Call(
		bls.G1AddModule.Contract,
		bls.G1AddAddress,
		input,
		true,
	)
	require.NoError(t, err, "G1Add should succeed with valid generator")
	require.Len(t, out, 128, "G1Add output should be 128 bytes (G1 point)")
	harness.GasReport(t, "G1Add", gas)

	// Verify output is a valid G1 point (non-zero)
	allZero := true
	for _, b := range out {
		if b != 0 {
			allZero = false
			break
		}
	}
	require.False(t, allZero, "G1Add output should not be all zeros")

	// The result of G + G should be 2G
	// Decode output and verify it's on the curve
	var result bls12381.G1Affine
	var xFp, yFp fp.Element
	xFp.SetBytes(out[16:64])
	yFp.SetBytes(out[80:128])
	result.X = xFp
	result.Y = yFp
	require.True(t, result.IsOnCurve(), "result must be on BLS12-381 G1 curve")
}
