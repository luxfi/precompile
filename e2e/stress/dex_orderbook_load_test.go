//go:build stress

// dex_orderbook_load_test benchmarks StableSwap AMM operations under load:
// - 10K swap calculations per second target
// - Invariant D computation throughput
// - Memory stability under sustained load
package stress

import (
	"math/big"
	"runtime"
	"testing"

	"github.com/luxfi/precompile/e2e/harness"
	"github.com/luxfi/precompile/stableswap"
	"github.com/stretchr/testify/require"
)

func BenchmarkStableSwap_GetDy_10K(b *testing.B) {
	balance := harness.PadLeft(new(big.Int).SetUint64(1_000_000).Bytes(), 32)
	amp := harness.PadLeft(new(big.Int).SetUint64(100).Bytes(), 32)
	dx := harness.PadLeft(new(big.Int).SetUint64(1000).Bytes(), 32)

	input := make([]byte, 0, 1+1+1+32+1+64+32)
	input = append(input, stableswap.OpGetDy)
	input = append(input, 0)    // i
	input = append(input, 1)    // j
	input = append(input, dx...)
	input = append(input, 2)    // numTokens
	input = append(input, balance...)
	input = append(input, balance...)
	input = append(input, amp...)

	var totalGas uint64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 10_000; j++ {
			_, gas, err := harness.Call(
				stableswap.Precompile,
				stableswap.ContractAddress,
				input,
				true,
			)
			if err != nil {
				b.Fatalf("GetDy failed at iteration %d: %v", j, err)
			}
			totalGas += gas
		}
	}
	b.ReportMetric(float64(totalGas)/float64(b.N), "gas/10Kops")
	b.ReportMetric(float64(b.N)*10_000/b.Elapsed().Seconds(), "ops/sec")
}

func BenchmarkStableSwap_GetD(b *testing.B) {
	balance := harness.PadLeft(new(big.Int).SetUint64(1_000_000).Bytes(), 32)
	amp := harness.PadLeft(new(big.Int).SetUint64(100).Bytes(), 32)

	input := make([]byte, 0, 1+1+64+32)
	input = append(input, stableswap.OpGetD)
	input = append(input, 2)
	input = append(input, balance...)
	input = append(input, balance...)
	input = append(input, amp...)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := harness.Call(
			stableswap.Precompile,
			stableswap.ContractAddress,
			input,
			true,
		)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestStableSwap_MemoryStability(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	balance := harness.PadLeft(new(big.Int).SetUint64(1_000_000).Bytes(), 32)
	amp := harness.PadLeft(new(big.Int).SetUint64(100).Bytes(), 32)
	dx := harness.PadLeft(new(big.Int).SetUint64(1000).Bytes(), 32)

	input := make([]byte, 0, 1+1+1+32+1+64+32)
	input = append(input, stableswap.OpGetDy)
	input = append(input, 0)
	input = append(input, 1)
	input = append(input, dx...)
	input = append(input, 2)
	input = append(input, balance...)
	input = append(input, balance...)
	input = append(input, amp...)

	// Take baseline memory measurement
	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	// Run 100K operations
	for i := 0; i < 100_000; i++ {
		_, _, err := harness.Call(
			stableswap.Precompile,
			stableswap.ContractAddress,
			input,
			true,
		)
		require.NoError(t, err)
	}

	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	// Memory growth should be bounded
	heapGrowth := int64(memAfter.HeapAlloc) - int64(memBefore.HeapAlloc)
	t.Logf("Heap before: %d MB, after: %d MB, growth: %d KB",
		memBefore.HeapAlloc/1024/1024, memAfter.HeapAlloc/1024/1024, heapGrowth/1024)
	t.Logf("GC pauses: %d total, %d ns max",
		memAfter.NumGC-memBefore.NumGC, memAfter.PauseNs[(memAfter.NumGC+255)%256])

	// Allow up to 50MB growth for 100K operations (generous bound)
	require.True(t, heapGrowth < 50*1024*1024,
		"memory grew by %d MB (max 50MB allowed for 100K ops)", heapGrowth/1024/1024)
}
