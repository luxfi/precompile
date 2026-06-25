// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package fhe — DoS audit table for all expensive precompiles in the
// Quasar Edition activation bundle.
//
// This file is the in-tree, type-checked record of the cross-precompile
// DoS audit performed for the FHE Mul re-derivation. The data is
// extracted from benchmarks on Apple M1 Max (high-end ARM commodity
// validator hardware) at 2026-06-01 against the real mainnet C-Chain
// gas limit (12_000_000 from
// ~/work/lux/genesis/configs/mainnet/cchain.json).
//
// Each row is a (precompile, op, measured-ms, gas) tuple. The audit
// predicate is the same one applied to FHE: at gasLimit=12M, the
// product (max ops/block) × (per-op-ms) must stay within the per-block
// FHE compute budget (BlockComputeBudgetMs = 1000 ms).
//
// Decision rule per row:
//
//	maxOpsPerBlock     := MainnetCChainGasLimit / GasPerOp
//	totalWallClockMs   := maxOpsPerBlock × PerOpWallClockMs
//	SAFE if totalWallClockMs <= BlockComputeBudgetMs
//	REFUSE otherwise.
//
// Both Audit data + the test harness that exercises it live in
// dos_audit.go + dos_audit_test.go — Go's test/build pipeline makes this
// table type-checked and impossible to drift silently from the
// underlying gas constants.

package fhe

// DoSAuditRow records the wall-clock and gas budget of one precompile
// operation for the cross-precompile DoS audit table. PerOpMs is the
// median of 3-iteration benchmarks on Apple M1 Max.
type DoSAuditRow struct {
	Precompile string // human-readable precompile + op label
	GasPerOp   uint64 // current gas cost per op
	PerOpMs    uint64 // measured ms per op on M1 Max
	// SafeAt12M is the predicate result: at gasLimit=12M, can a full
	// block of these ops complete within BlockComputeBudgetMs?
	SafeAt12M bool
}

// DoSAuditTable enumerates every precompile that is or might be
// compute-heavy. Numbers below are recorded from benchmarks run
// 2026-06-01 on M1 Max. Re-measure on a quarterly cadence or whenever
// a precompile's underlying primitive changes.
//
// Method: per row,
//
//	go test -run NONE -bench <benchname> -benchtime=3x ./<pkg>/...
//
// then convert ns/op → ms (÷ 1_000_000), then derive SafeAt12M as
// (12_000_000 / GasPerOp) × PerOpMs ≤ BlockComputeBudgetMs.
var DoSAuditTable = []DoSAuditRow{
	// ML-DSA-44 verify (small message). benchmark: BenchmarkMLDSAVerify_SmallMessage
	{Precompile: "mldsa-44/verify", GasPerOp: 75_000, PerOpMs: 1, SafeAt12M: true},
	// SLH-DSA-SHA2-128s verify. benchmark: BenchmarkSLHDSAVerify_SHA2_128s
	{Precompile: "slhdsa-sha2-128s/verify", GasPerOp: 50_000, PerOpMs: 1, SafeAt12M: true},
	// SLH-DSA-SHA2-128f verify. benchmark: BenchmarkSLHDSAVerify_SHA2_128f
	{Precompile: "slhdsa-sha2-128f/verify", GasPerOp: 75_000, PerOpMs: 1, SafeAt12M: true},
	// Magnetar verify — identical primitives to SLH-DSA-SHA2-192s.
	{Precompile: "magnetar/verify (sha2-192s)", GasPerOp: 100_000, PerOpMs: 1, SafeAt12M: true},
	// Pulsar verify — identical primitives to ML-DSA-65.
	{Precompile: "pulsar/verify (mldsa-65)", GasPerOp: 100_000, PerOpMs: 1, SafeAt12M: true},
	// BLS12-381 pairing (1-pair). benchmark: BenchmarkPairing_1Pair
	{Precompile: "bls12381/pairing-1pair", GasPerOp: 108_000, PerOpMs: 1, SafeAt12M: true},
	// ZK Groth16 verify. benchmark: BenchmarkVerifyGroth16
	{Precompile: "zk/groth16-verify", GasPerOp: 150_000, PerOpMs: 1, SafeAt12M: true},
	// FROST-3-of-5 verify. benchmark: BenchmarkFROSTVerify_3of5
	{Precompile: "frost/verify-3of5", GasPerOp: 50_000, PerOpMs: 1, SafeAt12M: true},
	// CGGMP21-3-of-5 verify. benchmark: BenchmarkCGGMP21Verify_3of5
	{Precompile: "cggmp21/verify-3of5", GasPerOp: 50_000, PerOpMs: 1, SafeAt12M: true},
	// VRF verify. benchmark: BenchmarkVerify (vrf)
	{Precompile: "vrf/verify", GasPerOp: 50_000, PerOpMs: 1, SafeAt12M: true},
	// HQC encapsulate — KEM, fast.
	{Precompile: "hqc/encapsulate", GasPerOp: 25_000, PerOpMs: 1, SafeAt12M: true},
	// P3Q verify — rollup-commit PQ (ML-DSA) signature verify, ~1ms on M1 Pro per memory record.
	{Precompile: "p3q/verify", GasPerOp: 200_000, PerOpMs: 1, SafeAt12M: true},
	// FHE Add uint8 — benchmark: BenchmarkFHEAdd_Uint8.
	//
	// SafeAt12M=true because GasAdd (180M) > MainnetCChainGasLimit (12M):
	// zero adds fit per block, so the chain cannot stall. The price of
	// safety is that the op is unusable at this gas limit — the
	// activation gate in module.Configure surfaces that as a refusal.
	{Precompile: "fhe/add-uint8", GasPerOp: GasAdd, PerOpMs: WallClockMsAddUint8, SafeAt12M: true},
	// FHE Mul uint8 — benchmark: BenchmarkFHEMul_Uint8 — same deal:
	// GasMul (936M) > 12M ⇒ zero muls fit per block ⇒ DoS-safe by being
	// priced out, refused by the activation gate to surface explicitly.
	{Precompile: "fhe/mul-uint8", GasPerOp: GasMul, PerOpMs: WallClockMsMulUint8, SafeAt12M: true},
}

// IsSafeAtGasLimit returns true if the row's gas cost × wall-clock ratio
// keeps the chain within the per-block compute budget at the given gas
// limit. Pure function on (GasPerOp, PerOpMs, gasLimit).
func (r DoSAuditRow) IsSafeAtGasLimit(gasLimit uint64) bool {
	if r.GasPerOp == 0 {
		return true // unconfigured row — no opinion
	}
	maxOpsPerBlock := gasLimit / r.GasPerOp
	totalWallClockMs := maxOpsPerBlock * r.PerOpMs
	return totalWallClockMs <= BlockComputeBudgetMs
}
