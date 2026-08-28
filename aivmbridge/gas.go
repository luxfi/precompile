// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// gas.go — flat, deterministic gas for the two bridge ops. Gas is a pure function
// of the selector (and, for verify, a per-proof-node increment) so every validator
// charges identically. No gas depends on any A-Chain observation.

package aivmbridge

const (
	// GasSubmitInferenceIntent is a write-class op: it derives a deterministic id,
	// runs the replay/calldata checks, and writes the C outbox record across a
	// handful of storage slots. Sized at the dex native-intent tier (write-class).
	GasSubmitInferenceIntent uint64 = 40_000

	// GasVerifyInferenceReceiptBase is the base for a committed-receipt verification:
	// decode + recompute receipt_hash + look up the committed root + match/consume the
	// pending intent. The merkle walk adds GasVerifyPerProofNode per path node so a
	// deep proof pays for its hashing (defense against a griefing oversized proof; the
	// path length is also hard-capped by MaxProofDepth in decoding).
	GasVerifyInferenceReceiptBase uint64 = 30_000

	// GasVerifyPerProofNode is charged per merkle path node hashed during verify.
	GasVerifyPerProofNode uint64 = 1_000

	// GasVerifyComputeProofBase is the base for a native proof-of-inference opening check: the
	// wire decode + the Merkle inclusion of the opened matmul. The Freivalds re-execution adds
	// the per-field-op price below.
	GasVerifyComputeProofBase uint64 = 30_000

	// GasVerifyComputeProofPerFieldOp prices each F_p mul-add of the Freivalds check
	// (O(tk+kn+tn) per challenge vector). Sized so a 256-wide slice costs ~1M gas and a whole
	// 4096-wide layer is unaffordable — which forces a challenger to open a bounded SLICE.
	GasVerifyComputeProofPerFieldOp uint64 = 2
)

// verifyGas returns the total gas for a VerifyInferenceReceipt call given the
// number of merkle path nodes. pathLen is bounded by MaxProofDepth at decode time,
// so this product can never overflow a uint64 in practice.
func verifyGas(pathLen int) uint64 {
	return GasVerifyInferenceReceiptBase + uint64(pathLen)*GasVerifyPerProofNode
}
