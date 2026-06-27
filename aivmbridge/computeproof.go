// computeproof.go — the NATIVE proof-of-inference verification (the `computeattest` op).
//
// A prover commits a forward pass as a keccak Merkle root over per-matmul exact-integer operands
// (hanzo-engine emits it; crypto/poi defines the wire). To enforce "no real compute, no mint", a
// challenger opens a beacon-selected matmul and this precompile re-checks it NATIVELY: Merkle
// inclusion under the committed root + Freivalds C == A·B over F_p (p = 2^61-1). Native because a
// real-model-sized opening is far too much arithmetic for gas-bounded EVM bytecode; the Solidity
// ComputeWitnessLib is the byte-identical reference for small slices, this is the production path.
//
// Pure (reads no state, writes none) → safe under a static call. Returns one 32-byte word whose
// low bits carry the verdict, so one native call serves both the attest and the slash paths.
package aivmbridge

import (
	"fmt"

	"github.com/luxfi/crypto/poi"
)

// computeProofK is the number of Freivalds challenge vectors checked on-chain. k = 2 gives a
// soundness error <= (1/p)^2 ~ 2^-122 — a fabricated matmul survives with negligible probability.
const computeProofK = 2

// Result bits in the returned word's last byte.
const (
	resultIncluded    = 1 // the operands are committed under the transcript root (Merkle inclusion)
	resultFreivaldsOK = 2 // C == A·B (the matmul is genuine)
)

// computeProofGas is the gas for an opening: a base plus the Freivalds work (O(tk+kn+tn) per
// challenge vector). Identical formula in RequiredGas and Run so accounting agrees. The per-op
// price makes a large opening expensive, which is what forces a challenger to open a bounded
// SLICE of a layer rather than a whole 4096-wide matmul.
func computeProofGas(op poi.Opening) uint64 {
	return GasVerifyComputeProofBase + poi.FieldOps(op, computeProofK)*GasVerifyComputeProofPerFieldOp
}

// verifyComputeProof decodes a proof-of-inference opening and returns (included, freivaldsOK) in
// the low bits of a 32-byte word. The caller derives genuine = included && freivaldsOK and
// fraud = included && !freivaldsOK. Charges base before any work (bounds griefing on a malformed
// frame), then the Freivalds cost computed from the decoded — and dimension-bounded — operands.
func verifyComputeProof(args []byte, suppliedGas uint64) ([]byte, uint64, error) {
	if suppliedGas < GasVerifyComputeProofBase {
		return nil, 0, fmt.Errorf("aivmbridge: out of gas: need %d have %d", GasVerifyComputeProofBase, suppliedGas)
	}
	root, beacon, op, err := poi.DecodeOpening(args)
	if err != nil {
		// the base was affordable; consume it and surface the decode error.
		return nil, suppliedGas - GasVerifyComputeProofBase, err
	}
	cost := computeProofGas(op)
	if suppliedGas < cost {
		return nil, 0, fmt.Errorf("aivmbridge: out of gas: compute proof needs %d have %d", cost, suppliedGas)
	}
	included, ok, err := poi.CheckDecoded(root, beacon, op, computeProofK)
	if err != nil {
		return nil, suppliedGas - cost, err
	}
	var out [32]byte
	if included {
		out[31] |= resultIncluded
	}
	if ok {
		out[31] |= resultFreivaldsOK
	}
	return out[:], suppliedGas - cost, nil
}

// computeProofRequiredGas is the EVM's pre-charge estimate, matching {computeProofGas}. A
// malformed frame falls back to the base (the call reverts on decode anyway).
func computeProofRequiredGas(args []byte) uint64 {
	_, _, op, err := poi.DecodeOpening(args)
	if err != nil {
		return GasVerifyComputeProofBase
	}
	return computeProofGas(op)
}
