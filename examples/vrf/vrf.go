// Package vrf demonstrates the ECVRF precompile (RFC 9381).
package vrf

import (
	"github.com/luxfi/precompile/examples"
	vrfpc "github.com/luxfi/precompile/vrf"
)

type VRFDemo struct{}

func (d VRFDemo) Name() string { return "vrf" }

func (d VRFDemo) Run() []examples.Result {
	// OpProofToHash (0x02): extract beta from a proof without verification.
	// We use a known proof structure: Gamma(32) + c(16) + s(32) = 80 bytes.
	// Gamma = identity point will fail gracefully, but we test the dispatch.
	proof := make([]byte, 80)
	// Set Gamma to the Ed25519 identity (which will fail proofToHash since it checks for identity)
	// Use a non-identity point: the Ed25519 basepoint compressed
	copy(proof[0:32], examples.HexDecode("5866666666666666666666666666666666666666666666666666666666666666"))
	// c and s = small valid scalars
	proof[32] = 1 // c = 1 (little-endian, first 16 bytes)
	proof[48] = 1 // s = 1 (little-endian, first 32 bytes)

	input := make([]byte, 0, 1+80)
	input = append(input, vrfpc.OpProofToHash)
	input = append(input, proof...)

	return []examples.Result{
		examples.CallPrecompileResult(
			"ECVRF ProofToHash",
			vrfpc.VRFPrecompile,
			vrfpc.ContractAddress,
			input,
			func(out []byte) bool {
				// proofToHash returns 64-byte SHA-512 output (beta_string)
				return len(out) == 64 && examples.IsNonZero(out)
			},
		),
	}
}
