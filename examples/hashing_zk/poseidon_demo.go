package hashing_zk

import (
	"github.com/luxfi/precompile/examples"
	"github.com/luxfi/precompile/poseidon"
)

// PoseidonDemo exercises the Poseidon2 ZK-friendly hash precompile (0x0500..05).
func PoseidonDemo() []examples.Result {
	// OpHash: hash 2 field elements (each 32 bytes, BN254 scalar field)
	elem1 := examples.PadLeft([]byte{1}, 32)
	elem2 := examples.PadLeft([]byte{2}, 32)

	input := make([]byte, 0, 1+64)
	input = append(input, poseidon.OpHash)
	input = append(input, elem1...)
	input = append(input, elem2...)

	// OpHashPair: optimized 2-element hash
	pairInput := make([]byte, 0, 1+64)
	pairInput = append(pairInput, poseidon.OpHashPair)
	pairInput = append(pairInput, elem1...)
	pairInput = append(pairInput, elem2...)

	return []examples.Result{
		examples.CallPrecompileResult(
			"Poseidon2 Hash (2 elements)",
			poseidon.PoseidonPrecompile,
			poseidon.ContractAddress,
			input,
			func(out []byte) bool { return len(out) == 32 && examples.IsNonZero(out) },
		),
		examples.CallPrecompileResult(
			"Poseidon2 HashPair",
			poseidon.PoseidonPrecompile,
			poseidon.ContractAddress,
			pairInput,
			func(out []byte) bool { return len(out) == 32 && examples.IsNonZero(out) },
		),
	}
}
