package hashing_zk

import (
	"github.com/luxfi/precompile/examples"
	"github.com/luxfi/precompile/pedersen"
)

// PedersenDemo exercises the Pedersen commitment precompile (0x0500..06).
func PedersenDemo() []examples.Result {
	// OpCommit: value(32) + blinding(32) -> commitment(32)
	value := examples.PadLeft([]byte{42}, 32)
	blinding := examples.PadLeft([]byte{7}, 32)

	commitInput := make([]byte, 0, 1+64)
	commitInput = append(commitInput, pedersen.OpCommit)
	commitInput = append(commitInput, value...)
	commitInput = append(commitInput, blinding...)

	return []examples.Result{
		examples.CallPrecompileResult(
			"Pedersen Commit",
			pedersen.PedersenPrecompile,
			pedersen.ContractAddress,
			commitInput,
			func(out []byte) bool { return len(out) == 32 && examples.IsNonZero(out) },
		),
	}
}
