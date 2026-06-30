package hashing_zk

import (
	"github.com/luxfi/precompile/examples"
	"github.com/luxfi/precompile/pasta"
)

// PastaDemo exercises the Pasta curves precompile (0x0500..08).
// Pasta = Pallas + Vesta curves, used in Halo2 proofs.
func PastaDemo() []examples.Result {
	// OpPallasAdd (0x01): add two Pallas points
	// Pallas generator: x,y each 32 bytes
	// Use identity points (zeros) for a simple test that exercises the dispatch path
	// Actually use the Pallas generator from gnark-crypto
	genX := examples.PadLeft([]byte{1}, 32) // x = 1 is not on Pallas, so use a known test vector
	genY := examples.PadLeft([]byte{2}, 32)

	// For a clean test, use the basepoint multiplication path
	// OpPallasBaseMul (0x03): scalar(32) -> point(64)
	scalarInput := make([]byte, 0, 1+32)
	scalarInput = append(scalarInput, 0x03) // OpPallasBaseMul
	scalarInput = append(scalarInput, examples.PadLeft([]byte{7}, 32)...)

	_ = genX
	_ = genY

	return []examples.Result{
		examples.CallPrecompileResult(
			"Pasta Pallas BaseMul",
			pasta.PastaPrecompile,
			pasta.ContractAddress,
			scalarInput,
			func(out []byte) bool { return len(out) == 64 && examples.IsNonZero(out) },
		),
	}
}
