package pq

import (
	"crypto/sha256"

	"github.com/luxfi/precompile/examples"
	rt "github.com/luxfi/precompile/corona"
)

// CoronaDemo exercises the Corona lattice threshold precompile (0x0200..0B).
// Corona requires a full threshold signing ceremony which is heavy to set up
// in a demo context. We test the input parsing and gas calculation path.
func CoronaDemo() []examples.Result {
	// Build minimal input: threshold(4) + totalParties(4) + messageHash(32) + signature
	// With threshold=2, totalParties=3
	hash := sha256.Sum256([]byte("Lux precompile Corona demo"))

	input := make([]byte, 0, 4+4+32)
	input = append(input, examples.Uint32BE(2)...)  // threshold
	input = append(input, examples.Uint32BE(3)...)  // total parties
	input = append(input, hash[:]...)                // message hash

	// This will fail with "invalid input length" since we don't have a real
	// Corona signature, but it exercises the precompile dispatch and gas calc
	r := examples.CallPrecompileResult(
		"Corona Threshold (parse test)",
		rt.CoronaThresholdPrecompile,
		rt.ContractCoronaThresholdAddress,
		input,
		func(out []byte) bool {
			// Expected to fail validation but not panic
			return true
		},
	)
	// This is a parse/gas test -- it will error but that is expected
	r.Pass = r.Error != nil // we EXPECT an error (short input)
	r.Error = nil           // clear the expected error for display

	return []examples.Result{r}
}
