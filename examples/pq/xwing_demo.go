package pq

import (
	"github.com/cloudflare/circl/kem/xwing"
	"github.com/luxfi/precompile/examples"
	xw "github.com/luxfi/precompile/xwing"
)

// XWingDemo exercises the X-Wing hybrid KEM precompile (0x2221).
func XWingDemo() []examples.Result {
	// Generate X-Wing key pair (X25519 + ML-KEM-768)
	pub, _, _ := xwing.Scheme().GenerateKeyPair()
	pubBytes, _ := pub.MarshalBinary()

	// Input: op(1) + pubkey
	input := make([]byte, 0, 1+len(pubBytes))
	input = append(input, xw.OpEncapsulate)
	input = append(input, pubBytes...)

	return []examples.Result{
		examples.CallPrecompileResult(
			"X-Wing Encapsulate",
			xw.XWingPrecompile,
			xw.ContractAddress,
			input,
			func(out []byte) bool {
				// X-Wing ct + shared secret -- non-empty output means success
				return len(out) > 32 && examples.IsNonZero(out)
			},
		),
	}
}
