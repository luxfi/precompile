package pq

import (
	circl768 "github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/luxfi/precompile/examples"
	"github.com/luxfi/precompile/mlkem"
)

// MLKEMDemo exercises the ML-KEM encapsulate precompile (0x0200..07).
func MLKEMDemo() []examples.Result {
	// Generate ML-KEM-768 key pair
	_, pub, _ := circl768.GenerateKeyPair(nil)
	pubBytes, _ := pub.MarshalBinary()

	// Input: op(1) + mode(1) + pubkey
	input := make([]byte, 0, 2+len(pubBytes))
	input = append(input, mlkem.OpEncapsulate)
	input = append(input, mlkem.ModeMLKEM768)
	input = append(input, pubBytes...)

	return []examples.Result{
		examples.CallPrecompileResult(
			"ML-KEM-768 Encapsulate",
			mlkem.MLKEMPrecompile,
			mlkem.ContractAddress,
			input,
			func(out []byte) bool {
				// Output: ciphertext(1088) + shared_secret(32) = 1120 bytes
				return len(out) == 1088+32 && examples.IsNonZero(out)
			},
		),
	}
}
