package pq

import (
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/luxfi/precompile/examples"
	"github.com/luxfi/precompile/mldsa"
)

// MLDSADemo exercises the ML-DSA verify precompile (0x0200..06).
func MLDSADemo() []examples.Result {
	// Generate ML-DSA-65 key pair
	pub, priv, _ := mldsa65.GenerateKey(nil)

	msg := []byte("Lux precompile ML-DSA-65 demo")
	sig := mldsa65.Sign(priv, msg, nil)

	pubBytes, _ := pub.MarshalBinary()
	sigBytes := sig

	// Input format: mode(1) + pubkey + msglen(32) + sig + msg
	input := make([]byte, 0, 1+len(pubBytes)+32+len(sigBytes)+len(msg))
	input = append(input, mldsa.ModeMLDSA65) // mode byte
	input = append(input, pubBytes...)        // public key
	input = append(input, examples.Uint256(uint64(len(msg)))...)
	input = append(input, sigBytes...)
	input = append(input, msg...)

	return []examples.Result{
		examples.CallPrecompileResult(
			"ML-DSA-65 Verify",
			mldsa.MLDSAVerifyPrecompile,
			mldsa.ContractMLDSAVerifyAddress,
			input,
			func(out []byte) bool { return examples.LastByte32IsOne(out) },
		),
	}
}
