package curves

import (
	schnorrkel "github.com/ChainSafe/go-schnorrkel"
	"github.com/luxfi/precompile/examples"
	"github.com/luxfi/precompile/sr25519"
)

// SR25519Demo exercises the SR25519 verify precompile (0x0A00).
func SR25519Demo() []examples.Result {
	// Generate SR25519 key pair using go-schnorrkel
	priv, pub, _ := schnorrkel.GenerateKeypair()

	msg := []byte("Lux precompile sr25519 demo")

	// Sign with "substrate" context (the default)
	transcript := schnorrkel.NewSigningContext([]byte("substrate"), msg)
	sig, _ := priv.Sign(transcript)

	// Input: pubkey(32) + sig(64) + message(variable)
	pubBytes := pub.Encode()
	sigBytes := sig.Encode()

	input := make([]byte, 0, 32+64+len(msg))
	input = append(input, pubBytes[:]...)
	input = append(input, sigBytes[:]...)
	input = append(input, msg...)

	return []examples.Result{
		examples.CallPrecompileResult(
			"SR25519 Verify",
			sr25519.SR25519VerifyPrecompile,
			sr25519.ContractAddress,
			input,
			func(out []byte) bool { return examples.LastByte32IsOne(out) },
		),
	}
}
