package curves

import (
	"crypto/ed25519"
	"crypto/sha256"

	"github.com/luxfi/geth/common"
	ed "github.com/luxfi/precompile/ed25519"
	"github.com/luxfi/precompile/examples"
)

// Ed25519Demo exercises the Ed25519 verify precompile (0x3211).
func Ed25519Demo() []examples.Result {
	// Generate a key pair and sign a message
	pub, priv, _ := ed25519.GenerateKey(nil)
	msg := []byte("Lux precompile Ed25519 demo")
	sig := ed25519.Sign(priv, msg)

	// The precompile expects: hash(32) + sig(64) + pubkey(32) = 128 bytes
	hash := sha256.Sum256(msg)

	input := make([]byte, 128)
	copy(input[0:32], hash[:])
	copy(input[32:96], sig)
	copy(input[96:128], pub)

	// We need to sign the hash, not the raw message, for the precompile
	sigOfHash := ed25519.Sign(priv, hash[:])
	copy(input[32:96], sigOfHash)

	return []examples.Result{
		examples.CallPrecompileResult(
			"Ed25519 Verify",
			ed.Ed25519VerifyPrecompile,
			ed.ContractAddress,
			input,
			func(out []byte) bool { return examples.LastByte32IsOne(out) },
		),
		// Invalid signature test
		func() examples.Result {
			bad := make([]byte, 128)
			copy(bad, input)
			bad[32] ^= 0xFF // corrupt first byte of signature
			return examples.CallPrecompileResult(
				"Ed25519 Verify (invalid sig)",
				ed.Ed25519VerifyPrecompile,
				ed.ContractAddress,
				bad,
				func(out []byte) bool { return len(out) == 0 }, // should return empty
			)
		}(),
		// Wrong length test
		examples.CallPrecompileResult(
			"Ed25519 Verify (bad length)",
			ed.Ed25519VerifyPrecompile,
			common.HexToAddress("0x3211000000000000000000000000000000000000"),
			[]byte{0x01, 0x02, 0x03}, // too short
			func(out []byte) bool { return len(out) == 0 },
		),
	}
}
