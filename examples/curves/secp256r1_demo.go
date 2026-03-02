package curves

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/examples"
	"github.com/luxfi/precompile/secp256r1"
)

// Secp256r1Demo exercises the P-256 verify precompile (EIP-7212, 0x0100).
func Secp256r1Demo() []examples.Result {
	// Generate P-256 key pair
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := &priv.PublicKey

	msg := []byte("Lux precompile secp256r1 demo")
	hash := sha256.Sum256(msg)

	r, s, _ := ecdsa.Sign(rand.Reader, priv, hash[:])

	// Input: hash(32) + r(32) + s(32) + x(32) + y(32) = 160 bytes
	input := make([]byte, 160)
	copy(input[0:32], hash[:])
	copy(input[32:64], examples.PadLeft(r.Bytes(), 32))
	copy(input[64:96], examples.PadLeft(s.Bytes(), 32))
	copy(input[96:128], examples.PadLeft(pub.X.Bytes(), 32))
	copy(input[128:160], examples.PadLeft(pub.Y.Bytes(), 32))

	// secp256r1 uses a different Run signature (not StatefulPrecompiledContract)
	// It has Run(input) ([]byte, error) -- call it directly
	c := &secp256r1.Contract{}
	out, err := c.Run(input)
	pass := err == nil && examples.LastByte32IsOne(out)
	gasUsed := uint64(secp256r1.P256VerifyGas)

	return []examples.Result{
		{
			Name:     "secp256r1 (P-256) Verify",
			Address:  common.HexToAddress(secp256r1.P256VerifyAddress),
			Calldata: input,
			Output:   out,
			GasUsed:  gasUsed,
			Pass:     pass,
			Error:    err,
		},
	}
}
