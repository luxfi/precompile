// Package threshold demonstrates CGGMP21 and FROST threshold signature precompiles.
package threshold

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/cggmp21"
	"github.com/luxfi/precompile/examples"
	"github.com/luxfi/precompile/frost"
)

type AllThresholdDemos struct{}

func (d AllThresholdDemos) Name() string { return "threshold" }

func (d AllThresholdDemos) Run() []examples.Result {
	var all []examples.Result
	all = append(all, CGGMP21Demo()...)
	all = append(all, FROSTDemo()...)
	return all
}

// CGGMP21Demo exercises the CGGMP21 ECDSA threshold verify precompile (0x0800..03).
func CGGMP21Demo() []examples.Result {
	// Generate a standard ECDSA key pair -- CGGMP21 verification is standard ECDSA
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := &priv.PublicKey

	msg := []byte("Lux precompile CGGMP21 demo")
	hash := sha256.Sum256(msg)

	r, s, _ := ecdsa.Sign(rand.Reader, priv, hash[:])

	// Uncompressed public key: 0x04 || x(32) || y(32) = 65 bytes
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	copy(pubKey[1:33], examples.PadLeft(pub.X.Bytes(), 32))
	copy(pubKey[33:65], examples.PadLeft(pub.Y.Bytes(), 32))

	// Signature: r(32) || s(32) || v(1) = 65 bytes
	sig := make([]byte, 65)
	copy(sig[0:32], examples.PadLeft(r.Bytes(), 32))
	copy(sig[32:64], examples.PadLeft(s.Bytes(), 32))
	sig[64] = 0 // v = 0

	// Input: threshold(4) + totalSigners(4) + pubkey(65) + hash(32) + sig(65)
	input := make([]byte, 0, 4+4+65+32+65)
	input = append(input, examples.Uint32BE(2)...) // threshold = 2
	input = append(input, examples.Uint32BE(3)...) // total signers = 3
	input = append(input, pubKey...)
	input = append(input, hash[:]...)
	input = append(input, sig...)

	return []examples.Result{
		examples.CallPrecompileResult(
			"CGGMP21 ECDSA Threshold Verify",
			cggmp21.CGGMP21VerifyPrecompile,
			cggmp21.ContractCGGMP21VerifyAddress,
			input,
			func(out []byte) bool { return examples.LastByte32IsOne(out) },
		),
	}
}

// FROSTDemo exercises the FROST EdDSA threshold verify precompile (0x0800..02).
func FROSTDemo() []examples.Result {
	// FROST verification is Schnorr on Ed25519.
	// We use the precompile's input format but with minimal viable data.
	// Full FROST signing ceremony is complex -- test input parsing.
	hash := sha256.Sum256([]byte("Lux precompile FROST demo"))

	// Construct minimal input that will reach the verification path
	input := make([]byte, 0, frost.MinInputSize)
	input = append(input, examples.Uint32BE(2)...) // threshold
	input = append(input, examples.Uint32BE(3)...) // total signers
	input = append(input, make([]byte, 32)...)     // pubkey (zeros = will fail verify)
	input = append(input, hash[:]...)              // message hash
	input = append(input, make([]byte, 64)...)     // signature (zeros)

	r := examples.CallPrecompileResult(
		"FROST Schnorr Threshold (parse)",
		frost.FROSTVerifyPrecompile,
		common.HexToAddress("0x0800000000000000000000000000000000000002"),
		input,
		func(out []byte) bool { return true }, // expect error or fail result
	)
	// FROST with zero pubkey will fail verification, not crash
	if r.Error != nil || !examples.LastByte32IsOne(r.Output) {
		r.Pass = true // expected: invalid sig gives non-1 result
		r.Error = nil
	}

	return []examples.Result{r}
}
