package pq

import (
	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/luxfi/precompile/examples"
	slh "github.com/luxfi/precompile/slhdsa"
)

// SLHDSADemo exercises the SLH-DSA verify precompile (0x0600..01).
func SLHDSADemo() []examples.Result {
	// Generate SLH-DSA-SHA2-128s key pair (smallest, fastest for demo)
	pub, priv, _ := slhdsa.GenerateKey(nil, slhdsa.ParamIDSHA2Small128)

	msg := []byte("Lux precompile SLH-DSA demo")
	sig := slhdsa.Sign(priv, msg, nil, false)

	pubBytes, _ := pub.MarshalBinary()

	// Input format: mode(1) + pubkeylen(2) + pubkey + msglen(2) + msg + sig
	input := make([]byte, 0, 1+2+len(pubBytes)+2+len(msg)+len(sig))
	input = append(input, slh.ModeSHA2_128s)
	input = append(input, examples.Uint16BE(uint16(len(pubBytes)))...)
	input = append(input, pubBytes...)
	input = append(input, examples.Uint16BE(uint16(len(msg)))...)
	input = append(input, msg...)
	input = append(input, sig...)

	return []examples.Result{
		examples.CallPrecompileResult(
			"SLH-DSA-SHA2-128s Verify",
			slh.SLHDSAVerifyPrecompile,
			slh.ContractSLHDSAVerifyAddress,
			input,
			func(out []byte) bool { return examples.LastByte32IsOne(out) },
		),
	}
}
