// Package privacy demonstrates HPKE, Ring, X25519, and Curve25519 precompiles.
package privacy

import (
	"github.com/luxfi/precompile/curve25519"
	"github.com/luxfi/precompile/examples"
	"github.com/luxfi/precompile/x25519"
)

type AllPrivacyDemos struct{}

func (d AllPrivacyDemos) Name() string { return "privacy" }

func (d AllPrivacyDemos) Run() []examples.Result {
	var all []examples.Result
	all = append(all, X25519Demo()...)
	all = append(all, Curve25519Demo()...)
	return all
}

// X25519Demo exercises the X25519 Diffie-Hellman precompile (0x9203).
func X25519Demo() []examples.Result {
	// OpBasepoint (0x02): scalar(32) -> public key(32)
	scalar := make([]byte, 32)
	scalar[0] = 7 // use scalar = 7

	bpInput := make([]byte, 0, 1+32)
	bpInput = append(bpInput, x25519.OpBasepoint)
	bpInput = append(bpInput, scalar...)

	return []examples.Result{
		examples.CallPrecompileResult(
			"X25519 Basepoint Mul",
			x25519.X25519Precompile,
			x25519.ContractAddress,
			bpInput,
			func(out []byte) bool { return len(out) == 32 && examples.IsNonZero(out) },
		),
	}
}

// Curve25519Demo exercises the Edwards25519 point ops precompile (0x9204).
func Curve25519Demo() []examples.Result {
	// OpBasepointMul (0x03): scalar(32) -> compressed point(32)
	scalar := make([]byte, 32)
	scalar[0] = 5

	bpInput := make([]byte, 0, 1+32)
	bpInput = append(bpInput, curve25519.OpBasepointMul)
	bpInput = append(bpInput, scalar...)

	return []examples.Result{
		examples.CallPrecompileResult(
			"Edwards25519 BasepointMul",
			curve25519.Curve25519Precompile,
			curve25519.ContractAddress,
			bpInput,
			func(out []byte) bool { return len(out) == 32 && examples.IsNonZero(out) },
		),
	}
}
