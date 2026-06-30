package hashing_zk

import (
	"bytes"

	zblake3 "github.com/zeebo/blake3"

	"github.com/luxfi/precompile/blake3"
	"github.com/luxfi/precompile/examples"
)

// Blake3Demo exercises the Blake3 hash precompile (0x0500..04).
func Blake3Demo() []examples.Result {
	msg := []byte("Lux precompile Blake3 demo")

	// OpHash256: op(1) + data
	input256 := make([]byte, 0, 1+len(msg))
	input256 = append(input256, blake3.OpHash256)
	input256 = append(input256, msg...)

	// Compute reference hash
	h := zblake3.New()
	h.Write(msg)
	ref := make([]byte, 32)
	h.Digest().Read(ref)

	return []examples.Result{
		examples.CallPrecompileResult(
			"Blake3 Hash256",
			blake3.Blake3Precompile,
			blake3.ContractAddress,
			input256,
			func(out []byte) bool { return bytes.Equal(out, ref) },
		),
		func() examples.Result {
			// OpHash512
			input := append([]byte{blake3.OpHash512}, msg...)
			return examples.CallPrecompileResult(
				"Blake3 Hash512",
				blake3.Blake3Precompile,
				blake3.ContractAddress,
				input,
				func(out []byte) bool { return len(out) == 64 && examples.IsNonZero(out) },
			)
		}(),
	}
}
