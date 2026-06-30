package hashing_zk

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/luxfi/precompile/babyjubjub"
	"github.com/luxfi/precompile/examples"
)

// BabyJubJubDemo exercises the Baby Jubjub curve precompile (0x0500..07).
func BabyJubJubDemo() []examples.Result {
	// Get the curve generator
	curve := twistededwards.GetEdwardsCurve()

	// Encode generator as 64 bytes: x(32) + y(32)
	genPoint := make([]byte, 64)
	xBytes := curve.Base.X.Bytes()
	yBytes := curve.Base.Y.Bytes()
	copy(genPoint[0:32], xBytes[:])
	copy(genPoint[32:64], yBytes[:])

	// OpPointAdd: G + G = 2G
	addInput := make([]byte, 0, 1+128)
	addInput = append(addInput, babyjubjub.OpPointAdd)
	addInput = append(addInput, genPoint...)
	addInput = append(addInput, genPoint...)

	// OpScalarMul: G * 2
	mulInput := make([]byte, 0, 1+64+32)
	mulInput = append(mulInput, babyjubjub.OpScalarMul)
	mulInput = append(mulInput, genPoint...)
	mulInput = append(mulInput, examples.PadLeft([]byte{2}, 32)...)

	// OpInCurve: check generator is on curve
	curveInput := make([]byte, 0, 1+64)
	curveInput = append(curveInput, babyjubjub.OpInCurve)
	curveInput = append(curveInput, genPoint...)

	return []examples.Result{
		examples.CallPrecompileResult(
			"BabyJubJub PointAdd",
			babyjubjub.BabyJubJubPrecompile,
			babyjubjub.ContractAddress,
			addInput,
			func(out []byte) bool { return len(out) == 64 && examples.IsNonZero(out) },
		),
		examples.CallPrecompileResult(
			"BabyJubJub ScalarMul",
			babyjubjub.BabyJubJubPrecompile,
			babyjubjub.ContractAddress,
			mulInput,
			func(out []byte) bool { return len(out) == 64 && examples.IsNonZero(out) },
		),
		examples.CallPrecompileResult(
			"BabyJubJub InCurve",
			babyjubjub.BabyJubJubPrecompile,
			babyjubjub.ContractAddress,
			curveInput,
			func(out []byte) bool { return examples.LastByte32IsOne(out) },
		),
	}
}
