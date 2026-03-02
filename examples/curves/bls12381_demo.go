package curves

import (
	"github.com/luxfi/precompile/bls12381"
	"github.com/luxfi/precompile/examples"
)

// BLS12381Demo exercises all 7 BLS12-381 precompiles (EIP-2537).
func BLS12381Demo() []examples.Result {
	var results []examples.Result

	// BLS12-381 G1 generator in EIP-2537 format (128 bytes):
	g1Gen := make([]byte, 128)
	copy(g1Gen[16:64], examples.HexDecode("17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"))
	copy(g1Gen[80:128], examples.HexDecode("08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"))

	// G1Add: G + G = 2G
	g1AddInput := make([]byte, 256)
	copy(g1AddInput[0:128], g1Gen)
	copy(g1AddInput[128:256], g1Gen)
	results = append(results, examples.CallPrecompileResult(
		"BLS12-381 G1Add",
		bls12381.G1AddModule.Contract,
		bls12381.G1AddAddress,
		g1AddInput,
		func(out []byte) bool { return len(out) == 128 && examples.IsNonZero(out) },
	))

	// G1Mul: G * 2
	g1MulInput := make([]byte, 160)
	copy(g1MulInput[0:128], g1Gen)
	g1MulInput[159] = 2
	results = append(results, examples.CallPrecompileResult(
		"BLS12-381 G1Mul",
		bls12381.G1MulModule.Contract,
		bls12381.G1MulAddress,
		g1MulInput,
		func(out []byte) bool { return len(out) == 128 && examples.IsNonZero(out) },
	))

	// G1MSM: 1 pair (G, scalar=3)
	g1MSMInput := make([]byte, 160)
	copy(g1MSMInput[0:128], g1Gen)
	g1MSMInput[159] = 3
	results = append(results, examples.CallPrecompileResult(
		"BLS12-381 G1MSM",
		bls12381.G1MSMModule.Contract,
		bls12381.G1MSMAddress,
		g1MSMInput,
		func(out []byte) bool { return len(out) == 128 && examples.IsNonZero(out) },
	))

	// G2 generator in EIP-2537 format (256 bytes):
	g2Gen := make([]byte, 256)
	copy(g2Gen[16:64], examples.HexDecode("13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"))
	copy(g2Gen[80:128], examples.HexDecode("024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"))
	copy(g2Gen[144:192], examples.HexDecode("0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"))
	copy(g2Gen[208:256], examples.HexDecode("0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"))

	// G2Add
	g2AddInput := make([]byte, 512)
	copy(g2AddInput[0:256], g2Gen)
	copy(g2AddInput[256:512], g2Gen)
	results = append(results, examples.CallPrecompileResult(
		"BLS12-381 G2Add",
		bls12381.G2AddModule.Contract,
		bls12381.G2AddAddress,
		g2AddInput,
		func(out []byte) bool { return len(out) == 256 && examples.IsNonZero(out) },
	))

	// G2Mul
	g2MulInput := make([]byte, 288)
	copy(g2MulInput[0:256], g2Gen)
	g2MulInput[287] = 2
	results = append(results, examples.CallPrecompileResult(
		"BLS12-381 G2Mul",
		bls12381.G2MulModule.Contract,
		bls12381.G2MulAddress,
		g2MulInput,
		func(out []byte) bool { return len(out) == 256 && examples.IsNonZero(out) },
	))

	// G2MSM
	g2MSMInput := make([]byte, 288)
	copy(g2MSMInput[0:256], g2Gen)
	g2MSMInput[287] = 3
	results = append(results, examples.CallPrecompileResult(
		"BLS12-381 G2MSM",
		bls12381.G2MSMModule.Contract,
		bls12381.G2MSMAddress,
		g2MSMInput,
		func(out []byte) bool { return len(out) == 256 && examples.IsNonZero(out) },
	))

	// Pairing: e(0, G2) * e(0, G2) = identity pairing (trivially true)
	pairingInput := make([]byte, 2*(128+256))
	copy(pairingInput[128:128+256], g2Gen)
	copy(pairingInput[128+256+128:], g2Gen)
	results = append(results, examples.CallPrecompileResult(
		"BLS12-381 Pairing",
		bls12381.PairingModule.Contract,
		bls12381.PairingAddress,
		pairingInput,
		func(out []byte) bool { return examples.LastByte32IsOne(out) },
	))

	return results
}
