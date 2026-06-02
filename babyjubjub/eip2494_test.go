// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// EIP-2494 conformance tests.
//
// Every test vector in the EIP is stated in the STANDARD twisted Edwards
// form (a = 168700, d = 168696). The Lux precompile operates on the
// REDUCED form (a = -1) used by circom/iden3/Polygon-zkEVM. We therefore
// convert each EIP vector to reduced form and verify the precompile
// computes the correct output.
//
// Conversion:
//     x' = x * (-f) mod r
//     y' = y
//     f  = 6360561867910373094066688120553762416144456282423235903351243436111059670888
//
// Reference: https://eips.ethereum.org/EIPS/eip-2494

package babyjubjub

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// r is the BN254 scalar field order.
var rBN254, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10,
)

// negF is the scaling constant (−f mod r) that maps standard-form
// Baby Jubjub to reduced-form Baby Jubjub.
// EIP-2494: f = 6360561867910373094066688120553762416144456282423235903351243436111059670888
//
//	−f = r − f = 15527681003928902128179717624703512672403908117992798440346960750464748824729
var negF, _ = new(big.Int).SetString(
	"15527681003928902128179717624703512672403908117992798440346960750464748824729", 10,
)

// toReducedForm converts an EIP-2494 standard-form (x, y) to reduced-form (x', y').
func toReducedForm(x, y *big.Int) (*big.Int, *big.Int) {
	xPrime := new(big.Int).Mul(x, negF)
	xPrime.Mod(xPrime, rBN254)
	yPrime := new(big.Int).Mod(y, rBN254)
	return xPrime, yPrime
}

func pointBytesFromBigInt(x, y *big.Int) []byte {
	var xFr, yFr fr.Element
	xFr.SetBigInt(x)
	yFr.SetBigInt(y)
	pt := twistededwards.PointAffine{X: xFr, Y: yFr}
	return encodePoint(&pt)
}

// --- EIP-2494 Test 1: addition of two distinct points ---

func TestEIP2494_Test1_Addition(t *testing.T) {
	// Standard-form inputs (from the EIP).
	p1x, _ := new(big.Int).SetString(
		"17777552123799933955779906779655732241715742912184938656739573121738514868268", 10)
	p1y, _ := new(big.Int).SetString(
		"2626589144620713026669568689430873010625803728049924121243784502389097019475", 10)
	p2x, _ := new(big.Int).SetString(
		"16540640123574156134436876038791482806971768689494387082833631921987005038935", 10)
	p2y, _ := new(big.Int).SetString(
		"20819045374670962167435360035096875258406992893633759881276124905556507972311", 10)
	wantX, _ := new(big.Int).SetString(
		"7916061937171219682591368294088513039687205273691143098332585753343424131937", 10)
	wantY, _ := new(big.Int).SetString(
		"14035240266687799601661095864649209771790948434046947201833777492504781204499", 10)

	// Convert all three points to reduced form.
	p1xR, p1yR := toReducedForm(p1x, p1y)
	p2xR, p2yR := toReducedForm(p2x, p2y)
	wantXR, wantYR := toReducedForm(wantX, wantY)

	p1Bytes := pointBytesFromBigInt(p1xR, p1yR)
	p2Bytes := pointBytesFromBigInt(p2xR, p2yR)
	wantBytes := pointBytesFromBigInt(wantXR, wantYR)

	p := &babyJubJubPrecompile{}
	input := make([]byte, 1+2*PointLen)
	input[0] = OpPointAdd
	copy(input[1:], p1Bytes)
	copy(input[1+PointLen:], p2Bytes)

	gas := p.RequiredGas(input)
	got, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err, "EIP-2494 Test 1 precompile Run failed")
	require.Equal(t, wantBytes, got, "EIP-2494 Test 1: P1+P2 mismatch after reduced-form conversion")
}

// --- EIP-2494 Test 2: point doubling ---

func TestEIP2494_Test2_Doubling(t *testing.T) {
	px, _ := new(big.Int).SetString(
		"17777552123799933955779906779655732241715742912184938656739573121738514868268", 10)
	py, _ := new(big.Int).SetString(
		"2626589144620713026669568689430873010625803728049924121243784502389097019475", 10)
	wantX, _ := new(big.Int).SetString(
		"6890855772600357754907169075114257697580319025794532037257385534741338397365", 10)
	wantY, _ := new(big.Int).SetString(
		"4338620300185947561074059802482547481416142213883829469920100239455078257889", 10)

	pxR, pyR := toReducedForm(px, py)
	wantXR, wantYR := toReducedForm(wantX, wantY)

	pBytes := pointBytesFromBigInt(pxR, pyR)
	wantBytes := pointBytesFromBigInt(wantXR, wantYR)

	p := &babyJubJubPrecompile{}
	input := make([]byte, 1+2*PointLen)
	input[0] = OpPointAdd
	copy(input[1:], pBytes)
	copy(input[1+PointLen:], pBytes) // P + P = 2P

	gas := p.RequiredGas(input)
	got, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err, "EIP-2494 Test 2 precompile Run failed")
	require.Equal(t, wantBytes, got, "EIP-2494 Test 2: 2*P mismatch")
}

// --- EIP-2494 Test 3: doubling the identity ---

func TestEIP2494_Test3_DoubleIdentity(t *testing.T) {
	// Identity (0, 1) is the same in both forms (x=0 → x' = 0*(-f) = 0).
	idBytes := pointBytesFromBigInt(big.NewInt(0), big.NewInt(1))

	p := &babyJubJubPrecompile{}
	input := make([]byte, 1+2*PointLen)
	input[0] = OpPointAdd
	copy(input[1:], idBytes)
	copy(input[1+PointLen:], idBytes)

	gas := p.RequiredGas(input)
	got, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err, "EIP-2494 Test 3 precompile Run failed")
	require.Equal(t, idBytes, got, "EIP-2494 Test 3: O+O should equal O")
}

// --- EIP-2494 Test 4: curve membership ---

func TestEIP2494_Test4_Membership(t *testing.T) {
	p := &babyJubJubPrecompile{}

	// (0, 1) is on the curve.
	onCurve := pointBytesFromBigInt(big.NewInt(0), big.NewInt(1))
	input := append([]byte{OpInCurve}, onCurve...)
	gas := p.RequiredGas(input)
	got, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, byte(1), got[31], "EIP-2494 Test 4: (0,1) should be on curve")

	// (1, 0) is NOT on the curve. Same in both forms since y=0 and a*x^2 = a ≠ 1.
	offCurve := pointBytesFromBigInt(big.NewInt(1), big.NewInt(0))
	input2 := append([]byte{OpInCurve}, offCurve...)
	gas2 := p.RequiredGas(input2)
	got2, _, err := p.Run(nil, common.Address{}, ContractAddress, input2, gas2, true)
	require.NoError(t, err)
	require.Equal(t, byte(0), got2[31], "EIP-2494 Test 4: (1,0) should NOT be on curve")
}

// --- EIP-2494 Test 5: base point is 8 * generator ---

func TestEIP2494_Test5_BaseIs8G(t *testing.T) {
	// Standard-form generator G.
	gx, _ := new(big.Int).SetString(
		"995203441582195749578291179787384436505546430278305826713579947235728471134", 10)
	gy, _ := new(big.Int).SetString(
		"5472060717959818805561601436314318772137091100104008585924551046643952123905", 10)
	// Standard-form base B.
	bx, _ := new(big.Int).SetString(
		"5299619240641551281634865583518297030282874472190772894086521144482721001553", 10)
	by, _ := new(big.Int).SetString(
		"16950150798460657717958625567821834550301663161624707787222815936182638968203", 10)

	gxR, gyR := toReducedForm(gx, gy)
	bxR, byR := toReducedForm(bx, by)

	gBytes := pointBytesFromBigInt(gxR, gyR)
	wantBBytes := pointBytesFromBigInt(bxR, byR)

	p := &babyJubJubPrecompile{}
	input := make([]byte, 1+PointLen+32)
	input[0] = OpScalarMul
	copy(input[1:], gBytes)
	// scalar = 8 (big-endian 32 bytes)
	input[1+PointLen+31] = 8

	gas := p.RequiredGas(input)
	got, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err, "EIP-2494 Test 5 precompile Run failed")
	require.Equal(t, wantBBytes, got, "EIP-2494 Test 5: 8*G should equal B")
}

// --- EIP-2494 Test 6: base point has order l ---

func TestEIP2494_Test6_BaseOrder(t *testing.T) {
	bx, _ := new(big.Int).SetString(
		"5299619240641551281634865583518297030282874472190772894086521144482721001553", 10)
	by, _ := new(big.Int).SetString(
		"16950150798460657717958625567821834550301663161624707787222815936182638968203", 10)
	l, _ := new(big.Int).SetString(
		"2736030358979909402780800718157159386076813972158567259200215660948447373041", 10)

	bxR, byR := toReducedForm(bx, by)
	bBytes := pointBytesFromBigInt(bxR, byR)
	// Identity (0, 1) is the expected output of l*B.
	idBytes := pointBytesFromBigInt(big.NewInt(0), big.NewInt(1))

	p := &babyJubJubPrecompile{}
	// l fits in 251 bits. Left-pad to 32 bytes big-endian.
	lBytes := l.Bytes()
	scalar := make([]byte, 32)
	copy(scalar[32-len(lBytes):], lBytes)

	input := make([]byte, 1+PointLen+32)
	input[0] = OpScalarMul
	copy(input[1:], bBytes)
	copy(input[1+PointLen:], scalar)

	gas := p.RequiredGas(input)
	got, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err, "EIP-2494 Test 6 precompile Run failed")
	require.Equal(t, idBytes, got, "EIP-2494 Test 6: l*B should equal identity")
}

// --- Regression: verify the reduced-form curve parameters that gnark uses ---

func TestReducedFormCurveParameters(t *testing.T) {
	params := twistededwards.GetEdwardsCurve()

	// a' = -1  (i.e. r - 1)
	wantA := new(big.Int).Sub(rBN254, big.NewInt(1))
	gotA := params.A.BigInt(new(big.Int))
	require.Equal(t, wantA.String(), gotA.String(), "a' must equal -1 mod r (reduced form)")

	// d' = 12181644023421730124874158521699555681764249180949974110617291017600649128846
	wantD, _ := new(big.Int).SetString(
		"12181644023421730124874158521699555681764249180949974110617291017600649128846", 10)
	gotD := params.D.BigInt(new(big.Int))
	require.Equal(t, wantD.String(), gotD.String(), "d' must match EIP-2494 reduced form")

	// Base x' = 9671717474070082183213120605117400219616337014328744928644933853176787189663
	wantBx, _ := new(big.Int).SetString(
		"9671717474070082183213120605117400219616337014328744928644933853176787189663", 10)
	gotBx := params.Base.X.BigInt(new(big.Int))
	require.Equal(t, wantBx.String(), gotBx.String(), "Bx' must match EIP-2494 reduced form")

	// Base y' = 16950150798460657717958625567821834550301663161624707787222815936182638968203
	wantBy, _ := new(big.Int).SetString(
		"16950150798460657717958625567821834550301663161624707787222815936182638968203", 10)
	gotBy := params.Base.Y.BigInt(new(big.Int))
	require.Equal(t, wantBy.String(), gotBy.String(), "By' must match EIP-2494")
}

// TestReducedFormCurveParameters_HelperConstants pins the conversion constants
// so a typo will be caught in CI instead of silently corrupting every test.
func TestEIP2494_ConversionConstants(t *testing.T) {
	// Verify negF + f == r  (i.e. negF is indeed r - f).
	f, _ := new(big.Int).SetString(
		"6360561867910373094066688120553762416144456282423235903351243436111059670888", 10)
	sum := new(big.Int).Add(f, negF)
	require.Equal(t, rBN254.String(), sum.String(), "f + (-f) must equal r")
}
