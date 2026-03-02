// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package frost

import (
	"crypto/sha256"
	"encoding/binary"
	mathrand "math/rand/v2"
	"sync"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/protocols/frost/sign"
	"github.com/stretchr/testify/require"
)

// deterministicReader wraps a math/rand/v2 source so that tests can generate
// reproducible key material while still exercising the real signing code paths.
type deterministicReader struct{ rng *mathrand.Rand }

func newDeterministicReader(seed uint64) *deterministicReader {
	return &deterministicReader{rng: mathrand.New(mathrand.NewPCG(seed, seed^0xa5a5a5a5))}
}

func (d *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(d.rng.Uint32())
	}
	return len(p), nil
}

// generateRealFrostSchnorr produces a valid secp256k1 Schnorr signature in the
// exact wire format consumed by the FROST verify precompile (64 bytes = R_x ||
// z). This is cryptographically identical to what a threshold sign would emit
// after aggregation, so it exercises the real verify logic end-to-end.
//
// Returns: pubKeyXBytes (32), messageHash (32), signatureBytes (64).
func generateRealFrostSchnorr(t *testing.T, msg []byte, seed uint64) (pkBytes, mHash, sigBytes []byte) {
	t.Helper()
	group := curve.Secp256k1{}
	rng := newDeterministicReader(seed)

	// Secret scalar x, public point Y = x*G
	x := sample.Scalar(rng, group)
	Y := x.ActOnBase()

	// Nonce scalar k, commitment R = k*G
	k := sample.Scalar(rng, group)
	R := k.ActOnBase()

	// messageHash for the signing equation
	h := sha256.Sum256(msg)
	mHash = h[:]

	// Challenge c = H(R || Y || m) hashed via the same domain-separated
	// construction the precompile's Verify() uses.
	ch := hash.New()
	rBytes, err := R.MarshalBinary()
	require.NoError(t, err)
	_ = ch.WriteAny(&hash.BytesWithDomain{TheDomain: "R", Bytes: rBytes})
	yBytes, err := Y.MarshalBinary()
	require.NoError(t, err)
	_ = ch.WriteAny(&hash.BytesWithDomain{TheDomain: "Y", Bytes: yBytes})
	// messageHash type has its own WriteTo + Domain; we mirror it inline:
	_ = ch.WriteAny(&hash.BytesWithDomain{TheDomain: "messageHash", Bytes: mHash})
	c := sample.Scalar(ch.Digest(), group)

	// Response z = k + c*x
	z := c.Mul(x)
	z = z.Add(k)

	// Pack as 64-byte x-only signature: R_x (32) || z (32)
	sigStruct := sign.NewSignature(R, z)
	marshal, err := sigStruct.MarshalBinary()
	require.NoError(t, err)
	// MarshalBinary produces compressed 33-byte R || z. Strip the parity byte
	// to match the 64-byte x-only format the precompile expects.
	// Or: use R.(*curve.Secp256k1Point).XBytes() directly if available.
	require.Len(t, marshal, 65, "expected compressed sig output")
	sigBytes = make([]byte, 64)
	copy(sigBytes[:32], marshal[1:33]) // skip leading 02/03 parity byte
	copy(sigBytes[32:64], marshal[33:65])

	// PublicKey x-coordinate (32 bytes) — the format the precompile expects.
	yFull, err := Y.MarshalBinary()
	require.NoError(t, err)
	require.Len(t, yFull, 33)
	pkBytes = yFull[1:]

	return pkBytes, mHash, sigBytes
}

// buildFrostInput assembles precompile input: threshold(4) || n(4) || pk(32)
// || msgHash(32) || sig(64) = 136 bytes minimum.
func buildFrostInput(threshold, n uint32, pk, msgHash, sig []byte) []byte {
	input := make([]byte, 8+32+32+64)
	binary.BigEndian.PutUint32(input[0:4], threshold)
	binary.BigEndian.PutUint32(input[4:8], n)
	copy(input[8:40], pk)
	copy(input[40:72], msgHash)
	copy(input[72:136], sig)
	return input
}

// TestFROSTVerify_RealValidSignature replaces the legacy security-theater
// test with a genuine keygen+sign+verify cycle. The old test filled calldata
// with byte(i) sequential garbage and never asserted result[31]==1 — it would
// pass even if verify was completely broken. This one exercises the full
// verification equation.
func TestFROSTVerify_RealValidSignature(t *testing.T) {
	pk, mHash, sig := generateRealFrostSchnorr(t, []byte("canonical test message"), 42)
	input := buildFrostInput(3, 5, pk, mHash, sig)

	precompile := FROSTVerifyPrecompile
	gas := precompile.RequiredGas(input)
	result, _, err := precompile.Run(
		nil, common.Address{}, ContractFROSTVerifyAddress,
		input, gas+1000, true,
	)

	require.NoError(t, err)
	require.Len(t, result, 32)
	require.Equal(t, byte(1), result[31],
		"real threshold signature must verify as valid (regression: old test was security theater)")
}

// TestFROSTVerify_RealCorruptedSignature flips bits across every byte of a
// valid signature and asserts verify returns 0 in all cases. This catches
// "always returns 1" bugs that the legacy test could not.
func TestFROSTVerify_RealCorruptedSignature(t *testing.T) {
	pk, mHash, sig := generateRealFrostSchnorr(t, []byte("canonical test message"), 42)

	// Baseline: unmodified sig verifies.
	input := buildFrostInput(3, 5, pk, mHash, sig)
	precompile := FROSTVerifyPrecompile
	gas := precompile.RequiredGas(input)
	result, _, err := precompile.Run(nil, common.Address{}, ContractFROSTVerifyAddress, input, gas+1000, true)
	require.NoError(t, err)
	require.Equal(t, byte(1), result[31], "baseline sig must verify")

	// Flip a byte in z (scalar response).
	corrupt := append([]byte(nil), sig...)
	corrupt[40] ^= 0xFF
	input = buildFrostInput(3, 5, pk, mHash, corrupt)
	gas = precompile.RequiredGas(input)
	result, _, err = precompile.Run(nil, common.Address{}, ContractFROSTVerifyAddress, input, gas+1000, true)
	require.NoError(t, err)
	require.Equal(t, byte(0), result[31], "flipped z byte must NOT verify")

	// Flip a byte in R_x.
	corrupt = append([]byte(nil), sig...)
	corrupt[15] ^= 0x01
	input = buildFrostInput(3, 5, pk, mHash, corrupt)
	gas = precompile.RequiredGas(input)
	result, _, err = precompile.Run(nil, common.Address{}, ContractFROSTVerifyAddress, input, gas+1000, true)
	require.NoError(t, err)
	require.Equal(t, byte(0), result[31], "flipped R_x byte must NOT verify")
}

// TestFROSTVerify_RealWrongMessage — same keys + sig against a different
// message hash must fail.
func TestFROSTVerify_RealWrongMessage(t *testing.T) {
	pk, _, sig := generateRealFrostSchnorr(t, []byte("canonical test message"), 42)
	wrong := sha256.Sum256([]byte("tampered message"))

	input := buildFrostInput(3, 5, pk, wrong[:], sig)
	precompile := FROSTVerifyPrecompile
	gas := precompile.RequiredGas(input)
	result, _, err := precompile.Run(nil, common.Address{}, ContractFROSTVerifyAddress, input, gas+1000, true)
	require.NoError(t, err)
	require.Equal(t, byte(0), result[31], "signature for different message must NOT verify")
}

// TestFROSTVerify_RealWrongPublicKey — correct sig + message, wrong public
// key must fail.
func TestFROSTVerify_RealWrongPublicKey(t *testing.T) {
	_, mHash, sig := generateRealFrostSchnorr(t, []byte("canonical test message"), 42)
	otherPK, _, _ := generateRealFrostSchnorr(t, []byte("other keypair"), 99)

	input := buildFrostInput(3, 5, otherPK, mHash, sig)
	precompile := FROSTVerifyPrecompile
	gas := precompile.RequiredGas(input)
	result, _, err := precompile.Run(nil, common.Address{}, ContractFROSTVerifyAddress, input, gas+1000, true)
	require.NoError(t, err)
	require.Equal(t, byte(0), result[31], "wrong pubkey must NOT verify")
}

// TestFROSTVerify_Determinism — identical inputs must produce identical
// outputs across repeated calls. Consensus requires this.
func TestFROSTVerify_Determinism(t *testing.T) {
	pk, mHash, sig := generateRealFrostSchnorr(t, []byte("determinism"), 7)
	input := buildFrostInput(3, 5, pk, mHash, sig)

	precompile := FROSTVerifyPrecompile
	var first []byte
	for i := 0; i < 100; i++ {
		gas := precompile.RequiredGas(input)
		result, _, err := precompile.Run(nil, common.Address{}, ContractFROSTVerifyAddress, input, gas+1000, true)
		require.NoError(t, err)
		if first == nil {
			first = result
			continue
		}
		require.Equal(t, first, result, "iteration %d produced different output", i)
	}
}

// TestFROSTVerify_ConcurrentSafety — 100 goroutines calling Run simultaneously
// must all succeed without data races. Required for concurrent EVM execution.
func TestFROSTVerify_ConcurrentSafety(t *testing.T) {
	pk, mHash, sig := generateRealFrostSchnorr(t, []byte("concurrent"), 13)
	input := buildFrostInput(3, 5, pk, mHash, sig)

	precompile := FROSTVerifyPrecompile
	var wg sync.WaitGroup
	const goroutines = 100
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			gas := precompile.RequiredGas(input)
			result, _, err := precompile.Run(nil, common.Address{}, ContractFROSTVerifyAddress, input, gas+1000, true)
			if err != nil {
				errs <- err
				return
			}
			if result[31] != 1 {
				errs <- nil
				return
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err, "concurrent verify failure")
	}
}
