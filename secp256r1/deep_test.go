// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256r1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"sync"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// --- Edge Case Tests ---

func TestRun_EmptyInput(t *testing.T) {
	c := &Contract{}
	ret, err := c.Run(nil)
	require.NoError(t, err)
	require.Nil(t, ret)
}

func TestRun_SingleByte(t *testing.T) {
	c := &Contract{}
	ret, err := c.Run([]byte{0x00})
	require.NoError(t, err)
	require.Nil(t, ret)
}

func TestRun_ShortInput(t *testing.T) {
	c := &Contract{}
	for _, size := range []int{0, 1, 31, 32, 64, 96, 128, 159} {
		ret, err := c.Run(make([]byte, size))
		require.NoError(t, err, "size=%d", size)
		require.Nil(t, ret, "size=%d should return nil", size)
	}
}

func TestRun_LongInput(t *testing.T) {
	c := &Contract{}
	ret, err := c.Run(make([]byte, 161))
	require.NoError(t, err)
	require.Nil(t, ret)
}

func TestRun_AllZeros(t *testing.T) {
	c := &Contract{}
	ret, err := c.Run(make([]byte, InputLength))
	require.NoError(t, err)
	require.Nil(t, ret) // (0,0) is not on the curve
}

func TestRun_AllOnes(t *testing.T) {
	c := &Contract{}
	input := make([]byte, InputLength)
	for i := range input {
		input[i] = 0xFF
	}
	ret, err := c.Run(input)
	require.NoError(t, err)
	require.Nil(t, ret) // invalid point
}

// --- Cryptographic Correctness ---

func TestRun_ValidSignature(t *testing.T) {
	c := &Contract{}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("test message for secp256r1"))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, msg[:])
	require.NoError(t, err)

	input := make([]byte, InputLength)
	copy(input[0:32], msg[:])
	copy(input[32:64], common.LeftPadBytes(r.Bytes(), 32))
	copy(input[64:96], common.LeftPadBytes(s.Bytes(), 32))
	copy(input[96:128], common.LeftPadBytes(privKey.PublicKey.X.Bytes(), 32))
	copy(input[128:160], common.LeftPadBytes(privKey.PublicKey.Y.Bytes(), 32))

	ret, err := c.Run(input)
	require.NoError(t, err)
	require.Equal(t, successResult, ret, "valid signature must return 1")
}

func TestRun_WrongMessage(t *testing.T) {
	c := &Contract{}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("original message"))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, msg[:])
	require.NoError(t, err)

	wrongMsg := sha256.Sum256([]byte("wrong message"))
	input := make([]byte, InputLength)
	copy(input[0:32], wrongMsg[:])
	copy(input[32:64], common.LeftPadBytes(r.Bytes(), 32))
	copy(input[64:96], common.LeftPadBytes(s.Bytes(), 32))
	copy(input[96:128], common.LeftPadBytes(privKey.PublicKey.X.Bytes(), 32))
	copy(input[128:160], common.LeftPadBytes(privKey.PublicKey.Y.Bytes(), 32))

	ret, err := c.Run(input)
	require.NoError(t, err)
	require.Nil(t, ret, "wrong message must fail verification")
}

func TestRun_WrongPublicKey(t *testing.T) {
	c := &Contract{}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("test message"))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, msg[:])
	require.NoError(t, err)

	input := make([]byte, InputLength)
	copy(input[0:32], msg[:])
	copy(input[32:64], common.LeftPadBytes(r.Bytes(), 32))
	copy(input[64:96], common.LeftPadBytes(s.Bytes(), 32))
	copy(input[96:128], common.LeftPadBytes(wrongKey.PublicKey.X.Bytes(), 32))
	copy(input[128:160], common.LeftPadBytes(wrongKey.PublicKey.Y.Bytes(), 32))

	ret, err := c.Run(input)
	require.NoError(t, err)
	require.Nil(t, ret, "wrong public key must fail verification")
}

func TestRun_BitFlipSignatureR(t *testing.T) {
	c := &Contract{}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("bit flip test"))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, msg[:])
	require.NoError(t, err)

	rBytes := common.LeftPadBytes(r.Bytes(), 32)
	rBytes[0] ^= 0x01 // flip one bit

	input := make([]byte, InputLength)
	copy(input[0:32], msg[:])
	copy(input[32:64], rBytes)
	copy(input[64:96], common.LeftPadBytes(s.Bytes(), 32))
	copy(input[96:128], common.LeftPadBytes(privKey.PublicKey.X.Bytes(), 32))
	copy(input[128:160], common.LeftPadBytes(privKey.PublicKey.Y.Bytes(), 32))

	ret, err := c.Run(input)
	require.NoError(t, err)
	require.Nil(t, ret, "bit-flipped r must fail verification")
}

func TestRun_PointNotOnCurve(t *testing.T) {
	c := &Contract{}
	msg := sha256.Sum256([]byte("test"))

	input := make([]byte, InputLength)
	copy(input[0:32], msg[:])
	// r and s set to 1
	input[63] = 1
	input[95] = 1
	// x = 1, y = 1 is NOT on P-256
	input[127] = 1
	input[159] = 1

	ret, err := c.Run(input)
	require.NoError(t, err)
	require.Nil(t, ret, "point not on curve must fail")
}

func TestRun_ZeroR(t *testing.T) {
	c := &Contract{}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("zero r"))

	input := make([]byte, InputLength)
	copy(input[0:32], msg[:])
	// r = 0 (all zeros at input[32:64])
	input[95] = 1 // s = 1
	copy(input[96:128], common.LeftPadBytes(privKey.PublicKey.X.Bytes(), 32))
	copy(input[128:160], common.LeftPadBytes(privKey.PublicKey.Y.Bytes(), 32))

	ret, err := c.Run(input)
	require.NoError(t, err)
	require.Nil(t, ret, "r=0 must fail")
}

func TestRun_ZeroS(t *testing.T) {
	c := &Contract{}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("zero s"))

	input := make([]byte, InputLength)
	copy(input[0:32], msg[:])
	input[63] = 1 // r = 1
	// s = 0 (all zeros)
	copy(input[96:128], common.LeftPadBytes(privKey.PublicKey.X.Bytes(), 32))
	copy(input[128:160], common.LeftPadBytes(privKey.PublicKey.Y.Bytes(), 32))

	ret, err := c.Run(input)
	require.NoError(t, err)
	require.Nil(t, ret, "s=0 must fail")
}

func TestRun_REqualsN(t *testing.T) {
	c := &Contract{}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	n := elliptic.P256().Params().N
	msg := sha256.Sum256([]byte("r=n"))

	input := make([]byte, InputLength)
	copy(input[0:32], msg[:])
	copy(input[32:64], common.LeftPadBytes(n.Bytes(), 32))
	input[95] = 1 // s = 1
	copy(input[96:128], common.LeftPadBytes(privKey.PublicKey.X.Bytes(), 32))
	copy(input[128:160], common.LeftPadBytes(privKey.PublicKey.Y.Bytes(), 32))

	ret, err := c.Run(input)
	require.NoError(t, err)
	require.Nil(t, ret, "r=n must fail")
}

// --- Gas Tests ---

func TestRequiredGas(t *testing.T) {
	c := &Contract{}
	require.Equal(t, uint64(GasP256Verify), c.RequiredGas(nil))
	require.Equal(t, uint64(GasP256Verify), c.RequiredGas(make([]byte, 0)))
	require.Equal(t, uint64(GasP256Verify), c.RequiredGas(make([]byte, 1000)))
}

func TestAddress(t *testing.T) {
	c := &Contract{}
	require.Equal(t, common.HexToAddress(P256VerifyAddress), c.Address())
}

// --- Concurrency Tests ---

func TestRun_Concurrent(t *testing.T) {
	c := &Contract{}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("concurrent test"))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, msg[:])
	require.NoError(t, err)

	input := make([]byte, InputLength)
	copy(input[0:32], msg[:])
	copy(input[32:64], common.LeftPadBytes(r.Bytes(), 32))
	copy(input[64:96], common.LeftPadBytes(s.Bytes(), 32))
	copy(input[96:128], common.LeftPadBytes(privKey.PublicKey.X.Bytes(), 32))
	copy(input[128:160], common.LeftPadBytes(privKey.PublicKey.Y.Bytes(), 32))

	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			ret, err := c.Run(input)
			require.NoError(t, err)
			require.Equal(t, successResult, ret)
		})
	}
	wg.Wait()
}

// --- Fuzz Tests ---

func FuzzRun(f *testing.F) {
	f.Add(make([]byte, InputLength))
	f.Add(make([]byte, 0))
	f.Add([]byte{0xFF})

	// Add a valid signature as seed
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	msg := sha256.Sum256([]byte("fuzz seed"))
	r, s, _ := ecdsa.Sign(rand.Reader, privKey, msg[:])
	seed := make([]byte, InputLength)
	copy(seed[0:32], msg[:])
	copy(seed[32:64], common.LeftPadBytes(r.Bytes(), 32))
	copy(seed[64:96], common.LeftPadBytes(s.Bytes(), 32))
	copy(seed[96:128], common.LeftPadBytes(privKey.PublicKey.X.Bytes(), 32))
	copy(seed[128:160], common.LeftPadBytes(privKey.PublicKey.Y.Bytes(), 32))
	f.Add(seed)

	c := &Contract{}
	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic on input len=%d: %v", len(input), r)
			}
		}()
		ret, err := c.Run(input)
		// Must never error -- invalid inputs return nil
		require.NoError(t, err)
		if ret != nil {
			require.Equal(t, successResult, ret, "non-nil result must be success")
		}
	})
}

// --- Determinism ---

func TestRun_Deterministic(t *testing.T) {
	c := &Contract{}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("determinism"))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, msg[:])
	require.NoError(t, err)

	input := make([]byte, InputLength)
	copy(input[0:32], msg[:])
	copy(input[32:64], common.LeftPadBytes(r.Bytes(), 32))
	copy(input[64:96], common.LeftPadBytes(s.Bytes(), 32))
	copy(input[96:128], common.LeftPadBytes(privKey.PublicKey.X.Bytes(), 32))
	copy(input[128:160], common.LeftPadBytes(privKey.PublicKey.Y.Bytes(), 32))

	ret1, _ := c.Run(input)
	ret2, _ := c.Run(input)
	require.Equal(t, ret1, ret2, "same input must produce same output")
}

// --- Malleability ---

func TestRun_HighSMalleability(t *testing.T) {
	c := &Contract{}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("malleability"))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, msg[:])
	require.NoError(t, err)

	// Compute malleable s' = n - s
	n := elliptic.P256().Params().N
	sMalleable := new(big.Int).Sub(n, s)

	input := make([]byte, InputLength)
	copy(input[0:32], msg[:])
	copy(input[32:64], common.LeftPadBytes(r.Bytes(), 32))
	copy(input[64:96], common.LeftPadBytes(sMalleable.Bytes(), 32))
	copy(input[96:128], common.LeftPadBytes(privKey.PublicKey.X.Bytes(), 32))
	copy(input[128:160], common.LeftPadBytes(privKey.PublicKey.Y.Bytes(), 32))

	// Malleable signature may or may not verify depending on implementation,
	// but must not panic
	_, err = c.Run(input)
	require.NoError(t, err)
}
