// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

var addr0 = common.Address{}

// --- Edge Cases ---

func TestEdge_NilInput(t *testing.T) {
	p := Ed25519VerifyPrecompile
	ret, _, err := p.Run(nil, addr0, ContractAddress, nil, 100000, true)
	require.NoError(t, err) // returns nil result, not error
	require.Nil(t, ret)
}

func TestEdge_EmptyInput(t *testing.T) {
	p := Ed25519VerifyPrecompile
	ret, _, err := p.Run(nil, addr0, ContractAddress, []byte{}, 100000, true)
	require.NoError(t, err)
	require.Nil(t, ret)
}

func TestEdge_SingleByte(t *testing.T) {
	p := Ed25519VerifyPrecompile
	ret, _, err := p.Run(nil, addr0, ContractAddress, []byte{0x01}, 100000, true)
	require.NoError(t, err)
	require.Nil(t, ret)
}

func TestEdge_WrongLength(t *testing.T) {
	p := Ed25519VerifyPrecompile
	for _, size := range []int{0, 1, 31, 64, 127, 129, 256} {
		ret, _, err := p.Run(nil, addr0, ContractAddress, make([]byte, size), 100000, true)
		require.NoError(t, err, "size=%d", size)
		require.Nil(t, ret, "wrong length %d must return nil", size)
	}
}

func TestEdge_AllZeros(t *testing.T) {
	p := Ed25519VerifyPrecompile
	input := make([]byte, 128)
	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
	require.NoError(t, err)
	require.Nil(t, ret, "all zeros must not verify")
}

// --- Cryptographic Correctness ---

func TestVerify_ValidSignature(t *testing.T) {
	p := Ed25519VerifyPrecompile

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// The precompile expects: hash(32) + signature(64) + pubkey(32) = 128 bytes
	// ed25519 stdlib signs messages directly, precompile takes the hash as input
	msgHash := make([]byte, 32)
	copy(msgHash, []byte("test hash for ed25519 deep test!"))
	sig := ed25519.Sign(priv, msgHash)

	input := make([]byte, InputLength)
	copy(input[0:32], msgHash)
	copy(input[32:96], sig)
	copy(input[96:128], pub)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
	require.NoError(t, err)
	require.NotNil(t, ret, "valid signature must return non-nil")
	require.Equal(t, byte(1), ret[31], "valid signature must verify")
}

func TestVerify_WrongHash(t *testing.T) {
	p := Ed25519VerifyPrecompile

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	msgHash := make([]byte, 32)
	copy(msgHash, []byte("original hash___________________"))
	sig := ed25519.Sign(priv, msgHash)

	wrongHash := make([]byte, 32)
	copy(wrongHash, []byte("tampered hash___________________"))

	input := make([]byte, InputLength)
	copy(input[0:32], wrongHash)
	copy(input[32:96], sig)
	copy(input[96:128], pub)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
	require.NoError(t, err)
	require.Nil(t, ret, "wrong hash must not verify")
}

func TestVerify_WrongPublicKey(t *testing.T) {
	p := Ed25519VerifyPrecompile

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	msgHash := make([]byte, 32)
	copy(msgHash, []byte("wrong key test__________________"))
	sig := ed25519.Sign(priv, msgHash)

	input := make([]byte, InputLength)
	copy(input[0:32], msgHash)
	copy(input[32:96], sig)
	copy(input[96:128], wrongPub)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
	require.NoError(t, err)
	require.Nil(t, ret, "wrong public key must not verify")
}

func TestVerify_BitFlip(t *testing.T) {
	p := Ed25519VerifyPrecompile

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	msgHash := make([]byte, 32)
	copy(msgHash, []byte("bit flip test___________________"))
	sig := ed25519.Sign(priv, msgHash)
	sig[0] ^= 0x01

	input := make([]byte, InputLength)
	copy(input[0:32], msgHash)
	copy(input[32:96], sig)
	copy(input[96:128], pub)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
	require.NoError(t, err)
	require.Nil(t, ret, "bit-flipped sig must not verify")
}

// --- Gas Accounting ---

func TestGas_ExactRequired(t *testing.T) {
	p := Ed25519VerifyPrecompile
	input := make([]byte, InputLength)
	gas := p.RequiredGas(input)
	_, remaining, err := p.Run(nil, addr0, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, uint64(0), remaining)
}

func TestGas_Insufficient(t *testing.T) {
	p := Ed25519VerifyPrecompile
	input := make([]byte, InputLength)
	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, addr0, ContractAddress, input, gas-1, true)
	require.Error(t, err)
}

func TestGas_Zero(t *testing.T) {
	p := Ed25519VerifyPrecompile
	input := make([]byte, InputLength)
	_, _, err := p.Run(nil, addr0, ContractAddress, input, 0, true)
	require.Error(t, err)
}

// --- Concurrency ---

func TestConcurrent(t *testing.T) {
	p := Ed25519VerifyPrecompile
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	msgHash := make([]byte, 32)
	copy(msgHash, []byte("concurrent ed25519 deep test!!!!"))
	sig := ed25519.Sign(priv, msgHash)

	input := make([]byte, InputLength)
	copy(input[0:32], msgHash)
	copy(input[32:96], sig)
	copy(input[96:128], pub)
	gas := p.RequiredGas(input)

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			ret, _, err := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
			require.NoError(t, err)
			require.NotNil(t, ret)
			require.Equal(t, byte(1), ret[31])
		})
	}
	wg.Wait()
}

// --- Fuzz ---

func FuzzEd25519(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	msgHash := make([]byte, 32)
	copy(msgHash, []byte("fuzz seed ed25519 hash 32 bytes!"))
	sig := ed25519.Sign(priv, msgHash)
	valid := make([]byte, InputLength)
	copy(valid[0:32], msgHash)
	copy(valid[32:96], sig)
	copy(valid[96:128], pub)
	f.Add(valid)
	f.Add([]byte{})
	f.Add(make([]byte, InputLength))

	p := Ed25519VerifyPrecompile
	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic: %v", r)
			}
		}()
		gas := p.RequiredGas(input)
		p.Run(nil, addr0, ContractAddress, input, gas+100000, true)
	})
}
