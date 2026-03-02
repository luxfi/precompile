// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quasar

import (
	"sync"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// --- Verkle Deep Tests ---

func TestDeep_Verkle_ExactGasConsumption(t *testing.T) {
	v := &verklePrecompile{}
	input := make([]byte, 65)
	input[64] = 1

	for _, extra := range []uint64{0, 1, 100, 10000} {
		_, remaining, err := v.Run(nil, common.Address{}, v.Address(), input, GasVerkleVerify+extra, true)
		require.NoError(t, err, "extra=%d", extra)
		require.Equal(t, extra, remaining, "extra=%d", extra)
	}
}

func TestDeep_Verkle_GasZero(t *testing.T) {
	v := &verklePrecompile{}
	input := make([]byte, 65)
	_, _, err := v.Run(nil, common.Address{}, v.Address(), input, 0, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
}

func TestDeep_Verkle_Concurrent(t *testing.T) {
	v := &verklePrecompile{}
	input := make([]byte, 65)
	for i := range 32 {
		input[i] = byte(i)
		input[32+i] = byte(i)
	}
	input[64] = 1

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			ret, _, err := v.Run(nil, common.Address{}, v.Address(), input, GasVerkleVerify+100, true)
			require.NoError(t, err)
			require.Equal(t, []byte{1}, ret)
		})
	}
	wg.Wait()
}

// --- BLS Deep Tests ---

func TestDeep_BLS_GasZero(t *testing.T) {
	b := &blsPrecompile{}
	input := make([]byte, 176)
	_, _, err := b.Run(nil, common.Address{}, b.Address(), input, 0, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
}

func TestDeep_BLS_ExactGas(t *testing.T) {
	b := &blsPrecompile{}
	input := make([]byte, 176)
	_, remaining, err := b.Run(nil, common.Address{}, b.Address(), input, GasBLSVerify, true)
	require.NoError(t, err)
	require.Equal(t, uint64(0), remaining)
}

func TestDeep_BLS_EmptyInput(t *testing.T) {
	b := &blsPrecompile{}
	_, _, err := b.Run(nil, common.Address{}, b.Address(), nil, GasBLSVerify, true)
	require.Error(t, err)
}

func TestDeep_BLS_Concurrent(t *testing.T) {
	b := &blsPrecompile{}
	input := make([]byte, 176)

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			_, _, err := b.Run(nil, common.Address{}, b.Address(), input, GasBLSVerify+100, true)
			require.NoError(t, err)
		})
	}
	wg.Wait()
}

// --- BLS Aggregate Deep Tests ---

func TestDeep_BLSAggregate_EmptyInput(t *testing.T) {
	b := &blsAggregatePrecompile{}
	gas := b.RequiredGas(nil)
	require.Equal(t, uint64(0), gas)
}

func TestDeep_BLSAggregate_GasZero(t *testing.T) {
	b := &blsAggregatePrecompile{}
	input := make([]byte, 96)
	_, _, err := b.Run(nil, common.Address{}, b.Address(), input, 0, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
}

// --- Ringtail Deep Tests ---

func TestDeep_Ringtail_GasZero(t *testing.T) {
	r := &ringtailPrecompile{}
	input := make([]byte, 100)
	_, _, err := r.Run(nil, common.Address{}, r.Address(), input, 0, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
}

func TestDeep_Ringtail_EmptyInput(t *testing.T) {
	r := &ringtailPrecompile{}
	_, _, err := r.Run(nil, common.Address{}, r.Address(), nil, GasRingtailVerify, true)
	require.Error(t, err)
}

// --- Hybrid Deep Tests ---

func TestDeep_Hybrid_GasZero(t *testing.T) {
	h := &hybridPrecompile{}
	input := make([]byte, 300)
	_, _, err := h.Run(nil, common.Address{}, h.Address(), input, 0, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
}

func TestDeep_Hybrid_EmptyInput(t *testing.T) {
	h := &hybridPrecompile{}
	_, _, err := h.Run(nil, common.Address{}, h.Address(), nil, GasHybridVerify, true)
	require.Error(t, err)
}

// --- Compressed Deep Tests ---

func TestDeep_Compressed_GasZero(t *testing.T) {
	c := &compressedPrecompile{}
	input := make([]byte, 44)
	_, _, err := c.Run(nil, common.Address{}, c.Address(), input, 0, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
}

func TestDeep_Compressed_EmptyInput(t *testing.T) {
	c := &compressedPrecompile{}
	_, _, err := c.Run(nil, common.Address{}, c.Address(), nil, GasCompressedVerify, true)
	require.Error(t, err)
}

// --- Fuzz ---

func FuzzVerkle(f *testing.F) {
	f.Add(make([]byte, 65))
	f.Add([]byte{})
	f.Add(make([]byte, 100))

	v := &verklePrecompile{}
	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic: %v", r)
			}
		}()
		v.Run(nil, common.Address{}, v.Address(), input, GasVerkleVerify+100000, true)
	})
}

func FuzzCompressed(f *testing.F) {
	f.Add(make([]byte, 44))
	f.Add([]byte{})

	c := &compressedPrecompile{}
	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic: %v", r)
			}
		}()
		c.Run(nil, common.Address{}, c.Address(), input, GasCompressedVerify+100000, true)
	})
}
