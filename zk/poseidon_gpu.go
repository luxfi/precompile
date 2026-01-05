// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build gpu

package zk

import (
	"github.com/luxfi/crypto/hash/poseidon2"
)

func init() {
	// Override the default hash function with GPU-accelerated version
	gpuHashFunc = func(input []byte) ([]byte, error) {
		return poseidon2.HashFromBytes(input)
	}
	gpuHashPairFunc = func(left, right [32]byte) ([32]byte, error) {
		leftElem := poseidon2.Element(left)
		rightElem := poseidon2.Element(right)
		result, err := poseidon2.HashPair(leftElem, rightElem)
		if err != nil {
			return [32]byte{}, err
		}
		return [32]byte(result), nil
	}
	gpuCommitmentFunc = func(value, blinding, salt [32]byte) ([32]byte, error) {
		v := poseidon2.Element(value)
		b := poseidon2.Element(blinding)
		s := poseidon2.Element(salt)
		result, err := poseidon2.Commitment(v, b, s)
		if err != nil {
			return [32]byte{}, err
		}
		return [32]byte(result), nil
	}
	gpuNullifierFunc = func(key, commitment, index [32]byte) ([32]byte, error) {
		k := poseidon2.Element(key)
		c := poseidon2.Element(commitment)
		i := poseidon2.Element(index)
		result, err := poseidon2.Nullifier(k, c, i)
		if err != nil {
			return [32]byte{}, err
		}
		return [32]byte(result), nil
	}
	useGPU = poseidon2.GPUAvailable()
}
