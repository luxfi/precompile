// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package inference

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/luxfi/geth/common"
)

func encodeGenerate(nNew uint32, prompt []uint32) []byte {
	input := make([]byte, 8+len(prompt)*4)
	binary.BigEndian.PutUint32(input[0:4], SelectorGenerate)
	binary.BigEndian.PutUint32(input[4:8], nNew)
	for i, p := range prompt {
		binary.BigEndian.PutUint32(input[8+i*4:8+i*4+4], p)
	}
	return input
}

// TestPrecompileRunGenerate drives the precompile end-to-end via its ABI and asserts the
// returned tokens match the cross-implementation reference sequence.
func TestPrecompileRunGenerate(t *testing.T) {
	input := encodeGenerate(10, []uint32{1, 7, 13, 2})
	gas := InferencePrecompile.RequiredGas(input)
	ret, rem, err := InferencePrecompile.Run(nil, common.Address{}, common.Address{}, input, gas+1000, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rem != 1000 {
		t.Fatalf("remaining gas = %d, want 1000", rem)
	}
	if len(ret)%4 != 0 {
		t.Fatalf("ret length %d not a multiple of 4", len(ret))
	}
	got := make([]int32, len(ret)/4)
	for i := range got {
		got[i] = int32(binary.BigEndian.Uint32(ret[i*4 : i*4+4]))
	}
	want := []int32{1, 7, 13, 2, 4, 28, 21, 17, 2, 19, 43, 35, 36, 15}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tokens:\n  got  %v\n  want %v", got, want)
	}
}

func TestPrecompileOutOfGas(t *testing.T) {
	input := encodeGenerate(1, []uint32{1})
	if _, _, err := InferencePrecompile.Run(nil, common.Address{}, common.Address{}, input, 1, false); err == nil {
		t.Fatal("expected out-of-gas error")
	}
}

func TestPrecompileRejectsBadToken(t *testing.T) {
	input := encodeGenerate(1, []uint32{9999}) // >= vocab (48)
	gas := InferencePrecompile.RequiredGas(input)
	if _, _, err := InferencePrecompile.Run(nil, common.Address{}, common.Address{}, input, gas, false); err == nil {
		t.Fatal("expected out-of-vocab error")
	}
}
