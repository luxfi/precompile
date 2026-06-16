// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// blue — talk to Beluga's on-chain brain.
//
// This invokes the SAME deterministic AI-inference precompile (0x0300…0003) that a
// transaction to the Beluga chain executes — in-process, so you get the exact bytes
// every validator would compute. The current brain is the MVP proof-of-correctness
// model (untrained, 48-token vocab): it "speaks" in deterministic token ids, not English.
// A trained model (e.g. zen-nano, int-quantized) plugs in via the model-registry
// precompile (0x0300…0002) to make blue actually converse.
//
// Usage:
//
//	go run ./cmd/blue/                 # blue continues the default prompt
//	go run ./cmd/blue/ 1 7 13 2        # send a token-id prompt (ids 0..47)
//	go run ./cmd/blue/ -n 16 5 9 2     # ask for 16 new tokens
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/inference"
)

func main() {
	nNew := uint32(10)
	var prompt []uint32
	for i := 1; i < len(os.Args); i++ {
		a := os.Args[i]
		if (a == "-n" || a == "--new") && i+1 < len(os.Args) {
			v, err := strconv.Atoi(os.Args[i+1])
			if err != nil || v < 1 {
				fail("bad -n value %q", os.Args[i+1])
			}
			nNew = uint32(v)
			i++
			continue
		}
		v, err := strconv.Atoi(a)
		if err != nil || v < 0 || v > 47 {
			fail("bad token %q — use integer token ids 0..47 (blue's MVP vocab is 48)", a)
		}
		prompt = append(prompt, uint32(v))
	}
	if len(prompt) == 0 {
		prompt = []uint32{1, 7, 13, 2}
	}

	// Encode the precompile calldata exactly as an on-chain caller would:
	//   selector(4) | nNew(uint32 BE, 4) | prompt tokens (uint32 BE each)
	input := make([]byte, 8+len(prompt)*4)
	binary.BigEndian.PutUint32(input[0:4], inference.SelectorGenerate)
	binary.BigEndian.PutUint32(input[4:8], nNew)
	for i, t := range prompt {
		binary.BigEndian.PutUint32(input[8+i*4:], t)
	}

	gas := inference.InferencePrecompile.RequiredGas(input)
	ret, _, err := inference.InferencePrecompile.Run(nil, common.Address{}, inference.ContractAddress, input, gas, false)
	if err != nil {
		fail("blue: %v", err)
	}

	out := make([]uint32, len(ret)/4)
	for i := range out {
		out[i] = binary.BigEndian.Uint32(ret[i*4:])
	}
	said := out[len(prompt):]

	fmt.Printf("  you  → %v\n", prompt)
	fmt.Printf("  blue → %v\n", said)
	fmt.Printf("\n  (full: %v)\n", out)
	fmt.Printf("  precompile %s · gas %d · deterministic: every validator computes this exact output\n",
		inference.ContractAddress.Hex(), gas)
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
