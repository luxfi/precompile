// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls12381

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// The vectors in testdata/ are the EIP-2537 reference set as shipped with
// go-ethereum (core/vm/testdata/precompiles). They are the only oracle here
// that is independent of this implementation: a round trip through encodeG1
// and decodeG1 agrees with itself no matter which curve it is on.
//
//   - eip2537_kat.json  input -> output, with the EIP's gas price
//   - eip2537_gas.json  input length -> gas, for every pair count the set reaches
//   - eip2537_fail.json input -> the class of refusal it must produce

const katGas = 1 << 30

type katVector struct {
	Op       string `json:"op"`
	Name     string `json:"name"`
	Input    string `json:"input"`
	Expected string `json:"expected"`
	Gas      uint64 `json:"gas"`
}

type gasVector struct {
	Op       string `json:"op"`
	Pairs    uint64 `json:"pairs"`
	InputLen int    `json:"inputLen"`
	Gas      uint64 `json:"gas"`
}

type failVector struct {
	Op            string `json:"op"`
	Name          string `json:"name"`
	Input         string `json:"input"`
	ExpectedError string `json:"expectedError"`
}

func loadVectors[T any](t *testing.T, name string) []T {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	var out []T
	require.NoError(t, json.Unmarshal(raw, &out))
	require.NotEmpty(t, out)
	return out
}

// run dispatches a vector to the operation it names.
var run = map[string]func(input []byte, gas uint64) ([]byte, uint64, error){
	"g1add":   blsOps.g1Add,
	"g1mul":   blsOps.g1Mul,
	"g1msm":   blsOps.g1MSM,
	"g2add":   blsOps.g2Add,
	"g2mul":   blsOps.g2Mul,
	"g2msm":   blsOps.g2MSM,
	"pairing": blsOps.pairing,
}

// TestEIP2537_KnownAnswers requires the published output for every published
// input, and requires the call to have cost the published price.
func TestEIP2537_KnownAnswers(t *testing.T) {
	for _, v := range loadVectors[katVector](t, "eip2537_kat.json") {
		t.Run(v.Op+"/"+v.Name, func(t *testing.T) {
			op, ok := run[v.Op]
			require.True(t, ok, "no operation named %q", v.Op)

			input, err := hex.DecodeString(v.Input)
			require.NoError(t, err)

			out, remaining, err := op(input, katGas)
			require.NoError(t, err)
			require.Equal(t, v.Expected, hex.EncodeToString(out))
			require.Equal(t, v.Gas, katGas-remaining, "charged the wrong price")
		})
	}
}

// TestEIP2537_GasSchedule pins the price of every pair count the reference set
// reaches -- 1 to 31, then 64, 128, 256 and beyond, which is where the MSM
// discount table stops improving and max_discount takes over.
func TestEIP2537_GasSchedule(t *testing.T) {
	seen := map[string]int{}
	for _, v := range loadVectors[gasVector](t, "eip2537_gas.json") {
		seen[v.Op]++
		t.Run(v.Op+"/k="+itoa(v.Pairs), func(t *testing.T) {
			var got uint64
			switch v.Op {
			case "g1msm":
				got = G1MSMGas(v.Pairs)
			case "g2msm":
				got = G2MSMGas(v.Pairs)
			case "pairing":
				got = PairingGas(v.InputLen)
			case "g1add":
				got = GasG1Add
			case "g2add":
				got = GasG2Add
			case "g1mul":
				got = GasG1Mul
			case "g2mul":
				got = GasG2Mul
			default:
				t.Fatalf("no gas function for %q", v.Op)
			}
			require.Equal(t, v.Gas, got)
		})
	}
	require.GreaterOrEqual(t, seen["g1msm"], 30, "the MSM discount table is barely exercised")
	require.GreaterOrEqual(t, seen["g2msm"], 30)
}

// TestEIP2537_GasIsChargedByTheOperation ties each operation's own accounting
// to the schedule, so the two cannot drift.
func TestEIP2537_GasIsChargedByTheOperation(t *testing.T) {
	for _, v := range loadVectors[gasVector](t, "eip2537_gas.json") {
		if v.Op != "g1msm" && v.Op != "g2msm" && v.Op != "pairing" {
			continue
		}
		if v.InputLen > 1<<20 {
			continue // the largest vectors are priced above, without the arithmetic
		}
		t.Run(v.Op+"/k="+itoa(v.Pairs), func(t *testing.T) {
			// A zero-filled body of the right length: every operation charges
			// before it looks at the contents, which is the property under test.
			_, remaining, _ := run[v.Op](make([]byte, v.InputLen), katGas)
			require.Equal(t, v.Gas, katGas-remaining)
		})
	}
}

// TestEIP2537_MSMDiscountRewardsBatching: past k=1 an MSM must cost strictly
// less than k separate multiplications, and the per-pair price must fall
// monotonically until the table runs out.
func TestEIP2537_MSMDiscountRewardsBatching(t *testing.T) {
	for _, tc := range []struct {
		name string
		gas  func(uint64) uint64
		unit uint64
		last uint64
	}{
		{"g1", G1MSMGas, GasG1MSM, msmMaxDiscountG1},
		{"g2", G2MSMGas, GasG2MSM, msmMaxDiscountG2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Zero(t, tc.gas(0))
			require.Equal(t, tc.unit, tc.gas(1))

			prevPerPair := tc.unit + 1
			for k := uint64(1); k <= 128; k++ {
				total := tc.gas(k)
				require.LessOrEqual(t, total, k*tc.unit, "k=%d is not discounted", k)
				perPair := total / k
				require.LessOrEqualf(t, perPair, prevPerPair, "per-pair price rose at k=%d", k)
				prevPerPair = perPair
			}

			// Beyond the table the discount is frozen at max_discount.
			for _, k := range []uint64{129, 256, 4096} {
				require.Equal(t, k*tc.unit*tc.last/msmMultiplier, tc.gas(k))
			}
		})
	}

	// G2 is priced separately from G1 and is not a scaled copy of it.
	require.NotEqual(t, msmDiscountG1, msmDiscountG2)
}

// TestEIP2537_Refusals requires the published class of refusal for every
// published bad input: a wrong length, non-zero padding, a field element at or
// above the modulus, a point off the curve, and -- the one that is not visible
// from the encoding -- a point on the curve but outside the r-order subgroup.
func TestEIP2537_Refusals(t *testing.T) {
	want := map[string]error{
		"invalid input length":                ErrInvalidInput,
		"invalid field element top bytes":     ErrInvalidFieldElem,
		"invalid fp.Element encoding":         ErrInvalidFieldElem,
		"invalid point: not on curve":         ErrPointNotOnCurve,
		"g1 point is not on correct subgroup": ErrPointNotInSubgrp,
		"g2 point is not on correct subgroup": ErrPointNotInSubgrp,
	}

	classes := map[string]int{}
	for _, v := range loadVectors[failVector](t, "eip2537_fail.json") {
		t.Run(v.Op+"/"+v.Name, func(t *testing.T) {
			expected, ok := want[v.ExpectedError]
			require.Truef(t, ok, "unmapped refusal class %q", v.ExpectedError)
			classes[v.ExpectedError]++

			input, err := hex.DecodeString(v.Input)
			require.NoError(t, err)

			out, _, err := run[v.Op](input, katGas)
			require.Error(t, err, "accepted an input the reference set rejects")
			require.Nil(t, out)

			if v.Op == "pairing" && v.ExpectedError == "invalid input length" {
				require.ErrorIs(t, err, ErrInvalidPairingLen)
				return
			}
			require.ErrorIs(t, err, expected)
		})
	}

	// Every class the reference set carries was actually reached.
	for class := range want {
		require.NotZerof(t, classes[class], "no vector exercised %q", class)
	}
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
