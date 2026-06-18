// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package inference

import (
	"reflect"
	"testing"
)

// TestTokenExactVsGPUStack asserts the pure-Go reference greedy-decodes the EXACT token
// sequence that the C++ oracle and the Metal/CUDA/HIP kernels produce on the same frozen
// fixture (validated byte/token-exact on M4 Max, GB10, Radeon gfx1151). A mismatch means
// the Go consensus path diverged from the GPU accelerator — a consensus bug.
func TestTokenExactVsGPUStack(t *testing.T) {
	want := []int32{1, 7, 13, 2, 4, 28, 21, 17, 2, 19, 43, 35, 36, 15}
	got := fixtureModel().Generate(fixturePrompt(), 10)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("token mismatch:\n  got  %v\n  want %v", got, want)
	}
}

// TestDeterministicAcrossRuns: the same model + prompt always yields the same tokens.
func TestDeterministicAcrossRuns(t *testing.T) {
	m := fixtureModel()
	a := m.Generate(fixturePrompt(), 12)
	b := m.Generate(fixturePrompt(), 12)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("non-deterministic: %v vs %v", a, b)
	}
}
