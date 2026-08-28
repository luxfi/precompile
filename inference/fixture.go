// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// fixture.go — the frozen reference model + prompt, identical to the C++/GPU fixture
// (ops/aivm/tiny_llm/tiny_llm_fixture.hpp): same LCG, same fill order, same seed. Used
// by the token-exact cross-implementation test and as the built-in MVP model for the
// precompile until on-chain model provisioning lands.

package inference

type lcg struct{ s uint64 }

func newLCG(seed uint64) *lcg { return &lcg{s: seed | 1} }

func (l *lcg) next() uint32 {
	l.s = l.s*6364136223846793005 + 1442695040888963407
	return uint32(l.s >> 32)
}

func (l *lcg) i8() int8 { return int8(int32(l.next()%256) - 128) }

func (l *lcg) fill(n uint32) []int8 {
	v := make([]int8, n)
	for i := range v {
		v[i] = l.i8()
	}
	return v
}

// fixtureModel builds the frozen reference model (matches make_fixture() in C++).
func fixtureModel() *Model {
	c := ModelConfig{
		Vocab: 48, Dim: 32, Hidden: 64, NLayers: 2,
		GemmShift: 9, GemmShiftH: 9, LmShift: 9,
		RmsMult: 5, RmsEps: 16, QkShift: 9, OvShift: 7, SwigluShift: 6,
	}
	r := newLCG(0x70E711A0BEEF1234)
	w := Weights{
		Embed: r.fill(c.Vocab * c.Dim),
		Rms1:  r.fill(c.NLayers * c.Dim),
		Wq:    r.fill(c.NLayers * c.Dim * c.Dim),
		Wk:    r.fill(c.NLayers * c.Dim * c.Dim),
		Wv:    r.fill(c.NLayers * c.Dim * c.Dim),
		Wo:    r.fill(c.NLayers * c.Dim * c.Dim),
		Rms2:  r.fill(c.NLayers * c.Dim),
		Wgate: r.fill(c.NLayers * c.Hidden * c.Dim),
		Wup:   r.fill(c.NLayers * c.Hidden * c.Dim),
		Wdown: r.fill(c.NLayers * c.Dim * c.Hidden),
		Rmsf:  r.fill(c.Dim),
		Wlm:   r.fill(c.Vocab * c.Dim),
	}
	return &Model{Cfg: c, W: w}
}

// fixturePrompt is the reference prompt token ids.
func fixturePrompt() []int32 { return []int32{1, 7, 13, 2} }
