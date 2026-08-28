// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Package inference is the deterministic int8 transformer that backs the AI-inference
// EVM precompile (0x0303). This is the CANONICAL consensus path: pure Go, CGO=0, so
// every validator computes it identically with no GPU required. The lux-private GPU
// kernels (Metal/CUDA/HIP) are an optional accelerator that is KAT-proven byte-equal to
// this reference — Go ≡ CPU-C++ ≡ Metal ≡ CUDA ≡ HIP, token-for-token.
//
// All arithmetic is integer (two's-complement int32/int64, arithmetic right shift,
// truncating divide) and matches ops/aivm/* in lux-private/gpu-kernels exactly. The
// exp/silu activation tables are FROZEN constants (luts.go), never recomputed via
// math (float libm diverges in the last ULP across platforms and would break consensus).

package inference

// ---- deterministic integer ops (mirror ops/aivm/*/cpu/*.hpp) ----------------------

func satI8(v int32) int8 {
	if v > 127 {
		return 127
	}
	if v < -128 {
		return -128
	}
	return int8(v)
}

func satI8FromI64(v int64) int8 {
	if v > 127 {
		return 127
	}
	if v < -128 {
		return -128
	}
	return int8(v)
}

func isqrtU64(n uint64) uint64 {
	var res uint64
	bit := uint64(1) << 62
	for bit > n {
		bit >>= 2
	}
	for bit != 0 {
		if n >= res+bit {
			n -= res + bit
			res = (res >> 1) + bit
		} else {
			res >>= 1
		}
		bit >>= 2
	}
	return res
}

// C[m,n] = sat_i8( (bias[n] + Σ_k A[m,k]·Bt[n,k]) >> shift ); Bt is row-major [N,K].
func gemmI8(a, bt []int8, bias []int32, c []int8, m, n, k uint32, shift int32) {
	for mi := uint32(0); mi < m; mi++ {
		for ni := uint32(0); ni < n; ni++ {
			acc := bias[ni]
			for ki := uint32(0); ki < k; ki++ {
				acc += int32(a[mi*k+ki]) * int32(bt[ni*k+ki])
			}
			acc >>= shift
			c[mi*n+ni] = satI8(acc)
		}
	}
}

// One RMSNorm row of length d.
func rmsnormI8(x, w, out []int8, d uint32, mult, eps int32) {
	var ss int64
	for ki := uint32(0); ki < d; ki++ {
		xv := int64(x[ki])
		ss += xv * xv
	}
	ss += int64(eps)
	denom := int64(isqrtU64(uint64(ss)))
	if denom == 0 {
		denom = 1
	}
	for i := uint32(0); i < d; i++ {
		num := int64(x[i]) * int64(w[i]) * int64(mult)
		out[i] = satI8FromI64(num / denom)
	}
}

// Single-head causal int8 attention: QKᵀ → shift → softmax(frozen LUT) → ·V → shift.
func attentionI8(q, k, v []int8, lut []int32, out []int8, t, d uint32, qkShift, ovShift int32, causal bool) {
	score := make([]int32, t)
	for ti := uint32(0); ti < t; ti++ {
		jmax := t - 1
		if causal {
			jmax = ti
		}
		var mx int32 = -128
		for j := uint32(0); j <= jmax; j++ {
			var acc int32
			for ki := uint32(0); ki < d; ki++ {
				acc += int32(q[ti*d+ki]) * int32(k[j*d+ki])
			}
			sc := int32(satI8(acc >> qkShift))
			score[j] = sc
			if sc > mx {
				mx = sc
			}
		}
		var sum int64
		for j := uint32(0); j <= jmax; j++ {
			d2 := mx - score[j]
			if d2 > 255 {
				d2 = 255
			}
			sum += int64(lut[d2])
		}
		if sum == 0 {
			sum = 1
		}
		for ki := uint32(0); ki < d; ki++ {
			var oacc int32
			for j := uint32(0); j <= jmax; j++ {
				d2 := mx - score[j]
				if d2 > 255 {
					d2 = 255
				}
				p := (int64(lut[d2])*127 + sum/2) / sum
				oacc += int32(p) * int32(v[j*d+ki])
			}
			out[ti*d+ki] = satI8(oacc >> ovShift)
		}
	}
}

// SwiGLU gate: out[i] = sat_i8( (SILU_LUT[gate[i]+128] · up[i]) >> shift ).
func swigluI8(gate, up []int8, lut []int32, out []int8, n uint32, shift int32) {
	for i := uint32(0); i < n; i++ {
		s := lut[int32(gate[i])+128]
		out[i] = satI8(int32(s*int32(up[i])) >> shift)
	}
}

func residualAddI8(a, b, out []int8, n uint32) {
	for i := uint32(0); i < n; i++ {
		out[i] = satI8(int32(a[i]) + int32(b[i]))
	}
}

func embedGather(tokens []int32, table, out []int8, t, d uint32) {
	for ti := uint32(0); ti < t; ti++ {
		tok := uint32(tokens[ti])
		for ki := uint32(0); ki < d; ki++ {
			out[ti*d+ki] = table[tok*d+ki]
		}
	}
}

func argmaxI8(logits []int8, n uint32) int32 {
	best := int32(0)
	bv := int32(logits[0])
	for i := uint32(1); i < n; i++ {
		if v := int32(logits[i]); v > bv {
			bv = v
			best = int32(i)
		}
	}
	return best
}

// ---- model ------------------------------------------------------------------------

// ModelConfig mirrors aivm::tiny_llm::Config (the transformer dims + requant shifts).
type ModelConfig struct {
	Vocab, Dim, Hidden, NLayers                                                    uint32
	GemmShift, GemmShiftH, LmShift, RmsMult, RmsEps, QkShift, OvShift, SwigluShift int32
}

// Weights are int8 row-major; per-layer arrays concatenated by layer.
type Weights struct {
	Embed          []int8 // [vocab*dim]
	Rms1           []int8 // [n_layers*dim]
	Wq, Wk, Wv, Wo []int8 // [n_layers*dim*dim]
	Rms2           []int8 // [n_layers*dim]
	Wgate, Wup     []int8 // [n_layers*hidden*dim]
	Wdown          []int8 // [n_layers*dim*hidden]
	Rmsf           []int8 // [dim]
	Wlm            []int8 // [vocab*dim]
}

// Model is a deterministic int8 transformer (no KV cache; recomputes the prefix).
type Model struct {
	Cfg ModelConfig
	W   Weights
}

func maxu32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

// step returns the next greedy token for the given prefix (len <= 256).
func (m *Model) step(tokens []int32) int32 {
	c := m.Cfg
	w := m.W
	t := uint32(len(tokens))
	d, h := c.Dim, c.Hidden
	zb := make([]int32, maxu32(c.Vocab, h)) // zero bias

	x := make([]int8, t*d)
	embedGather(tokens, w.Embed, x, t, d)

	hh := make([]int8, t*d)
	q := make([]int8, t*d)
	k := make([]int8, t*d)
	v := make([]int8, t*d)
	attn := make([]int8, t*d)
	tmp := make([]int8, t*d)
	h2 := make([]int8, t*d)
	gate := make([]int8, t*h)
	up := make([]int8, t*h)
	act := make([]int8, t*h)
	mlp := make([]int8, t*d)

	for l := uint32(0); l < c.NLayers; l++ {
		for ti := uint32(0); ti < t; ti++ {
			rmsnormI8(x[ti*d:], w.Rms1[l*d:], hh[ti*d:], d, c.RmsMult, c.RmsEps)
		}
		gemmI8(hh, w.Wq[l*d*d:], zb, q, t, d, d, c.GemmShift)
		gemmI8(hh, w.Wk[l*d*d:], zb, k, t, d, d, c.GemmShift)
		gemmI8(hh, w.Wv[l*d*d:], zb, v, t, d, d, c.GemmShift)
		attentionI8(q, k, v, aivmExpLUT[:], attn, t, d, c.QkShift, c.OvShift, true)
		gemmI8(attn, w.Wo[l*d*d:], zb, tmp, t, d, d, c.GemmShift)
		residualAddI8(x, tmp, x, t*d)

		for ti := uint32(0); ti < t; ti++ {
			rmsnormI8(x[ti*d:], w.Rms2[l*d:], h2[ti*d:], d, c.RmsMult, c.RmsEps)
		}
		gemmI8(h2, w.Wgate[l*h*d:], zb, gate, t, h, d, c.GemmShift)
		gemmI8(h2, w.Wup[l*h*d:], zb, up, t, h, d, c.GemmShift)
		swigluI8(gate, up, aivmSiluLUT[:], act, t*h, c.SwigluShift)
		gemmI8(act, w.Wdown[l*d*h:], zb, mlp, t, d, h, c.GemmShiftH)
		residualAddI8(x, mlp, x, t*d)
	}

	xf := make([]int8, d)
	rmsnormI8(x[(t-1)*d:], w.Rmsf, xf, d, c.RmsMult, c.RmsEps)
	logits := make([]int8, c.Vocab)
	gemmI8(xf, w.Wlm, zb, logits, 1, c.Vocab, d, c.LmShift)
	return argmaxI8(logits, c.Vocab)
}

// Generate greedy-decodes nNew tokens appended to the prompt.
func (m *Model) Generate(prompt []int32, nNew uint32) []int32 {
	out := append([]int32(nil), prompt...)
	for i := uint32(0); i < nNew; i++ {
		out = append(out, m.step(out))
	}
	return out
}
