# Blue — porting zen-nano (Qwen3-0.6B) to deterministic on-chain inference

Goal: replace the toy fixture model in this package with a **real** small LLM —
**zen-nano** (Qwen3-0.6B) — running as a deterministic, byte-exact integer transformer so
every validator computes identical tokens. This is the brain of the Zoo L3 **Beluga** ("blue").

The hard prerequisites were all **validated 2026-06-15** against the real weights
(`~/work/zen/models/zen-nano-0.6b/model.safetensors`); see "Coherence results" below. The
research risk is retired — what remains is the Go port (this doc is its blueprint).

## Architecture (Qwen3-0.6B, from config.json)

| field | value | note |
|---|---|---|
| hidden_size | 1024 | |
| num_hidden_layers | 28 | |
| num_attention_heads | 16 | query heads |
| num_key_value_heads | 8 | **GQA** — 2 q-heads per kv-head |
| head_dim | 128 | decoupled: 16·128=2048 q-proj ≠ hidden |
| intermediate_size | 3072 | SwiGLU |
| rms_norm_eps | 1e-6 | |
| rope_theta | 1e6 | |
| vocab_size | 151936 | |
| tie_word_embeddings | true | lm_head = embed.T |
| attention_bias | false | no QKV bias |
| **q_norm / k_norm** | RMSNorm[128] | Qwen3-specific: per-head RMSNorm on Q and K **before** RoPE |

Per layer: `rmsnorm → q/k/v_proj → q_norm/k_norm → RoPE → GQA causal attn → o_proj →
+residual → rmsnorm → SwiGLU(gate,up,down) → +residual`. Then final `rmsnorm → lm_head(tied) → argmax`.

## Gaps vs the current toy engine (`inference.go`)

1. **Config**: generalize `ModelConfig` to the dims above (vocab 151936, 28 layers, GQA).
2. **Attention**: toy is single-head; need **multi-head + GQA** (16 q / 8 kv, head_dim 128),
   per-head **q_norm/k_norm**, and RoPE at head_dim 128 / θ=1e6. Scale 1/√128.
3. **GEMM requant**: toy uses one power-of-2 `>>shift`; a real model needs **per-output-channel
   fixed-point requant** (gemmlowp: int32 multiply-high + rounding shift). The `requant_i8`
   op already does this — wire per-channel `(mult,shift)`.
4. **Weights**: load zen-nano's quantized int8 weights + scales (today's fixture is LCG noise).

## Quantization recipe (validated)

- **Weights**: per-output-channel symmetric int8. `s_w[o]=max(|W[o,:]|)/127`,
  `Wq[o,:]=round(W[o,:]/s_w[o])∈[-127,127]`. Precomputed offline → fixed model data → deterministic.
- **Activations**: int8. Two consensus-safe options:
  - **dynamic-integer** (preferred, better quality): per-token `s_a = max(|x|)` is an **integer**
    (x is int) → bit-exact across machines. Requant multiplier folds `s_a·s_w[o]/s_out` as a
    precomputed/recomputed integer `(mult,shift)`.
  - **static** (simplest): per-tensor scales calibrated offline; fully integer at runtime.
- **Requant**: gemmlowp `SaturatingRoundingDoublingHighMul(acc, mult[o])` then
  `RoundingDivideByPOT(·, shift[o])` → int8. All integer.
- **Activation ops** (already in the engine, integer): RMSNorm (int64 Σx², bit-by-bit isqrt),
  softmax (frozen Q16 exp LUT), SiLU (frozen LUT), RoPE (frozen Q14 sin/cos LUT).

## Coherence results (real zen-nano, greedy)

| scheme | output for "The capital of France is" | consensus-safe |
|---|---|---|
| float reference (arch check) | "Paris. …Italy is Rome. …Spain is Madrid. …China is Beijing." | n/a (validation) |
| dynamic int8 (float scales) | "Paris. …also the capital of the EU…" | no (float) |
| **static int8** (per-tensor) | "…center of the French Revolution…" — coherent, degraded | **yes** ✓ |
| chat (int8, `/no_think`) | *"Hello! I'm Lina, a language model designed to assist…"* | (demo) |

Takeaway: even the **coarsest** deterministic scheme stays coherent; dynamic-integer scales
recover most of the quality while remaining bit-exact. **Deterministic on-chain blue is viable.**

## Go port plan

1. Generalize `inference.go`: `ModelConfig`(Qwen3) · GQA multi-head attention w/ q/k-norm + RoPE ·
   per-channel `requant_i8`. Keep the toy path as a special case (1 head, no q/k-norm) so existing
   tests pass.
2. Weight format: a binary blob = header(config) + per-tensor {int8 weights, per-channel
   `(mult,shift)` or `s_w`} + the frozen LUTs. A Python exporter quantizes the safetensors → this blob.
3. Verify: Go greedy-decode == the Python integer reference, **token-exact**, on a fixed prompt
   (the byte-exact KAT — same discipline as the 6-impl toy proof).
4. Tokenizer: Qwen3 BPE runs **client-side** (off-chain); the precompile takes/returns token ids.
5. Provisioning: the **model-registry precompile (0x0300…0002)** holds the weight-commitment hash;
   validators load the matching blob out-of-band, verified against it. The inference precompile
   (0x0300…0003) reads the approved commitment.

## Speed

- Demo: 30s → **2.3s** (~13×) via KV cache + Metal (torch-MPS, fp16) — see `blue_fast.py`.
- Production on-chain: the deterministic **Metal/CUDA/HIP `aivm` kernels** (lux-private/gpu-kernels)
  — GPU-accelerated *and* byte-identical to this Go reference. That's their purpose.
- Off-chain serving: hanzo-engine / llama.cpp on Metal, ~100+ tok/s for 0.6B.

## Validation tooling (this session)

`/tmp/blue_float.py` (arch ref) · `blue_int8.py` (dynamic int8) · `blue_det.py` (static int8,
deterministic-friendly) · `blue_chat.py` (CPU int8 chat) · `blue_fast.py` (MPS+KV-cache chat).
To be productized into `cmd/blue` + a quant exporter.
