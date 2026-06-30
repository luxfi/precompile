# aivmbridge — A-Chain Inference Bridge Precompile

The C-Chain EVM precompile that on-ramps a contract to A-Chain (aivm)
large-model inference via two consensus-safe ops and a native
proof-of-inference verifier.

> Companion to [LP-5301](https://github.com/luxfi/lps/blob/main/LPs/lp-5301-ai-bridge-precompile-aivmbridge.md)
> (the AI Bridge Precompile) and [LP-5300](https://github.com/luxfi/lps/blob/main/LPs/lp-5300-thinking-chains-cognitive-consensus-proof-of-thought.md)
> (Thinking Chains / Cognitive Consensus / Proof-of-Thought). This README
> is contributor-onboarding only; the LPs are the normative spec.

## Overview

- **Address:** `0x0300000000000000000000000000000000000004` (the AI range
  slot `0x04`). Disjoint from `0x0300…0003` (deterministic in-consensus
  inference) and `0x0300…0000` (AI mining).
- **Three method selectors:**
  - **Pattern A — `submitInferenceIntent` (`0x10000000`).** Writes a
    committed C-side outbox intent + returns a deterministic `intent_id`.
    No A query. No A mutation.
  - **Pattern B — `verifyInferenceReceipt` (`0x11000000`).** Verifies a
    committed A receipt against a `receipt_root` C already holds, matches
    a pending outbox intent, records canonical output. No A query.
  - **`verifyComputeProof` (`0x12000000`).** Native proof-of-inference:
    Merkle inclusion under a committed transcript root + Freivalds
    `C == A·B` over `F_p` (`p = 2^61-1`), `k = 2` (soundness `~2^-122`).
    Pure. Safe under a static call.

## Status

- **LP-5301** — normative spec for this precompile (Pattern A/B + the
  receipt/proof wire). The 12-vector security map in §Security maps
  one-to-one to code citations in this package.
- **LP-5300** — Thinking Chains / Cognitive Consensus / PoT. Defines
  the bridge law, the receipt schema, and the full off-chain attack
  surface (beacon grinding, slash-grief, recursion runaway) that lives
  with the settlement engine.
- **HIP-0114** — ZAP Inter-VM Cognitive Transport. ZAP carries `cog.*`
  procedures (intent / receipt / artifact / operator / health / sim);
  ZAP is transport-only and is never a consensus input on its own.
- **Build:** `go build ./aivmbridge/...` clean.
- **Tests:** the package ships the red-team harness — see "Usage" below.
- **Audit:** the `computeattest` op (`computeproof.go`, commit `9fbe02b`,
  2026-06-24) closes audit item G10.

## Files

| File | Role |
|---|---|
| `module.go` | Precompile registration, address (`0x0300…0004`), config, `Configurator`, `RequiredGas` dispatch. |
| `bridge.go` | `Run()` body: selector routing, calldata hardening, sourcing C tx identity, Pattern A/B dispatch. |
| `intent.go` | Deterministic `intent_id` derivation (pure function of calldata + C tx identity, never of any A response). |
| `verify.go` | Pattern B receipt verification: receipt-root committedness, Merkle inclusion, bind-field equality, CEI ordering. |
| `proof.go` | Merkle proof decode + check; index high-bit aliasing rejected. |
| `receipt.go` | A-Chain receipt wire decode (byte-for-byte canonical). |
| `state.go` | C-side outbox storage: `OutboxPending`, `OutboxConsumed` slots. |
| `errors.go` | All sentinel revert reasons (e.g. `ErrIntentReplay`, `ErrReceiptRootNotCommitted`, `ErrReadOnly`). |
| `gas.go` | Per-op gas: `GasSubmitInferenceIntent`, `verifyGas(pathLen)`, `GasVerifyComputeProofBase + …`. |
| `achain_client.go` | The node-LOCAL A-Chain on-ramp interface. Proof/receipt-oriented; no live-query method exists by construction. Install-once `CompareAndSwap` with atomic publish. |
| `native_achain_client.go` | Default no-op A-Chain client (`achainUnavailable`) so a node that does not wire its local A on-ramp reverts cleanly per selector. |
| `computeproof.go` | NATIVE proof-of-inference verifier (`computeattest`). Decodes a beacon-selected matmul opening, runs Merkle inclusion + Freivalds. Shipped 2026-06-24 in `9fbe02b`. |

Test files: `wire_test.go` (golden vectors), `crossmodule_test.go` (seam
parity with the inference precompile), `redteam_test.go` (the 12-vector
attack harness), `gas_test.go`, `harness_test.go`, `install_test.go`,
`decode_test.go`, `achain_submit_test.go`, `achain_verify_test.go`,
`zap_test.go`, `computeproof_test.go`.

## Security (12-vector map from LP-5301 §Security)

| # | Vector | One-line defense | Cited files |
|---|---|---|---|
| 1 | Live A read | No live-read method exists; Pattern B verifies committed C state + calldata proof only | `achain_client.go`, `verify.go` |
| 2 | Direct A mutation | Leaf library; cannot reach chain manager; Pattern A writes only C outbox | `achain_client.go`, `state.go` |
| 3 | Intent replay | Deterministic injective `intent_id`; `OutboxPending` guard (`ErrIntentReplay`) | `intent.go`, `state.go`, `bridge.go` |
| 4 | Receipt replay / double-consume | `OutboxConsumed` guard, CEI order (`ErrIntentConsumed`) | `verify.go` |
| 5 | Wrong model / prompt | Bound-field equality check (`ErrReceiptBindMismatch`) | `verify.go` step 7 |
| 6 | Pending → credit | Only `Completed` + non-zero output is actionable (`ErrReceiptNotCompleted`, `ErrZeroOutput`) | `verify.go` steps 1–2 |
| 7 | Forged proof | Root must be C-committed (`ErrReceiptRootNotCommitted`); leaf recomputed from receipt bytes; index high-bit aliasing rejected | `verify.go` step 3–4, `proof.go` |
| 8 | ZAP-without-proof | Routing hint is transport-only, NOT consensus state, NOT in the `intent_id` preimage | `bridge.go`, `state.go`, `zap_test.go` |
| 9 | Install TOCTOU | Install-once `CompareAndSwap` + atomic publish; second install errors | `achain_client.go` |
| 10 | Calldata | Exact-length frames (reject short AND oversized); dirty-high-byte rejection; `MaxFanout = 256` | `bridge.go`, `errors.go` |
| 11 | Read-only abuse | Both Pattern A/B mutate the C outbox, so a static call reverts (`ErrReadOnly`) | `bridge.go` |
| 12 | Missing atomic capability | No cross-chain atomic capability ⇒ revert (`ErrNoAtomicState`); zero `c_tx_hash` ⇒ revert (`ErrZeroTxHash`) | `bridge.go` |

The off-chain attack surface (beacon grinding, slash-grief, recursion
runaway) and the value-conservation argument live with the settlement
engine — see LP-5300 §Security.

## Constraints (the Bridge Law)

Three invariants, copied from LP-5300 §Bridge Law and enforced at the
package boundary. They are the reason this precompile exists in exactly
the shape it does:

1. **No live-A-read.** A C Run() MUST NOT make consensus state depend
   on observing live A-Chain process state. There is, by construction,
   no `GetInferenceReceipt(id)` method on `AChainClient`. Verification
   takes the receipt + proof as calldata.
2. **No live-A-mutate.** A C Run() MUST NOT mutate live A-Chain state.
   Pattern A writes only to the committed C-side outbox; A's own
   consensus imports it later (Blue-B's importer reads the committed C
   outbox / staged atomic object).
3. **No consensus path outside ZAP.** The ZAP routing hint is
   transport-only — it is NOT consensus state and is NOT in the
   `intent_id` preimage. Certification is by committed outbox entries,
   Merkle proofs against `receipt_root`, or signer policy under
   HIP-0113 — never by ZAP delivery alone.

A node that does not wire its local A on-ramp leaves the default
`achainUnavailable` client in place, and every bridge selector reverts
cleanly. This is the fail-secure default.

## Usage

Build the package:

```bash
go build ./aivmbridge/...
```

Run the full harness (golden wire vectors, cross-module seam parity, the
12-vector red-team suite, gas accounting, install discipline):

```bash
go test ./aivmbridge/...
```

Run just the red-team vectors:

```bash
go test ./aivmbridge/ -run RedTeam
```

## References

- **[LP-5300](https://github.com/luxfi/lps/blob/main/LPs/lp-5300-thinking-chains-cognitive-consensus-proof-of-thought.md)** — Thinking Chains / Cognitive Consensus / Proof-of-Thought. The settlement engine, the bridge law, the receipt schema.
- **[LP-5301](https://github.com/luxfi/lps/blob/main/LPs/lp-5301-ai-bridge-precompile-aivmbridge.md)** — AI Bridge Precompile (this package). Normative spec.
- **[HIP-0114](https://github.com/hanzoai/hips/blob/main/HIPs/hip-0114-zap-inter-vm-cognitive-transport.md)** — ZAP Inter-VM Cognitive Transport. The `cog.*` procedure family that carries intents, receipts, and artifacts off the consensus path.
- **[ZIP-0901](https://github.com/zooai/zips)** — Zoo-side Thinking Chains profile.
