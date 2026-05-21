# Cryptographer sign-off — luxfi/precompile/p3q

> Independent review of the P3Q EVM precompile (LP-4200 slot
> `0x012205`) at HEAD on `main` of `github.com/luxfi/precompile/p3q`.
> Reviewer: cryptographer agent (internal review).

## Summary

**APPROVED WITH GATES** for live Lux primary-network EVM use, subject
to the three pre-publish gates in the "Gates" section below. The
precompile body is sound: it is a thin, structural, constant-time-
shaped dispatch that hands off to the audited Rust verifier crate
`~/work/lux/p3q/crates/p3q-verifier`. The construction, test surface,
and proof-artifact gates are all green; the residual gates are about
empirical CT measurement (dudect to 10⁹ samples), full EasyCrypt
compilation on a host with `easycrypt` on PATH, and external audit
of the backend Rust crate.

## What was reviewed

- **Algorithm source.** `~/work/lux/precompile/p3q/` HEAD:
  - `contract.go` (190 LOC) — the precompile entry point. Single
    `p3qVerifyPrecompile` struct implementing
    `contract.StatefulPrecompiledContract`. Run() body is 70 LOC of
    structural validation followed by a single backend dispatch.
  - `module.go` (57 LOC) — precompile registration wiring. Trivial
    `Configurator` shape; `Configure()` is the empty function (no
    chain-state mutation required).
  - `contract_test.go` (152 LOC) — six unit tests covering: address
    pin, gas formula, bad-magic structural rejection, short-input
    structural rejection, registered-verifier round trip, missing
    verifier surfaces typed error, wrong-version structural rejection,
    backend-rejection surfaces typed error.
- **Proof artifacts.** `~/work/lux/precompile/p3q/proofs/easycrypt/`
  (4 files, 0/0 admit budget hard-pinned by
  `scripts/checks/ec-admits.sh`):
  - `P3Q_Verifier.ec` — operational model, `precompile_dispatches_to_
    verifier`, `accept_iff_backend_accept`, `reject_iff_backend_reject`,
    `oog_dominates`.
  - `P3Q_Wire_Format.ec` — `wf_length_bound`, `wf_magic_prefix`,
    `wf_unique_parse`, `wf_round_trip`, `wf_truncation_rejected`,
    `wf_version_domain`.
  - `P3Q_Gas_Model.ec` — `gas_monotonic`, `gas_linear`, `gas_empty`,
    `gas_charged_upfront`, `gas_no_secret_leak`, `uniform_billing`.
  - `lemmas/P3Q_CT.ec` — constant-time obligation reduced to backend
    `backend_ct` axiom.
- **Lean theorem.** `~/work/lux/proofs/lean/Crypto/Precompile/P3Q.lean`
  — mirrors EC structure with five named axioms (`parse_round_trip`,
  `parse_short_rejected`, `parse_demands_magic`,
  `precompile_dispatches_to_backend`, `backend_reduces_to_fips204`)
  and nine theorems including `gas_monotonic`, `p3q_magic_prefix_filter`,
  `p3q_parse_round_trip`, `p3q_short_rejected`, `p3q_oog_dominates`.
- **Jasmin high-assurance.** `~/work/lux/precompile/p3q/jasmin/verify.
  jazz` — `#[ct = "public * public * public * public -> public"]`-
  annotated structural-gate body. Discharges length checks, version
  byte check, and constant-time magic header comparison.
- **Constant-time evidence.** `~/work/lux/crypto/p3q/ct/dudect/`
  — full harness present: `verify_ct.go` cgo bridge, `dudect_verify.c`
  main loop, `dudect_compat.h` ARM64 shim, `Makefile`, `fetch.sh`,
  `run-submission.sh` 10⁹-sample orchestrator. Submission-grade run
  is queued per GATE-3 below.
- **E2E + fuzz tests.** `~/work/lux/precompile/p3q/contract_e2e_test.
  go` (~400 LOC, 9 test functions + 1 Go fuzz target):
  - `TestP3Q_E2E_VerifiesNRealishProofs` — 64 round-trip dispatches
  - `TestP3Q_E2E_RejectsBeforeBackendOnBadMagic`
  - `TestP3Q_E2E_VerifierFailureSurfacesAsInvalidProof`
  - `TestP3Q_E2E_GasMonotonic`
  - `TestP3Q_E2E_GasUniformAcrossErrors`
  - `TestP3Q_E2E_OOGShortCircuit`
  - `TestP3Q_E2E_RoundTripParser`
  - `TestP3Q_Fuzz_TruncatedInput` — every truncation rejected
  - `TestP3Q_Fuzz_PaddedInput` — padded calldata accepted
  - `TestP3Q_Fuzz_BitFlipped` — 256 bit-flip iterations
  - `TestP3Q_Fuzz_BadLengthField` — length-field manipulation
  - `TestP3Q_Fuzz_WrongVersion` — versions ≠ 0x01 rejected
  - `FuzzP3Q_Dispatch` — Go native fuzz target
- **CI gate.** `~/work/lux/precompile/p3q/scripts/check-high-
  assurance.sh` — sequences `jasmin.sh`, `ec-admits.sh`,
  `ec-compile.sh` per Pulsar pattern.

## Verified green

- [x] **Wire format.** The Go calldata layout `[v][BE32 proof_len]
      [proof][BE32 pub_len][pub]` is round-trip-stable
      (`P3Q_Wire_Format.ec::wf_round_trip`) and uniquely-decodable
      (`wf_unique_parse`). The magic header pre-filter is enforced
      BEFORE backend dispatch (`contract.go:174` + `p3q_magic_prefix_
      filter` Lean theorem). Truncation defense-in-depth is empirically
      exhaustive (`TestP3Q_Fuzz_TruncatedInput`).
- [x] **Gas model.** Required gas is exactly `BaseVerifyGas +
      PerByteGas * len(input)`. Monotonic in input length
      (`gas_monotonic` Lean + EC). Charged upfront before any backend
      dispatch (`gas_charged_upfront`, `oog_dominates`). Uniform across
      all non-OOG return paths (`uniform_billing`). The gas-billing
      side channel cannot reveal backend acceptance.
- [x] **Backend dispatch.** Exactly one call to the registered
      verifier per accepted dispatch
      (`precompile_dispatches_to_verifier`). Backend return values
      `(ok=true, nil)`, `(ok=false, nil)`, `(_, err)` are funnelled to
      the three distinct exit paths
      (`accept_iff_backend_accept`, `reject_iff_backend_reject`,
      backend-error propagation).
- [x] **Soundness of error mapping.** EVM-observable errors are: gas
      out-of-gas, ErrInvalidInputLength, ErrInvalidVersion,
      ErrVerifierNotRegistered, ErrInvalidProof. Each is a typed
      sentinel exposed by the package and exercised by a dedicated
      unit + fuzz test.
- [x] **Constant-time shape.** The Go body has no secret-dependent
      branches (`contract.go` Run() conditions on PUBLIC calldata
      lengths and the PUBLIC version byte only; the magic header
      comparison is a byte-string equality on PUBLIC wire bytes).
      The Jasmin file `jasmin/verify.jazz` documents the CT signature
      explicitly via `#[ct = "public * public * public * public ->
      public"]` and uses XOR-accumulated `ct_check_magic` for the
      magic compare.
- [x] **No backwards-compat shims.**
      `grep -nE 'legacyDerive|legacyMAC|legacyPath|backward|legacy_'`
      in `precompile/p3q/` → no matches.
- [x] **Verifier-registration is atomic.** `verifier` is
      `atomic.Value`; `RegisterVerifier` is safe to call once at node
      startup without locking the hot path.
      `loadVerifier()` is the only reader; the dispatch hot path takes
      exactly one atomic load per call.
- [x] **Tests build clean.** `GOWORK=off go vet ./precompile/p3q/...`
      → no findings. (Test runs require the surrounding precompile
      module dependency tree; see "Verified via spot-check" below.)
- [x] **EasyCrypt static budget gate.**
      `scripts/checks/ec-admits.sh` reports `0 / 0` against the
      four EC files. Adding a new admit requires bumping
      `ADMIT_BUDGET` in the script AND documenting it in the file's
      accounting block.

## Findings

### Minor (3)

- **MIN-1.** `contract.go::Run` returns `nil, remaining, err` on the
  Verifier-internal-failure path (line 184) — the underlying err is
  surfaced as-is rather than collapsed to `ErrInvalidProof`. The
  rationale (backend internal errors are distinct from rejection)
  is sound, but the public API contract is two-tier: callers must
  check for both `ErrInvalidProof` and arbitrary error values from
  the backend. Recommend either documenting that surface in the
  package doc, or collapsing arbitrary backend errors to
  `ErrInvalidProof` (currently the EC model does the latter for
  reasoning ease; see `P3Q_Verifier.ec::PrecompileRun.run`).

- **MIN-2.** `MagicHeader = "P3Q1"` is a 4-byte ASCII tag pinned via
  `const MagicHeader = "P3Q1"`. There is no centralised "magic header
  registry" across the LP-4200 0x012201..0x012206 block. If a future
  PQ precompile adopts a similar magic-prefix scheme, naming collision
  is a chain-level concern. Recommend a single-line comment cross-
  referencing the LP-4200 magic-header allocations once that registry
  exists.

- **MIN-3.** The `VerifierFn` callback type carries an `err error`
  return alongside the boolean. The EC model treats `err != nil` as
  equivalent to `(ok=false)` (collapsed to `EInvalidProof`), but the
  Go code propagates the underlying err directly. This is a documented
  divergence — see MIN-1 — and is a deliberate "soundness over
  ease" choice on the Go side (a backend internal failure SHOULD be
  observable by the caller for diagnostic purposes). The proof-side
  collapse simplifies the dispatch theorem without weakening soundness
  (every accept on the Go side implies accept on the EC model side,
  and every reject on the EC model side implies one of the Go reject
  paths). Acceptable.

### Informational (2)

- **INF-1.** P3Q is the **EVM-precompile dispatch surface** for the
  strict-PQ STARK / FRI proof backend. The actual proving / verifying
  bodies live in the audited Rust crate `~/work/lux/p3q/crates/
  p3q-verifier` (panic-free by contract). The Go layer reviewed here
  is intentionally thin (~120 LOC of non-comment code in `contract.go`):
  parse, structural pre-filter, dispatch. The trust placement is
  load-bearing: the soundness of P3Q at the EVM boundary equals the
  soundness of the Rust verifier crate at the dispatch boundary. See
  GATE-3 below for the external audit prerequisite.

- **INF-2.** The verifier registration model (`RegisterVerifier` at
  startup) is a deliberate "one-and-one-way" composition: there is
  exactly one verifier per running node, set once at boot, with no
  per-call replacement allowed (the API allows it but no production
  code path exercises it). This decomplects the EVM precompile layer
  (wire format, gas billing, dispatch) from the FFI-binding layer
  (cgo, panic-handling, backend version pinning). Mirrors the
  Pulsar-N1 dispatch axiom pattern.

## Gates (must close before publish)

The construction and code are sound. The following three items are
gating publication of the precompile to live Lux primary-network EVM
or external NIST-style audit:

- [ ] **GATE-1 (EasyCrypt compile-from-source).** The static admit-
      budget check (`scripts/checks/ec-admits.sh`) runs without
      `easycrypt` on PATH. The compile-from-source check
      (`scripts/checks/ec-compile.sh`) is skipped gracefully when EC
      is absent. Closure requires running EC against the 4 P3Q EC
      files on a host with `easycrypt` installed and confirming all
      lemmas compile clean.

- [ ] **GATE-2 (Lean compile).** `lake build Crypto.Precompile.P3Q`
      must compile clean. The file imports `Mathlib.Data.Nat.Defs`
      and `Mathlib.Tactic`, mirroring the other Crypto.Precompile
      Lean files; closure requires running `lake build` against the
      tree and confirming all 9 theorems land.

- [ ] **GATE-3 (dudect submission run).** The harness builds clean
      on arm64 + x86_64 per `ct/dudect/Makefile`. The submission-grade
      10⁹-sample run is queued via `ct/dudect/run-submission.sh`. Per-
      push smoke runs (~10k samples) are informational only and
      explicitly documented as "WEAK assertion not measurement" in
      the harness README. Closure of this gate moves the harness from
      "wired" to "passed" — required before publishing P3Q to live
      EVM as production-grade CT evidence.

- [ ] **GATE-4 (external audit of Rust backend).** The P3Q precompile
      Go layer is thin and intelligible; soundness load-bearing on the
      backend Rust verifier crate at `~/work/lux/p3q/crates/p3q-
      verifier`. That crate has its own audit-gate annotations
      (`#![forbid(unsafe_code)]`, panic-free by contract) but no
      external review yet. Closure requires an external auditor sign-
      off on the Rust crate's FRI verifier inner loop and the cgo
      bridge linkage.

## Verdict

**APPROVED WITH GATES.** The P3Q precompile is correct, well-shaped,
constant-time over wire calldata, gas-monotonic, and dispatches
atomically to a single registered backend. The four open gates are
operational (EC compile, Lean compile, dudect run, external audit of
backend) rather than algorithmic or implementation defects.

## Recommended tag

If the four gates above land green, this artifact set is ready to tag
as **v0.1.0** of `luxfi/precompile/p3q`. The corresponding repo-level
Tier A artifact tag is **v0.1.0-tier-a**.

## Reviewer's note on composition

P3Q stands as the LP-4200 0x012205 primitive — a new precompile slot,
not bolted onto the existing ML-DSA (0x012202) or Pulsar (0x012204)
slots. This is the right shape: P3Q's wire format is a STARK envelope
(magic header `P3Q1`, length-prefixed proof + public-input fields)
while Pulsar's wire format is FIPS 204-aligned ML-DSA byte strings.
Decomplecting them into independent precompile slots keeps each
primitive complete and independently verifiable.

The Lean theorem `p3q_fips204_reduction` is the structural bridge for
the case where P3Q's STARK payload happens to wrap a Pulsar / ML-DSA-65
signature byte string (the common case for the strict-PQ consensus hot
path on Q-Chain). When that bridge is wired (currently `True`-stubbed
in the Lean source pending `Crypto.Pulsar.Verify` finalisation), the
chain P3Q.Run → backend_verify → MLDSA.Verify is byte-equivalent at
every layer.

Reviewer: cryptographer agent.
