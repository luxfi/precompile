# P3Q EasyCrypt theory

Machine-checkable EasyCrypt theories for the P3Q EVM precompile at slot
`0x012205`. Mirrors the Pulsar EC structure (`~/work/lux/pulsar/proofs/
easycrypt/`) and is wired through the same `scripts/check-high-
assurance.sh` orchestrator on this side.

## Admit budget

`0 / 0` — pinned by `scripts/checks/ec-admits.sh`. Adding a new admit
requires bumping `ADMIT_BUDGET` in that script AND documenting the new
admit in the relevant file's accounting block.

## Files

| File | Purpose |
|------|---------|
| `P3Q_Verifier.ec` | Operational model of `precompile/p3q/contract.go::Run`. Defines `parsed_t`, `precompile_result_t`, `PrecompileRun(B)`, and proves: `precompile_dispatches_to_verifier`, `accept_iff_backend_accept`, `reject_iff_backend_reject`, `oog_dominates`. |
| `P3Q_Wire_Format.ec` | Wire-format invariants: `wf_length_bound`, `wf_magic_prefix`, `wf_unique_parse`, `wf_round_trip`, `wf_truncation_rejected`, `wf_version_domain`. |
| `P3Q_Gas_Model.ec` | Gas model lemmas: `gas_monotonic`, `gas_linear`, `gas_empty`, `gas_charged_upfront`, `gas_no_secret_leak`, `uniform_billing`. |
| `lemmas/P3Q_CT.ec` | Constant-time obligation: `precompile_ct` reduces to backend CT axiom `backend_ct`. The axiom is the Rust-verifier hand-off (libjade-style); discharged by jasmin/p3q + the audited `p3q-verifier` crate. |

## Axiom inventory

| Axiom | Source | Discharge path |
|-------|--------|----------------|
| `parse_spec_ok`, `parse_spec_fail` | wire-format spec | Mirrors `binary.BigEndian.Uint32` decoder in Go std lib; rederived from `Pulsar_N1_Memory.ec` codec idioms. |
| `be_uint32_len`, `be_decode_encode`, `be_encode_decode` | std endian | Algebraic; equivalent to libcore byte slicing. |
| `backend_verifier_axiom`, `backend_verifier_terminates` | external | Discharged by the audited `p3q-verifier` Rust crate via cgo `RegisterVerifier`. |
| `backend_ct` | external | Discharged by `jasminc -checkCT` over `jasmin/verify.jazz` or empirically via `ct/dudect/`. |

## Composition

`P3Q_Verifier.ec` is the apex. `P3Q_Wire_Format.ec` and `P3Q_Gas_Model.ec`
discharge the parsing and gas obligations cited by `P3Q_Verifier.ec`.
`lemmas/P3Q_CT.ec` is a side-channel obligation file mirroring
Pulsar's `lemmas/Pulsar_CT.ec`.

## Reduction story

P3Q's headline reduction: the precompile-level `Run()` accept path is
byte-equivalent to a single call to the registered backend verifier on
the parsed `(version, proof, pub)` triple. The backend semantics is the
external hand-off — concretely, the audited `p3q-verifier` Rust crate
that implements the strict-PQ STARK / FRI verifier on the Plonky3 fork
under cSHAKE256 over the Goldilocks 64-bit prime field. The EC theory
makes the dispatch atomic at the EVM boundary: if the precompile
accepts, the backend accepted; if the backend accepts, the precompile
accepts (modulo gas and structural well-formedness).

## How to check

```
cd ~/work/lux/precompile/p3q
bash scripts/check-high-assurance.sh
```

The `ec-admits.sh` check runs statically (does not require `easycrypt`
on PATH) so a regression on a host without EC still trips. The
`ec-compile.sh` check is the one that needs `easycrypt`; it is skipped
gracefully if the binary is absent.
