# P3Q constant-time analysis (dudect)

Empirical CT measurement of the P3Q EVM precompile structural gate
plus its backend dispatch. Mirrors the Pulsar harness layout
(`~/work/lux/pulsar/ct/dudect/`).

## What this harness measures

The P3Q precompile holds NO long-term secret. Wire calldata is
public-by-EVM-precompile-ABI. The CT property we test is therefore not
confidentiality but SOUNDNESS:

* A timing oracle over magic-mismatch vs length-mismatch lets an
  attacker probe the chain's structural pre-filter.
* An attacker who can distinguish accept-cycles from reject-cycles on
  the verification dispatch can use the signal as a consensus-relevant
  oracle over time.

The harness compares cycle distributions over two populations of
STRUCTURALLY VALID inputs (same length, magic header in place, lengths
consistent), differing only in proof / pub byte payload. Any timing
difference detected is a real content-dependent path in
`precompile/p3q/contract.go::Run` or its cgo dispatch to the backend
verifier.

## Quick start

```
./fetch.sh           # one-time: clone dudect.h at pinned commit
make                 # build the harness
./dudect_verify      # smoke run (10000 samples per batch, 4 batches)
```

## Submission-grade run (10^9 samples)

```
./run-submission.sh
```

This is the run that closes GATE-3 in
`../../CRYPTOGRAPHER-SIGN-OFF.md`. Pre-flight checklist is documented
in the script header.

## Files

| File | Purpose |
|------|---------|
| `verify_ct.go` | cgo bridge exporting setup + invocation symbols to C |
| `dudect_verify.c` | C dudect main loop |
| `dudect_compat.h` | ARM64 compatibility shim for x86-only dudect intrinsics |
| `Makefile` | Build orchestration |
| `fetch.sh` | One-time clone of `oreparaz/dudect` at pinned ref |
| `run-submission.sh` | Submission-grade orchestrator (10^9 samples) |

## CT-population framing

Both classes are STRUCTURALLY VALID inputs:

* **Class A** — pool[0], byte-identical across all class-A samples
  (Welch's t-test requires identical class-A inputs).
* **Class B** — pool[rand % 64], uniformly drawn from the precomputed
  pool of 64 valid inputs. Each pool entry has the magic header and a
  randomly-drawn proof / pub byte payload.

The class B varying-but-valid framing is the operationally meaningful
CT population: an attacker can submit any number of calldata payloads
to the precompile and observe per-block latency. If the precompile's
cycle distribution depends on calldata content, that signal is
observable.

## Interpreting results

dudect prints a verdict every batch:
- `not enough measurements (...)` — keep running
- `For the moment, maybe constant time.` — clean batch, run another
- `Definitely not constant time` — leakage detected, investigate

For submission-grade evidence we want all 10 consecutive 10^8-sample
batches to land in the "maybe constant time" verdict with the absolute
t-statistic staying below the |t| < 4.5 threshold.

## Limitations

dudect is an *empirical* CT measurement, not a proof. The
authoritative CT evidence lives in two places:

1. `../../proofs/easycrypt/lemmas/P3Q_CT.ec` — Barthe-Gregoire-Laporte
   leakage-model obligation, reduced to the backend `backend_ct`
   axiom.
2. `../../jasmin/verify.jazz` — `#[ct = ...]`-annotated Jasmin source
   for the structural gate, statically checkable with
   `jasminc -checkCT verify.jazz`.

dudect complements these by exercising the COMPOSED system (Go
dispatch + cgo bridge + Rust backend verifier) under realistic
calldata loads.
