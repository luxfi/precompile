# P3Q Jasmin high-assurance gate

Constant-time Jasmin source for the structural pre-dispatch path of the
P3Q EVM precompile.

## Scope

Concern split:

1. `verify.jazz` — structural gate (length checks, version byte,
   magic-header constant-time equality). This is the CT-anchor for the
   precompile's pre-dispatch path. Statically checkable with
   `jasminc -checkCT verify.jazz`.

2. STARK / FIPS 204 backend — delegated to the audited Rust crate
   `~/work/lux/p3q/crates/p3q-verifier` (panic-free by contract). For
   the Pulsar / ML-DSA-65 hot path the backend further delegates to
   libjade's CT-proven `mldsa{65}` Verify; see
   `~/work/lux/pulsar/jasmin/threshold/` for the libjade-Pulsar bridge.

## CT obligation

The structural pre-dispatch path operates over PUBLIC wire calldata.
Constant-time is required for SOUNDNESS, not confidentiality: a timing
oracle over magic-mismatch vs length-mismatch lets an attacker probe
the chain's structural pre-filter. The Jasmin annotation
`#[ct = "public * public * public * public -> public"]` declares the
flow contract.

## Verification

```
jasminc -checkCT verify.jazz
```

This is run by `scripts/checks/jasmin.sh` (in this repo) and surfaced
through `scripts/check-high-assurance.sh`.

## Status code table

| Code | Symbol                  | Go error                  |
|------|-------------------------|---------------------------|
|  0   | OK                      | nil (accept)              |
|  1   | InvalidInputLength      | ErrInvalidInputLength     |
|  2   | InvalidVersion          | ErrInvalidVersion         |
|  3   | InvalidProof (magic)    | ErrInvalidProof           |
|  4   | reserved                | n/a                       |

`ErrVerifierNotRegistered` is not a structural-gate failure — it lives
above this Jasmin layer, in the Go dispatch path.

## Parsed output layout (24 bytes)

```
[ 0]       version_byte
[ 1.. 5)   proof_len (BE32)
[ 5.. 9)   proof_off (BE32)
[ 9..13)   pub_len   (BE32)
[13..17)   pub_off   (BE32)
[17..24)   reserved (zero)
```

The Go side decodes this and passes (version, proof slice, pub slice)
into the registered backend verifier.
