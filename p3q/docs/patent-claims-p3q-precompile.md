# P3Q On-Chain Strict-PQ STARK Precompile — Patent Claim Drafts (Attorney Review)

> **Internal working document.** Bundle #5 of the Lux PATENT-INVENTORY.
> Not a filed application; not a legal opinion.

## §0 Bundle summary

- **Title**: On-chain post-quantum STARK verifier precompile at a
  reserved EVM contract address, with version-byte forward
  compatibility, magic-header structural validation, and a Plonky3-
  derived prover stack stripped of classical-curve surfaces.
- **Inventors**: Lux Industries cryptography team (commit-history
  audit on `~/work/lux/precompile/p3q/` and `~/work/lux/p3q/`).
- **Priority date**: file as US provisional within **90 days** of
  this document (target by 2026-08-19).
- **Filing class**: software / cryptography; class 380; G06F 21/60.
- **Estimated claim count**: 19 (3 independent + 16 dependent).
- **Defensive-vs-offensive**: **Offensive**.

## §1 Background and prior art

Prior art constellation:

1. **EIP-196 / EIP-197** (Ethereum BN254 pairing precompiles, 2017):
   on-chain elliptic-curve precompiles for ZK verifiers. Classical
   curve, classical hardness.
2. **EIP-2537** (BLS12-381 precompiles, draft 2020+): on-chain BLS
   pairing precompile for Ethereum 2.0 consensus verification.
3. **EIP-4844** (KZG point evaluation precompile, 2024 Cancun):
   KZG-commitment-based blob verification.
4. **Polygon Zero Plonky2 / Plonky3** (Polygon Zero, 2022-2026):
   STARK proving system over Goldilocks `2^64 - 2^32 + 1`,
   Poseidon/SHA3 Merkle, FRI low-degree testing. Plonky3 is open
   source.
5. **StarkWare Cairo / StarkNet** (StarkWare 2021-2026): on-chain
   STARK verifiers (Solidity) for the Cairo zkVM; uses Goldilocks
   and a custom hash. Solidity contract, NOT a node-level
   precompile.
6. **EthSTARK** (EthSTARK 2020): Solidity verifier for the
   EthSTARK paper protocol.
7. **Risc0** (RISC Zero 2022-2026): STARK-based zkVM with on-chain
   verifier (Solidity); not a node-level precompile in any standard
   EVM-compatible chain.
8. **NIST PQC standards** (FIPS 203/204/205, 2024): the PQ
   primitives Lux's STARK builds over.

Closest prior art is [5] StarkNet and [7] Risc0, both of which
ship STARK verifiers as Solidity contracts. Lux's contribution
is **distinct**: a node-level **EVM precompile** at a reserved
address (0x012205) within the unified PQCrypto block
(0x012201-0x012206), with:

- Strict-PQ posture: the underlying STARK prover (Plonky3 fork in
  `~/work/lux/p3q`) has had its **classical-curve surface
  stripped** (no KZG, no pairings; cSHAKE256 Merkle over
  Goldilocks).
- Version byte for forward-compat with future proof formats.
- Magic-header (`P3Q1`) structural validation in the precompile
  itself; the FFI verifier is registered via an atomic-value
  callback to keep the hot path lock-free.
- Profile-gated activation: the same precompile is **available**
  under permissive profile and **refused** under the strict-PQ
  profile's classical-curve refusal gate (which targets
  `secp256k1`, `BN254`, `BLS12-381` precompiles — P3Q is the
  PQ-native replacement that survives the gate).

## §2 Inventive concept (plain English)

A blockchain provides a node-level EVM precompile at a reserved
address (Lux: `0x0000000000000000000000000000000000012205`)
that verifies post-quantum STARK proofs whose underlying prover
is a **strict-PQ fork of Plonky3**:

- Goldilocks prime field `2^64 - 2^32 + 1`.
- cSHAKE256 (FIPS 202 / SP 800-185) Merkle hashing over the field.
- FRI low-degree testing for proof compression.
- NO classical-curve surface (no KZG, no pairings).

The precompile contract's `Run()` performs:

1. Gas charge: `BaseVerifyGas + len(input) × PerByteGas`.
2. Length validation: `len(input) >= MinInputLength`.
3. Version-byte gate: `input[0] == VersionV1 (0x01)`; other bytes
   reserved for future proof formats.
4. Wire parse: `[1 byte version][4 bytes proof_len][proof_len bytes
   proof][4 bytes pub_len][pub_len bytes public_inputs]`,
   big-endian length fields.
5. Magic-header structural validation: the first 4 bytes of the
   proof MUST be `P3Q1`, pinning the wire to the Plonky3-fork
   profile.
6. FFI dispatch to a Rust verifier registered at node startup via
   an `atomic.Value` callback. No ceremony state; pure verify.
7. Result: empty bytes + remaining gas + nil error on success;
   typed error on failure.

The precompile's positioning at slot `0x012205` is within the
**unified LP-4200 PQCrypto block** alongside:
- `0x012201` ML-KEM (FIPS 203)
- `0x012202` ML-DSA (FIPS 204)
- `0x012203` SLH-DSA (FIPS 205)
- `0x012204` Pulsar (threshold FIPS 204)
- `0x012205` P3Q (this precompile)
- `0x012206` Corona (R-LWE threshold)

This addressing convention groups every PQ primitive into a
single contiguous EVM address block, distinct from the legacy
per-VM precompile layout.

## §3 Independent claims (drafts)

### Claim 1 (precompile dispatch claim, draft)

> **Claim 1.** A computer-implemented method for verifying a
> post-quantum scalable transparent argument of knowledge (STARK)
> proof as a native precompiled contract within an Ethereum
> Virtual Machine (EVM) executing on a blockchain node, the method
> comprising:
>
> (a) reserving an EVM contract address `A_P3Q` within a
>     contiguous unified post-quantum cryptography address block,
>     said block further including reserved addresses for ML-KEM,
>     ML-DSA, SLH-DSA, threshold ML-DSA, and threshold Ring-LWE
>     primitives;
>
> (b) on receipt of an EVM call to address `A_P3Q` with an input
>     byte string `I`, computing a required gas amount equal to a
>     base verification gas constant plus a per-byte gas constant
>     multiplied by the length of `I`;
>
> (c) deducting the required gas from the caller's gas counter and
>     returning out-of-gas if insufficient;
>
> (d) validating the input length against a minimum input length
>     equal to the sum of (i) one byte for a version byte, (ii)
>     four bytes for a proof-length field, (iii) the byte length
>     of a fixed magic header, and (iv) four bytes for a public-
>     input length field; returning an invalid-input-length error
>     if the input is shorter;
>
> (e) extracting a version byte from `I[0]` and rejecting the call
>     with an invalid-version error if the version byte does not
>     match a supported version;
>
> (f) extracting a big-endian uint32 proof-length field from
>     `I[1:5]` and rejecting the call with an invalid-input-length
>     error if the remaining input cannot accommodate a proof of
>     that length plus the public-input-length field;
>
> (g) extracting the proof byte string from `I[5 : 5 + proof_len]`
>     and rejecting the call with an invalid-proof error if the
>     first bytes of the proof do not equal the fixed magic header
>     `P3Q1`;
>
> (h) extracting a big-endian uint32 public-input-length field
>     and the corresponding public-input byte string;
>
> (i) invoking a previously-registered verifier callback with
>     `(version, proof, public_inputs)` and returning the
>     verifier's success or failure status as the precompile's
>     return code; and
>
> (j) returning, on successful verification, an empty byte string
>     and the remaining gas; returning, on any failure, an empty
>     byte string, the remaining gas, and a typed error,
>
> wherein the registered verifier callback dispatches to a
> foreign-function-interface call against a Rust prover library
> implementing a STARK over the Goldilocks prime field `2^64 -
> 2^32 + 1` with Merkle hashing over cSHAKE256 per SP 800-185, and
> no classical-curve cryptographic primitive.

### Claim 2 (strict-PQ prover-stack claim, draft)

> **Claim 2.** A computer-implemented post-quantum proving system
> for use with the precompile of claim 1, the proving system
> comprising:
>
> (a) a polynomial-commitment scheme based on the Fast Reed-
>     Solomon Interactive Oracle Proof (FRI) low-degree testing
>     protocol;
>
> (b) a Merkle commitment tree whose hash function is cSHAKE256
>     per SP 800-185, with a fixed customization string identifying
>     the proving system version;
>
> (c) a field arithmetic backend operating exclusively over the
>     Goldilocks prime `q_G = 2^64 - 2^32 + 1`, said arithmetic
>     using a closed-form 128-to-64-bit reduction with mask-based
>     branchless corrections producing output in `[0, q_G)`;
>
> (d) NO classical-curve elliptic-curve primitive in the proving
>     pipeline, such that the verifier of claim 1 does NOT
>     dispatch to any pairing-based, ECDSA, or BLS computation as
>     part of proof verification; and
>
> (e) a proof byte serialization beginning with a fixed 4-byte
>     magic header `P3Q1` followed by a recursive STARK proof
>     structure compatible with a Plonky3-derived FRI-STARK
>     protocol stripped of all classical-curve surface.

### Claim 3 (callback-registration / hot-path claim, draft)

> **Claim 3.** A computer-implemented method for safe lock-free
> verifier dispatch within the precompile of claim 1, the method
> comprising:
>
> (a) maintaining within the node process a verifier callback
>     pointer stored in an `atomic.Value` or equivalent lock-free
>     atomic-pointer container;
>
> (b) at node startup, registering a non-nil verifier callback into
>     the atomic-pointer container via a `RegisterVerifier` API,
>     said callback dispatching to the FFI Rust verifier of claim 2;
>
> (c) on each invocation of the precompile, loading the verifier
>     callback via a lock-free atomic load from the atomic-pointer
>     container, returning an "verifier not registered" typed error
>     if the loaded callback is nil; and
>
> (d) optionally, at runtime, swapping the registered verifier
>     callback by issuing a `RegisterVerifier` call with a non-nil
>     replacement, said swap being atomic with respect to in-flight
>     precompile invocations,
>
> wherein the precompile's hot path is free of mutex acquisition
> or other blocking synchronization primitives, allowing the
> precompile to be invoked under concurrent EVM execution without
> contention.

## §4 Dependent claims (drafts)

**Claim 4.** The method of claim 1, wherein the reserved EVM
contract address `A_P3Q` is `0x0000000000000000000000000000000000012205`.

**Claim 5.** The method of claim 1, wherein the unified post-
quantum cryptography address block comprises at least the
following reserved addresses:
- `0x012201` for an ML-KEM precompile;
- `0x012202` for an ML-DSA precompile;
- `0x012203` for an SLH-DSA precompile;
- `0x012204` for a threshold ML-DSA precompile (Pulsar);
- `0x012205` for the P3Q STARK precompile of claim 1;
- `0x012206` for a threshold Ring-LWE precompile (Corona).

**Claim 6.** The method of claim 1, wherein the base verification
gas constant is `200_000` and the per-byte gas constant is `10`,
yielding a gas formula `gas = 200_000 + 10 × len(input)`.

**Claim 7.** The method of claim 1, wherein the supported version
byte is `0x01` for a first wire format and additional version
bytes `0x02`, `0x03`, etc., are reserved for future wire formats
within the same precompile address, providing forward-compatibility
without requiring a new precompile address per format.

**Claim 8.** The method of claim 1, wherein the magic header is
the four-byte ASCII string `P3Q1`, pinning the wire format to a
specific Plonky3-fork profile.

**Claim 9.** The method of claim 1, wherein the typed errors
returned by the precompile comprise distinct enumerated error
codes for `ErrInvalidInputLength`, `ErrInvalidVersion`,
`ErrVerifierNotRegistered`, and `ErrInvalidProof`.

**Claim 10.** The method of claim 1, wherein the structural
validations of steps (d), (e), (f), and (g) are performed in
constant time with respect to public inputs only; no input to
the precompile is secret by construction, so no constant-time-
against-secret-input guarantee is required.

**Claim 11.** The method of claim 2, wherein the STARK proving
system is configured to verify a statement of the form "there
exists a witness `w` such that `R(w; pub) = 0`" where `R` is an
arithmetic constraint system over the Goldilocks prime field
expressed as a Plonky3-style AIR (Algebraic Intermediate
Representation).

**Claim 12.** The method of claim 2, wherein the FRI query
schedule and Merkle commitment depth are chosen such that the
soundness error is at most `2^{-100}` against any polynomial-time
quantum adversary under the random oracle model with cSHAKE256
as the random oracle.

**Claim 13.** The method of claim 2, wherein the proving system
is configured to verify a statement asserting the validity of a
sequence of FIPS 204 ML-DSA-65 signatures or a sequence of FIPS
205 SLH-DSA signatures over input messages, enabling the
precompile of claim 1 to verify aggregated batches of post-
quantum signatures with a single STARK proof.

**Claim 14.** The method of claim 1, wherein the precompile is
positioned within a profile-gated activation framework such that
the precompile is enabled under the chain's `BLSOnly` and
`BLSPlusMLDSA` profiles AND under a `StrictPQ` profile, and
optionally disabled under a `LegacyOnly` profile.

**Claim 15.** A computer system comprising the precompile of
claim 1 and a non-precompile Rust proving binary that produces
proofs verifiable by the precompile, the Rust binary running
out-of-band of the node process and producing proofs that are
submitted to the chain as EVM transaction input data.

**Claim 16.** The system of claim 15, wherein the Rust proving
binary is structured into a plurality of independent crates
comprising at least a Goldilocks field crate, a cSHAKE256 hash
crate, a Merkle commitment crate, a FRI low-degree-test crate, a
STARK challenger crate, a STARK verifier crate, and a recursion
crate enabling proof-of-proof compression.

**Claim 17.** The method of claim 1, further comprising
recording, in a metric-collection database, the input length,
the verification result, and the gas charged for each
invocation of the precompile, enabling fee-market analysis and
proof-size-distribution monitoring for the chain.

**Claim 18.** The method of claim 1, wherein the precompile is
deployed on multiple chains within a blockchain network at the
identical reserved EVM contract address, providing cross-chain
proof-verification interoperability without per-chain ABI drift.

**Claim 19.** A non-transitory computer-readable medium storing
the source code of the precompile of claim 1 in Go and the
source code of the proving system of claim 2 in Rust, together
with a registration shim that wires the Rust verifier as the
Go-side callback at node startup.

## §5 Reference to implementation

- Go precompile: `~/work/lux/precompile/p3q/contract.go`
  (190 lines; address `0x012205`; gas `200_000 + 10/byte`).
- Module registration: `~/work/lux/precompile/p3q/module.go`.
- Rust prover/verifier: `~/work/lux/p3q/crates/`:
  - `p3q-core/` — proving system core.
  - `p3q-field/` — Goldilocks field.
  - `p3q-sha3/` — cSHAKE / KMAC / TupleHash (SP 800-185).
  - `p3q-merkle/` — Merkle commitment tree.
  - `p3q-fri/` — FRI low-degree test.
  - `p3q-stark/` — STARK proof shell.
  - `p3q-challenger/` — Fiat-Shamir challenger.
  - `p3q-recursion/` — recursive STARK aggregation.
  - `p3q-verifier/` — verifier wired to FFI.
  - `p3q-zchain/` — Z-Chain Groth16/STARK aggregation.
- Tests: `~/work/lux/precompile/p3q/contract_test.go`,
  `~/work/lux/precompile/p3q/contract_e2e_test.go`,
  `~/work/lux/precompile/p3q/jasmin/verify.jazz` (constant-time
  structural gate).
- Sign-off: `~/work/lux/precompile/p3q/CRYPTOGRAPHER-SIGN-OFF.md`.
- Paper: `~/work/lux/papers/lux-p3q-precompile.tex`.

## §6 Prior-art differentiation summary

| Reference | Closest aspect | Why claim 1 still novel |
|-----------|----------------|--------------------------|
| EIP-196/197 (BN254 pairing) | EVM precompile for ZK verify | Classical curve, not PQ; not version-byte gated; no profile gate |
| EIP-2537 (BLS12-381) | EVM precompile for BLS pairing | Classical curve; same reasoning |
| EIP-4844 (KZG) | EVM precompile for KZG | Classical curve KZG; specific to blob data; no PQ STARK |
| StarkNet Solidity verifier | STARK verify in Solidity contract | Solidity user-deployed contract, NOT a node-level precompile; different gas / dispatch model |
| Risc0 Solidity verifier | STARK zkVM verify in Solidity | Same: Solidity not precompile |
| EthSTARK Solidity verifier | STARK verify | Solidity not precompile |
| Plonky3 (open-source) | The Lux STARK prover IS a fork of Plonky3 | Plonky3 itself is acknowledged prior art; novelty is in (a) classical-curve removal, (b) the precompile dispatch + magic-header + version-byte ABI |
| Polygon zkEVM precompile | EVM precompile for Polygon-specific ZK | Different ZK system (Plonk-style not STARK); classical curve underneath |

## §7 Filing strategy and timing

- US provisional: target by **2026-08-19** in URGENT batch with
  #1, #2, #3.
- Strategic value: PQ-native on-chain proof verification at a
  stable EVM address is an important rollup-bridge primitive
  for the L2 ecosystem.
- PCT at 12 months → designate US, EPO, JP, KR, CN, IN, SG.

## §8 Defensive vs offensive recommendation

**OFFENSIVE.** The PQ STARK precompile at a reserved EVM address
is novel; competitor L1/L2s shipping similar functionality should
either license from Lux or design around the claim. The Plonky3-
fork classical-curve removal is a meaningful technical choice
that Lux can defend.

---

**Document metadata**
- Path: `precompile/p3q/docs/patent-claims-p3q-precompile.md`
- Bundle: #5 of `lps/PATENT-INVENTORY.md`
- Created: 2026-05-19
- Status: **Internal working triage for attorney engagement**
