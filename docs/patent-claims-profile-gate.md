# Profile-Gated EVM Precompile Policy — Patent Claim Drafts (Attorney Review)

> **Internal working document.** Bundle #7 of the Lux PATENT-INVENTORY.
> Not a filed application; not a legal opinion.

## §0 Bundle summary

- **Title**: Profile-gated EVM precompile execution policy in which a
  single shared refusal function is called at the entry of every
  classical-cryptography precompile, gating execution on a chain-
  configuration-reported strict-post-quantum profile flag while
  preserving precompile address-space stability.
- **Inventors**: Lux Industries cryptography team.
- **Priority date**: file as US provisional within 12 months OR
  defensive publication.
- **Estimated claim count**: 12 (1 independent + 11 dependent).
- **Defensive-vs-offensive**: **Defensive.** This is more of a
  software-architecture decomplecting pattern than a patentable
  technical invention; recommended for defensive publication on the
  Lux engineering blog as the primary route, with provisional
  filing as a backup option.

## §1 Background and prior art

1. **EVM hardfork timestamp / block-number activation** (EIP-2718,
   EIP-1559, Ethereum hardforks 2015-2026): activation of new
   precompiles or rule changes by block number / timestamp.
2. **ChainConfig-based feature flags** (go-ethereum and forks 2018-
   2026): boolean feature detection on chain config.
3. **NIST PQC migration guidance** (NIST IR 8413, 2025-2026):
   classical → PQ migration via removal of classical primitives.

Lux's contribution is a **single shared refusal function** called by
every classical precompile (KZG, Groth16, PLONK, fflonk, Halo2,
BN254-Pedersen, BabyJubJub, Pallas/Vesta) at the entry of its
`Run()`, rather than per-precompile activation tables. The shared
function `contract.RefuseUnderStrictPQ` is the canonical
decomplecting pattern: verification logic stays in the precompile,
policy (refusal under strict-PQ) lives in ONE place.

## §2 Inventive concept

The Lux EVM precompile architecture:

1. Defines a feature-detection interface `StrictPQReporter` on the
   chain configuration: `IsStrictPQ(timestamp uint64) bool`.
2. Defines a shared error `ErrClassicalForbiddenInPQ`.
3. Defines a shared function `RefuseUnderStrictPQ(state) error`
   that returns the error if the chain's `StrictPQReporter` reports
   strict-PQ at the current block's timestamp, else nil.
4. Each classical precompile (BN254 add, BN254 mul, BN254 pairing,
   KZG point-eval, BLS12-381 pairing, Groth16 verify, PLONK verify,
   Halo2, BabyJubJub, etc.) calls `RefuseUnderStrictPQ` at the top
   of its `Run()` BEFORE any work, and returns the error if it
   fires.
5. PQ-native precompiles (ML-KEM, ML-DSA, SLH-DSA, Pulsar,
   Corona, P3Q) do NOT call the function — they are always allowed.
6. Address-space stability: the classical precompiles remain
   registered at their stable addresses (no renumbering at strict-
   PQ activation) so cross-chain integrations that depend on
   address-stability are not broken.
7. Non-Lux chains integrating Lux precompiles do NOT implement
   `StrictPQReporter` on their `ChainConfig`, and the default
   behaviour is permissive (no refusal) — preserving full
   backwards compatibility.

## §3 Independent claim (draft)

> **Claim 1.** A computer-implemented method for activating a
> strict-post-quantum cryptographic policy on a blockchain virtual
> machine without renumbering or removing classical precompiles
> from the virtual machine's address space, the method comprising:
>
> (a) defining, in the virtual machine's chain configuration
>     interface, an optional feature-detection method
>     `IsStrictPQ(timestamp) → bool` returning whether the chain
>     reports a strict-post-quantum profile at a given block
>     timestamp;
>
> (b) defining, as a single shared function in the precompile
>     contract framework, a `RefuseUnderStrictPQ(state) → error`
>     procedure that:
>
>     (b1) returns no error if the precompile's accessible state
>          is nil, if the chain configuration is nil, or if the
>          chain configuration does not implement the optional
>          `IsStrictPQ` method (permissive default);
>
>     (b2) returns no error if `IsStrictPQ(block.timestamp)`
>          returns false (chain in permissive profile);
>
>     (b3) returns a typed `ErrClassicalForbiddenInPQ` error if
>          `IsStrictPQ(block.timestamp)` returns true;
>
> (c) configuring each classical-cryptography precompile in the
>     virtual machine, identified by being based on an elliptic-
>     curve discrete-logarithm, pairing-based, or RSA-based
>     primitive whose security is broken by a polynomial-time
>     quantum adversary, to invoke `RefuseUnderStrictPQ` at the
>     entry of its `Run` method before any cryptographic
>     computation; and
>
> (d) leaving the precompile registered at its stable address even
>     when refused, preserving the virtual machine's precompile
>     address space across the strict-post-quantum activation
>     boundary.

## §4 Dependent claims (drafts)

**Claim 2.** The method of claim 1, wherein the classical
precompiles configured to call `RefuseUnderStrictPQ` include at
least: a BN254 elliptic-curve addition precompile, a BN254
elliptic-curve scalar multiplication precompile, a BN254 pairing
precompile, a BLS12-381 pairing precompile, a KZG point-evaluation
precompile, a Groth16 verifier precompile, a PLONK verifier
precompile, a Halo2 verifier precompile, a BabyJubJub primitive
precompile, and a Pallas/Vesta curve precompile.

**Claim 3.** The method of claim 1, wherein the post-quantum-
native precompiles in the same virtual machine — specifically
ML-KEM, ML-DSA, SLH-DSA, threshold ML-DSA, threshold Ring-LWE,
and PQ STARK verifier precompiles — are NOT configured to call
`RefuseUnderStrictPQ` and execute unconditionally.

**Claim 4.** The method of claim 1, wherein the `StrictPQReporter`
interface is implemented only by Lux-configured chain
configurations, while non-Lux chains that integrate the Lux
precompile framework do not implement this interface, resulting
in the classical precompiles executing normally on such non-Lux
chains and preserving cross-chain integration compatibility.

**Claim 5.** The method of claim 1, wherein the strict-post-
quantum profile is activated at a specific block timestamp
configured per chain, allowing different Lux chains to schedule
their strict-PQ activation independently while sharing the same
precompile registry.

**Claim 6.** The method of claim 1, wherein an additional
profile-name field on the chain configuration identifies one of
a plurality of named profiles (e.g., `Pulsar`, `Aurora`,
`Polaris`), each profile specifying a distinct subset of
allowed cryptographic primitives, and wherein
`RefuseUnderStrictPQ` returns the typed error for profiles
specifying classical-curve refusal.

**Claim 7.** The method of claim 1, wherein the typed error
`ErrClassicalForbiddenInPQ` is propagated through the EVM
execution as a precompile-revert event, allowing smart contracts
to introspect the error code and adapt by dispatching to a PQ-
native alternative precompile at a different address.

**Claim 8.** The method of claim 1, wherein the refusal-gate
function is implemented as a single Go function
`contract.RefuseUnderStrictPQ` in a shared `precompile/contract`
package imported by every classical precompile, decomplecting
the refusal policy from the per-precompile verification logic.

**Claim 9.** The method of claim 1, wherein the strict-post-
quantum profile activation is recorded immutably in the chain's
block header or genesis configuration, ensuring the activation
is observable to all participating nodes.

**Claim 10.** A computer system comprising a blockchain
virtual machine configured per claim 1, in which the
`StrictPQReporter` interface is dynamically dispatched via
runtime type-assertion against the chain configuration
implementation, providing static-typing decoupling between
the precompile framework and the chain configuration.

**Claim 11.** The method of claim 1, wherein the
`RefuseUnderStrictPQ` function is unit-tested with both a
strict-PQ-reporting `ChainConfig` (expected to return the
error) and a permissive `ChainConfig` (expected to return nil),
with the test suite enforcing both behaviours.

**Claim 12.** A non-transitory computer-readable medium storing
the Go source code of `contract.RefuseUnderStrictPQ`,
`contract.ErrClassicalForbiddenInPQ`, and the
`contract.StrictPQReporter` interface, together with at least
one classical precompile that calls `RefuseUnderStrictPQ` at
the entry of its `Run` method.

## §5 Reference to implementation

- `~/work/lux/precompile/contract/strict_pq.go` (59 lines —
  the entire gate, decomplecting policy from logic).
- `~/work/lux/precompile/contract/strict_pq_test.go`
  (unit tests for both branches).
- Per-precompile call sites: `~/work/lux/precompile/{kzg4844,
  groth16,plonk,fflonk,halo2,bn254,babyjubjub,pallas,vesta}/*.go`
  (each calling `contract.RefuseUnderStrictPQ` at top of `Run`).

## §6 Defensive vs offensive

**DEFENSIVE.** This is more of a software-decomplecting pattern
than a hard technical invention. Defensive publication on the
Lux engineering blog (Hickey-cited) is recommended as the primary
route. File a provisional only if attorney review elevates the
patentability prospect.

---

**Document metadata**
- Path: `precompile/docs/patent-claims-profile-gate.md`
- Bundle: #7 of `lps/PATENT-INVENTORY.md`
- Created: 2026-05-19
