# A Pedagogical Primer to DeFi Excellence

*How 33 precompiles compose into a complete financial system — one layer at a time.*

This primer walks the `luxfi/precompile` library bottom-up. Each layer is
self-contained; each layer is also the raw material for the next. Read it in
order and you will have built, in your head, a full-stack DeFi platform from
hash functions to on-chain GraphQL.

---

## Layer 0 — Hash primitives

Every cryptographic system rests on hash functions. Two precompiles here:

| Precompile | Address | Role |
|------------|---------|------|
| `blake3`   | `0x0500..04` | Fast tree hash — preimage resistance, parallel |
| `poseidon` | `0x0500..05` | ZK-friendly sponge — cheap inside SNARK circuits |

**Why two?** Blake3 is optimal for off-chain hashing (e.g. block identifiers,
Merkle trees) because it's fast on CPUs and GPUs. Poseidon is optimal for
hashing *inside* ZK proofs — one Poseidon call is roughly 1000× cheaper than
one SHA-256 call in a Groth16 circuit.

**Key lesson:** Choose the hash function for the context. Performance off-chain
and performance in-proof are different constraints.

---

## Layer 1 — Curves

Elliptic curves are groups with a hard discrete-log. That's the foundation for
signatures, key exchange, ZK proofs, and commitments.

| Precompile   | Address | Curve | Use |
|--------------|---------|-------|-----|
| `bls12381`   | `0x000B-0x0011` | BLS12-381 | Pairings, aggregate signatures (EIP-2537) |
| `ed25519`    | `0x3211` | Edwards25519 | EdDSA signatures (RFC 8032) |
| `secp256r1`  | `0x0100` | NIST P-256 | WebAuthn / passkeys (EIP-7212) |
| `sr25519`    | `0x0A00` | Ristretto over 25519 | Substrate / Polkadot signatures |
| `babyjubjub` | `0x0500..07` | BN254 twisted Edwards | ZK-circuit-embedded signatures |
| `pasta`      | `0x0500..08` | Pallas + Vesta | Halo2 recursive proofs |
| `curve25519` | `0x9204` | Edwards25519 | Raw point ops for custom protocols |
| `x25519`     | `0x9203` | Curve25519 | Diffie-Hellman key exchange (RFC 7748) |

**Why eight?** Each curve optimizes a different trade-off:

- **Pairing curves** (BLS12-381, BN254 via babyjubjub) — support bilinear
  maps, enabling signature aggregation and many SNARK constructions.
- **Twisted Edwards** (ed25519, sr25519) — fast, complete addition formulas
  with no exceptional cases; ideal for constant-time signing.
- **NIST curves** (P-256) — mandated by standards bodies; browser-native
  passkey support.
- **Special curves** (Pallas/Vesta) — cycle-friendly pairs for proof recursion.

**Key lesson:** Curve choice is a protocol-level decision. Bridging to WebAuthn
means P-256. Bridging to Polkadot means sr25519. Building recursive SNARKs
means Pallas/Vesta. You cannot mix them without extra machinery.

---

## Layer 2 — Classical signatures and commitments

Now we have curves. Sign things with them. Commit to things with them.

| Precompile  | Address | Primitive |
|-------------|---------|-----------|
| `vrf`       | `0x3213` | ECVRF (RFC 9381) — verifiable randomness |
| `pedersen`  | `0x0500..06` | Pedersen commitment — hiding + binding |
| `ring`      | `0x9202` | LSAG ring signature — signer anonymity within a set |

**VRF** gives you a deterministic signature that also produces a pseudorandom
output. Lotteries, leader elections, NFT drops all want this: an attacker
can't bias the output, but everyone can verify it.

**Pedersen commitment** = `g^v · h^r`, where `r` is a random blinding factor.
Hiding (you can't extract `v` from the commitment without `r`) and binding
(you can't change `v` without being caught). The foundation of confidential
transactions and ZK range proofs.

**Ring signatures** let a signer prove "one of these N people signed this"
without revealing which one. Monero uses them for sender anonymity. Our LSAG
verify-only implementation supports secp256k1 and Ed25519 schemes.

**Key lesson:** These three layers give you three different privacy primitives
(randomness, hiding, anonymity). Mix them to taste.

---

## Layer 3 — Post-quantum

A quantum computer running Shor's algorithm breaks every curve in Layer 1.
Post-quantum cryptography replaces the hardness assumption.

| Precompile | Address | Standard | Hardness |
|------------|---------|----------|----------|
| `mldsa`    | `0x0200..06` | FIPS 204 (Dilithium) | Module-LWE + Module-SIS |
| `mlkem`    | `0x0200..07` | FIPS 203 (Kyber) | Module-LWE |
| `slhdsa`   | `0x0600..01` | FIPS 205 (SPHINCS+) | Hash-based (no structured math) |
| `corona` | `0x0200..0B` | — | LWE threshold signatures |
| `xwing`    | `0x2221` | Draft hybrid | X25519 + ML-KEM-768 |

**NIST standardized ML-DSA, ML-KEM, and SLH-DSA in 2024.** That's the
quantum-resistant future of signatures and key exchange. Our precompiles
expose them at stable EVM addresses.

**X-Wing** is a hybrid KEM: it runs X25519 *and* ML-KEM in parallel and
combines the resulting shared secrets. If either one is unbroken, the
combined secret is safe. This is the conservative migration path — classical
security today, quantum security tomorrow, at the cost of doubled key size.

**Key lesson:** ML-KEM's encapsulation uses randomness. On-chain, that
randomness must be *deterministic* or every validator produces different
ciphertexts (consensus split). Our precompile requires a caller-supplied
32-byte seed; the seed expands via iterated SHA-256 into the bytes ML-KEM
consumes. Same seed + same public key = same ciphertext on every node.

---

## Layer 4 — Threshold signatures

One key held by *N* parties, usable by any *t* of them. No single party ever
sees the full private key.

| Precompile | Address | Protocol | Signature type |
|------------|---------|----------|----------------|
| `cggmp21`  | `0x0800..03` | CGGMP21 | Threshold ECDSA (secp256k1) |
| `frost`    | `0x0800..02` | FROST | Threshold Schnorr / EdDSA |

**CGGMP21** is the state-of-the-art threshold ECDSA protocol. It supports
non-interactive signing after one round of presignatures, and is resilient
to up to `t-1` adversarial parties. Used for exchange custody, MPC wallets,
and cross-chain bridges.

**FROST** is the equivalent for Schnorr/EdDSA. Simpler than CGGMP21 (no
presignatures needed), higher throughput, but only works for Schnorr-family
signatures.

**Key lesson:** Threshold signatures replace multi-sig. Where multi-sig
publishes `t` separate signatures on-chain (visible, expensive), threshold
signatures publish one aggregate. Smaller, cheaper, indistinguishable from a
single-signer signature.

---

## Layer 5 — Zero-knowledge proofs

Prove you know something without revealing it. Four proof systems, each with
different trade-offs:

| Precompile | Address | Systems |
|------------|---------|---------|
| `zk`       | `0x0900` | Groth16 + PLONK + fflonk + Halo2 |
| `kzg4844`  | `0xB002` | KZG polynomial commitments (EIP-4844) |

**Groth16** — smallest proof (~200 bytes), fastest verification, but requires
a trusted setup per circuit.

**PLONK** — universal trusted setup (one per curve, not per circuit), slightly
larger proofs.

**fflonk** — Plonk with better prover/verifier trade-offs via aggregation.

**Halo2** — no trusted setup (uses Pallas/Vesta for recursive composition).

**KZG** — polynomial commitment scheme used in EIP-4844 blob transactions.
Not a full proof system, but a building block: commit to a polynomial, later
open at any point with a 48-byte proof.

**Key lesson:** Proof system choice is usually dictated by your framework
(Circom → Groth16; Noir → Halo2 or PLONK). Our precompile supports all four
so you're not locked in.

---

## Layer 6 — Privacy and encryption

Send encrypted data on-chain safely — which means *without* the sender's
private key ever touching calldata (which would be public and ruin the
whole scheme).

| Precompile | Address | Primitive |
|------------|---------|-----------|
| `hpke`     | `0x9200` | HPKE Seal (RFC 9180) — send-only encryption |

**HPKE (Hybrid Public-Key Encryption)** combines a KEM (key encapsulation)
with an AEAD (authenticated encryption). Sender encrypts to recipient's
public key; only recipient's private key opens it.

**We only expose Seal, not Open.** Why? Open requires the recipient's private
key — and on-chain, that would mean the private key in calldata, which is
catastrophic (public forever). Decryption happens off-chain. The precompile
lets a smart contract *send* encrypted data (e.g. sealed bids, encrypted
governance proposals) and verify the ciphertext was properly formed.

**Key lesson:** Never put private keys in calldata. Design your protocol so
the EVM only does the *public* half of any cryptosystem.

---

## Layer 7 — TEE attestation and compute

The EVM runs deterministically — but real-world AI compute does not. How do
you verify an off-chain GPU actually ran a specific model? Trusted Execution
Environments.

| Precompile | Address | Role |
|------------|---------|------|
| `attestation` | `0x0300..01` | Verify TEE quotes (NVTrust/SGX/SEV-SNP/TDX) |
| `compute`     | `0x0300..10` | AI compute marketplace — register, submit, claim |
| `ai`          | `0x0300` | AI inference / mining primitives |

**NVTrust** (H100 GPUs), **SGX** (Intel CPUs), **SEV-SNP** (AMD CPUs), **TDX**
(Intel newer) — each is a hardware root of trust that signs measurements of
the code that ran inside. A verifier checks the signature and the
measurement against a known-good hash.

**The compute marketplace** lets anyone offer compute, anyone consume it,
with on-chain attestation binding payment to verified execution. Proof-of-AI
by construction.

**Key lesson:** Attestation is non-deterministic in two ways — real wall
clocks and real hardware state. Our attestation precompile freezes these:
timestamps come from block time, not `time.Now()`; hardware state is
committed on-chain at attestation-creation time. Everything else is replay-
friendly.

---

## Layer 8 — Consensus verification

Chain-level consensus aggregates signatures from validators. Our precompile
verifies those aggregates in one call.

| Precompile | Address | Verifies |
|------------|---------|----------|
| `quasar` | `0x0300..20-24` | BLS + Verkle + Corona + hybrid |

**Quasar** is the post-quantum consensus family: fast path uses BLS12-381
aggregate signatures; PQ path uses Corona LWE threshold signatures; the
two combine into a hybrid proof that's safe under both classical and quantum
attackers. This precompile lets any contract (e.g. a bridge, a rollup)
verify that a Quasar-consensus block was finalized.

**Key lesson:** Hybrid consensus means you never have to pick. Both
verifiers run; both have to pass. Downside: 2× verification cost. Upside:
resistance to a break in either assumption.

---

## Layer 9 — Cross-chain and state anchoring

| Precompile | Address | Role |
|------------|---------|------|
| `bridge` | `0x0440-0443` | Gateway + Router + Verifier + Liquidity |
| `anchor` | `0x0700..00` | CRDT / off-chain state checkpoints |

**Bridge** moves assets between chains. The four sub-precompiles split the
lifecycle: Gateway receives deposits, Router picks the cheapest outbound
path, Verifier validates proof-of-inclusion on the source chain, Liquidity
manages bonded collateral.

**Anchor** takes the opposite view: rather than move state, commit to it.
Off-chain CRDTs (conflict-free replicated data types) produce state hashes;
the anchor precompile notarizes each hash on-chain, giving verifiers a
monotonic timeline to compare against.

**Key lesson:** Bridging and anchoring are dual. Bridging moves tokens and
uses storage as a ledger. Anchoring moves commitments and uses the ledger as
storage. Real systems use both.

---

## Layer 10 — DEX

| Precompile   | Address | What |
|--------------|---------|------|
| `dex`        | `0x9010-0x9080` | CLOB + AMM + Oracle + Router + Hooks + Flash + Book + Vault + Price + Lend + Repayer + Liquidator + Transmuter |
| `stableswap` | `0x0400..60` | Curve StableSwap invariant (low-slippage same-asset pools) |

The `dex` precompile is the full stack: orderbook matching, AMM math, hooks
for custom logic, flash loans, price oracles, lending, liquidation. All on-
chain, all deterministic, all addressable from Solidity.

**StableSwap** is a specialization — for pools of closely-correlated assets
(stablecoins, pegged derivatives), the flat-region of the Curve invariant
gives much tighter slippage than constant-product AMMs.

**Key lesson:** Building a DEX from scratch is a 100k-line job. Composing
one from precompiles is a few hundred lines of Solidity — the heavy math
lives at native speed inside the precompile.

---

## Layer 11 — Applications

| Precompile | Address | Role |
|------------|---------|------|
| `fhe`   | `0x0700` | Fully homomorphic encryption (compute on ciphertexts) |
| `graph` | `0x0500` | On-chain GraphQL query evaluation |

**FHE** lets you compute over encrypted values. Add two encrypted numbers
and get the encryption of their sum — without decrypting. Foundation of
private voting, confidential auctions, encrypted portfolio balances.

**Graph** exposes a GraphQL resolver *on-chain*. Contracts can query
structured data (protocol state, off-chain indexers, user preferences) with
a single precompile call instead of bespoke getters.

**Key lesson:** These two are the "escape hatch" layer — when the fixed
primitives below don't fit, FHE gives you private computation and Graph
gives you flexible query. Most protocols don't need them. The ones that do
can't do without.

---

## Why this order matters

Each layer is a complete, testable primitive.

- Build a **leader election**? Layer 0 (hash) + Layer 2 (vrf).
- Build a **multi-sig custody**? Layer 1 (curves) + Layer 4 (threshold).
- Build a **private voting**? Layer 3 (pq) + Layer 6 (hpke) + Layer 11 (fhe).
- Build a **cross-chain bridge**? Layer 1 (bls12381) + Layer 8 (quasar) +
  Layer 9 (bridge).
- Build an **AMM**? Layer 0 (poseidon for ZK LP proofs) + Layer 10 (dex) +
  Layer 11 (graph for analytics).

Every pattern in modern DeFi — auctions, lending, stablecoins, bridges,
rollups, prediction markets, privacy pools, MEV redistribution, restaking —
composes from these eleven layers.

## The philosophy

**Simplicity at each layer.** A precompile is a small, well-audited, native-
speed implementation of exactly one primitive. No knobs. No configuration.

**Composability across layers.** The only dependencies are upward: Layer N+1
may use Layer N, never the reverse. Every layer is independently replaceable
(swap Groth16 for Halo2; swap CGGMP21 for FROST).

**Determinism everywhere.** Every precompile is consensus-safe. No wall
clocks, no `crypto/rand`, no non-deterministic library behavior. Given the
same calldata, every validator produces the same output. Always.

**Post-quantum by default.** Every signature/KEM has a PQ equivalent on the
same curve family. Migration is a library call, not a hard fork.

## Where to go next

- Each precompile has its own `contract.go` with inline specs, `contract_test.go`
  with correctness + negative tests, and `deep_test.go` with edge cases,
  fuzzing, and concurrency checks.
- Protocol specs live in `~/work/lux/lps/` — one LP per precompile.
- Formal Lean4 proofs live in `~/work/lux/proofs/lean/Crypto/Precompile/`.
- Academic papers live in `~/work/lux/papers/precompile-*.tex`.

The art of DeFi excellence is not cleverness. It is choosing the right layer
for each problem, and letting the math do the rest.
