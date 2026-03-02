# Architecture Review: Universal Unification

Date: 2026-04-13
Reviewer: CTO
Scope: precompile, indexer, graph, explore, consensus, node, chains, dex, fhe

---

## Section 1: Dedup Targets (ranked by impact)

### 1.1 Error Sentinels — 22 packages, 22 copies of `ErrInvalidInput`

**Current state:** Every precompile defines its own local `ErrInvalidInput`:
- `babyjubjub/contract.go:67` — `errors.New("invalid babyjubjub input")`
- `hpke/contract.go:43` — `errors.New("invalid HPKE input")`
- `blake3/contract.go:42` — `errors.New("invalid blake3 input")`
- `anchor/contract.go:39` — `errors.New("anchor: invalid input")`
- `poseidon/contract.go:35` — `errors.New("invalid poseidon input")`
- ... 17 more identical patterns

Three naming variants: `ErrInvalidInput`, `ErrInvalidInputLength`, `ErrInvalidOp`.
These all mean the same thing: calldata failed validation.

Similarly: `ErrInvalidSignature` is defined independently in `corona`, `cggmp21`,
`frost`, `ring`, `quasar` (5 copies).

**Proposed state:** Add to `contract/errors.go`:
```go
var (
    ErrInvalidInput     = errors.New("invalid input")
    ErrInvalidSignature = errors.New("invalid signature")
    ErrInvalidThreshold = errors.New("invalid threshold")
)
```
Each precompile wraps with context: `fmt.Errorf("blake3: %w", contract.ErrInvalidInput)`.
Callers use `errors.Is(err, contract.ErrInvalidInput)` uniformly.

**Effort:** S (touch 22 files, mechanical)
**Risk:** Low (error messages change; no ABI implications)
**Impact:** Eliminates ~70 duplicate error declarations. Makes error handling testable
via a single sentinel. Unblocks a generic gas+error test harness.

---

### 1.2 Gas Deduction — Two incompatible patterns across 28 precompiles

**Current state:** 11 precompiles use `contract.DeductGas()`:
```
babyjubjub, bls12381, compute, curve25519, math, pasta, pedersen,
poseidon, stableswap, x25519, xwing
```

17 precompiles use manual `if suppliedGas < gasCost`:
```
anchor, blake3, cggmp21, dead, ed25519, frost, hpke, kzg4844,
mldsa, mlkem, quasar, ring, corona, slhdsa, sr25519, vrf, zk
```

The manual pattern is error-prone: `dead/contract.go:81` defines its own
`ErrInsufficientGas = errors.New("insufficient gas")` instead of using
`contract.ErrOutOfGas`. `fhe/contract.go:72` wraps it. `math/contract.go:37`
aliases it. Three ways to say "out of gas."

**Proposed state:** All precompiles call `contract.DeductGas()`. Delete
local gas aliases and manual checks. One function, one sentinel, everywhere.

**Effort:** S (17 files to refactor, each is a 3-line change)
**Risk:** Low (behavior identical, just standardized)
**Impact:** Eliminates a class of gas accounting bugs. Makes gas-zero tests
trivially table-driven against every precompile.

---

### 1.3 Address Scheme — Three incompatible formats in production

**Current state:** `ContractAddress` in each `contract.go` uses one of three formats:

| Format | Example | Used by |
|--------|---------|---------|
| High-byte (leading significant) | `0x3211000000000000000000000000000000000000` | ed25519, mldsa, mlkem, slhdsa, xwing, anchor, compute, blake3, poseidon, pedersen, pasta, babyjubjub, stableswap, math, sr25519 |
| Low-byte (trailing significant) | `0x0000000000000000000000000000000000009203` | x25519, curve25519, vrf |
| Short (geth zero-pads) | `0x9200`, `0x9202`, `0xB002` | hpke, ring, kzg4844 |

`registry.go` documents a trailing-significant scheme (LP-PCII) at line 17,
but the majority of actual `ContractAddress` values use leading-significant.
The registry constants themselves mix both: `VRFCChain` at line 124 is low-byte
(`0x000...3213`), while `Ed25519CChain` at line 122 is high-byte (`0x3211...000`).

**Proposed state:** Pick one format. The registry says trailing-significant.
Migrate the 15 high-byte addresses to match. This is a consensus-level change
so it must coincide with a genesis update.

**Effort:** M (15 contract.go files + registry.go + genesis configs + Solidity bindings)
**Risk:** Medium (requires coordinated genesis update; testnet-first)
**Impact:** Eliminates developer confusion. Makes `PrecompileAddress(p,c,ii)` the
single source of truth. Currently `PrecompileAddress()` produces trailing-significant
but half the codebase ignores it.

---

### 1.4 `ChainType` — Three independent type definitions

**Current state:**
- `indexer/chain/chain.go:24` — `type ChainType string` (1 value: `pchain`)
- `indexer/dag/dag.go:24` — `type ChainType string` (7 values: xchain..kchain)
- `indexer/multichain/manager.go:17` — `type ChainType string` (33 values: all external + all Lux)

Three types, same name, different packages, overlapping values. Importing code
must alias or cast. The `platform_indexer.go` switch at line 250 has 15 cases
duplicated at line 307 (same mapping, two switch statements).

**Proposed state:** One `ChainType` in `indexer/chain/chain.go`. Chain and DAG
packages import it. Multichain extends with external chain types in the same
enum. Delete duplicate definitions in `dag/dag.go` and `multichain/manager.go`.

**Effort:** S (3 files to merge, one rename sweep)
**Risk:** Low
**Impact:** Eliminates import confusion and the duplicated 15-case switch.

---

### 1.5 VM Boilerplate — 14 near-identical `main.go` in `chains/`

**Current state:** Each VM binary in `chains/` is a copy-paste main.go:
```
chains/aivm/main.go      — imports aivm, creates Factory, calls rpc.Serve
chains/identityvm/main.go — imports identityvm, creates Factory, calls rpc.Serve
chains/keyvm/main.go     — imports keyvm, creates NewDefaultFactory, calls rpc.Serve
chains/dexvm/main.go     — imports dexvm, creates NewChainVM, calls rpc.Serve
```

14 files. Three different factory patterns:
- `&aivm.Factory{}` (7 VMs)
- `keyvm.NewDefaultFactory()` (1 VM)
- `dexvm.NewChainVM(log.Root())` (1 VM — different: creates VM directly)

**Proposed state:** One `cmd/vmlaunch/main.go` with a build-tag or registration
table. Each VM registers its factory. The binary name determines which VM to
launch (like BusyBox). Alternatively, a shared `chains/cmd.go` function that
takes `(name string, factory vms.Factory)` and does the ulimit+version+serve
boilerplate.

**Effort:** S (extract shared function, call from each main.go — 14 files shrink
to 5-line stubs)
**Risk:** Low
**Impact:** ~400 lines of duplicated main.go eliminated. New VMs become a 5-line
registration, not a 40-line copy-paste.

---

### 1.6 Dockerfiles — Proliferation of variants

**Current state:**
- `indexer/` has 4: `Dockerfile`, `Dockerfile.indexer`, `Dockerfile.orig`, `Dockerfile.simple`
- `dex/` has 4: `Dockerfile`, `Dockerfile.devnet`, `Dockerfile.gateway`, `Dockerfile.minimal`
- `explore/` has 4: `Dockerfile`, `Dockerfile.branded`, `Dockerfile.liquidity`, `Dockerfile.lux`
- `node/` has 3: `Dockerfile`, `Dockerfile.bootnode`, `Dockerfile.custom`
- `iam/` has 4: `Dockerfile`, `Dockerfile.deploy`, `Dockerfile.doapp`, `Dockerfile.prebuilt`

26+ Dockerfiles across just these 5 repos. Many are dead (`.orig`, `.simple`).

**Proposed state:** One `Dockerfile` per repo. Multi-stage with build args for
variants. Delete `.orig`, `.simple`, `.prebuilt`. If a repo needs both a server
and a gateway binary, use multi-stage targets (`--target gateway`).

**Effort:** M (audit each, delete dead ones, consolidate live ones)
**Risk:** Low (CI must be updated to use `--target`)
**Impact:** Fewer moving parts. One way to build.

---

### 1.7 `docker-compose.yml` naming violations

**Current state:**
- `explore/docker-compose.lux.yml` — wrong name
- `dao/docker-compose.yml`, `dao/docker-compose.ghcr.yml`, `dao/docker-compose.full.yml` — wrong name

PHILOSOPHY.md mandates `compose.yml`.

**Proposed state:** Rename all `docker-compose*.yml` to `compose*.yml`.

**Effort:** XS (4 file renames)
**Risk:** Low
**Impact:** Convention compliance. One way to name things.

---

### 1.8 Duplicated switch in `platform_indexer.go`

**Current state:** `indexer/multichain/platform_indexer.go` lines 250-276 and
lines 307-333 contain the same 15-case `ChainType` switch. One dispatches to
adapter constructors, the other to RPC method prefixes. Same enum, same order.

**Proposed state:** Extract a `ChainTypeInfo` struct with `AdapterFactory` and
`RPCPrefix` fields. One registration map, two lookups.

**Effort:** XS (single file, ~30 lines saved)
**Risk:** Low
**Impact:** Eliminates a guaranteed source of drift when adding chain 16.

---

### 1.9 `dead/` precompile re-invents error sentinels

**Current state:** `dead/contract.go:77-82` defines 6 local errors including
`ErrInsufficientGas` (duplicate of `contract.ErrOutOfGas`) and `ErrInvalidInput`
(duplicate of proposed `contract.ErrInvalidInput`).

**Proposed state:** Import from `contract/errors.go`. Delete local copies.

**Effort:** XS
**Risk:** Low
**Impact:** Covered by 1.1 above; listed separately because `dead/` also has
`module.go` which is the only precompile with a module pattern — worth checking
if anchor and fhe should use the same structure, or if dead is the outlier.

---

### 1.10 Graph resolvers — 29 resolver packages vs 14 indexer adapters

**Current state:** `graph/resolvers/` has 29 subdirectories. `indexer/` has 14
adapter directories. The mapping is not 1:1. Extra resolver packages like
`amm/`, `dao/`, `derivatives/`, `governance/`, `prediction/`, `privacy/`,
`securities/`, `treasury/` have no corresponding indexer adapter.

**Proposed state:** Either: (a) resolvers that lack an indexer adapter are stubs
and should be deleted, or (b) they consume data from existing adapters and the
naming should document which adapter feeds which resolver. Audit required.

**Effort:** S (audit), then XS or M depending on findings
**Risk:** Low
**Impact:** Reduces confusion about what is real vs scaffolded.

---

## Section 2: Naming First-Principles Review

### `ChainType` vs `VMType` vs `ChainID`

- `ChainType` is used in 3 packages (indexer/chain, indexer/dag, indexer/multichain)
  with different values. It means "which logical chain."
- `VMType` does not exist as a type, but `VMID` exists in every `node/vms/*vm/` package
  as an `ids.ID`. It means "which VM binary."
- `ChainID` is used as a numeric EVM chain ID (8675309 etc).

**Decision:** These are three distinct concepts. The naming is correct but the
`ChainType` duplication (1.4) must be resolved. `VMType` should remain absent —
`VMID` is the identifier, not a "type."

### `Precompile` vs `Contract` vs `StatefulPrecompiledContract`

- `StatefulPrecompiledContract` — the interface in `contract/interfaces.go:19`.
  This is the canonical type name for the Go interface.
- `Precompile` — the exported singleton in each package (e.g., `blake3.Precompile`).
  This is the canonical instance name.
- `Contract` — not used as a type. `contract/` is the shared package.

**Decision:** This is correct. `StatefulPrecompiledContract` is the interface,
`Precompile` is the instance. No change needed except: each package's unexported
struct (e.g., `blake3Precompile`, `poseidonPrecompile`) should follow the pattern
`<pkg>Precompile` consistently. Currently 20 of 22 do. Consistent.

### `mode` vs `op` vs `selector`

Three words for the first byte of calldata:
- `op := input[0]` — used in blake3, hpke, ring, kzg4844, mlkem, math, zk, compute (8)
- `mode := input[0]` — used in mldsa, slhdsa (2)
- `selector` — used in anchor (`ErrInvalidSelector`)

**Decision:** The first byte is a **function selector** in the EVM sense. Call it
`op` everywhere. `mode` is appropriate only when it selects a parameter set within
one operation (e.g., ML-DSA-44 vs ML-DSA-65), not when it selects between distinct
operations. Currently mldsa uses `mode` to mean both "which ML-DSA variant" and
"verify vs batch-verify" — that is overloaded. Split: byte 0 = `op`, byte 1 (or
part of byte 0) = `mode` for variant selection.

**Effort:** XS (2 files: mldsa, slhdsa)

### `Vertex` vs `Block` vs `Transaction`

- `Vertex` — DAG consensus (multiple parents). Used in `indexer/dag/dag.go`.
- `Block` — linear chain consensus (single parent). Used in `indexer/chain/chain.go`.
- `Transaction` — individual operation within a block/vertex.

**Decision:** This distinction is correct and maps to the consensus engine. DAG
chains produce vertices. Linear chains produce blocks. Do not merge them.

### Gas constant naming

Three patterns observed:
- `Gas{Operation}` — `GasPointAdd`, `GasScalarMul` (babyjubjub, pasta, curve25519)
- `Gas{Operation}Base` + `Gas{Operation}Per{Unit}` — `GasBase256`, `GasPerInputWord` (blake3)
- `{Operation}Gas` — `GasBase` (stableswap, dead)

**Decision:** Standardize on `Gas{Operation}` for fixed costs and
`Gas{Operation}Base` + `Gas{Operation}Per{Unit}` for variable costs. The bare
`GasBase` in stableswap/dead is too ambiguous; rename to `GasSwap`/`GasBurn`.

**Effort:** XS (2 files)

---

## Section 3: Filesystem vs PRIMER Layers

### Current state

The PRIMER documents 12 layers (0-11). The filesystem is flat — 33 directories
at the root of `precompile/`, no grouping:

```
precompile/
  blake3/        (Layer 0 - Hash)
  poseidon/      (Layer 0 - Hash)
  bls12381/      (Layer 1 - Curves)
  ed25519/       (Layer 1 - Curves)
  ...
  dex/           (Layer 10 - DEX)
  fhe/           (Layer 11 - Applications)
```

### Should we add subdirectories?

Two options:

**Option A: Layer subdirectories**
```
precompile/
  hash/          blake3/, poseidon/
  curves/        bls12381/, ed25519/, secp256r1/, sr25519/, babyjubjub/, pasta/, curve25519/, x25519/
  classical/     vrf/, pedersen/, ring/
  pq/            mldsa/, mlkem/, slhdsa/, corona/, xwing/
  threshold/     cggmp21/, frost/
  zk/            zk/, kzg4844/
  privacy/       hpke/
  tee/           attestation/, compute/, ai/
  consensus/     quasar/
  crosschain/    bridge/, anchor/
  dex/           dex/, stableswap/, math/
  app/           fhe/, graph/
```

**Option B: Layer constant on each precompile**
```go
// In blake3/contract.go
const Layer = 0 // Hash primitives
```

Then a `registry/layers.go` iterates all precompiles by layer for docs/visualization.

### Decision

Option B. Do not add subdirectories.

**Rationale:**
1. Go import paths get longer (`luxfi/precompile/curves/bls12381` vs
   `luxfi/precompile/bls12381`). Every downstream file changes.
2. The flat layout is grep-friendly — `precompile/bls12381` is unambiguous.
3. The PRIMER layers are pedagogical, not architectural. A `Layer` constant
   achieves the same organization without import churn.
4. Three concrete cases do not yet exist for layer-based dispatch at runtime.

**Effort:** XS (add one `const Layer = N` per package, one `layers.go` in registry)
**Risk:** None

---

## Section 4: Top 10 Tasks for Universal Unification

### P0 — Must do before next release

| # | Task | Scope | Effort |
|---|------|-------|--------|
| 1 | **Shared error sentinels** (1.1) — Add `contract.ErrInvalidInput`, `contract.ErrInvalidSignature`, `contract.ErrInvalidThreshold` to `contract/errors.go`. Every precompile wraps with `fmt.Errorf("<pkg>: %w", contract.Err...)`. | 22 files | S |
| 2 | **Standardize gas deduction** (1.2) — All 17 manual-check precompiles switch to `contract.DeductGas()`. Delete `dead.ErrInsufficientGas`, `fhe.ErrInsufficientGas`, `math.ErrOutOfGas` aliases. | 17 files | S |
| 3 | **Unify `ChainType`** (1.4) — Single definition in `indexer/chain/types.go`. DAG and multichain packages import it. Delete the two duplicates. | 3 files | XS |

### P1 — Should do this sprint

| # | Task | Scope | Effort |
|---|------|-------|--------|
| 4 | **Fix address scheme** (1.3) — Migrate 15 high-byte `ContractAddress` values to trailing-significant to match `registry.go` and `PrecompileAddress()`. Coordinate with genesis config. Testnet first. | 15 contract.go + registry.go + genesis | M |
| 5 | **Delete dead Dockerfiles** (1.6) — Remove `Dockerfile.orig`, `Dockerfile.simple`, `Dockerfile.prebuilt` across all repos. Consolidate live variants to multi-stage targets. | ~15 files | M |
| 6 | **Rename docker-compose violations** (1.7) — `explore/docker-compose.lux.yml` + 3 in `dao/` to `compose*.yml`. | 4 files | XS |
| 7 | **Standardize `op` naming** (Section 2) — `mldsa/contract.go` and `slhdsa/contract.go`: rename `mode` to `op` for the first byte (operation selector). Keep `mode` for parameter-set selection (ML-DSA-44/65/87). | 2 files | XS |

### P2 — Next sprint

| # | Task | Scope | Effort |
|---|------|-------|--------|
| 8 | **VM boilerplate extraction** (1.5) — Shared `chains/launch.go` with `Launch(name string, factory vms.Factory)`. Each `main.go` becomes a 5-line stub. | 14 files | S |
| 9 | **Audit graph resolvers** (1.10) — Determine which of the 29 resolver packages are live vs scaffolded. Delete scaffolds or mark them clearly. | 29 dirs | S |
| 10 | **Add `Layer` constant** (Section 3) — Each precompile declares `const Layer = N`. Registry iterates by layer for documentation generation. | 33 files | XS |

---

## Summary

The prior session's cleanups (umbrella deletion, rpcadapter extraction, xvm rename,
ErrOutOfGas unification, brand-neutral ChainType, PlatformIndexer rename) eliminated
the most visible inconsistencies. What remains is a layer deeper: error sentinels,
gas patterns, address formats, and filesystem conventions that drift because there
is no single enforcing mechanism.

The 10 tasks above, executed in order, will achieve: one error sentinel per concept,
one gas deduction function, one address format, one ChainType enum, one Dockerfile
per repo, one compose file name, one variable name for the operation byte, one VM
launch function, and one layer tag per precompile.

Total estimated effort: ~3 days of mechanical refactoring. No architectural risk.
No consensus changes except task 4 (address scheme), which requires a testnet
genesis update and should be batched with the next planned hard fork.
