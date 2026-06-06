# Go 1.26 Modernization Analysis — luxfi/precompile

Analysis date: 2026-04-10
Go version: 1.26.1
Codebase: 72,578 lines across 137 Go files
Test baseline: 5 failures (ed25519 panic, mldsa/mlkem build, go vet warnings)

## 1. Go Version Compatibility Matrix

| Repo | Current | Recommended | Action |
|------|---------|-------------|--------|
| `lux/precompile` | 1.26.1 | 1.26.1 | None |
| `lux/evm` | 1.26.1 | 1.26.1 | None |
| `lux/node` | 1.26.1 | 1.26.1 | None |
| `liquidity/evm` | 1.26.1 | 1.26.1 | None |
| `liquidity/dex` | 1.26 | 1.26.1 | Bump to 1.26.1 |
| `liquidity/fhe` | 1.26 | 1.26.1 | Bump to 1.26.1 |

Two repos are on 1.26 (no patch). Go 1.26.1 includes security fixes [1].
`zoo/chains` and `hanzo/chains` directories do not exist.

## 2. Critical: Consensus Safety Bug in pqcrypto

**File**: `pqcrypto/contract.go:339`
**Severity**: CRITICAL (chain-splitting)

```go
// CURRENT — NON-DETERMINISTIC:
ciphertext, sharedSecret, err := pubKey.Encapsulate(rand.Reader)
```

`rand.Reader` produces different bytes on every validator. Different validators
will produce different ciphertexts for the same input, causing state divergence.

The `hpke/contract.go` handles this correctly with a `deterministicReader` that
derives pseudorandom bytes from a caller-provided seed via iterated SHA-256.
The `mlkem/contract.go` also avoids this by not passing an explicit reader.

**Fix**: Replace `rand.Reader` with a deterministic reader seeded from calldata,
identical to the pattern in `hpke/contract.go:100-114`. Or require a 32-byte
seed in the encapsulate calldata format and use `newDeterministicReader(seed)`.

## 3. Actionable Improvements

### 3a. `interface{}` to `any` (30+ occurrences)

Go 1.18 introduced `any` as an alias for `interface{}`. The `go fix` tool's
`any` modernizer handles this automatically.

**Files affected** (partial list):
- `dex/pool_manager.go:858` — `args ...interface{}`
- `attestation/attestation.go:463,467,546` — decode/encode helpers
- `graph/graphvm/types.go:31,37,48` — all map/interface types
- `graph/graph.go:27,30,175,259,320,351` — query interfaces
- `graph/graphvm_client.go:48,84` — client query methods
- `blake3/contract_test.go:18-19` — mock state methods

**Command**: `go fix -fix any ./...`

### 3b. `sort.Sort` to `slices.SortFunc` (modules/registerer.go)

The `moduleArray` type in `modules/module.go:25-37` exists solely to satisfy
`sort.Interface`. Replace with `slices.SortFunc` and delete the type.

**Current** (`modules/module.go:25-37` + `modules/registerer.go:257`):
```go
type moduleArray []Module
func (u moduleArray) Len() int           { return len(u) }
func (u moduleArray) Swap(i, j int)      { u[i], u[j] = u[j], u[i] }
func (m moduleArray) Less(i, j int) bool { return bytes.Compare(...) < 0 }

sort.Sort(moduleArray(data))
```

**After**:
```go
slices.SortFunc(data, func(a, b Module) int {
    return bytes.Compare(a.Address.Bytes(), b.Address.Bytes())
})
```

Deletes 13 lines of boilerplate. Also applies to `dex/state_export.go` which
uses `sort.Slice` (can migrate to `slices.SortFunc` for consistency).

### 3c. `rand.Read` error checks (10 occurrences)

Since Go 1.24, `crypto/rand.Read` never returns an error [2]. Error checks on
`rand.Read` are dead code.

| File | Line | Current | After |
|------|------|---------|-------|
| `x25519/deep_test.go` | 88 | `_, err := rand.Read(scalar)` | `rand.Read(scalar)` |
| `x25519/deep_test.go` | 112-113 | `_, _ = rand.Read(...)` | `rand.Read(...)` |
| `curve25519/deep_test.go` | 213 | `_, err := rand.Read(buf[:])` | `rand.Read(buf[:])` |
| `xwing/contract_test.go` | 130 | `_, err := rand.Read(garbage)` | `rand.Read(garbage)` |
| `Corona/contract_test.go` | 227 | `if _, err := rand.Read(prfKey); err != nil` | `rand.Read(prfKey)` |
| `ed25519/security_test.go` | 34,75 | `_, _ = rand.Read(message)` | `rand.Read(message)` |
| `ring/security_test.go` | 55,152 | `_, _ = rand.Read(...)` | `rand.Read(...)` |

### 3d. `runtime/secret` for cryptographic erasure (Go 1.26 experimental)

Go 1.26 adds `runtime/secret` (GOEXPERIMENT=runtimesecret) which zeroes
registers and stack after a function returns [3]. Directly applicable to:

| Package | Hot path | Why |
|---------|----------|-----|
| `frost/contract.go` | `verifySchnorrSignature` | LiftX handles public key points |
| `pqcrypto/contract.go` | `mlkemDecapsulate` | Private key in calldata |
| `pqcrypto/extended_contract.go` | `mldsaSign`, `slhdsaSign` | Private key signing |
| `threshold/accel.go` | `verifySingleSignature` | Key material during verify |
| `fhe/fhe_ops.go` | `initTFHE` | Secret key generation |

**Implementation**: Wrap with `secret.Do(func() { ... })` once
GOEXPERIMENT=runtimesecret is stable. Currently amd64+arm64 Linux only.

**Risk**: Experimental. Do not gate production builds on it. Use build tags:
```go
//go:build goexperiment.runtimesecret
```

### 3e. `crypto/hpke` stdlib replacement (Go 1.26)

Go 1.26 added `crypto/hpke` implementing RFC 9180 [4]. Current code uses
`github.com/cloudflare/circl/hpke`.

**Compatibility check**:

| Feature | circl | stdlib crypto/hpke |
|---------|-------|--------------------|
| P-256/P-384/P-521 KEMs | Yes | Yes |
| X25519 KEM | Yes | Yes |
| X25519+Kyber768 hybrid | Yes | Yes (post-quantum) |
| X-Wing hybrid | Yes | Needs verification |
| Deterministic Setup (custom rand) | Yes (sender.Setup accepts io.Reader) | Needs verification |

**Blocker**: The `hpke/contract.go:381` passes `nil` to `sender.Setup()` which
circl interprets as "use default randomness". The deterministic reader is used
via a different code path. Must verify stdlib `crypto/hpke` accepts a custom
io.Reader for consensus-safe deterministic encryption before migrating.

**Verdict**: Investigate but do not migrate until the custom-reader API is
confirmed. If confirmed, drop `cloudflare/circl` (saves ~15MB of transitive
dependencies).

### 3f. `go vet` fixes (5 issues found)

```
blake3/deep_test.go:245     TestDeriveKey redeclared in this block
curve25519/deep_test.go:206 basepoint redeclared in this block
mlkem/deep_test.go:73       priv.Decapsulate undefined (API mismatch)
mldsa/deep_test.go:21       undefined: ContractAddress
pedersen/contract.go:273    unreachable code
```

These cause build failures in `mldsa` and `mlkem` packages and indicate stale
deep_test.go files that were not updated after API changes.

### 3g. `bytes.Equal` in tests — use `require.Equal`

28 occurrences of `require.True(t, bytes.Equal(a, b), ...)` in test files.
Replace with `require.Equal(t, a, b)` which provides better diff output on
failure.

Affected packages: `babyjubjub`, `x25519`, `pasta`, `pedersen`, `poseidon`,
`curve25519`, `blake3`.

## 4. Dependency Reductions

### Can drop (with work)

| Dependency | Used by | Replacement | Savings |
|------------|---------|-------------|---------|
| `cloudflare/circl` | `hpke/` | `crypto/hpke` (stdlib) | ~15MB transitive deps |
| `golang.org/x/crypto/curve25519` | `x25519/` | None (see below) | Minimal |

### Cannot drop

| Dependency | Reason |
|------------|--------|
| `luxfi/crypto/mlkem` | Wraps all 3 modes (512/768/1024). Stdlib only has 768+1024. Mode-based API differs. |
| `luxfi/crypto/mldsa` | No stdlib equivalent. ML-DSA (FIPS 204) not in Go stdlib. |
| `luxfi/crypto/slhdsa` | No stdlib equivalent. SLH-DSA (FIPS 205) not in Go stdlib. |
| `golang.org/x/crypto/curve25519` | Stdlib `crypto/ecdh` wraps X25519 in high-level key API. Precompile needs raw `X25519(scalar, point)` which only x/crypto provides. |
| `consensys/gnark-crypto` | BLS12-381, BN254, Pasta curves, Poseidon hash. No stdlib equivalent. |
| `supranational/blst` | BLS12-381 via CGO. Performance-critical. |
| `zeebo/blake3` | No stdlib Blake3. |
| `holiman/uint256` | 256-bit integer math for EVM. No stdlib equivalent. |

### Free performance from Go 1.26 (already active)

- **Green Tea GC**: 10-40% lower GC overhead for marking/scanning [5]. Benefits
  all precompiles that allocate during execution (ZK verifier, DEX math).
- **30% faster cgo**: Benefits `supranational/blst` (BLS12-381) directly [6].
- **Stack-allocated slices**: Compiler allocates small slices on stack. Benefits
  the many `make([]byte, 32)` patterns in crypto precompiles.

## 5. Performance Wins

### 5a. PGO (Profile-Guided Optimization)

No PGO profile exists. Go 1.21+ supports PGO for 2-7% throughput improvement
on hot paths, with some workloads seeing up to 15% [7].

**Plan**:
1. Add benchmark suite covering hot paths (FROST verify, BLS aggregate, ZK
   Groth16 verify, DEX swap math, Poseidon hash)
2. Run benchmarks with `-cpuprofile=default.pgo`
3. Commit `default.pgo` to repo root
4. Go toolchain automatically uses it on subsequent builds

**Estimated gas savings**: 2-7% reduction in wall-clock time for crypto
precompiles translates to more accurate gas pricing (current gas costs are
calibrated to unoptimized builds).

**Hot paths for profiling** (by test duration):
- `fhe`: 71.8s (FHE is inherently slow; PGO helps most here)
- `pqcrypto`: 4.7s
- `Corona`: 4.8s
- `slhdsa`: 3.7s
- `zk`: 3.8s

### 5b. Frost liftXCache improvement

`frost/contract.go:147-182` uses a `sync.RWMutex` + `map[[32]byte]curve.Point`
bounded to 1024 entries with no eviction policy. When full, new keys are silently
dropped.

**Improvement**: Replace with `sync.Map` (better for read-heavy workloads, which
this is — validators reuse the same keys) or implement LRU eviction. The current
"stop caching when full" behavior means the 1025th unique public key gets zero
cache benefit permanently.

### 5c. SIMD (not ready)

Go 1.26 adds experimental `simd/archsimd` (GOEXPERIMENT=simd) for AMD64 only [8].
ARM64 SVE support is planned but not yet available. Since production nodes run on
both architectures, this is not actionable now. Revisit when ARM64 is supported.

Potential targets when ready:
- `pasta/contract.go` — field element arithmetic
- `poseidon/contract.go` — sponge state permutation
- `bls12381/contract.go` — point addition/multiplication
- `dex/full_math.go` — 256-bit multiplication

## 6. `go fix` Modernizer Batch

Go 1.26 ships 24 built-in modernizers [9]. Applicable ones:

| Modernizer | Occurrences | Risk |
|------------|-------------|------|
| `any` | 30+ | None (alias, identical semantics) |
| `slicessort` | 1 (`modules/`) + 5 (`dex/`) | None |
| `slicescontains` | Check needed | None |
| `forvar` | 0 (already correct) | N/A |
| `rangeint` | Check needed | None |

**Command**: `go fix -fix any,slicessort,slicescontains,rangeint ./...`

Run `go fix -diff ./...` first to preview changes without applying them.

## 7. Existing Bugs Found During Analysis

| Issue | File | Severity |
|-------|------|----------|
| Non-deterministic `rand.Reader` in encapsulate | `pqcrypto/contract.go:339` | CRITICAL |
| `TestEdge_AllZeros` panic | `ed25519/deep_test.go:45` | Medium |
| `priv.Decapsulate` undefined | `mlkem/deep_test.go:73` | Medium (build fail) |
| `ContractAddress` undefined | `mldsa/deep_test.go:21` | Medium (build fail) |
| `TestDeriveKey` redeclared | `blake3/deep_test.go:245` | Low (build fail) |
| `basepoint` redeclared | `curve25519/deep_test.go:206` | Low (build fail) |
| Unreachable code | `pedersen/contract.go:273` | Low |

## 8. Summary of Recommendations

Priority order:

1. **FIX** `pqcrypto/contract.go:339` consensus bug (deterministic encapsulation)
2. **FIX** 5 go vet failures (build-breaking in mldsa, mlkem, blake3, curve25519)
3. **RUN** `go fix -fix any,slicessort ./...` (mechanical, zero-risk)
4. **REMOVE** `rand.Read` error checks (10 occurrences, dead code since Go 1.24)
5. **REPLACE** `sort.Sort(moduleArray(...))` with `slices.SortFunc` (delete boilerplate)
6. **GENERATE** PGO profile from benchmark suite (2-7% throughput improvement)
7. **INVESTIGATE** `crypto/hpke` stdlib migration (potential circl dep removal)
8. **PLAN** `runtime/secret` integration (when GOEXPERIMENT stabilizes)
9. **BUMP** `liquidity/dex` and `liquidity/fhe` from Go 1.26 to 1.26.1

## Sources

- [1] https://go.dev/doc/devel/release — Go release history
- [2] https://go.dev/doc/go1.24 — `crypto/rand.Read` infallible since 1.24
- [3] https://pkg.go.dev/runtime/secret — runtime/secret experimental package
- [4] https://pkg.go.dev/crypto/hpke — stdlib HPKE (RFC 9180)
- [5] https://github.com/golang/go/issues/73581 — Green Tea GC
- [6] https://go.dev/doc/go1.26 — Go 1.26 release notes (cgo 30% faster)
- [7] https://go.dev/doc/pgo — Profile-Guided Optimization
- [8] https://pkg.go.dev/simd/archsimd — experimental SIMD
- [9] https://go.dev/blog/gofix — go fix modernizers (Go 1.26)
- [10] https://pkg.go.dev/crypto/mlkem — stdlib ML-KEM (FIPS 203)
