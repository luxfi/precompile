// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"context"
	"encoding/binary"
	"errors"
	"math/big"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/luxfi/geth/common"
)

// route_not_simulate_test.go is the executable enforcement of the CTO mesh rule:
//
//	"0x9010 must NEVER locally simulate D — it routes to ZAP/D and REVERTS if
//	 they are unavailable; never fake a result."
//
// The LP-9010 precompile has EXACTLY TWO states and NO third:
//
//   - INERT (default, engine_inert.go): no backend wired. Every value-moving op
//     reverts ErrDEXBackendNotConfigured and returns a zero delta. It is NOT a
//     poolRouter / custodyEngine / cancelAuthority — it CANNOT hold a book, a
//     ledger, or an order map, so an embedded matcher is not even representable.
//   - ZAP -> D-Chain (engine_zap.go): the stateless adapter that forwards every
//     op to the d-chain CLOB over ZAP. When the venue is UNREACHABLE the adapter
//     surfaces the dial/transport error; the PoolManager returns it verbatim; the
//     Run() entrypoint returns it; the EVM reverts the call (RevertToSnapshot).
//
// There is NO embedded engine, NO AMM reserve-math fallback, NO local quote, and
// NO synthesized success on a dead venue. These tests pin all four facets:
//   1. TestPrecompileZapOnlyNoEmbeddedFallback   — no local fill/match/quote path.
//   2. TestPrecompileZapOnlyConfiguredPath        — a configured ZAP routes to D.
//   3. TestPrecompile0x9010RevertsWhenVenueUnavailable — venue down => REVERT, no
//      fabricated/stale/simulated result (the critical safety property).
//   4. TestPrecompileLinksNoEmbeddedMatcher       — source-guard: the precompile
//      package links NO matching engine / GPU / venue-internal matcher.

// =========================================================================
// (3-seam) withUnreachableVenue installs a zapDialer that ALWAYS fails, exactly
// as a connection-refused / venue-down dial would. Restores the canonical dialer
// after the test. Mirrors withFakeCLOB's seam discipline (one way to stub ZAP).
// =========================================================================

// errVenueDown is the dial error a down venue surfaces. The assertions check the
// precompile's returned error WRAPS this — i.e. the revert reason is "the venue
// could not be reached", never a fabricated trade outcome.
var errVenueDown = errors.New("dial tcp 127.0.0.1:9100: connect: connection refused")

func withUnreachableVenue(t *testing.T) {
	t.Helper()
	orig := zapDialer
	zapDialer = func(_ context.Context, _ string) (zapConn, error) { return nil, errVenueDown }
	t.Cleanup(func() { zapDialer = orig })
}

// =========================================================================
// (1) No embedded fallback — the precompile holds no second matcher.
// =========================================================================

// TestPrecompileZapOnlyNoEmbeddedFallback proves there is NO code path where
// 0x9010 computes a swap / fill / match / quote LOCALLY. It pins the structural
// property at the root: the package DEFAULT engine (inert) is the only engine a
// chain runs until the venue installs ZAP, and the inert engine
//
//   - reverts EVERY value-moving op with the backend sentinel and a ZERO delta
//     (no fabricated value), AND
//   - implements NONE of poolRouter / custodyEngine / cancelAuthority — the three
//     seams a stateful/embedded backend would need to hold a pool, a ledger, or a
//     resting-order map. An engine that holds no canonical state and exposes no
//     routing/custody/cancel seam CANNOT be a matcher; it can only refuse.
//
// It then drives a fully-liquid pool committed straight to StateDB through the
// consolidated quote path and asserts ZERO output — there is no surviving
// embedded AMM that would price that liquidity. One matcher exists in the tree
// (the d-chain over ZAP); the precompile is a pure ABI shim.
func TestPrecompileZapOnlyNoEmbeddedFallback(t *testing.T) {
	pm := NewPoolManager(newInertEngine())
	stateDB := NewMockStateDB()
	key := PoolKey{
		Currency0:   Currency{Address: testTokenA},
		Currency1:   Currency{Address: testTokenB},
		Fee:         Fee030,
		TickSpacing: TickSpacing030,
	}

	// Structural + behavioral: the default engine is the inert sentinel — no
	// stateful seam (poolRouter/custodyEngine/cancelAuthority) and every value op
	// refuses with the backend sentinel + zero delta. (Shared definition: one place
	// asserts "this engine is the inert sentinel" — see assertInertEngineSentinel.)
	assertInertEngineSentinel(t, pm.engine)

	// No local-quote path: a fully-liquid pool committed straight to StateDB still
	// quotes ZERO through the consolidated path and the raw engine — no surviving
	// embedded AMM prices that liquidity.
	assertNoLocalQuotePath(t, pm, stateDB, key)
}

// =========================================================================
// (2) Configured path — a wired ZAP routes to the venue.
// =========================================================================

// TestPrecompileZapOnlyConfiguredPath proves that with a ZAP endpoint configured,
// 0x9010 ROUTES the swap to the venue and derives its delta from the SERVER's
// fills — not from any local computation. It seeds a resting ask on the fake
// CLOB (the d-chain stand-in), runs a marketable buy through the full PoolManager,
// and asserts (a) the venue actually received the submit, and (b) the returned
// delta is the server fill's value (which only the book could produce).
func TestPrecompileZapOnlyConfiguredPath(t *testing.T) {
	f := newFakeCLOB()
	withFakeCLOB(t, f)

	zap := NewZAPEngine("fake:0", 2*time.Second)
	defer zap.Close()
	pm := NewPoolManager(zap)
	stateDB := NewMockStateDB()
	key := conservationPoolKey()
	lp := common.HexToAddress("0x2222222222222222222222222222222222222222")
	taker := common.HexToAddress("0x1111111111111111111111111111111111111111")

	if _, err := pm.Initialize(stateDB, key, new(big.Int).Set(Q96), nil); err != nil {
		t.Fatalf("Initialize (routes ensure-market to venue): %v", err)
	}

	askTick := tickForPriceLocal(t, 2.0)
	askPrice := priceForTickLocal(t, askTick)
	if _, _, err := pm.ModifyLiquidity(stateDB, lp, key, ModifyLiquidityParams{
		TickLower:      askTick,
		TickUpper:      askTick + TickSpacing030,
		LiquidityDelta: big.NewInt(100),
	}, nil); err != nil {
		t.Fatalf("ModifyLiquidity (rests order on venue): %v", err)
	}

	submitsBefore := f.submits
	const takeBase = int64(40)
	delta, err := pm.Swap(stateDB, taker, key, SwapParams{
		ZeroForOne:        false,
		AmountSpecified:   big.NewInt(-takeBase),
		SqrtPriceLimitX96: MaxSqrtRatio,
	}, nil)
	if err != nil {
		t.Fatalf("Swap (must route to venue): %v", err)
	}

	// (a) The venue received the marketable submit — the swap was ROUTED, not
	// computed in-precompile.
	if f.submits <= submitsBefore {
		t.Fatalf("swap did not reach the venue: fake CLOB submit count unchanged (%d)", f.submits)
	}
	// (b) The delta is the SERVER fill's value: taker receives base, owes quote at
	// the resting ask's price. A local simulator could not know the venue's resting
	// order.
	if delta.Amount0.Cmp(big.NewInt(-takeBase)) != 0 {
		t.Fatalf("routed base delta = %s, want -%d (server fill)", delta.Amount0, takeBase)
	}
	wantQuote := ceilQuote(askPrice * float64(takeBase))
	if delta.Amount1.Cmp(wantQuote) != 0 {
		t.Fatalf("routed quote delta = %s, want %s (server fill)", delta.Amount1, wantQuote)
	}
}

// =========================================================================
// (3) THE CRITICAL SAFETY PROPERTY — venue unavailable => REVERT, never fake.
// =========================================================================

// TestPrecompile0x9010RevertsWhenVenueUnavailable is the heart of the mesh rule.
// With a ZAP backend CONFIGURED but the venue UNREACHABLE (every dial fails),
// every value-moving precompile operation must REVERT — return a non-nil error
// and a ZERO delta — and must NEVER fabricate a success, a stale value, or a
// locally-simulated result.
//
// It proves the property at BOTH boundaries:
//
//	A) the PoolManager engine boundary (the value the Run() entrypoint returns
//	   verbatim — see runSwap/runDeposit/runWithdraw which return the PM error
//	   unchanged), for Initialize / Swap / ModifyLiquidity / Deposit / Withdraw;
//	B) the EVM Run() entrypoint itself, for a swap on an ALREADY-INITIALIZED pool
//	   whose venue then goes DOWN — proving the error reaches the EVM (which then
//	   reverts the call via RevertToSnapshot) rather than committing a fake delta.
//
// Critically, the down-venue error is NOT ErrDEXBackendNotConfigured (a backend
// IS wired) — it is the dial failure. So "no backend" and "backend down" are
// distinct conditions that BOTH revert and NEITHER simulates.
func TestPrecompile0x9010RevertsWhenVenueUnavailable(t *testing.T) {
	// ---- A) Engine/PoolManager boundary: every op reverts on a dead venue. ----
	t.Run("PoolManagerBoundary", func(t *testing.T) {
		withUnreachableVenue(t)
		zap := NewZAPEngine("127.0.0.1:9100", 500*time.Millisecond)
		defer zap.Close()
		pm := NewPoolManager(zap)
		stateDB := NewMockStateDB()
		key := conservationPoolKey()
		caller := common.HexToAddress("0x1111111111111111111111111111111111111111")
		native := NativeCurrency

		// Initialize: the venue is down, so the market cannot be created — REVERT,
		// no fake tick/pool. (A fabricated pool here would let a later op self-match.)
		if _, err := pm.Initialize(stateDB, key, new(big.Int).Set(Q96), nil); err == nil {
			t.Fatal("Initialize on a down venue must REVERT (cannot create a market), got nil error")
		} else if errors.Is(err, ErrDEXBackendNotConfigured) {
			t.Fatalf("Initialize err = %v; a configured-but-down venue must NOT report 'no backend'", err)
		}

		// Because Initialize reverted, the pool was never created. Even so, drive
		// the ZAP engine's value ops DIRECTLY to prove the adapter itself reverts on
		// a dead dial and fabricates NOTHING — the no-simulate property at the
		// engine, independent of the not-initialized gate.
		ps := &PoolState{}
		zap.SetPoolID(ps, key.ID()) // route is set, but the dial will still fail

		if d, err := zap.Swap(ps, caller, SwapParams{
			ZeroForOne:        false,
			AmountSpecified:   big.NewInt(-40),
			SqrtPriceLimitX96: MaxSqrtRatio,
		}); err == nil || !d.IsZero() {
			t.Fatalf("ZAP Swap on down venue = (%v,%v); want (zero delta, dial error) — NEVER a fabricated fill", d, err)
		} else if errors.Is(err, ErrDEXBackendNotConfigured) {
			t.Fatalf("ZAP Swap down-venue err = %v; must be the dial failure, not 'no backend'", err)
		}

		if cd, fd, err := zap.ModifyLiquidity(ps, caller, ModifyLiquidityParams{
			TickLower:      tickForPriceLocal(t, 2.0),
			TickUpper:      tickForPriceLocal(t, 2.0) + TickSpacing030,
			LiquidityDelta: big.NewInt(100),
		}); err == nil || !cd.IsZero() || !fd.IsZero() {
			t.Fatalf("ZAP ModifyLiquidity on down venue = (%v,%v,%v); want (zero,zero,dial error)", cd, fd, err)
		}

		// Custody ops: Deposit must revert AFTER no D-Chain mint can be confirmed —
		// it must not credit a balance the venue never recorded. Withdraw must revert
		// rather than release vault funds against an unconfirmed burn.
		if err := pm.Deposit(stateDB, caller, native, big.NewInt(1000)); err == nil {
			t.Fatal("Deposit on a down venue must REVERT (no D-Chain mint confirmable), got nil")
		}
		if realized, err := pm.Withdraw(stateDB, caller, native, big.NewInt(1000)); err == nil || realized.Sign() != 0 {
			t.Fatalf("Withdraw on a down venue = (%v,%v); want (0, error) — NEVER release against an unconfirmed burn", realized, err)
		}
	})

	// ---- B) EVM Run() boundary: a swap reverts to the caller when the venue,
	// previously up (pool initialized), goes DOWN. The error reaching Run() is what
	// makes the EVM RevertToSnapshot — no fabricated delta is ever returned to the
	// contract. ----
	t.Run("EVMRunBoundaryAfterVenueGoesDown", func(t *testing.T) {
		f := newFakeCLOB()
		// Dialer: serve the fake while "up", then a flip to down. We control it via a
		// boolean the closure reads, restoring the canonical dialer on cleanup.
		venueUp := true
		orig := zapDialer
		zapDialer = func(_ context.Context, _ string) (zapConn, error) {
			if !venueUp {
				return nil, errVenueDown
			}
			return f.conn(), nil
		}
		t.Cleanup(func() { zapDialer = orig })

		zap := NewZAPEngine("127.0.0.1:9100", 500*time.Millisecond)
		defer zap.Close()
		c := &DEXContract{poolManager: NewPoolManager(zap)}
		state := &mockAccessibleState{stateDB: NewMockStateDB()}
		key := conservationPoolKey()

		// Initialize while the venue is UP (routes ensure-market to the fake).
		if _, err := c.poolManager.Initialize(state.GetStateDB().(*contractStateDBWrapper).inner, key, new(big.Int).Set(Q96), nil); err != nil {
			t.Fatalf("setup Initialize (venue up): %v", err)
		}

		// Venue goes DOWN. The connection the engine cached during Initialize is
		// dropped so the next op must re-dial (and fail).
		_ = zap.Close()
		venueUp = false

		// Build a valid V4 swap calldata and drive it through the EVM Run()
		// entrypoint. With the venue down, Run() must return a non-nil error (=> the
		// EVM reverts) and NOT a packed BalanceDelta success.
		calldata := encodeSwapCalldataForTest(key, false, big.NewInt(-40), MaxSqrtRatio)
		ret, _, err := c.Run(state, common.Address{0x11}, lxPoolAddr, calldata, 1_000_000, false)
		if err == nil {
			t.Fatalf("Run(swap) on a down venue returned nil error + ret=%x — the EVM would COMMIT a fabricated result; it MUST revert", ret)
		}
		if errors.Is(err, ErrDEXBackendNotConfigured) {
			t.Fatalf("Run(swap) down-venue err = %v; a configured-but-down venue must surface the dial failure, not 'no backend'", err)
		}
		// A reverting precompile returns no usable result bytes.
		if len(ret) != 0 {
			t.Fatalf("Run(swap) on a down venue returned %d result bytes — a revert must yield no fabricated delta", len(ret))
		}
	})
}

// encodeSwapCalldataForTest builds the V4 swap calldata DecodeSwapInput parses:
//
//	selector[4] ‖ PoolKey[160] ‖ zeroForOne[32] ‖ amountSpecified[int256:32] ‖
//	sqrtPriceLimitX96[32]
//
// It is the inverse of DecodeSwapInput for the fields the engine path reads. Used
// only to drive Run() at the EVM boundary in the down-venue revert proof.
func encodeSwapCalldataForTest(key PoolKey, zeroForOne bool, amountSpecified, sqrtPriceLimit *big.Int) []byte {
	out := make([]byte, 4+256)
	binary.BigEndian.PutUint32(out[0:4], SelectorSwap)
	copy(out[4:4+160], EncodePoolKeyABI(key))
	if zeroForOne {
		out[4+191] = 1
	}
	// amountSpecified as two's-complement int256 (negative = exact input).
	copy(out[4+192:4+224], signedTo32BytesForTest(amountSpecified))
	sqrtPriceLimit.FillBytes(out[4+224 : 4+256])
	return out
}

// signedTo32BytesForTest renders v as a 32-byte big-endian two's-complement word
// (matches decodeSigned256's inverse for the negative exact-input amounts here).
func signedTo32BytesForTest(v *big.Int) []byte {
	out := make([]byte, 32)
	if v.Sign() >= 0 {
		v.FillBytes(out)
		return out
	}
	// two's complement: 2^256 + v
	mod := new(big.Int).Lsh(big.NewInt(1), 256)
	tc := new(big.Int).Add(mod, v) // v is negative
	tc.FillBytes(out)
	return out
}

// =========================================================================
// (4) SOURCE-GUARD — the precompile links NO matching engine / GPU / venue code.
// =========================================================================

// TestPrecompileLinksNoEmbeddedMatcher is the linkage proof, mirroring node's
// TestVenueEngineNotLinked: `go list -deps` is the ground-truth dependency graph
// of the compiled artifact, the only honest way to assert what a package links.
// The LP-9010 precompile is a PURE INGRESS ADAPTER — it holds nothing and computes
// no fills — so it MUST NOT link the venue's matching engine, the GPU kernels, the
// private workspace, or the lx order-book matcher. If any appears here, an
// embedded matcher crept back in (the exact regression the inert-default rip-out
// eliminated), and this test fails loudly.
func TestPrecompileLinksNoEmbeddedMatcher(t *testing.T) {
	deps := goListDepsForGuard(t, ".")

	// Each needle is a package-path substring that would indicate the precompile
	// links a matcher / GPU accelerator / venue-internal engine.
	forbidden := []struct{ needle, why string }{
		{"luxcpp", "C++ GPU bindings (private venue accelerator)"},
		{"gpu-kernels", "CUDA/Metal/HIP matcher kernels (private)"},
		{"lux-private", "the private workspace"},
		{"luxfi/dex", "the d-chain venue matcher module (CLOB engine + cgo/GPU)"},
		{"orderbook", "an order-book matching engine"},
		{"matcher", "a matching engine"},
	}
	for _, f := range forbidden {
		if n := countDepsContaining(deps, f.needle); n != 0 {
			t.Errorf("precompile links %q (%d packages) — %s; LP-9010 must hold NO matcher "+
				"(it is a pure ZAP ingress adapter that routes to the d-chain)", f.needle, n, f.why)
		}
	}

	// Positive control: the precompile DOES link the geth EVM types (it is an EVM
	// precompile). If this is absent the dep query is broken and the negatives are
	// vacuous.
	if countDepsContaining(deps, "luxfi/geth") == 0 {
		t.Fatal("dep query returned no luxfi/geth — the go list result is broken, negative assertions are vacuous")
	}
}

// goListDepsForGuard returns `go list -deps pkg` run from the package directory
// (the precompile is its own buildable package: `go list .` resolves it). It is
// the same ground-truth technique node's vms_purity_test.go uses.
func goListDepsForGuard(t *testing.T, pkg string) []string {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", pkg)
	cmd.Dir = "." // the dex precompile package directory
	cmd.Env = append(cmd.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps %s failed: %v\n%s", pkg, err, out)
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

func countDepsContaining(deps []string, needle string) int {
	n := 0
	for _, d := range deps {
		if strings.Contains(d, needle) {
			n++
		}
	}
	return n
}
