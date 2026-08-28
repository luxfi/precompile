// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	dexcore "github.com/luxfi/dex/pkg/dex"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// zzmop_market_test.go covers settle_market.go — the C-AUTHORITATIVE market registry.
// Two properties carry the weight:
//
//   - DETERMINISM: the record every validator writes is a pure function of (key,
//     sqrtPriceX96). The tick comes from the pure TickMath port, NEVER from the
//     best-effort D-Chain OpenMarket, so two nodes — one with a local D-Chain, one
//     without — must write byte-identical state.
//   - ADMISSION: a market RECORD may exist only over two REAL (resolvable +
//     on-chain-real) assets, refused with the same fail-closed errors a swap raises.

// zzmpInitData builds initialize(PoolKey, uint160 sqrtPriceX96) calldata.
func zzmpInitData(key PoolKey, sqrtPriceX96 *big.Int) []byte {
	data := make([]byte, 192)
	copy(data[0:160], EncodePoolKeyABI(key))
	if sqrtPriceX96 != nil && sqrtPriceX96.Sign() > 0 {
		sqrtPriceX96.FillBytes(data[160:192])
	}
	return data
}

// zzmpFreshKey returns a well-formed pool key over the harness's admitted assets with
// a caller-chosen fee tier, so each test registers its OWN pool id.
func zzmpFreshKey(h *settleHarness, fee uint24) PoolKey {
	k := h.key
	k.Fee = fee
	return k
}

func TestZzmpInitializeRefusesReadOnlyOutOfGasAndShortInput(t *testing.T) {
	h := newSettleHarness(t)
	good := zzmpInitData(zzmpFreshKey(h, 500), new(big.Int).Set(Q96))

	if _, gasLeft, err := zzmpRun(h, h.caller, SelectorInitialize, good, 5_000_000, true); err == nil {
		t.Fatal("read-only initialize must be refused")
	} else if gasLeft != 5_000_000 {
		t.Fatalf("read-only refusal must charge no gas, got %d", gasLeft)
	}
	if _, gasLeft, err := zzmpRun(h, h.caller, SelectorInitialize, good, GasPoolCreate-1, false); err == nil {
		t.Fatal("initialize under GasPoolCreate must be refused")
	} else if gasLeft != 0 {
		t.Fatalf("out-of-gas refusal must consume the supply, got %d", gasLeft)
	}
	for n := 0; n < 192; n++ {
		n := n
		zzmpNoPanic(t, "initialize truncated body", func() {
			if _, _, err := zzmpRun(h, h.caller, SelectorInitialize, good[:n], 5_000_000, false); err == nil {
				t.Errorf("initialize accepted a %d-byte body (needs 192)", n)
			}
		})
	}
	// No market may have been registered by any of those refusals.
	if MarketExists(zzmpDB(h), zzmpFreshKey(h, 500)) {
		t.Fatal("a refused initialize registered a market")
	}
}

func TestZzmpInitializeRefusesMalformedKeysAndPrices(t *testing.T) {
	h := newSettleHarness(t)
	db := zzmpDB(h)

	// Currencies must be sorted (native 0x0 first).
	unsorted := zzmpFreshKey(h, 500)
	unsorted.Currency0, unsorted.Currency1 = unsorted.Currency1, unsorted.Currency0
	if _, _, err := zzmpRun(h, h.caller, SelectorInitialize, zzmpInitData(unsorted, new(big.Int).Set(Q96)), 5_000_000, false); !errors.Is(err, ErrCurrencyNotSorted) {
		t.Fatalf("unsorted currencies: want ErrCurrencyNotSorted, got %v", err)
	}
	// A pair with c0 == c1 is not sorted either (strict <).
	same := zzmpFreshKey(h, 500)
	same.Currency0 = same.Currency1
	if _, _, err := zzmpRun(h, h.caller, SelectorInitialize, zzmpInitData(same, new(big.Int).Set(Q96)), 5_000_000, false); !errors.Is(err, ErrCurrencyNotSorted) {
		t.Fatalf("degenerate self-pair: want ErrCurrencyNotSorted, got %v", err)
	}

	// Fee ceiling.
	tooRich := zzmpFreshKey(h, FeeMax+1)
	if _, _, err := zzmpRun(h, h.caller, SelectorInitialize, zzmpInitData(tooRich, new(big.Int).Set(Q96)), 5_000_000, false); !errors.Is(err, ErrInitFeeTooHigh) {
		t.Fatalf("fee above FeeMax: want ErrInitFeeTooHigh, got %v", err)
	}
	atMax := zzmpFreshKey(h, FeeMax)
	if _, _, err := zzmpRun(h, h.caller, SelectorInitialize, zzmpInitData(atMax, new(big.Int).Set(Q96)), 5_000_000, false); err != nil {
		t.Fatalf("fee exactly at FeeMax must be admitted, got %v", err)
	}

	// tickSpacing must be in (0, MaxTickSpacing].
	for _, spacing := range []int24{0, -1, -60, MaxTickSpacing + 1} {
		k := zzmpFreshKey(h, 600)
		k.TickSpacing = spacing
		if _, _, err := zzmpRun(h, h.caller, SelectorInitialize, zzmpInitData(k, new(big.Int).Set(Q96)), 5_000_000, false); !errors.Is(err, ErrInitTickSpacing) {
			t.Fatalf("tickSpacing %d: want ErrInitTickSpacing, got %v", spacing, err)
		}
	}
	edge := zzmpFreshKey(h, 700)
	edge.TickSpacing = MaxTickSpacing
	if _, _, err := zzmpRun(h, h.caller, SelectorInitialize, zzmpInitData(edge, new(big.Int).Set(Q96)), 5_000_000, false); err != nil {
		t.Fatalf("tickSpacing exactly at MaxTickSpacing must be admitted, got %v", err)
	}

	// sqrtPriceX96 must sit in [MinSqrtRatio, MaxSqrtRatio).
	for _, price := range []*big.Int{
		big.NewInt(0),
		new(big.Int).Sub(MinSqrtRatio, big.NewInt(1)),
		new(big.Int).Set(MaxSqrtRatio),
		new(big.Int).Add(MaxSqrtRatio, big.NewInt(1)),
	} {
		k := zzmpFreshKey(h, 800)
		if _, _, err := zzmpRun(h, h.caller, SelectorInitialize, zzmpInitData(k, price), 5_000_000, false); !errors.Is(err, ErrInitSqrtRange) {
			t.Fatalf("sqrtPrice %s: want ErrInitSqrtRange, got %v", price, err)
		}
	}
	// The two inclusive/exclusive boundaries themselves.
	lo := zzmpFreshKey(h, 900)
	if _, _, err := zzmpRun(h, h.caller, SelectorInitialize, zzmpInitData(lo, new(big.Int).Set(MinSqrtRatio)), 5_000_000, false); err != nil {
		t.Fatalf("sqrtPrice == MinSqrtRatio must be admitted, got %v", err)
	}
	hi := zzmpFreshKey(h, 1000)
	if _, _, err := zzmpRun(h, h.caller, SelectorInitialize, zzmpInitData(hi, new(big.Int).Sub(MaxSqrtRatio, big.NewInt(1))), 5_000_000, false); err != nil {
		t.Fatalf("sqrtPrice == MaxSqrtRatio-1 must be admitted, got %v", err)
	}

	if MarketExists(db, tooRich) || MarketExists(db, unsorted) {
		t.Fatal("a refused initialize left a market record behind")
	}

	// ORDERING: the pure input validation runs BEFORE any state read, so a malformed
	// call against an ALREADY-REGISTERED pool still reports the malformed input rather
	// than the registry's idempotency refusal. Without its own range check the handler
	// would reach the idempotency read first and answer ErrPoolAlreadyInitialized, which
	// tells the caller nothing about the price it actually sent.
	live := zzmpFreshKey(h, 1050)
	if _, _, err := zzmpRun(h, h.caller, SelectorInitialize, zzmpInitData(live, new(big.Int).Set(Q96)), 5_000_000, false); err != nil {
		t.Fatalf("initialize the live pool: %v", err)
	}
	for _, price := range []*big.Int{
		big.NewInt(0),
		new(big.Int).Sub(MinSqrtRatio, big.NewInt(1)),
		new(big.Int).Set(MaxSqrtRatio),
	} {
		if _, _, err := zzmpRun(h, h.caller, SelectorInitialize, zzmpInitData(live, price), 5_000_000, false); !errors.Is(err, ErrInitSqrtRange) {
			t.Fatalf("an out-of-range price (%s) on a live pool must be refused for its PRICE, not deferred to the idempotency read: got %v", price, err)
		}
	}
}

// TestZzmpInitializeIsIdempotentAndDeterministic pins BOTH registry invariants: a
// re-init is refused (the status slot is the witness), and the record two independent
// nodes write from the same call is byte-identical.
func TestZzmpInitializeIsIdempotentAndDeterministic(t *testing.T) {
	h := newSettleHarness(t)
	key := zzmpFreshKey(h, 2500)
	price := new(big.Int).Mul(Q96, big.NewInt(2)) // price = 4.0

	out, _, err := zzmpRun(h, h.caller, SelectorInitialize, zzmpInitData(key, price), 5_000_000, false)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	wantTick, terr := GetTickAtSqrtRatio(price)
	if terr != nil {
		t.Fatalf("GetTickAtSqrtRatio: %v", terr)
	}
	if got := new(big.Int).SetBytes(out); got.Int64() != int64(wantTick) {
		t.Fatalf("initialize returned tick %s, want the PURE on-C tick %d", got, wantTick)
	}

	db := zzmpDB(h)
	rec := loadMarket(db, key.ID())
	if rec.Status != MarketStatusActive {
		t.Fatalf("market status: want Active, got %d", rec.Status)
	}
	if rec.Tick != wantTick || rec.Fee != key.Fee || rec.TickSpacing != key.TickSpacing ||
		rec.Currency0 != key.Currency0.Address || rec.Currency1 != key.Currency1.Address ||
		rec.Creator != h.caller || rec.SqrtPriceX96.Cmp(price) != 0 {
		t.Fatalf("market record does not round-trip: %+v", rec)
	}
	if !MarketExists(db, key) {
		t.Fatal("MarketExists must report a registered market")
	}
	// An unregistered key is not a market.
	if MarketExists(db, zzmpFreshKey(h, 2501)) {
		t.Fatal("MarketExists reported an unregistered pool")
	}

	// Idempotency: a second registration of the SAME pool id is refused, whatever the
	// caller or the price.
	for _, caller := range []common.Address{h.caller, h.operator()} {
		if _, _, err := zzmpRun(h, caller, SelectorInitialize, zzmpInitData(key, new(big.Int).Set(Q96)), 5_000_000, false); !errors.Is(err, ErrPoolAlreadyInitialized) {
			t.Fatalf("re-initialize: want ErrPoolAlreadyInitialized, got %v", err)
		}
	}
	if got := loadMarket(db, key.ID()); got.SqrtPriceX96.Cmp(price) != 0 || got.Creator != h.caller {
		t.Fatalf("a refused re-initialize mutated the record: %+v", got)
	}

	// DETERMINISM: a second, independent node executing the identical call writes the
	// identical record — no D-Chain answer participates.
	h2 := newSettleHarness(t)
	if _, _, err := zzmpRun(h2, h.caller, SelectorInitialize, zzmpInitData(key, price), 5_000_000, false); err != nil {
		t.Fatalf("initialize on the second node: %v", err)
	}
	rec2 := loadMarket(zzmpDB(h2), key.ID())
	for _, suffix := range [][]byte{marketMetaSuffix, marketPriceSuffix, marketCurrency0Suffix, marketCurrency1Suffix, marketCreatorSuffix} {
		slot := marketSlot(key.ID(), suffix)
		if a, b := db.GetState(poolManagerAddr9999, slot), zzmpDB(h2).GetState(poolManagerAddr9999, slot); a != b {
			t.Fatalf("registry slot %q diverged between nodes: %x vs %x", suffix, a, b)
		}
	}
	if rec2.Tick != rec.Tick {
		t.Fatalf("tick diverged between nodes: %d vs %d", rec.Tick, rec2.Tick)
	}
}

// TestZzmpMarketRecordEncodesNegativeTicksAndBigFees pins the packed meta slot's
// round-trip over the whole int24/uint24 domain, including a negative tick and a
// negative tickSpacing (which storeMarket must encode two's-complement).
func TestZzmpMarketRecordRoundTripsSignedFields(t *testing.T) {
	h := newSettleHarness(t)
	db := zzmpDB(h)
	for _, rec := range []MarketRecord{
		{Status: MarketStatusActive, SqrtPriceX96: big.NewInt(0), Tick: -887272, Fee: 0, TickSpacing: 1},
		{Status: MarketStatusActive, SqrtPriceX96: new(big.Int).Set(Q96), Tick: 887272, Fee: FeeMax, TickSpacing: MaxTickSpacing},
		{Status: MarketStatusActive, SqrtPriceX96: big.NewInt(12345), Tick: -1, Fee: 0xFFFFFF, TickSpacing: -60},
	} {
		var id [32]byte
		id[0] = byte(rec.Tick)
		id[1] = byte(rec.TickSpacing)
		id[2] = byte(rec.Fee)
		rec.Currency0 = common.HexToAddress("0x0000000000000000000000000000000000000001")
		rec.Currency1 = common.HexToAddress("0x0000000000000000000000000000000000000002")
		rec.Creator = h.caller
		storeMarket(db, id, rec)
		got := loadMarket(db, id)
		if got.Tick != rec.Tick || got.Fee != rec.Fee || got.TickSpacing != rec.TickSpacing ||
			got.Currency0 != rec.Currency0 || got.Currency1 != rec.Currency1 || got.Creator != rec.Creator ||
			got.SqrtPriceX96.Cmp(rec.SqrtPriceX96) != 0 {
			t.Fatalf("market record round-trip: wrote %+v read %+v", rec, got)
		}
	}
	// A never-written pool id reads as MarketStatusNone with no other field decoded.
	if got := loadMarket(db, [32]byte{0xEE}); got.Status != MarketStatusNone {
		t.Fatalf("unwritten pool id: want MarketStatusNone, got %+v", got)
	}
}

// ---------------------------------------------------------------------------
// admitMarketAssets — the permissionless real-asset gate
// ---------------------------------------------------------------------------

func TestZzmpInitializeRefusesFabricatedAssets(t *testing.T) {
	h := newSettleHarness(t)

	// A token address with NO on-chain code is a fabricated asset: the live-reality
	// verifier refuses it, so no market RECORD can be written over it.
	phantom := common.HexToAddress("0x00000000000000000000000000000000DEADBEEF")
	key := zzmpFreshKey(h, 1100)
	key.Currency1 = Currency{Address: phantom}
	if _, _, err := zzmpRun(h, h.caller, SelectorInitialize, zzmpInitData(key, new(big.Int).Set(Q96)), 5_000_000, false); err == nil {
		t.Fatal("initialize over a code-less asset must be refused")
	}
	if MarketExists(zzmpDB(h), key) {
		t.Fatal("a fabricated-asset initialize wrote a market record")
	}

	// Seeding real on-chain code at that address admits it permissionlessly.
	h.state.stateDB.SetCodeSize(phantom, 1)
	if _, _, err := zzmpRun(h, h.caller, SelectorInitialize, zzmpInitData(key, new(big.Int).Set(Q96)), 5_000_000, false); err != nil {
		t.Fatalf("initialize over a REAL asset must be admitted, got %v", err)
	}
	if !MarketExists(zzmpDB(h), key) {
		t.Fatal("an admitted initialize wrote no market record")
	}
}

func TestZzmpAdmitMarketAssetsFailsClosed(t *testing.T) {
	h := newSettleHarness(t)
	db := zzmpDB(h)

	// No AtomicState at all -> no runtime identity -> refuse.
	if err := admitMarketAssets(zzmpPlain(h), db, h.key); !errors.Is(err, ErrSettleNoAtomicState) {
		t.Fatalf("admission with no AtomicState: want ErrSettleNoAtomicState, got %v", err)
	}
	if _, _, err := h.c.Run(zzmpPlain(h), h.caller, poolManagerAddr9999, prependSelector(SelectorInitialize, zzmpInitData(zzmpFreshKey(h, 1200), new(big.Int).Set(Q96))), 5_000_000, false); !errors.Is(err, ErrSettleNoAtomicState) {
		t.Fatalf("initialize with no AtomicState: want ErrSettleNoAtomicState, got %v", err)
	}

	// A resolver bound to a DIFFERENT chain identity is refused (identity mismatch),
	// never silently trusted.
	prev := installedAssetResolver.Load()
	t.Cleanup(func() { installedAssetResolver.Store(prev) })
	installedAssetResolver.Store(nil) // clear the harness's binding first
	if err := InstallAssetResolver(newTestAssetResolver(h.networkID+1, h.cChainID), h.networkID+1, h.cChainID); err != nil {
		t.Fatalf("InstallAssetResolver: %v", err)
	}
	if err := admitMarketAssets(h.state, db, h.key); err == nil {
		t.Fatal("a resolver bound to another network must be refused")
	}

	// With NO resolver installed at all the admission is fail-closed too.
	installedAssetResolver.Store(nil)
	if err := admitMarketAssets(h.state, db, h.key); err == nil {
		t.Fatal("admission with no resolver installed must fail closed")
	}
}

// TestZzmpAdmitMarketAssetsChecksBothSides proves the gate is applied to currency0 AND
// currency1 independently — a real base with a fabricated quote (and the reverse) is
// refused, so one real side can never carry a fake one onto the registry.
func TestZzmpAdmitMarketAssetsChecksBothSides(t *testing.T) {
	h := newSettleHarness(t)
	db := zzmpDB(h)

	realA := common.HexToAddress("0x000000000000000000000000000000000000AA01")
	realB := common.HexToAddress("0x000000000000000000000000000000000000BB02")
	fake := common.HexToAddress("0x000000000000000000000000000000000000CC03")
	h.state.stateDB.SetCodeSize(realA, 1)
	h.state.stateDB.SetCodeSize(realB, 1)

	key := h.key
	key.Currency0 = Currency{Address: realA}
	key.Currency1 = Currency{Address: fake}
	if err := admitMarketAssets(h.state, db, key); err == nil {
		t.Fatal("a fabricated QUOTE must be refused")
	}
	key.Currency0 = Currency{Address: fake}
	key.Currency1 = Currency{Address: realB}
	if err := admitMarketAssets(h.state, db, key); err == nil {
		t.Fatal("a fabricated BASE must be refused")
	}
	key.Currency0 = Currency{Address: realA}
	key.Currency1 = Currency{Address: realB}
	if err := admitMarketAssets(h.state, db, key); err != nil {
		t.Fatalf("two real assets must be admitted, got %v", err)
	}

	// The verifier is the AUTHORITY: removing the code de-admits the asset again
	// (a self-destructed token stops being real).
	h.state.stateDB.SetCodeSize(realB, 0)
	if err := admitMarketAssets(h.state, db, key); err == nil {
		t.Fatal("a self-destructed (code-less) asset must stop being admitted")
	}
}

// zzmpDenyResolver resolves everything EXCEPT one banned reference — a per-asset deny /
// emergency halt, the case the AssetResolver contract calls out. It lets the test prove
// the QUOTE side is resolved independently of the base (a base that resolves cannot carry
// a denied quote onto the registry).
type zzmpDenyResolver struct {
	inner  *testAssetResolver
	banned []byte
}

func (r *zzmpDenyResolver) ResolveAsset(kind dexcore.AssetKind, ref []byte) (ids.ID, uint8, error) {
	if len(r.banned) == len(ref) && string(r.banned) == string(ref) {
		return ids.Empty, 0, errors.New("zzmp: asset reference is denied on this network")
	}
	return r.inner.ResolveAsset(kind, ref)
}

var _ dexcore.AssetResolver = (*zzmpDenyResolver)(nil)

// TestZzmpAdmitMarketAssetsResolvesEachSideIndependently drives a resolver that denies
// exactly ONE reference and proves BOTH the base and the quote are resolved on their own
// — a resolvable base never carries a denied quote onto the C registry.
func TestZzmpAdmitMarketAssetsResolvesEachSideIndependently(t *testing.T) {
	h := newSettleHarness(t)
	db := zzmpDB(h)

	base := common.HexToAddress("0x000000000000000000000000000000000000D101")
	quote := common.HexToAddress("0x000000000000000000000000000000000000D202")
	h.state.stateDB.SetCodeSize(base, 1)
	h.state.stateDB.SetCodeSize(quote, 1)
	key := h.key
	key.Currency0 = Currency{Address: base}
	key.Currency1 = Currency{Address: quote}

	prev := installedAssetResolver.Load()
	t.Cleanup(func() { installedAssetResolver.Store(prev) })

	install := func(banned common.Address) {
		t.Helper()
		installedAssetResolver.Store(nil)
		r := &zzmpDenyResolver{inner: newTestAssetResolver(h.networkID, h.cChainID), banned: banned.Bytes()}
		if err := InstallAssetResolver(r, h.networkID, h.cChainID); err != nil {
			t.Fatalf("InstallAssetResolver: %v", err)
		}
	}

	install(quote)
	if err := admitMarketAssets(h.state, db, key); err == nil {
		t.Fatal("a DENIED quote must be refused even though the base resolves")
	}
	install(base)
	if err := admitMarketAssets(h.state, db, key); err == nil {
		t.Fatal("a DENIED base must be refused even though the quote resolves")
	}
	install(common.HexToAddress("0x000000000000000000000000000000000000FFFF"))
	if err := admitMarketAssets(h.state, db, key); err != nil {
		t.Fatalf("two resolvable, real assets must be admitted, got %v", err)
	}
}

// TestZzmpAssetSideForCurrencyIsInjectiveOverTheTwoEVMKinds pins the (kind, ref)
// mapping the admission consumes: native maps to the EVM-native marker, an ERC-20 to
// its own 20-byte address, and the two never alias.
func TestZzmpAssetSideForCurrencyIsInjectiveOverTheTwoEVMKinds(t *testing.T) {
	native := assetSideForCurrency(Currency{})
	if native.Kind != dexcore.AssetKindEVMNative {
		t.Fatalf("native kind: want EVMNative, got %v", native.Kind)
	}
	tok := common.HexToAddress("0x000000000000000000000000000000000000AB01")
	erc := assetSideForCurrency(Currency{Address: tok})
	if erc.Kind != dexcore.AssetKindERC20 {
		t.Fatalf("erc20 kind: want ERC20, got %v", erc.Kind)
	}
	if string(erc.Ref) != string(tok.Bytes()) {
		t.Fatalf("erc20 ref: want the token address, got %x", erc.Ref)
	}
	if string(erc.Ref) == string(native.Ref) {
		t.Fatal("native and ERC-20 refs alias")
	}
	// The returned refs are COPIES: mutating one must not corrupt the shared marker.
	erc.Ref[0] ^= 0xFF
	if again := assetSideForCurrency(Currency{Address: tok}); string(again.Ref) != string(tok.Bytes()) {
		t.Fatalf("assetSideForCurrency returned an aliased ref: %x", again.Ref)
	}
	native.Ref[0] ^= 0xFF
	if again := assetSideForCurrency(Currency{}); string(again.Ref) != string(dexcore.EVMNativeMarker) {
		t.Fatalf("assetSideForCurrency aliased the native marker: %x", again.Ref)
	}
}

// ---------------------------------------------------------------------------
// bestEffortOpenMarketOnLocalD — fire-and-forget by construction
// ---------------------------------------------------------------------------

// zzmpCustodyEngine is an Engine that ALSO carries a custody ledger, so the initialize
// path reaches the best-effort D OpenMarket. openErr drives the failure branch, which
// must NEVER surface to the caller: the C registry is authoritative.
type zzmpCustodyEngine struct {
	mockEngine
	openErr  error
	opened   int
	lastPool [32]byte
}

func (e *zzmpCustodyEngine) OpenMarket(poolID [32]byte, _, _ Currency) error {
	e.opened++
	e.lastPool = poolID
	return e.openErr
}
func (e *zzmpCustodyEngine) Deposit(common.Address, Currency, uint64, [32]byte) error { return nil }
func (e *zzmpCustodyEngine) Withdraw(common.Address, Currency, uint64, [32]byte) (uint64, error) {
	return 0, nil
}
func (e *zzmpCustodyEngine) Balance(common.Address, Currency) (uint64, error) { return 0, nil }

var _ custodyEngine = (*zzmpCustodyEngine)(nil)

func TestZzmpBestEffortOpenMarketNeverFailsTheRegistration(t *testing.T) {
	h := newSettleHarness(t)

	// (a) No pool manager at all (a node that never composed one): a no-op.
	savedPM := DEXPrecompile.poolManager
	t.Cleanup(func() { DEXPrecompile.poolManager = savedPM })
	DEXPrecompile.poolManager = nil
	keyA := zzmpFreshKey(h, 3100)
	if _, _, err := zzmpRun(h, h.caller, SelectorInitialize, zzmpInitData(keyA, new(big.Int).Set(Q96)), 5_000_000, false); err != nil {
		t.Fatalf("initialize with no pool manager: %v", err)
	}
	if !MarketExists(zzmpDB(h), keyA) {
		t.Fatal("the C registry must be written even with no pool manager")
	}

	// (b) A pool manager with NO engine: also a no-op.
	DEXPrecompile.poolManager = NewPoolManager()
	keyB := zzmpFreshKey(h, 3200)
	if _, _, err := zzmpRun(h, h.caller, SelectorInitialize, zzmpInitData(keyB, new(big.Int).Set(Q96)), 5_000_000, false); err != nil {
		t.Fatalf("initialize with an engine-less pool manager: %v", err)
	}
	if !MarketExists(zzmpDB(h), keyB) {
		t.Fatal("the C registry must be written with an engine-less pool manager")
	}

	// (c) A custody-capable engine whose OpenMarket FAILS: logged only, never fatal,
	//     and the record is byte-identical to the no-D case.
	failing := &zzmpCustodyEngine{openErr: errors.New("zzmp D book unavailable")}
	DEXPrecompile.poolManager = NewPoolManager(failing)
	keyC := zzmpFreshKey(h, 3300)
	if _, _, err := zzmpRun(h, h.caller, SelectorInitialize, zzmpInitData(keyC, new(big.Int).Set(Q96)), 5_000_000, false); err != nil {
		t.Fatalf("a failing D OpenMarket must NOT fail the C registration, got %v", err)
	}
	if failing.opened != 1 || failing.lastPool != keyC.ID() {
		t.Fatalf("OpenMarket was not attempted for the registered pool (opened=%d)", failing.opened)
	}
	if !MarketExists(zzmpDB(h), keyC) {
		t.Fatal("the C registry must be written even when the D book refuses")
	}

	// (d) A succeeding OpenMarket writes the SAME record a D-less node writes — the D
	//     answer is discarded, so the two nodes cannot disagree.
	ok := &zzmpCustodyEngine{}
	DEXPrecompile.poolManager = NewPoolManager(ok)
	keyD := zzmpFreshKey(h, 3400)
	if _, _, err := zzmpRun(h, h.caller, SelectorInitialize, zzmpInitData(keyD, new(big.Int).Set(Q96)), 5_000_000, false); err != nil {
		t.Fatalf("initialize with a live D book: %v", err)
	}
	hNoD := newSettleHarness(t)
	DEXPrecompile.poolManager = nil
	if _, _, err := zzmpRun(hNoD, h.caller, SelectorInitialize, zzmpInitData(keyD, new(big.Int).Set(Q96)), 5_000_000, false); err != nil {
		t.Fatalf("initialize on a D-less node: %v", err)
	}
	for _, suffix := range [][]byte{marketMetaSuffix, marketPriceSuffix, marketCurrency0Suffix, marketCurrency1Suffix, marketCreatorSuffix} {
		slot := marketSlot(keyD.ID(), suffix)
		if a, b := zzmpDB(h).GetState(poolManagerAddr9999, slot), zzmpDB(hNoD).GetState(poolManagerAddr9999, slot); a != b {
			t.Fatalf("registry slot %q diverged between a D-having and a D-less node: %x vs %x", suffix, a, b)
		}
	}
}

// zzmpKeepIDsImported keeps the ids import used by this file's helpers.
var zzmpKeepIDsImported = ids.Empty
