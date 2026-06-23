// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/holiman/uint256"
	"github.com/luxfi/dex/pkg/dexcore"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// settle_market.go is the 0x9999 `initialize` path — the C-AUTHORITATIVE market
// registry. It is a NEW concern at the SAME money-path module, decomplected from
// settlement: it creates the pool↔market mapping the rest of the surface reads
// (StateView.getMarket, the maker-lock halt scope, Quoter's C-side fallback) but
// moves NO value (a pool that exists holds nothing until a swap settles a fill).
//
// THE FORK-SAFETY CRUX (identical in spirit to the swap path): the registry write
// every C validator performs MUST be a pure deterministic function of the call
// (key, sqrtPriceX96) and the configured chain — it must NOT depend on any D-Chain
// response. So the tick is computed ON C via the package's pure GetTickAtSqrtRatio
// (TickMath.sol port), NEVER from engine.Initialize. On a build-path proposer that
// runs a local D-Chain we ALSO best-effort OpenMarket on D so the D book learns the
// pair, but the tick D returns is DISCARDED (logged only) — a non-D validator
// re-executing the block computes the byte-identical registry write from the same
// pure function. Two validators can never disagree on the market record.
//
// Idempotent: re-initializing an already-registered pool reverts
// ErrPoolAlreadyInitialized (the registry status slot is the witness).

// marketRegistryPrefix keys a market record in the 0x9999 namespace. One record
// per poolID (= PoolKey.ID()). Stored across a small fixed set of fine-grained
// slots so reads are cheap and a registration is NOT a global hot write — two
// concurrent initializes of DIFFERENT pools touch disjoint slots (Block-STM).
var marketRegistryPrefix = []byte(settleStateNamespace + "mkt")

// MarketStatus is the lifecycle of a registered market.
type MarketStatus uint8

const (
	// MarketStatusNone is the zero value: no market registered for this poolID.
	MarketStatusNone MarketStatus = 0
	// MarketStatusActive is a registered, initialized market.
	MarketStatusActive MarketStatus = 1
)

// MarketRecord is the C-authoritative registry entry for one pool. Every field is
// derived deterministically at initialize time; the record is the single source of
// truth StateView and the Quoter C-fallback read. currency0/currency1 are recovered
// from the PoolKey (sorted), so the record alone identifies the pair + fee tier.
type MarketRecord struct {
	Status       MarketStatus
	SqrtPriceX96 *big.Int       // initial price (Q64.96), as supplied + range-checked
	Tick         int24          // computed ON C from SqrtPriceX96 (deterministic)
	Currency0    common.Address // lower-address token (native = 0x0)
	Currency1    common.Address // higher-address token
	Fee          uint24         // LP fee in pips (<= FeeMax)
	TickSpacing  int24          // from the pool key
	Creator      common.Address // caller that registered the market
}

// market record slot suffixes — fine-grained, one concern per slot. The packed
// meta slot holds status|tick|fee|tickSpacing (all small, fits one 32-byte word);
// price, the two currencies, and the creator each get their own slot.
var (
	marketMetaSuffix      = []byte("m") // status(1) | tick(int24) | fee(uint24) | tickSpacing(int24)
	marketPriceSuffix     = []byte("p") // sqrtPriceX96 (uint256)
	marketCurrency0Suffix = []byte("0") // currency0 (address, low 20 bytes)
	marketCurrency1Suffix = []byte("1") // currency1 (address)
	marketCreatorSuffix   = []byte("c") // creator (address)
)

func marketSlot(poolID [32]byte, suffix []byte) common.Hash {
	id := make([]byte, 0, 32+len(suffix))
	id = append(id, poolID[:]...)
	id = append(id, suffix...)
	return makeStorageKey(marketRegistryPrefix, id)
}

// initialize-path errors.
var (
	ErrInitSqrtRange   = errors.New("dex: initialize sqrtPriceX96 out of range [MinSqrtRatio, MaxSqrtRatio)")
	ErrInitFeeTooHigh  = errors.New("dex: initialize fee exceeds FeeMax")
	ErrInitTickSpacing = errors.New("dex: initialize tickSpacing must be in (0, MaxTickSpacing]")
)

// MaxTickSpacing bounds tickSpacing so a registration cannot encode a degenerate
// spacing (V4 enforces tickSpacing in [1, 32767]; we mirror that ceiling).
const MaxTickSpacing int24 = 32767

// loadMarket reads the registry record for a poolID. Status==MarketStatusNone
// (zero) means no market. Deterministic StateDB reads, no engine, no D-Chain.
func loadMarket(stateDB stateKV, poolID [32]byte) MarketRecord {
	meta := stateDB.GetState(poolManagerAddr9999, marketSlot(poolID, marketMetaSuffix))
	var rec MarketRecord
	rec.Status = MarketStatus(meta[0])
	if rec.Status == MarketStatusNone {
		return rec
	}
	// meta layout (big-endian within the 32-byte word):
	//   [0]      status
	//   [1:4]    tick        (int24, sign-extended)
	//   [4:7]    fee         (uint24)
	//   [7:10]   tickSpacing (int24, sign-extended)
	rec.Tick = decodeInt24(meta[1:4])
	rec.Fee = uint24(uint32(meta[4])<<16 | uint32(meta[5])<<8 | uint32(meta[6]))
	rec.TickSpacing = decodeInt24(meta[7:10])
	rec.SqrtPriceX96 = new(big.Int).SetBytes(stateDB.GetState(poolManagerAddr9999, marketSlot(poolID, marketPriceSuffix)).Bytes())
	rec.Currency0 = common.BytesToAddress(stateDB.GetState(poolManagerAddr9999, marketSlot(poolID, marketCurrency0Suffix)).Bytes())
	rec.Currency1 = common.BytesToAddress(stateDB.GetState(poolManagerAddr9999, marketSlot(poolID, marketCurrency1Suffix)).Bytes())
	rec.Creator = common.BytesToAddress(stateDB.GetState(poolManagerAddr9999, marketSlot(poolID, marketCreatorSuffix)).Bytes())
	return rec
}

// storeMarket writes a market record across its fine-grained slots. Caller has
// already validated every field (sorted, fee, sqrt range, tick computed on C).
func storeMarket(stateDB stateKV, poolID [32]byte, rec MarketRecord) {
	var meta common.Hash
	meta[0] = byte(rec.Status)
	putInt24(meta[1:4], rec.Tick)
	meta[4] = byte(rec.Fee >> 16)
	meta[5] = byte(rec.Fee >> 8)
	meta[6] = byte(rec.Fee)
	putInt24(meta[7:10], rec.TickSpacing)
	stateDB.SetState(poolManagerAddr9999, marketSlot(poolID, marketMetaSuffix), meta)

	var price common.Hash
	if rec.SqrtPriceX96 != nil && rec.SqrtPriceX96.Sign() > 0 {
		rec.SqrtPriceX96.FillBytes(price[:])
	}
	stateDB.SetState(poolManagerAddr9999, marketSlot(poolID, marketPriceSuffix), price)
	stateDB.SetState(poolManagerAddr9999, marketSlot(poolID, marketCurrency0Suffix), common.BytesToHash(rec.Currency0.Bytes()))
	stateDB.SetState(poolManagerAddr9999, marketSlot(poolID, marketCurrency1Suffix), common.BytesToHash(rec.Currency1.Bytes()))
	stateDB.SetState(poolManagerAddr9999, marketSlot(poolID, marketCreatorSuffix), common.BytesToHash(rec.Creator.Bytes()))
}

// putInt24 writes a signed int24 into a 3-byte big-endian slice (two's complement
// in 3 bytes; decodeInt24 is the inverse).
func putInt24(b []byte, v int24) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

// runSettleInitialize handles 0x9999 `initialize(PoolKey, uint160 sqrtPriceX96)`.
// It validates the key + price, computes the tick deterministically ON C, and
// writes the C-authoritative market record. It moves NO value. Re-initializing an
// existing pool reverts ErrPoolAlreadyInitialized (idempotent registration).
//
// V4 ABI (UNCHANGED): PoolKey (5 slots = 160 bytes) + sqrtPriceX96 (32 bytes),
// optional trailing hookData (ignored here — there are no init hooks in the
// receipt model). Same selector 0x6276CBBE the V4 SDK emits.
func (s *SettleContract) runSettleInitialize(
	state contract.AccessibleState, caller common.Address, input []byte, gas uint64, readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, gas, errors.New("dex: cannot initialize in read-only mode")
	}
	if gas < GasPoolCreate {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := gas - GasPoolCreate
	if len(input) < 192 {
		return nil, gasLeft, errors.New("dex: initialize input too short (need PoolKey + sqrtPriceX96)")
	}

	key, err := DecodePoolKey(input[:160])
	if err != nil {
		return nil, gasLeft, err
	}
	sqrtPriceX96 := new(big.Int).SetBytes(input[160:192])

	// --- Validation (pure, deterministic). Currencies sorted; fee bounded; price
	// in the canonical V4 range; tickSpacing sane.
	if !currenciesSorted(key.Currency0, key.Currency1) {
		return nil, gasLeft, ErrCurrencyNotSorted
	}
	if key.Fee > FeeMax {
		return nil, gasLeft, ErrInitFeeTooHigh
	}
	if key.TickSpacing <= 0 || key.TickSpacing > MaxTickSpacing {
		return nil, gasLeft, ErrInitTickSpacing
	}
	if sqrtPriceX96.Cmp(MinSqrtRatio) < 0 || sqrtPriceX96.Cmp(MaxSqrtRatio) >= 0 {
		return nil, gasLeft, ErrInitSqrtRange
	}

	stateDB := newPoolStateAdapter(state)

	// --- Idempotency: refuse re-init of an existing pool.
	poolID := key.ID()
	if loadMarket(stateDB, poolID).Status != MarketStatusNone {
		return nil, gasLeft, ErrPoolAlreadyInitialized
	}

	// --- Compute the tick ON C from the supplied price (TickMath.sol port). This
	// is THE determinism guarantee: every validator computes the identical tick
	// from the identical price, with no D-Chain dependency.
	tick, err := GetTickAtSqrtRatio(sqrtPriceX96)
	if err != nil {
		// In-range price always yields a tick; treat any failure as a bad price.
		return nil, gasLeft, ErrInitSqrtRange
	}

	// --- C1 PARITY: admit BOTH currencies through the SAME real-asset gate the swap
	// path uses (resolver registry-admission + live-code verifier) BEFORE writing the
	// MarketRecord. Without this, initialize would write a phantom market over arbitrary
	// (currency0, currency1) — a fabricated-asset pair the swap path would later refuse,
	// but whose stub record + Initialize event still leaked onto C and into the graph.
	// Gating here refuses a fake-asset initialize outright (not merely ignoring it at swap
	// time), so a market RECORD can exist only over two registered, enabled, on-chain-real
	// assets — identical admission, identical fail-closed shape (no resolver ->
	// ErrNoAssetResolver; unregistered/disabled -> ErrAssetNotAdmitted; no live code ->
	// ErrAssetNotOnChain). The check is pure and runs before any state write.
	if err := admitMarketAssets(state, stateDB, key); err != nil {
		return nil, gasLeft, err
	}

	// --- Best-effort D-Chain OpenMarket on a build-path proposer ONLY. The tick D
	// returns is DISCARDED (logged) — C already computed the authoritative tick. A
	// non-D validator skips this entirely and writes the same record. NEVER let a D
	// failure fail the C registration: the market is C-authoritative.
	bestEffortOpenMarketOnLocalD(poolID, key)

	// --- Write the C-authoritative record (fine-grained slots; no hot write).
	rec := MarketRecord{
		Status:       MarketStatusActive,
		SqrtPriceX96: sqrtPriceX96,
		Tick:         tick,
		Currency0:    key.Currency0.Address,
		Currency1:    key.Currency1.Address,
		Fee:          key.Fee,
		TickSpacing:  key.TickSpacing,
		Creator:      caller,
	}
	storeMarket(stateDB, poolID, rec)

	// --- Emit the canonical V4 Initialize log so the off-chain graph learns the
	// pair + fee tier (handleInitializeV4 reads poolId/currency0/currency1/fee and
	// creates the DEX Market entity). Without this log a native market is invisible
	// to eth_getLogs and the graph degrades to a poolID-only stub. It is the SAME
	// event signature a vanilla V4 PoolManager emits (topic
	// keccak256("Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)")),
	// so the indexer needs no new handler. Gated on the SAME dated fork as 0x9999
	// dispatch (defense in depth — see dexLogsActive): a consensus-visible log MUST
	// NOT enter a receipt root before activation. The state write above is the
	// authoritative registry (C is source of truth); the log is the indexable mirror.
	if dexLogsActive(state.GetBlockContext().Timestamp()) {
		emitInitializeEvent(stateDB, poolManagerAddr9999, poolID, key, sqrtPriceX96, tick)
	}

	// V4 initialize returns the int24 tick (ABI: int24, sign-extended to a word).
	return encodeInt24Word(tick), gasLeft, nil
}

// admitMarketAssets runs the value-path real-asset admission on BOTH of a market's
// currencies — the SAME two orthogonal gates the swap path's OpenMarketChecked runs,
// in the SAME order (resolve base -> resolve quote -> verify base -> verify quote),
// BEFORE any state write — so an initialize over a fabricated/unregistered/disabled or
// code-less asset is REFUSED with the identical fail-closed errors a swap would raise.
// It performs NO state mutation: it is a pure admission check (it does not bind the
// dexcore book; initialize writes only the C MarketRecord), so a refused initialize
// leaves C untouched.
//
// Identity discipline (mirrors swap_sync.runSyncSwap exactly): the runtime
// (networkID, cChainID) come from the consensus-supplied AtomicState capability, and
// resolverForRuntime cross-checks the installed resolver's bound identity against them
// (fail-closed on mismatch). A node with no resolver installed yields a nil resolver,
// which RequireEnabledAsset turns into ErrNoAssetResolver — initialize fails closed,
// never admitting a left-padded address as a real asset.
func admitMarketAssets(state contract.AccessibleState, stateDB StateDB, key PoolKey) error {
	atomicState, ok := state.(contract.AtomicState)
	if !ok {
		return ErrSettleNoAtomicState
	}
	resolver, err := resolverForRuntime(atomicState.NetworkID(), atomicState.CChainID())
	if err != nil {
		return err
	}
	verifier := onChainVerifierFor(stateDB)

	base := assetSideForCurrency(key.Currency0)
	quote := assetSideForCurrency(key.Currency1)

	// (1) Registry admission (registered + enabled) for both sides.
	if _, _, err := dexcore.RequireEnabledAsset(resolver, base.Kind, base.Ref); err != nil {
		return err
	}
	if _, _, err := dexcore.RequireEnabledAsset(resolver, quote.Kind, quote.Ref); err != nil {
		return err
	}
	// (2) Live on-chain reality (contract code present) for both sides.
	if err := dexcore.RequireRealOnChain(verifier, base.Kind, base.Ref); err != nil {
		return err
	}
	if err := dexcore.RequireRealOnChain(verifier, quote.Kind, quote.Ref); err != nil {
		return err
	}
	return nil
}

// currenciesSorted reports whether c0 < c1 by address bytes (the V4 PoolKey
// ordering invariant). Native (0x0) sorts first. This is the package-level twin of
// PoolManager.areCurrenciesSorted, lifted to a free function so the settle module
// does not reach into a PoolManager value it does not own.
func currenciesSorted(c0, c1 Currency) bool {
	return new(big.Int).SetBytes(c0.Address.Bytes()).Cmp(new(big.Int).SetBytes(c1.Address.Bytes())) < 0
}

// encodeInt24Word encodes a signed int24 tick as a 32-byte ABI word (two's
// complement, sign-extended). V4 initialize returns int24.
func encodeInt24Word(tick int24) []byte {
	out := make([]byte, 32)
	v := big.NewInt(int64(tick))
	if v.Sign() < 0 {
		v = new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 256), v)
	}
	v.FillBytes(out)
	return out
}

// bestEffortOpenMarketOnLocalD opens the market on the node-LOCAL D-Chain when an
// engine that carries a custody/market ledger is installed (a build-path proposer
// node). It is FIRE-AND-FORGET: any returned tick is DISCARDED and any error is
// logged, NEVER propagated — the C registry is authoritative and must produce a
// byte-identical write on a node that has no D-Chain at all. This is the ONLY place
// the initialize path touches D, and it touches it only off the consensus-critical
// computation.
func bestEffortOpenMarketOnLocalD(poolID [32]byte, key PoolKey) {
	pm := DEXPrecompile.poolManager
	if pm == nil || pm.engine == nil {
		return
	}
	custody, ok := pm.engine.(custodyEngine)
	if !ok {
		return // a non-custody engine (the default dchainUnavailable) has no market to open.
	}
	if err := custody.OpenMarket(poolID, key.Currency0, key.Currency1); err != nil {
		// Logged-only: the D book simply will not know the pair until a later op;
		// the C-authoritative registry is unaffected. Stderr is the lifecycle sink.
		fmt.Fprintf(os.Stderr, "dex: 0x9999 best-effort D OpenMarket failed (non-fatal, market is C-authoritative): %v\n", err)
	}
}

// MarketExists reports whether a market is registered for key. Read-only helper
// shared by StateView/PositionManager so "is this a real pool" is answered one way.
func MarketExists(stateDB stateKV, key PoolKey) bool {
	return loadMarket(stateDB, key.ID()).Status == MarketStatusActive
}

// ensure uint256 import is used (range checks on price are big.Int; the import is
// retained for symmetry with sibling files that uint256-convert — guard with a
// no-op so a future refactor that needs it does not re-add the import churn).
var _ = uint256.NewInt
