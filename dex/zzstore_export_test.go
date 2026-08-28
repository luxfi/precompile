// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/geth/common"
)

// zzstore_export_test.go covers state_export.go — the snapshot serializer. A
// snapshot is how a node's DEX state leaves the process and comes back, so the
// properties are the serializer properties:
//
//   - export -> import -> export is the identity, field for field, including zero,
//     negative and 256-bit-wide values;
//   - export is DETERMINISTIC: the same PoolManager encodes byte-identically every
//     time, even though the state it reads lives in Go MAPS whose range order the
//     runtime randomises on every iteration;
//   - a truncated or corrupt snapshot is REFUSED, never half-applied;
//   - a failed import leaves the previous state untouched.

// =========================================================================
// Fixtures
// =========================================================================

// zzstBigs are the values a money serializer has to survive: zero, one, the
// boundaries of the widths the DEX uses (uint128/uint160/uint256), and a value
// with a long decimal expansion that a lazy encoder would round.
func zzstBigs() []*big.Int {
	pow := func(n uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), n) }
	return []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(-1),
		big.NewInt(4295128739), // MIN_SQRT_RATIO
		new(big.Int).Sub(pow(64), big.NewInt(1)),
		pow(96),
		new(big.Int).Sub(pow(128), big.NewInt(1)),
		new(big.Int).Sub(pow(160), big.NewInt(1)),
		new(big.Int).Sub(pow(256), big.NewInt(1)),
		new(big.Int).Neg(new(big.Int).Sub(pow(255), big.NewInt(1))),
	}
}

// zzstPoolStateFixture builds a PoolState dense enough that a map-ordered encoder
// cannot pass by luck: 40 positions, 40 ticks and 40 bitmap words, with the
// extreme big.Int values threaded through every numeric field.
func zzstPoolStateFixture(rng *rand.Rand, nPos, nTicks, nWords int) *PoolState {
	bigs := zzstBigs()
	pick := func(i int) *big.Int { return new(big.Int).Set(bigs[i%len(bigs)]) }

	ps := &PoolState{
		Pool: &Pool{
			SqrtPriceX96:   pick(3),
			Tick:           -887272, // MIN_TICK — a negative tick must survive
			Liquidity:      pick(6),
			FeeGrowth0X128: pick(8),
			FeeGrowth1X128: pick(7),
			ProtocolFees0:  pick(1),
			ProtocolFees1:  pick(4),
		},
		Ticks:       map[int32]*TickInfo{},
		TickBitmap:  NewTickBitmap(),
		Positions:   map[[32]byte]*Position{},
		TickSpacing: -60, // negative spacing: the sign must not be dropped
		LPFee:       3000,
		ProtocolFee: 1 << 20,
	}

	for i := 0; i < nPos; i++ {
		var k [32]byte
		for j := range k {
			k[j] = byte(rng.Intn(256))
		}
		ps.Positions[k] = &Position{
			Owner:                    common.BytesToAddress([]byte{byte(i), 0xAB, byte(i * 7)}),
			TickLower:                int32(-887272 + i),
			TickUpper:                int32(887272 - i),
			Liquidity:                pick(i),
			FeeGrowthInside0LastX128: pick(i + 1),
			FeeGrowthInside1LastX128: pick(i + 2),
			TokensOwed0:              pick(i + 3),
			TokensOwed1:              pick(i + 4),
		}
	}
	for i := 0; i < nTicks; i++ {
		idx := int32(i*13) - int32(nTicks*6) // straddles zero
		ps.Ticks[idx] = &TickInfo{
			LiquidityGross:        pick(i),
			LiquidityNet:          pick(i + 2), // includes negatives
			FeeGrowthOutside0X128: pick(i + 5),
			FeeGrowthOutside1X128: pick(i + 8),
		}
	}
	for i := 0; i < nWords; i++ {
		w := int16(i*7) - int16(nWords*3)
		ps.TickBitmap.Words[w] = pick(i + 6)
	}
	return ps
}

// zzstManagerFixture builds a PoolManager holding n dense pools.
func zzstManagerFixture(rng *rand.Rand, n int) *PoolManager {
	pm := NewPoolManager(newDChainUnavailable())
	for i := 0; i < n; i++ {
		var id [32]byte
		for j := range id {
			id[j] = byte(rng.Intn(256))
		}
		ps := zzstPoolStateFixture(rng, 6, 6, 6)
		pm.poolStates[id] = ps
		pm.pools[id] = ps.Pool
	}
	return pm
}

// =========================================================================
// 1. Round-trip exactness
// =========================================================================

// The whole point of a snapshot: export, import into a fresh manager, export
// again, and the two encodings must be byte-identical. Every field of every pool,
// position, tick and bitmap word rides on this.
func TestZzstExportImportIsTheIdentity(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 10))
	pm := zzstManagerFixture(rng, 5)

	first, err := pm.ExportState(nil)
	if err != nil {
		t.Fatalf("ExportState: %v", err)
	}
	if len(first.Pools) != 5 {
		t.Fatalf("exported %d pools, want 5", len(first.Pools))
	}

	restored := NewPoolManager(newDChainUnavailable())
	if err := restored.ImportState(nil, first); err != nil {
		t.Fatalf("ImportState: %v", err)
	}
	second, err := restored.ExportState(nil)
	if err != nil {
		t.Fatalf("re-ExportState: %v", err)
	}

	wantJSON, _ := json.Marshal(first.Pools)
	gotJSON, _ := json.Marshal(second.Pools)
	if string(wantJSON) != string(gotJSON) {
		t.Fatalf("export -> import -> export is lossy:\n want %s\n  got %s", wantJSON, gotJSON)
	}

	// And the in-memory maps must agree, not just their encodings.
	if len(restored.pools) != len(pm.pools) || len(restored.poolStates) != len(pm.poolStates) {
		t.Fatalf("import rebuilt %d/%d pools, want %d/%d",
			len(restored.pools), len(restored.poolStates), len(pm.pools), len(pm.poolStates))
	}
	var wantPositions int
	for _, ps := range pm.poolStates {
		wantPositions += len(ps.Positions)
	}
	if len(restored.positions) != wantPositions {
		t.Fatalf("import rebuilt %d positions, want %d", len(restored.positions), wantPositions)
	}
}

// Field-by-field, on a single pool, so a failure names the field that moved.
func TestZzstExportPreservesEveryField(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 11))
	ps := zzstPoolStateFixture(rng, 3, 3, 3)
	var poolID [32]byte
	poolID[0], poolID[31] = 0xAB, 0xCD

	snap := exportPoolState(poolID, ps)

	if snap.PoolID != fmt.Sprintf("%x", poolID) {
		t.Fatalf("PoolID = %q", snap.PoolID)
	}
	if snap.Tick != ps.Tick {
		t.Fatalf("Tick = %d, want %d", snap.Tick, ps.Tick)
	}
	if snap.TickSpacing != ps.TickSpacing {
		t.Fatalf("TickSpacing = %d, want %d (a negative spacing must survive)", snap.TickSpacing, ps.TickSpacing)
	}
	if snap.LPFee != ps.LPFee || snap.ProtocolFee != ps.ProtocolFee {
		t.Fatalf("fees = (%d, %d), want (%d, %d)", snap.LPFee, snap.ProtocolFee, ps.LPFee, ps.ProtocolFee)
	}
	for name, pair := range map[string][2]string{
		"SqrtPriceX96":   {snap.SqrtPriceX96, ps.SqrtPriceX96.String()},
		"Liquidity":      {snap.Liquidity, ps.Liquidity.String()},
		"FeeGrowth0X128": {snap.FeeGrowth0X128, ps.FeeGrowth0X128.String()},
		"FeeGrowth1X128": {snap.FeeGrowth1X128, ps.FeeGrowth1X128.String()},
		"ProtocolFees0":  {snap.ProtocolFees0, ps.ProtocolFees0.String()},
		"ProtocolFees1":  {snap.ProtocolFees1, ps.ProtocolFees1.String()},
	} {
		if pair[0] != pair[1] {
			t.Fatalf("%s = %q, want %q", name, pair[0], pair[1])
		}
	}

	if len(snap.Positions) != 3 || len(snap.Ticks) != 3 || len(snap.BitmapWords) != 3 {
		t.Fatalf("counts = (%d pos, %d ticks, %d words), want 3/3/3",
			len(snap.Positions), len(snap.Ticks), len(snap.BitmapWords))
	}

	// Re-import and compare every leaf against the original object.
	_, back, positions, err := importPoolSnapshot(snap)
	if err != nil {
		t.Fatalf("importPoolSnapshot: %v", err)
	}
	if back.Tick != ps.Tick || back.TickSpacing != ps.TickSpacing ||
		back.LPFee != ps.LPFee || back.ProtocolFee != ps.ProtocolFee {
		t.Fatalf("scalar fields moved across the round trip")
	}
	if back.SqrtPriceX96.Cmp(ps.SqrtPriceX96) != 0 || back.Liquidity.Cmp(ps.Liquidity) != 0 ||
		back.FeeGrowth0X128.Cmp(ps.FeeGrowth0X128) != 0 || back.FeeGrowth1X128.Cmp(ps.FeeGrowth1X128) != 0 ||
		back.ProtocolFees0.Cmp(ps.ProtocolFees0) != 0 || back.ProtocolFees1.Cmp(ps.ProtocolFees1) != 0 {
		t.Fatalf("a 256-bit pool value did not survive the round trip")
	}
	if len(positions) != len(ps.Positions) {
		t.Fatalf("imported %d positions, want %d", len(positions), len(ps.Positions))
	}
	for k, want := range ps.Positions {
		got, ok := positions[k]
		if !ok {
			t.Fatalf("position %x was lost", k[:4])
		}
		if got.Owner != want.Owner || got.TickLower != want.TickLower || got.TickUpper != want.TickUpper {
			t.Fatalf("position %x header moved: %+v vs %+v", k[:4], got, want)
		}
		for name, pair := range map[string][2]*big.Int{
			"Liquidity":   {got.Liquidity, want.Liquidity},
			"FeeInside0":  {got.FeeGrowthInside0LastX128, want.FeeGrowthInside0LastX128},
			"FeeInside1":  {got.FeeGrowthInside1LastX128, want.FeeGrowthInside1LastX128},
			"TokensOwed0": {got.TokensOwed0, want.TokensOwed0},
			"TokensOwed1": {got.TokensOwed1, want.TokensOwed1},
		} {
			if pair[0].Cmp(pair[1]) != 0 {
				t.Fatalf("position %x %s = %s, want %s", k[:4], name, pair[0], pair[1])
			}
		}
	}
	for idx, want := range ps.Ticks {
		got, ok := back.Ticks[idx]
		if !ok {
			t.Fatalf("tick %d was lost", idx)
		}
		if got.LiquidityGross.Cmp(want.LiquidityGross) != 0 || got.LiquidityNet.Cmp(want.LiquidityNet) != 0 ||
			got.FeeGrowthOutside0X128.Cmp(want.FeeGrowthOutside0X128) != 0 ||
			got.FeeGrowthOutside1X128.Cmp(want.FeeGrowthOutside1X128) != 0 {
			t.Fatalf("tick %d values moved", idx)
		}
	}
	for w, want := range ps.TickBitmap.Words {
		got, ok := back.TickBitmap.Words[w]
		if !ok {
			t.Fatalf("bitmap word %d was lost", w)
		}
		if got.Cmp(want) != 0 {
			t.Fatalf("bitmap word %d = %s, want %s", w, got, want)
		}
	}
}

// A pool with no positions, no ticks and no bitmap must round-trip as empty, not
// as nil-vs-empty confusion or a spurious zero row.
func TestZzstExportEmptyCollectionsRoundTrip(t *testing.T) {
	ps := &PoolState{
		Pool:       &Pool{SqrtPriceX96: big.NewInt(1), Liquidity: big.NewInt(0)},
		Ticks:      map[int32]*TickInfo{},
		TickBitmap: NewTickBitmap(),
		Positions:  map[[32]byte]*Position{},
	}
	snap := exportPoolState([32]byte{0x01}, ps)
	if len(snap.Positions) != 0 || len(snap.Ticks) != 0 || len(snap.BitmapWords) != 0 {
		t.Fatalf("empty pool exported %d/%d/%d rows", len(snap.Positions), len(snap.Ticks), len(snap.BitmapWords))
	}
	_, back, positions, err := importPoolSnapshot(snap)
	if err != nil {
		t.Fatalf("importPoolSnapshot: %v", err)
	}
	if len(back.Positions) != 0 || len(back.Ticks) != 0 || len(back.TickBitmap.Words) != 0 || len(positions) != 0 {
		t.Fatalf("empty collections did not round-trip empty")
	}

	// A nil TickBitmap is the other empty: export must skip it rather than deref.
	ps.TickBitmap = nil
	snap = exportPoolState([32]byte{0x02}, ps)
	if snap.BitmapWords != nil {
		t.Fatalf("a nil TickBitmap exported %d words", len(snap.BitmapWords))
	}
}

// Nil *big.Int fields (an under-initialised pool) must encode as "0" and decode
// back to zero, never as an empty string that later parses as garbage.
func TestZzstBigIntStringRoundTrip(t *testing.T) {
	if got := bigIntToStr(nil); got != "0" {
		t.Fatalf("bigIntToStr(nil) = %q, want \"0\"", got)
	}
	for _, v := range zzstBigs() {
		s := bigIntToStr(v)
		back := strToBigInt(s)
		if back.Cmp(v) != 0 {
			t.Fatalf("%s round-tripped to %s via %q", v, back, s)
		}
	}
	// The refusal side: anything unparseable becomes zero rather than a panic or a
	// silently truncated value.
	for _, s := range []string{"", "0", "  ", "0x10", "1e9", "not a number", "12345678901234567890abc", "-"} {
		got := strToBigInt(s)
		if got == nil {
			t.Fatalf("strToBigInt(%q) = nil", s)
		}
		if s != "0" && s != "" && got.Sign() != 0 {
			t.Fatalf("strToBigInt(%q) = %s, want 0 for an unparseable value", s, got)
		}
	}
}

// =========================================================================
// 2. Determinism — the map-iteration fork hunt
// =========================================================================

// Go randomises map range order on EVERY iteration. exportPoolState reads three
// maps (positions, ticks, bitmap words) and ExportState reads a fourth (pools).
// Encode the same manager 64 times: if any of those four sorts were dropped, two
// nodes taking a snapshot of identical state would produce different bytes.
func TestZzstExportIsByteIdenticalAcrossRepeats(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 12))
	pm := zzstManagerFixture(rng, 8)
	for _, ps := range pm.poolStates {
		// Widen each pool so a shuffled map order is essentially certain to show.
		dense := zzstPoolStateFixture(rng, 40, 40, 40)
		ps.Positions, ps.Ticks, ps.TickBitmap = dense.Positions, dense.Ticks, dense.TickBitmap
	}

	var want string
	for i := 0; i < 64; i++ {
		snap, err := pm.ExportState(nil)
		if err != nil {
			t.Fatalf("ExportState: %v", err)
		}
		b, err := json.Marshal(snap.Pools)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if i == 0 {
			want = string(b)
			continue
		}
		if string(b) != want {
			t.Fatalf("ExportState produced different bytes on repeat %d — a map is being "+
				"encoded in range order, which forks the snapshot between nodes", i)
		}
	}
}

// The same property one level down, on the single-pool encoder, so a failure says
// which encoder lost its ordering.
func TestZzstExportPoolStateIsSorted(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 13))
	ps := zzstPoolStateFixture(rng, 40, 40, 40)

	var want string
	for i := 0; i < 64; i++ {
		snap := exportPoolState([32]byte{0x5A}, ps)
		for j := 1; j < len(snap.Positions); j++ {
			if snap.Positions[j-1].PositionID >= snap.Positions[j].PositionID {
				t.Fatalf("positions are not sorted at %d", j)
			}
		}
		for j := 1; j < len(snap.Ticks); j++ {
			if snap.Ticks[j-1].Index >= snap.Ticks[j].Index {
				t.Fatalf("ticks are not sorted at %d", j)
			}
		}
		for j := 1; j < len(snap.BitmapWords); j++ {
			if snap.BitmapWords[j-1].WordIndex >= snap.BitmapWords[j].WordIndex {
				t.Fatalf("bitmap words are not sorted at %d", j)
			}
		}
		b, _ := json.Marshal(snap)
		if i == 0 {
			want = string(b)
			continue
		}
		if string(b) != want {
			t.Fatalf("exportPoolState is not deterministic (repeat %d)", i)
		}
	}
}

func TestZzstExportStatePoolsAreSortedById(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 14))
	pm := zzstManagerFixture(rng, 24)
	snap, err := pm.ExportState(nil)
	if err != nil {
		t.Fatalf("ExportState: %v", err)
	}
	for i := 1; i < len(snap.Pools); i++ {
		if snap.Pools[i-1].PoolID >= snap.Pools[i].PoolID {
			t.Fatalf("pools are not sorted by id at %d", i)
		}
	}
}

// ExportState stamps the version and reads the block number off the state, so a
// snapshot names the height it belongs to.
func TestZzstExportStateHeader(t *testing.T) {
	pm := NewPoolManager(newDChainUnavailable())
	sdb := NewMockStateDB()
	sdb.SetBlockNumber(123456)

	snap, err := pm.ExportState(sdb)
	if err != nil {
		t.Fatalf("ExportState: %v", err)
	}
	if snap.Version != SnapshotVersion {
		t.Fatalf("Version = %d, want %d", snap.Version, SnapshotVersion)
	}
	if snap.BlockNum != 123456 {
		t.Fatalf("BlockNum = %d, want 123456", snap.BlockNum)
	}
	if snap.Timestamp == 0 {
		t.Fatalf("Timestamp = 0")
	}
	if len(snap.Pools) != 0 {
		t.Fatalf("empty manager exported %d pools", len(snap.Pools))
	}

	// With no state to read, the height is simply absent rather than guessed.
	noState, err := pm.ExportState(nil)
	if err != nil {
		t.Fatalf("ExportState(nil): %v", err)
	}
	if noState.BlockNum != 0 {
		t.Fatalf("BlockNum without a StateDB = %d, want 0", noState.BlockNum)
	}
}

// =========================================================================
// 3. Refusal — version, truncation, corruption
// =========================================================================

func TestZzstImportRefusesEveryOtherVersion(t *testing.T) {
	pm := NewPoolManager(newDChainUnavailable())
	for _, v := range []uint32{0, SnapshotVersion - 1, SnapshotVersion + 1, 1 << 31, ^uint32(0)} {
		err := pm.ImportState(nil, &DEXStateSnapshot{Version: v})
		if !errors.Is(err, ErrVersionMismatch) {
			t.Fatalf("ImportState(version %d) = %v, want ErrVersionMismatch", v, err)
		}
	}
}

// Every proper prefix of a marshalled snapshot must fail to decode. A serializer
// that accepts a truncated snapshot imports a state nobody produced.
func TestZzstSnapshotRefusesEveryTruncation(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 15))
	pm := zzstManagerFixture(rng, 3)
	snap, err := pm.ExportState(nil)
	if err != nil {
		t.Fatalf("ExportState: %v", err)
	}
	full, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	for n := 0; n < len(full); n++ {
		var got DEXStateSnapshot
		if err := json.Unmarshal(full[:n], &got); err == nil {
			t.Fatalf("a %d-byte truncation of a %d-byte snapshot decoded successfully", n, len(full))
		}
	}
	var round DEXStateSnapshot
	if err := json.Unmarshal(full, &round); err != nil {
		t.Fatalf("the untruncated snapshot failed to decode: %v", err)
	}
	restored := NewPoolManager(newDChainUnavailable())
	if err := restored.ImportState(nil, &round); err != nil {
		t.Fatalf("ImportState of the round-tripped snapshot: %v", err)
	}
	again, err := restored.ExportState(nil)
	if err != nil {
		t.Fatalf("re-export: %v", err)
	}
	a, _ := json.Marshal(snap.Pools)
	b, _ := json.Marshal(again.Pools)
	if string(a) != string(b) {
		t.Fatalf("JSON round trip through the wire format is lossy")
	}
}

// A pool whose id cannot be read is refused, and the refusal names it.
func TestZzstImportRefusesUnreadablePoolID(t *testing.T) {
	pm := NewPoolManager(newDChainUnavailable())
	for _, id := range []string{"", "zz", "0x", "abcd", "not-hex-at-all", fmt.Sprintf("%x", make([]byte, 33))} {
		snap := &DEXStateSnapshot{
			Version: SnapshotVersion,
			Pools:   []PoolSnapshot{{PoolID: id, SqrtPriceX96: "1"}},
		}
		err := pm.ImportState(nil, snap)
		if !errors.Is(err, ErrImportFailed) {
			t.Fatalf("ImportState(pool id %q) = %v, want ErrImportFailed", id, err)
		}
	}
	// A well-formed id is accepted in both spellings the encoder and the wire use.
	want := fmt.Sprintf("%x", [32]byte{0xAA, 0xBB})
	for _, id := range []string{want, "0x" + want} {
		got, _, _, err := importPoolSnapshot(PoolSnapshot{PoolID: id, SqrtPriceX96: "1"})
		if err != nil {
			t.Fatalf("importPoolSnapshot(%q): %v", id, err)
		}
		if got[0] != 0xAA || got[1] != 0xBB {
			t.Fatalf("pool id %q decoded to %x", id, got[:4])
		}
	}
}

// A failed import must leave the manager exactly as it was. Half a snapshot is a
// state nobody agreed on.
func TestZzstImportIsAllOrNothing(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 16))
	pm := zzstManagerFixture(rng, 3)
	before, err := pm.ExportState(nil)
	if err != nil {
		t.Fatalf("ExportState: %v", err)
	}
	beforeJSON, _ := json.Marshal(before.Pools)
	beforePools := len(pm.pools)

	// Good pool first, bad pool second: the good one must NOT survive.
	good := before.Pools[0]
	bad := PoolSnapshot{PoolID: "nonsense", SqrtPriceX96: "1"}
	err = pm.ImportState(nil, &DEXStateSnapshot{
		Version: SnapshotVersion,
		Pools:   []PoolSnapshot{good, bad},
	})
	if !errors.Is(err, ErrImportFailed) {
		t.Fatalf("ImportState = %v, want ErrImportFailed", err)
	}
	if len(pm.pools) != beforePools {
		t.Fatalf("a refused import replaced state: %d pools, want %d", len(pm.pools), beforePools)
	}
	after, _ := pm.ExportState(nil)
	afterJSON, _ := json.Marshal(after.Pools)
	if string(afterJSON) != string(beforeJSON) {
		t.Fatalf("a refused import mutated the manager's state")
	}
}

// Import with a StateDB persists what it rebuilt, so the EVM trie and the
// in-memory manager do not disagree after a restore.
func TestZzstImportPersistsToStateDB(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 17))
	src := zzstManagerFixture(rng, 2)
	snap, err := src.ExportState(nil)
	if err != nil {
		t.Fatalf("ExportState: %v", err)
	}

	sdb := NewMockStateDB()
	dst := NewPoolManager(newDChainUnavailable())
	if err := dst.ImportState(sdb, snap); err != nil {
		t.Fatalf("ImportState: %v", err)
	}
	if len(sdb.states[poolManagerAddr]) == 0 {
		t.Fatalf("ImportState with a StateDB wrote no storage")
	}

	// Persisting is deterministic: the same snapshot into two fresh states must
	// produce identical storage, even though the persist loops range over maps.
	fingerprint := func(m *MockStateDB) string {
		lines := make([]string, 0, len(m.states[poolManagerAddr]))
		for k, v := range m.states[poolManagerAddr] {
			lines = append(lines, k.Hex()+"="+v.Hex())
		}
		return zzstSortedJoin(lines)
	}
	want := fingerprint(sdb)
	for i := 0; i < 16; i++ {
		other := NewMockStateDB()
		again := NewPoolManager(newDChainUnavailable())
		if err := again.ImportState(other, snap); err != nil {
			t.Fatalf("ImportState repeat %d: %v", i, err)
		}
		if fingerprint(other) != want {
			t.Fatalf("ImportState repeat %d wrote different storage — the persist loops "+
				"depend on Go map order", i)
		}
	}
}

// =========================================================================
// 4. ExportPoolState — the single-pool surface
// =========================================================================

func TestZzstExportPoolStateFoundMissingUninitialised(t *testing.T) {
	pm := NewPoolManager(newDChainUnavailable())
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x01")},
		Currency1:   Currency{Address: common.HexToAddress("0x02")},
		Fee:         3000,
		TickSpacing: 60,
	}

	if _, err := pm.ExportPoolState(nil, key); !errors.Is(err, ErrPoolNotFound) {
		t.Fatalf("unknown pool = %v, want ErrPoolNotFound", err)
	}

	// Present but never initialised (sqrtPrice zero) is a distinct refusal — an
	// exported uninitialised pool would import as a live market at price zero.
	id := key.ID()
	pm.poolStates[id] = &PoolState{
		Pool:       &Pool{SqrtPriceX96: big.NewInt(0), Liquidity: big.NewInt(0)},
		Ticks:      map[int32]*TickInfo{},
		TickBitmap: NewTickBitmap(),
		Positions:  map[[32]byte]*Position{},
	}
	if _, err := pm.ExportPoolState(nil, key); !errors.Is(err, ErrPoolNotInitialized) {
		t.Fatalf("uninitialised pool = %v, want ErrPoolNotInitialized", err)
	}

	pm.poolStates[id].Pool.SqrtPriceX96 = new(big.Int).Lsh(big.NewInt(1), 96) // 2^96, which does not fit an int64
	got, err := pm.ExportPoolState(nil, key)
	if err != nil {
		t.Fatalf("initialised pool: %v", err)
	}
	if got.PoolID != fmt.Sprintf("%x", id) {
		t.Fatalf("PoolID = %q, want %x", got.PoolID, id)
	}
	if got.SqrtPriceX96 != "79228162514264337593543950336" {
		t.Fatalf("SqrtPriceX96 = %q", got.SqrtPriceX96)
	}
}

// =========================================================================
// 5. The ZapDB surface
// =========================================================================

func TestZzstZapDBRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 18))
	pm := zzstManagerFixture(rng, 4)
	snap, err := pm.ExportState(nil)
	if err != nil {
		t.Fatalf("ExportState: %v", err)
	}

	db := memdb.New()
	if err := WriteToZapDB(db, snap); err != nil {
		t.Fatalf("WriteToZapDB: %v", err)
	}
	back, err := ReadFromZapDB(db)
	if err != nil {
		t.Fatalf("ReadFromZapDB: %v", err)
	}
	if back.Version != snap.Version || back.Timestamp != snap.Timestamp || back.BlockNum != snap.BlockNum {
		t.Fatalf("header did not round-trip: %+v vs %+v", back, snap)
	}
	a, _ := json.Marshal(snap.Pools)
	b, _ := json.Marshal(back.Pools)
	if string(a) != string(b) {
		t.Fatalf("pools did not round-trip through the database:\n want %s\n  got %s", a, b)
	}

	// The per-tick and per-bitmap rows the writer emits must be there and must be
	// addressable by their own keys.
	for _, p := range snap.Pools {
		for _, tick := range p.Ticks {
			if _, err := db.Get(makeTickDBKey([]byte(p.PoolID), tick.Index)); err != nil {
				t.Fatalf("tick row %d of pool %s is missing: %v", tick.Index, p.PoolID, err)
			}
		}
		for _, bw := range p.BitmapWords {
			if _, err := db.Get(makeBitmapDBKey([]byte(p.PoolID), bw.WordIndex)); err != nil {
				t.Fatalf("bitmap row %d of pool %s is missing: %v", bw.WordIndex, p.PoolID, err)
			}
		}
		for _, pos := range p.Positions {
			key := append(append([]byte(nil), dbPrefixPosition...), []byte(p.PoolID+":"+pos.PositionID)...)
			if _, err := db.Get(key); err != nil {
				t.Fatalf("position row %s of pool %s is missing: %v", pos.PositionID, p.PoolID, err)
			}
		}
	}
}

// Writing the same snapshot twice must land the same bytes at the same keys.
func TestZzstZapDBWriteIsDeterministic(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 19))
	pm := zzstManagerFixture(rng, 3)
	snap, err := pm.ExportState(nil)
	if err != nil {
		t.Fatalf("ExportState: %v", err)
	}

	dump := func() string {
		db := memdb.New()
		if err := WriteToZapDB(db, snap); err != nil {
			t.Fatalf("WriteToZapDB: %v", err)
		}
		it := db.NewIterator()
		defer it.Release()
		var lines []string
		for it.Next() {
			lines = append(lines, fmt.Sprintf("%x=%x", it.Key(), it.Value()))
		}
		return zzstSortedJoin(lines)
	}
	want := dump()
	for i := 0; i < 16; i++ {
		if got := dump(); got != want {
			t.Fatalf("WriteToZapDB repeat %d produced different rows", i)
		}
	}
}

func TestZzstReadFromZapDBRefusesMissingCorruptAndWrongVersion(t *testing.T) {
	metaKey := append(append([]byte(nil), dbPrefixMeta...), []byte("snapshot")...)

	// No metadata at all.
	if _, err := ReadFromZapDB(memdb.New()); err == nil {
		t.Fatalf("ReadFromZapDB of an empty database succeeded")
	}

	// Corrupt metadata: every proper prefix of the real metadata JSON.
	rng := rand.New(rand.NewSource(zzstSeed + 20))
	pm := zzstManagerFixture(rng, 2)
	snap, err := pm.ExportState(nil)
	if err != nil {
		t.Fatalf("ExportState: %v", err)
	}
	full := memdb.New()
	if err := WriteToZapDB(full, snap); err != nil {
		t.Fatalf("WriteToZapDB: %v", err)
	}
	metaBytes, err := full.Get(metaKey)
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	for n := 0; n < len(metaBytes); n++ {
		db := memdb.New()
		if err := db.Put(metaKey, metaBytes[:n]); err != nil {
			t.Fatalf("put: %v", err)
		}
		if _, err := ReadFromZapDB(db); err == nil {
			t.Fatalf("ReadFromZapDB accepted a %d-byte truncation of the metadata", n)
		}
	}

	// Version mismatch is its own, named refusal.
	for _, v := range []uint32{0, SnapshotVersion + 1, ^uint32(0)} {
		db := memdb.New()
		bad, _ := json.Marshal(map[string]any{"version": v, "timestamp": 1, "blockNum": 2, "poolCount": 0})
		if err := db.Put(metaKey, bad); err != nil {
			t.Fatalf("put: %v", err)
		}
		if _, err := ReadFromZapDB(db); !errors.Is(err, ErrVersionMismatch) {
			t.Fatalf("version %d = %v, want ErrVersionMismatch", v, err)
		}
	}

	// A corrupt pool row must fail the whole read, not yield a partial snapshot.
	db := memdb.New()
	if err := db.Put(metaKey, metaBytes); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := db.Put(append(append([]byte(nil), dbPrefixPool...), []byte("deadbeef")...), []byte("{not json")); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, err := ReadFromZapDB(db); err == nil {
		t.Fatalf("ReadFromZapDB accepted a corrupt pool row")
	}
}

// A database whose pool iterator fails must surface the failure, not report an
// empty snapshot — "no pools" and "could not read the pools" are different facts.
func TestZzstReadFromZapDBSurfacesIteratorError(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 21))
	pm := zzstManagerFixture(rng, 1)
	snap, _ := pm.ExportState(nil)
	inner := memdb.New()
	if err := WriteToZapDB(inner, snap); err != nil {
		t.Fatalf("WriteToZapDB: %v", err)
	}

	boom := errors.New("zzst: iterator exploded")
	got, err := ReadFromZapDB(&zzstIterErrDB{Database: inner, err: boom})
	if err == nil {
		t.Fatalf("ReadFromZapDB returned (%+v, nil) despite a failing iterator", got)
	}
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want it to wrap the iterator error", err)
	}
}

// Every batch failure the writer can meet must be returned, and each one must
// name the row it was writing.
func TestZzstWriteToZapDBSurfacesEveryBatchFailure(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 22))
	ps := zzstPoolStateFixture(rng, 1, 1, 1)
	snap := &DEXStateSnapshot{
		Version: SnapshotVersion,
		Pools:   []PoolSnapshot{exportPoolState([32]byte{0x11}, ps)},
	}

	// Put order for one pool with one position, one tick and one bitmap word.
	rows := []string{"metadata", "pool", "position", "tick", "bitmap"}
	for i, name := range rows {
		boom := fmt.Errorf("zzst: %s put failed", name)
		db := &zzstFailBatchDB{Database: memdb.New(), failPutAt: i + 1, putErr: boom}
		err := WriteToZapDB(db, snap)
		if err == nil {
			t.Fatalf("%s: WriteToZapDB succeeded despite a failing Put", name)
		}
		if !errors.Is(err, boom) {
			t.Fatalf("%s: error = %v, want it to wrap the batch failure", name, err)
		}
	}

	// And the commit itself.
	boom := errors.New("zzst: batch write failed")
	db := &zzstFailBatchDB{Database: memdb.New(), writeErr: boom}
	if err := WriteToZapDB(db, snap); !errors.Is(err, boom) {
		t.Fatalf("commit failure = %v, want the batch write error", err)
	}
}

// =========================================================================
// 6. StateExporter
// =========================================================================

func TestZzstStateExporterExportWritesAndPropagatesFailure(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 23))
	pm := zzstManagerFixture(rng, 2)
	sdb := NewMockStateDB()
	sdb.SetBlockNumber(99)

	db := memdb.New()
	se := NewStateExporter(pm, db)
	if se.pm != pm || se.db != db {
		t.Fatalf("NewStateExporter did not bind its manager and database")
	}
	if err := se.Export(sdb); err != nil {
		t.Fatalf("Export: %v", err)
	}
	back, err := ReadFromZapDB(db)
	if err != nil {
		t.Fatalf("ReadFromZapDB: %v", err)
	}
	if back.BlockNum != 99 || len(back.Pools) != 2 {
		t.Fatalf("exported snapshot = block %d, %d pools; want block 99, 2 pools", back.BlockNum, len(back.Pools))
	}

	// The exporting flag is cleared on the way out, so a second export works.
	if err := se.Export(sdb); err != nil {
		t.Fatalf("second Export: %v", err)
	}

	// A write failure is returned, and it still clears the flag.
	boom := errors.New("zzst: exporter write failed")
	failing := NewStateExporter(pm, &zzstFailBatchDB{Database: memdb.New(), writeErr: boom})
	if err := failing.Export(sdb); !errors.Is(err, boom) {
		t.Fatalf("Export over a failing database = %v, want the write error", err)
	}
	if failing.exporting {
		t.Fatalf("the exporting flag survived a failed export — every later export would be refused")
	}
}

// Two exports at once must not interleave two snapshots into one database. The
// second caller is refused by name.
func TestZzstStateExporterRefusesConcurrentExport(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 24))
	pm := zzstManagerFixture(rng, 1)

	gate := &zzstGateDB{Database: memdb.New(), entered: make(chan struct{}), release: make(chan struct{})}
	se := NewStateExporter(pm, gate)

	done := make(chan error, 1)
	go func() { done <- se.Export(nil) }()

	<-gate.entered // the first export is inside WriteToZapDB and holds the flag
	if err := se.Export(nil); !errors.Is(err, ErrExportInProgress) {
		t.Fatalf("concurrent Export = %v, want ErrExportInProgress", err)
	}
	close(gate.release)
	if err := <-done; err != nil {
		t.Fatalf("the first Export failed: %v", err)
	}

	// The flag is released, so a later export runs.
	if err := se.Export(nil); err != nil {
		t.Fatalf("Export after the concurrent one: %v", err)
	}
}

// =========================================================================
// 7. Database key derivation
// =========================================================================

// A tick key must name exactly one (pool, tick). If two ticks shared a key, a
// snapshot would silently overwrite one tick's liquidity with another's.
func TestZzstTickAndBitmapKeysAreInjective(t *testing.T) {
	pools := []string{"", "aa", "deadbeef", fmt.Sprintf("%x", [32]byte{0x01}), fmt.Sprintf("%x", [32]byte{0x02})}
	ticks := []int32{0, 1, -1, 60, -60, 887272, -887272, 1 << 30, -(1 << 30), 1<<31 - 1, -(1 << 31)}
	words := []int16{0, 1, -1, 127, -128, 1<<15 - 1, -(1 << 15)}

	seen := map[string]string{}
	for _, p := range pools {
		for _, tk := range ticks {
			k := string(makeTickDBKey([]byte(p), tk))
			ref := fmt.Sprintf("tick(pool %q, %d)", p, tk)
			if prev, dup := seen[k]; dup {
				t.Fatalf("KEY COLLISION: %s and %s", ref, prev)
			}
			seen[k] = ref
		}
		for _, w := range words {
			k := string(makeBitmapDBKey([]byte(p), w))
			ref := fmt.Sprintf("bitmap(pool %q, %d)", p, w)
			if prev, dup := seen[k]; dup {
				t.Fatalf("KEY COLLISION: %s and %s", ref, prev)
			}
			seen[k] = ref
		}
	}

	// Shape: prefix, pool id, a ':' separator, then the fixed-width index.
	k := makeTickDBKey([]byte("abcd"), 0x01020304)
	if len(k) != len(dbPrefixTick)+4+1+4 {
		t.Fatalf("tick key length = %d", len(k))
	}
	if k[len(dbPrefixTick)+4] != ':' {
		t.Fatalf("tick key is missing its separator")
	}
	if string(k[len(k)-4:]) != string([]byte{0x01, 0x02, 0x03, 0x04}) {
		t.Fatalf("tick index is not big-endian at the tail: %x", k[len(k)-4:])
	}
	b := makeBitmapDBKey([]byte("abcd"), 0x0102)
	if len(b) != len(dbPrefixBitmap)+4+1+2 {
		t.Fatalf("bitmap key length = %d", len(b))
	}
	if string(b[len(b)-2:]) != string([]byte{0x01, 0x02}) {
		t.Fatalf("bitmap index is not big-endian at the tail: %x", b[len(b)-2:])
	}
}

// DEFECT characterisation. The tick and bitmap indices are written as raw
// two's-complement (uint32(tickIndex) / uint16(wordIndex)) with no order-preserving
// bias, so in a byte-ordered database EVERY negative tick sorts ABOVE every
// positive one. The keys stay injective — nothing is lost — but the "range
// queries" the writer is built for cannot span zero. state_export.go:523 and :533
// are the two lines; a bias (index ^ 1<<31 / ^ 1<<15) is the usual fix.
func TestZzstTickKeyOrderingIsNotSignedDEFECT(t *testing.T) {
	pool := []byte("deadbeef")
	neg := string(makeTickDBKey(pool, -1))
	pos := string(makeTickDBKey(pool, 1))
	if neg <= pos {
		t.Fatalf("state_export.go:523 now orders tick -1 below tick 1 — the signed bias was "+
			"added; update this characterisation test to assert the ordering instead (neg %x, pos %x)", neg, pos)
	}
	negW := string(makeBitmapDBKey(pool, -1))
	posW := string(makeBitmapDBKey(pool, 1))
	if negW <= posW {
		t.Fatalf("state_export.go:533 now orders bitmap word -1 below word 1 — update this " +
			"characterisation test to assert the ordering instead")
	}
}

// =========================================================================
// 8. Import laxness worth knowing about
// =========================================================================

// A position id that is not 32 bytes is not refused — it lands at the ZERO key,
// so two unreadable ids collapse onto one position and the earlier one is lost
// with no error (state_export.go:462). This test states the current behaviour so
// the loss is visible; the refusal belongs at that line.
func TestZzstImportUnreadablePositionIDCollapsesDEFECT(t *testing.T) {
	snap := PoolSnapshot{
		PoolID:       fmt.Sprintf("%x", [32]byte{0x01}),
		SqrtPriceX96: "1",
		Positions: []PositionSnapshot{
			{PositionID: "short", Owner: common.HexToAddress("0x01").Hex(), Liquidity: "111"},
			{PositionID: "also-short", Owner: common.HexToAddress("0x02").Hex(), Liquidity: "222"},
		},
	}
	_, ps, positions, err := importPoolSnapshot(snap)
	if err != nil {
		t.Fatalf("importPoolSnapshot: %v", err)
	}
	if len(positions) != 1 || len(ps.Positions) != 1 {
		t.Fatalf("two unreadable position ids produced %d positions — state_export.go:462 now "+
			"refuses or disambiguates them; update this characterisation test", len(positions))
	}
	survivor, ok := positions[[32]byte{}]
	if !ok {
		t.Fatalf("the surviving position is not at the zero key")
	}
	if survivor.Liquidity.String() != "222" {
		t.Fatalf("the surviving position holds %s; the first position's 111 was overwritten silently",
			survivor.Liquidity)
	}
}

// Two pools sharing a PoolID collapse into one, silently, for the same reason:
// the import writes into a map with no duplicate check (state_export.go:169).
func TestZzstImportDuplicatePoolIDCollapsesDEFECT(t *testing.T) {
	id := fmt.Sprintf("%x", [32]byte{0xDD})
	pm := NewPoolManager(newDChainUnavailable())
	err := pm.ImportState(nil, &DEXStateSnapshot{
		Version: SnapshotVersion,
		Pools: []PoolSnapshot{
			{PoolID: id, SqrtPriceX96: "111", Liquidity: "1"},
			{PoolID: id, SqrtPriceX96: "222", Liquidity: "2"},
		},
	})
	if err != nil {
		t.Fatalf("ImportState: %v", err)
	}
	if len(pm.pools) != 1 {
		t.Fatalf("two pools with the same id produced %d pools — state_export.go:169 now refuses "+
			"duplicates; update this characterisation test", len(pm.pools))
	}
	if pm.pools[[32]byte{0xDD}].SqrtPriceX96.String() != "222" {
		t.Fatalf("the surviving pool is not the last one; the collapse rule changed")
	}
}

// The snapshot carries a PoolKeySnapshot field that the exporter never fills and
// the importer never reads, so a restored manager cannot recover any pool's
// currencies, fee, spacing or hooks — only its 32-byte id. Pinned here because a
// snapshot that looks complete and is not is the expensive kind of surprise.
func TestZzstSnapshotDoesNotCarryThePoolKeyDEFECT(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 25))
	ps := zzstPoolStateFixture(rng, 1, 1, 1)
	snap := exportPoolState([32]byte{0x07}, ps)
	if snap.Key != (PoolKeySnapshot{}) {
		t.Fatalf("exportPoolState now fills PoolSnapshot.Key (%+v) — the pool key is carried; "+
			"update this characterisation test to assert the round trip instead", snap.Key)
	}
}

// Nothing in the database contract makes a prefix iterator ascending, which is
// why ReadFromZapDB sorts what it read. Served the same rows in DESCENDING order,
// it must still hand back the same snapshot — otherwise one database decodes into
// two different snapshots on two backends.
func TestZzstReadFromZapDBNormalisesPoolOrder(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 27))
	pm := zzstManagerFixture(rng, 12)
	snap, err := pm.ExportState(nil)
	if err != nil {
		t.Fatalf("ExportState: %v", err)
	}
	inner := memdb.New()
	if err := WriteToZapDB(inner, snap); err != nil {
		t.Fatalf("WriteToZapDB: %v", err)
	}

	back, err := ReadFromZapDB(&zzstReverseIterDB{Database: inner})
	if err != nil {
		t.Fatalf("ReadFromZapDB: %v", err)
	}
	if len(back.Pools) != len(snap.Pools) {
		t.Fatalf("read %d pools, want %d", len(back.Pools), len(snap.Pools))
	}
	for i := 1; i < len(back.Pools); i++ {
		if back.Pools[i-1].PoolID >= back.Pools[i].PoolID {
			t.Fatalf("ReadFromZapDB returned pools in the backend's iteration order at %d — "+
				"one database would decode to two different snapshots on two backends", i)
		}
	}
	a, _ := json.Marshal(snap.Pools)
	b, _ := json.Marshal(back.Pools)
	if string(a) != string(b) {
		t.Fatalf("reading through a descending iterator changed the snapshot")
	}
}

// A Batch may keep the key slice it is handed. Every key here is built with
// append() on a PACKAGE-LEVEL prefix, so if a prefix ever carried spare capacity
// two keys would share one array and the second append would rewrite the first key
// in place. The prefixes have cap == len today; this states the property rather
// than the accident, so a later change to how they are built cannot bring it back.
func TestZzstWriteToZapDBKeysDoNotAlias(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 28))
	ps := zzstPoolStateFixture(rng, 3, 3, 3)
	snap := &DEXStateSnapshot{
		Version: SnapshotVersion,
		Pools:   []PoolSnapshot{exportPoolState([32]byte{0x01}, ps), exportPoolState([32]byte{0x02}, ps)},
	}
	// Short ids are the dangerous case: a short append is the one that fits in
	// spare capacity without reallocating.
	snap.Pools[0].PoolID, snap.Pools[1].PoolID = "a", "b"
	for i := range snap.Pools {
		for j := range snap.Pools[i].Positions {
			snap.Pools[i].Positions[j].PositionID = fmt.Sprintf("%d", j)
		}
	}

	rec := &zzstKeepKeyDB{Database: memdb.New()}
	if err := WriteToZapDB(rec, snap); err != nil {
		t.Fatalf("WriteToZapDB: %v", err)
	}
	if len(rec.keys) < 8 {
		t.Fatalf("recorded only %d keys", len(rec.keys))
	}
	seen := map[string]bool{}
	for i, k := range rec.keys {
		if !bytes.Equal(k.live, k.taken) {
			t.Fatalf("key %d changed after it was handed to the batch: %q became %q — "+
				"the key builders share a backing array", i, k.taken, k.live)
		}
		if seen[string(k.live)] {
			t.Fatalf("key %d (%q) was written twice in one batch", i, k.live)
		}
		seen[string(k.live)] = true
	}
}

// DEFECT characterisation. WriteToZapDB only PUTs. It never clears what an earlier
// snapshot left, and ReadFromZapDB reads every row under the pool prefix, so a
// second export over the same database yields the UNION of the two snapshots. For
// the periodic exporter that means a pool which leaves the manager never leaves the
// database, and the metadata's poolCount — which IS overwritten — then disagrees
// with the rows. state_export.go:194 has to clear its namespace, or the reader has
// to be told which generation to read.
func TestZzstZapDBSecondExportUnionsWithTheFirstDEFECT(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 29))
	ps := zzstPoolStateFixture(rng, 1, 1, 1)
	db := memdb.New()

	first := &DEXStateSnapshot{Version: SnapshotVersion, Pools: []PoolSnapshot{exportPoolState([32]byte{0x0A}, ps)}}
	if err := WriteToZapDB(db, first); err != nil {
		t.Fatalf("first WriteToZapDB: %v", err)
	}
	second := &DEXStateSnapshot{Version: SnapshotVersion, Pools: []PoolSnapshot{exportPoolState([32]byte{0x0B}, ps)}}
	if err := WriteToZapDB(db, second); err != nil {
		t.Fatalf("second WriteToZapDB: %v", err)
	}

	back, err := ReadFromZapDB(db)
	if err != nil {
		t.Fatalf("ReadFromZapDB: %v", err)
	}
	if len(back.Pools) != 2 {
		t.Fatalf("state_export.go:194 now replaces the previous snapshot (%d pools read) — "+
			"update this characterisation test to assert the replacement", len(back.Pools))
	}
	if back.Pools[0].PoolID != fmt.Sprintf("%x", [32]byte{0x0A}) {
		t.Fatalf("the first snapshot's pool is not the one that survived: %s", back.Pools[0].PoolID)
	}
}

// DEFECT characterisation. The metadata carries poolCount, but ReadFromZapDB never
// compares it against what it actually read, so a database that lost pool rows
// decodes as a smaller, apparently valid snapshot with no error. That is precisely
// the truncation a snapshot reader exists to refuse (state_export.go:269).
func TestZzstReadFromZapDBIgnoresPoolCountDEFECT(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 30))
	pm := zzstManagerFixture(rng, 3)
	snap, err := pm.ExportState(nil)
	if err != nil {
		t.Fatalf("ExportState: %v", err)
	}
	db := memdb.New()
	if err := WriteToZapDB(db, snap); err != nil {
		t.Fatalf("WriteToZapDB: %v", err)
	}

	// Lose one pool row, exactly as a partial copy or a truncated restore would.
	dropped := append(append([]byte(nil), dbPrefixPool...), []byte(snap.Pools[1].PoolID)...)
	if err := db.Delete(dropped); err != nil {
		t.Fatalf("delete: %v", err)
	}

	back, err := ReadFromZapDB(db)
	if err != nil {
		t.Fatalf("state_export.go:269 now refuses a database with fewer pools than its metadata "+
			"claims (%v) — update this characterisation test to assert the refusal", err)
	}
	if len(back.Pools) != 2 {
		t.Fatalf("read %d pools after dropping one of three", len(back.Pools))
	}
}

// =========================================================================
// Test doubles
// =========================================================================

// zzstRow is one (key, value) pair the iterator doubles hold in memory.
type zzstRow struct{ key, val []byte }

// zzstSliceIter serves a fixed list of rows.
type zzstSliceIter struct {
	rows []zzstRow
	pos  int
	err  error
}

func (it *zzstSliceIter) Next() bool   { it.pos++; return it.pos < len(it.rows) }
func (it *zzstSliceIter) Error() error { return it.err }
func (it *zzstSliceIter) Release()     {}

func (it *zzstSliceIter) Key() []byte {
	if it.pos < 0 || it.pos >= len(it.rows) {
		return nil
	}
	return it.rows[it.pos].key
}

func (it *zzstSliceIter) Value() []byte {
	if it.pos < 0 || it.pos >= len(it.rows) {
		return nil
	}
	return it.rows[it.pos].val
}

// zzstReverseIterDB serves prefix rows in DESCENDING key order.
type zzstReverseIterDB struct{ database.Database }

func (d *zzstReverseIterDB) NewIteratorWithPrefix(prefix []byte) database.Iterator {
	inner := d.Database.NewIteratorWithPrefix(prefix)
	defer inner.Release()
	var rows []zzstRow
	for inner.Next() {
		rows = append(rows, zzstRow{
			key: append([]byte(nil), inner.Key()...),
			val: append([]byte(nil), inner.Value()...),
		})
	}
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	return &zzstSliceIter{rows: rows, pos: -1, err: inner.Error()}
}

// zzstKeepKeyDB records the exact key slice each Put is handed, alongside a copy
// taken at that instant, so a later in-place rewrite of that array is visible.
type zzstKeepKeyDB struct {
	database.Database
	keys []zzstKeyPair
}

type zzstKeyPair struct{ live, taken []byte }

func (d *zzstKeepKeyDB) NewBatch() database.Batch {
	return &zzstKeepKeyBatch{Batch: d.Database.NewBatch(), db: d}
}

type zzstKeepKeyBatch struct {
	database.Batch
	db *zzstKeepKeyDB
}

func (b *zzstKeepKeyBatch) Put(key, value []byte) error {
	b.db.keys = append(b.db.keys, zzstKeyPair{live: key, taken: append([]byte(nil), key...)})
	return b.Batch.Put(key, value)
}

// zzstSortedJoin sorts and joins lines so a fingerprint is order-independent.
func zzstSortedJoin(lines []string) string {
	out := append([]string(nil), lines...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	s := ""
	for _, l := range out {
		s += l + "\n"
	}
	return s
}

// zzstIterErrDB is a database whose prefix iterator fails.
type zzstIterErrDB struct {
	database.Database
	err error
}

func (d *zzstIterErrDB) NewIteratorWithPrefix([]byte) database.Iterator {
	return &database.IteratorError{Err: d.err}
}

// zzstFailBatchDB hands out a batch whose n-th Put fails (1-based; 0 = never) or
// whose commit fails.
type zzstFailBatchDB struct {
	database.Database
	failPutAt int
	putErr    error
	writeErr  error
}

func (d *zzstFailBatchDB) NewBatch() database.Batch {
	return &zzstFailBatch{Batch: d.Database.NewBatch(), db: d}
}

type zzstFailBatch struct {
	database.Batch
	db *zzstFailBatchDB
	n  int
}

func (b *zzstFailBatch) Put(key, value []byte) error {
	b.n++
	if b.db.failPutAt != 0 && b.n == b.db.failPutAt {
		return b.db.putErr
	}
	return b.Batch.Put(key, value)
}

func (b *zzstFailBatch) Write() error {
	if b.db.writeErr != nil {
		return b.db.writeErr
	}
	return b.Batch.Write()
}

// zzstGateDB parks a batch commit until the test releases it, so a second export
// can be attempted while the first is still running.
type zzstGateDB struct {
	database.Database
	entered chan struct{}
	release chan struct{}
}

func (d *zzstGateDB) NewBatch() database.Batch {
	return &zzstGateBatch{Batch: d.Database.NewBatch(), db: d}
}

type zzstGateBatch struct {
	database.Batch
	db *zzstGateDB
}

func (b *zzstGateBatch) Write() error {
	select {
	case b.db.entered <- struct{}{}:
		<-b.db.release
	default:
	}
	return b.Batch.Write()
}
