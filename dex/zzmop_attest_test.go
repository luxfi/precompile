// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// zzmop_attest_test.go covers fill_attestation.go — the broker-fill attestation ledger
// (LP-9090). The load-bearing properties:
//
//   - AUTHORIZATION: only the registered attester may attest, challenge, or move the
//     ceiling / fraud window. An UNSET attester authorizes nobody.
//   - ONE FILL, ONE ATTESTATION: a duplicate order id is refused, and each lifecycle
//     transition happens at most once (a finalized or reversed fill is terminal).
//   - OUTSTANDING CONSERVATION: outstanding rises by amount x price on attest and falls
//     by exactly the same product on the terminal transition — clamped at zero, never
//     negative.
//   - THE PREFUND CEILING actually bounds the total outstanding value.

var (
	zzmpAttester   = common.HexToAddress("0x00000000000000000000000000000000A77E57E4")
	zzmpUser       = common.HexToAddress("0x000000000000000000000000000000000000C0DE")
	zzmpChallenger = common.HexToAddress("0x00000000000000000000000000000000CAAA1E43")
)

// zzmpAttestState seeds a manager with an attester registered and returns both.
func zzmpAttestState(t *testing.T) (*SettlementManager, *MockStateDB) {
	t.Helper()
	m := NewSettlementManager()
	db := NewMockStateDB()
	if err := m.SetAttester(db, zzmpAttester, zzmpAttester); err != nil {
		t.Fatalf("SetAttester: %v", err)
	}
	return m, db
}

// zzmpSetAttestBlock advances the block the attestation ledger measures its fraud
// window against (the ledger reads it from its own config slot).
func zzmpSetAttestBlock(db *MockStateDB, block uint64) {
	var w common.Hash
	new(big.Int).SetUint64(block).FillBytes(w[:])
	db.SetState(settlementAddr, makeStorageKey(fillConfigPrefix, []byte("block")), w)
}

// ---------------------------------------------------------------------------
// authorization
// ---------------------------------------------------------------------------

// TestZzmpAttestAuthorizesNobodyUntilAnAttesterExists pins the fail-closed default: with
// no attester registered, EVERY caller — including the zero address, which is what the
// unset slot decodes to — is refused.
func TestZzmpAttestAuthorizesNobodyUntilAnAttesterExists(t *testing.T) {
	m := NewSettlementManager()
	db := NewMockStateDB()

	for _, caller := range []common.Address{{}, zzmpAttester, zzmpUser} {
		err := m.Attest(db, caller, [32]byte{1}, SymbolToBytes32("AAPL"), big.NewInt(10), big.NewInt(100), zzmpUser, 1)
		if !errors.Is(err, ErrUnauthorizedAttester) {
			t.Fatalf("attest with no attester registered (caller %s): want ErrUnauthorizedAttester, got %v", caller.Hex(), err)
		}
	}
	if got := m.GetOutstanding(db); got.Sign() != 0 {
		t.Fatalf("a refused attestation moved outstanding to %s", got)
	}
	if m.GetAttestation(db, [32]byte{1}) != nil {
		t.Fatal("a refused attestation was recorded")
	}
}

// TestZzmpSetAttesterIsGenesisOpenThenLocked pins the rotation rule: the FIRST attester
// may be set by anyone (genesis initialization); every later change requires the CURRENT
// attester's signature.
func TestZzmpSetAttesterIsGenesisOpenThenLocked(t *testing.T) {
	m := NewSettlementManager()
	db := NewMockStateDB()

	if err := m.SetAttester(db, zzmpUser, zzmpAttester); err != nil {
		t.Fatalf("genesis SetAttester by an arbitrary caller must succeed, got %v", err)
	}
	if got := m.getAttester(db); got != zzmpAttester {
		t.Fatalf("attester: want %s, got %s", zzmpAttester.Hex(), got.Hex())
	}
	// A stranger can no longer rotate it.
	if err := m.SetAttester(db, zzmpUser, zzmpUser); !errors.Is(err, ErrUnauthorizedAttester) {
		t.Fatalf("rotation by a stranger: want ErrUnauthorizedAttester, got %v", err)
	}
	if got := m.getAttester(db); got != zzmpAttester {
		t.Fatalf("a refused rotation changed the attester to %s", got.Hex())
	}
	// The incumbent can.
	next := common.HexToAddress("0x00000000000000000000000000000000000000AB")
	if err := m.SetAttester(db, zzmpAttester, next); err != nil {
		t.Fatalf("rotation by the incumbent: %v", err)
	}
	if got := m.getAttester(db); got != next {
		t.Fatalf("after rotation: want %s, got %s", next.Hex(), got.Hex())
	}
	// And the OLD attester is now a stranger.
	if err := m.SetAttester(db, zzmpAttester, zzmpAttester); !errors.Is(err, ErrUnauthorizedAttester) {
		t.Fatalf("rotation by the retired attester: want ErrUnauthorizedAttester, got %v", err)
	}
}

func TestZzmpAdminSettersRequireTheAttester(t *testing.T) {
	m, db := zzmpAttestState(t)

	if err := m.SetCeiling(db, zzmpUser, big.NewInt(1_000)); !errors.Is(err, ErrUnauthorizedAttester) {
		t.Fatalf("SetCeiling by a stranger: want ErrUnauthorizedAttester, got %v", err)
	}
	if got := m.GetCeiling(db); got.Sign() != 0 {
		t.Fatalf("a refused SetCeiling moved the ceiling to %s", got)
	}
	if err := m.SetFraudWindow(db, zzmpUser, 5); !errors.Is(err, ErrUnauthorizedAttester) {
		t.Fatalf("SetFraudWindow by a stranger: want ErrUnauthorizedAttester, got %v", err)
	}
	if got := m.getFraudWindow(db); got != DefaultFraudWindowBlocks {
		t.Fatalf("a refused SetFraudWindow changed the window to %d", got)
	}

	// The attester may set both, and the reads round-trip.
	if err := m.SetCeiling(db, zzmpAttester, big.NewInt(4_242)); err != nil {
		t.Fatalf("SetCeiling: %v", err)
	}
	if got := m.GetCeiling(db); got.Int64() != 4_242 {
		t.Fatalf("GetCeiling: want 4242, got %s", got)
	}
	if err := m.SetFraudWindow(db, zzmpAttester, 12); err != nil {
		t.Fatalf("SetFraudWindow: %v", err)
	}
	if got := m.getFraudWindow(db); got != 12 {
		t.Fatalf("fraud window: want 12, got %d", got)
	}
}

// TestZzmpFraudWindowSentinelDistinguishesUnsetFromZero pins why the sentinel exists: an
// UNSET window falls back to the default, while a window explicitly set to ZERO means
// zero (instant finality) — the two must not be conflated by reading the value slot alone.
func TestZzmpFraudWindowSentinelDistinguishesUnsetFromZero(t *testing.T) {
	m, db := zzmpAttestState(t)

	if got := m.getFraudWindow(db); got != DefaultFraudWindowBlocks {
		t.Fatalf("unset fraud window: want the default %d, got %d", DefaultFraudWindowBlocks, got)
	}
	if err := m.SetFraudWindow(db, zzmpAttester, 0); err != nil {
		t.Fatalf("SetFraudWindow(0): %v", err)
	}
	if got := m.getFraudWindow(db); got != 0 {
		t.Fatalf("an EXPLICIT zero window must read back as 0, got %d", got)
	}
	// A large window round-trips too.
	if err := m.SetFraudWindow(db, zzmpAttester, 1<<40); err != nil {
		t.Fatalf("SetFraudWindow(2^40): %v", err)
	}
	if got := m.getFraudWindow(db); got != 1<<40 {
		t.Fatalf("large fraud window: want 2^40, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// attest — parameters, duplicates, ceiling
// ---------------------------------------------------------------------------

func TestZzmpAttestRefusesUnauthorizedAndInvalidParameters(t *testing.T) {
	m, db := zzmpAttestState(t)
	sym := SymbolToBytes32("BTC")

	if err := m.Attest(db, zzmpUser, [32]byte{1}, sym, big.NewInt(1), big.NewInt(1), zzmpUser, 1); !errors.Is(err, ErrUnauthorizedAttester) {
		t.Fatalf("attest by a stranger: want ErrUnauthorizedAttester, got %v", err)
	}

	for _, tc := range []struct {
		name   string
		amount *big.Int
		price  *big.Int
		user   common.Address
	}{
		{"nil amount", nil, big.NewInt(1), zzmpUser},
		{"zero amount", big.NewInt(0), big.NewInt(1), zzmpUser},
		{"negative amount", big.NewInt(-1), big.NewInt(1), zzmpUser},
		{"nil price", big.NewInt(1), nil, zzmpUser},
		{"zero price", big.NewInt(1), big.NewInt(0), zzmpUser},
		{"negative price", big.NewInt(1), big.NewInt(-1), zzmpUser},
		{"zero user", big.NewInt(1), big.NewInt(1), common.Address{}},
	} {
		err := m.Attest(db, zzmpAttester, [32]byte{2}, sym, tc.amount, tc.price, tc.user, 1)
		if !errors.Is(err, ErrInvalidAttestationParam) {
			t.Fatalf("%s: want ErrInvalidAttestationParam, got %v", tc.name, err)
		}
	}
	if m.GetAttestation(db, [32]byte{2}) != nil {
		t.Fatal("a parameter-refused attestation was recorded")
	}
	if got := m.GetOutstanding(db); got.Sign() != 0 {
		t.Fatalf("a parameter-refused attestation moved outstanding to %s", got)
	}
}

// TestZzmpAttestIsOncePerOrderID pins the replay refusal: an order id already attested
// cannot be attested again, whatever the amounts.
func TestZzmpAttestIsOncePerOrderID(t *testing.T) {
	m, db := zzmpAttestState(t)
	id := OrderIDFromString("alpaca-order-0001")

	if err := m.Attest(db, zzmpAttester, id, SymbolToBytes32("AAPL"), big.NewInt(10), big.NewInt(100), zzmpUser, 1); err != nil {
		t.Fatalf("first attest: %v", err)
	}
	before := m.GetOutstanding(db)
	for _, amount := range []int64{10, 1, 1_000_000} {
		if err := m.Attest(db, zzmpAttester, id, SymbolToBytes32("MSFT"), big.NewInt(amount), big.NewInt(7), zzmpUser, 2); !errors.Is(err, ErrDuplicateAttestation) {
			t.Fatalf("replayed attest (amount %d): want ErrDuplicateAttestation, got %v", amount, err)
		}
	}
	if got := m.GetOutstanding(db); got.Cmp(before) != 0 {
		t.Fatalf("a replayed attestation moved outstanding: %s -> %s", before, got)
	}
	// The original record is untouched.
	att := m.GetAttestation(db, id)
	if att == nil || att.Amount.Int64() != 10 || att.Price.Int64() != 100 || att.Symbol != SymbolToBytes32("AAPL") {
		t.Fatalf("a replayed attestation overwrote the original: %+v", att)
	}
}

// TestZzmpPrefundCeilingBoundsTotalOutstanding pins the ceiling as a bound on the SUM,
// not on a single fill: attestations accumulate until the next one would cross it, and
// a ceiling of zero means unlimited.
func TestZzmpPrefundCeilingBoundsTotalOutstanding(t *testing.T) {
	m, db := zzmpAttestState(t)
	sym := SymbolToBytes32("ETH")

	if err := m.SetCeiling(db, zzmpAttester, big.NewInt(1_000)); err != nil {
		t.Fatalf("SetCeiling: %v", err)
	}
	// 4 x 250 exactly fills the ceiling (the boundary is inclusive).
	for i := 0; i < 4; i++ {
		if err := m.Attest(db, zzmpAttester, [32]byte{byte(i)}, sym, big.NewInt(25), big.NewInt(10), zzmpUser, uint64(i)); err != nil {
			t.Fatalf("attest %d under the ceiling: %v", i, err)
		}
	}
	if got := m.GetOutstanding(db); got.Int64() != 1_000 {
		t.Fatalf("outstanding at the ceiling: want 1000, got %s", got)
	}
	// One more unit crosses it.
	if err := m.Attest(db, zzmpAttester, [32]byte{0xFF}, sym, big.NewInt(1), big.NewInt(1), zzmpUser, 9); !errors.Is(err, ErrPrefundCeilingExceeded) {
		t.Fatalf("attest over the ceiling: want ErrPrefundCeilingExceeded, got %v", err)
	}
	if got := m.GetOutstanding(db); got.Int64() != 1_000 {
		t.Fatalf("a ceiling-refused attestation moved outstanding to %s", got)
	}
	if m.GetAttestation(db, [32]byte{0xFF}) != nil {
		t.Fatal("a ceiling-refused attestation was recorded")
	}

	// Retiring one attestation frees room again (the ceiling bounds OUTSTANDING, not
	// lifetime volume).
	if err := m.SetFraudWindow(db, zzmpAttester, 0); err != nil {
		t.Fatalf("SetFraudWindow: %v", err)
	}
	if err := m.Finalize(db, [32]byte{0}); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if got := m.GetOutstanding(db); got.Int64() != 750 {
		t.Fatalf("outstanding after finalizing one: want 750, got %s", got)
	}
	if err := m.Attest(db, zzmpAttester, [32]byte{0xFE}, sym, big.NewInt(25), big.NewInt(10), zzmpUser, 10); err != nil {
		t.Fatalf("attest into the freed room: %v", err)
	}

	// A ceiling of ZERO is unlimited (the "no ceiling configured" case).
	m2, db2 := zzmpAttestState(t)
	huge := new(big.Int).Lsh(big.NewInt(1), 200)
	if err := m2.Attest(db2, zzmpAttester, [32]byte{1}, sym, huge, big.NewInt(1), zzmpUser, 1); err != nil {
		t.Fatalf("attest with no ceiling configured: %v", err)
	}
	if got := m2.GetOutstanding(db2); got.Cmp(huge) != 0 {
		t.Fatalf("outstanding with no ceiling: want %s, got %s", huge, got)
	}
}

// ---------------------------------------------------------------------------
// challenge / finalize — one terminal transition each, conserved outstanding
// ---------------------------------------------------------------------------

func TestZzmpChallengeRefusesUnknownUnauthorizedAndProofless(t *testing.T) {
	m, db := zzmpAttestState(t)
	id := OrderIDFromString("alpaca-order-challenge")

	// Unknown order id.
	if err := m.Challenge(db, zzmpAttester, [32]byte{0xAA}, []byte("proof")); !errors.Is(err, ErrAttestationNotFound) {
		t.Fatalf("challenge of an unknown order: want ErrAttestationNotFound, got %v", err)
	}

	if err := m.Attest(db, zzmpAttester, id, SymbolToBytes32("SPY"), big.NewInt(3), big.NewInt(200), zzmpUser, 1); err != nil {
		t.Fatalf("attest: %v", err)
	}
	// An unauthorized challenger cannot reverse a fill.
	if err := m.Challenge(db, zzmpChallenger, id, []byte("proof")); !errors.Is(err, ErrUnauthorizedAttester) {
		t.Fatalf("challenge by a stranger: want ErrUnauthorizedAttester, got %v", err)
	}
	if got := m.GetAttestation(db, id).Status; got != FillPending {
		t.Fatalf("an unauthorized challenge changed the status to %d", got)
	}
	// An EMPTY reversal proof is refused (a reversal must carry evidence).
	for _, proof := range [][]byte{nil, {}} {
		if err := m.Challenge(db, zzmpAttester, id, proof); !errors.Is(err, ErrInvalidReversalProof) {
			t.Fatalf("challenge with an empty proof: want ErrInvalidReversalProof, got %v", err)
		}
	}
	if got := m.GetOutstanding(db); got.Int64() != 600 {
		t.Fatalf("a refused challenge moved outstanding to %s", got)
	}

	// The authorized challenge reverses it and retires the outstanding value exactly.
	if err := m.Challenge(db, zzmpAttester, id, []byte{0x01}); err != nil {
		t.Fatalf("challenge: %v", err)
	}
	if got := m.GetAttestation(db, id).Status; got != FillReversed {
		t.Fatalf("status after challenge: want FillReversed, got %d", got)
	}
	if got := m.GetOutstanding(db); got.Sign() != 0 {
		t.Fatalf("outstanding after the reversal: want 0, got %s", got)
	}
	// Terminal: a second challenge and a finalize both refuse.
	if err := m.Challenge(db, zzmpAttester, id, []byte{0x01}); !errors.Is(err, ErrAttestationReversed) {
		t.Fatalf("second challenge: want ErrAttestationReversed, got %v", err)
	}
	if err := m.Finalize(db, id); !errors.Is(err, ErrAttestationReversed) {
		t.Fatalf("finalize of a reversed fill: want ErrAttestationReversed, got %v", err)
	}
	if got := m.GetOutstanding(db); got.Sign() != 0 {
		t.Fatalf("a refused terminal transition moved outstanding to %s", got)
	}
}

func TestZzmpFinalizeWaitsOutTheFraudWindowThenIsTerminal(t *testing.T) {
	m, db := zzmpAttestState(t)
	id := OrderIDFromString("alpaca-order-finalize")

	if err := m.Finalize(db, [32]byte{0xBB}); !errors.Is(err, ErrAttestationNotFound) {
		t.Fatalf("finalize of an unknown order: want ErrAttestationNotFound, got %v", err)
	}
	if err := m.SetFraudWindow(db, zzmpAttester, 10); err != nil {
		t.Fatalf("SetFraudWindow: %v", err)
	}
	zzmpSetAttestBlock(db, 100)
	if err := m.Attest(db, zzmpAttester, id, SymbolToBytes32("QQQ"), big.NewInt(4), big.NewInt(50), zzmpUser, 1); err != nil {
		t.Fatalf("attest: %v", err)
	}
	if got := m.GetAttestation(db, id).Block; got != 100 {
		t.Fatalf("attestation block: want 100, got %d", got)
	}

	// Inside the window (and at its exact last block) finalization is refused.
	for _, block := range []uint64{100, 105, 109} {
		zzmpSetAttestBlock(db, block)
		if err := m.Finalize(db, id); !errors.Is(err, ErrFraudWindowActive) {
			t.Fatalf("finalize at block %d (window ends at 110): want ErrFraudWindowActive, got %v", block, err)
		}
	}
	if got := m.GetAttestation(db, id).Status; got != FillPending {
		t.Fatalf("a refused finalize changed the status to %d", got)
	}

	// At the first block PAST the window it succeeds and retires the outstanding value.
	zzmpSetAttestBlock(db, 110)
	if err := m.Finalize(db, id); err != nil {
		t.Fatalf("finalize at the window boundary: %v", err)
	}
	if got := m.GetAttestation(db, id).Status; got != FillFinalized {
		t.Fatalf("status after finalize: want FillFinalized, got %d", got)
	}
	if got := m.GetOutstanding(db); got.Sign() != 0 {
		t.Fatalf("outstanding after finalize: want 0, got %s", got)
	}

	// Terminal: a second finalize and a challenge both refuse.
	if err := m.Finalize(db, id); !errors.Is(err, ErrAttestationFinalized) {
		t.Fatalf("second finalize: want ErrAttestationFinalized, got %v", err)
	}
	if err := m.Challenge(db, zzmpAttester, id, []byte{1}); !errors.Is(err, ErrAttestationFinalized) {
		t.Fatalf("challenge of a finalized fill: want ErrAttestationFinalized, got %v", err)
	}
	if got := m.GetOutstanding(db); got.Sign() != 0 {
		t.Fatalf("a refused terminal transition moved outstanding to %s", got)
	}
}

// TestZzmpOutstandingIsConservedAcrossManyFills is the accounting invariant: outstanding
// equals the sum of amount x price over the PENDING attestations at every step, and the
// terminal transitions retire exactly their own contribution.
func TestZzmpOutstandingIsConservedAcrossManyFills(t *testing.T) {
	m, db := zzmpAttestState(t)
	sym := SymbolToBytes32("NVDA")
	if err := m.SetFraudWindow(db, zzmpAttester, 0); err != nil {
		t.Fatalf("SetFraudWindow: %v", err)
	}

	type fill struct {
		id            [32]byte
		amount, price int64
	}
	fills := []fill{
		{[32]byte{1}, 3, 700},
		{[32]byte{2}, 11, 13},
		{[32]byte{3}, 1, 1},
		{[32]byte{4}, 1_000_000, 999_983},
	}
	want := big.NewInt(0)
	for _, f := range fills {
		if err := m.Attest(db, zzmpAttester, f.id, sym, big.NewInt(f.amount), big.NewInt(f.price), zzmpUser, 1); err != nil {
			t.Fatalf("attest %x: %v", f.id[0], err)
		}
		want.Add(want, big.NewInt(f.amount*f.price))
		if got := m.GetOutstanding(db); got.Cmp(want) != 0 {
			t.Fatalf("outstanding after attesting %x: want %s, got %s", f.id[0], want, got)
		}
	}

	// Retire two by finalizing and one by challenging; each retires its OWN product.
	if err := m.Finalize(db, fills[0].id); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	want.Sub(want, big.NewInt(fills[0].amount*fills[0].price))
	if got := m.GetOutstanding(db); got.Cmp(want) != 0 {
		t.Fatalf("outstanding after finalize: want %s, got %s", want, got)
	}
	if err := m.Challenge(db, zzmpAttester, fills[1].id, []byte{1}); err != nil {
		t.Fatalf("challenge: %v", err)
	}
	want.Sub(want, big.NewInt(fills[1].amount*fills[1].price))
	if got := m.GetOutstanding(db); got.Cmp(want) != 0 {
		t.Fatalf("outstanding after challenge: want %s, got %s", want, got)
	}
	// Retiring everything lands on exactly zero — no rounding drift, no residue.
	for _, f := range fills[2:] {
		if err := m.Finalize(db, f.id); err != nil {
			t.Fatalf("finalize %x: %v", f.id[0], err)
		}
	}
	if got := m.GetOutstanding(db); got.Sign() != 0 {
		t.Fatalf("outstanding after retiring everything: want 0, got %s", got)
	}
}

// TestZzmpOutstandingClampsAtZeroRatherThanGoingNegative pins the underflow floor: if
// the outstanding accumulator is ever below an attestation's value (a corrupted or
// externally-written slot), the retire clamps to zero instead of wrapping to a colossal
// number through the big.Int -> 32-byte-word encoding.
func TestZzmpOutstandingClampsAtZeroRatherThanGoingNegative(t *testing.T) {
	for _, retire := range []struct {
		name string
		fn   func(*SettlementManager, *MockStateDB, [32]byte) error
	}{
		{"finalize", func(m *SettlementManager, db *MockStateDB, id [32]byte) error { return m.Finalize(db, id) }},
		{"challenge", func(m *SettlementManager, db *MockStateDB, id [32]byte) error {
			return m.Challenge(db, zzmpAttester, id, []byte{1})
		}},
	} {
		m, db := zzmpAttestState(t)
		if err := m.SetFraudWindow(db, zzmpAttester, 0); err != nil {
			t.Fatalf("SetFraudWindow: %v", err)
		}
		id := [32]byte{0x5A}
		if err := m.Attest(db, zzmpAttester, id, SymbolToBytes32("X"), big.NewInt(1_000), big.NewInt(1_000), zzmpUser, 1); err != nil {
			t.Fatalf("attest: %v", err)
		}
		// Corrupt the accumulator downward, then retire the fill.
		m.setOutstanding(db, big.NewInt(1))
		if err := retire.fn(m, db, id); err != nil {
			t.Fatalf("%s: %v", retire.name, err)
		}
		got := m.GetOutstanding(db)
		if got.Sign() != 0 {
			t.Fatalf("%s under a short accumulator left outstanding at %s — it must clamp to 0, never wrap", retire.name, got)
		}
	}
}

// ---------------------------------------------------------------------------
// persistence — state is the source of truth
// ---------------------------------------------------------------------------

// TestZzmpAttestationRoundTripsThroughStateForAColdManager proves the ledger lives in
// StateDB, not in the process: a FRESH manager (empty in-memory cache) reads back every
// attested field from the same state.
func TestZzmpAttestationRoundTripsThroughStateForAColdManager(t *testing.T) {
	m, db := zzmpAttestState(t)
	id := OrderIDFromString("alpaca-order-persist")
	sym := SymbolToBytes32("GOOGL")
	zzmpSetAttestBlock(db, 4_242)

	if err := m.Attest(db, zzmpAttester, id, sym, big.NewInt(17), big.NewInt(31_415), zzmpUser, 1_700_000_000); err != nil {
		t.Fatalf("attest: %v", err)
	}

	cold := NewSettlementManager()
	got := cold.GetAttestation(db, id)
	if got == nil {
		t.Fatal("a cold manager could not read the persisted attestation")
	}
	if got.OrderID != id || got.Symbol != sym || got.User != zzmpUser || got.Attester != zzmpAttester {
		t.Fatalf("identity fields did not round-trip: %+v", got)
	}
	if got.Amount.Int64() != 17 || got.Price.Int64() != 31_415 {
		t.Fatalf("value fields did not round-trip: amount=%s price=%s", got.Amount, got.Price)
	}
	if got.Timestamp != 1_700_000_000 || got.Block != 4_242 || got.Status != FillPending {
		t.Fatalf("lifecycle fields did not round-trip: ts=%d block=%d status=%d", got.Timestamp, got.Block, got.Status)
	}
	// A never-attested id reads as absent on a cold manager too.
	if cold.GetAttestation(db, [32]byte{0xEE}) != nil {
		t.Fatal("a cold manager invented an attestation for an unknown order")
	}
	// A status change persists too: the cold manager sees the reversal.
	if err := m.Challenge(db, zzmpAttester, id, []byte{9}); err != nil {
		t.Fatalf("challenge: %v", err)
	}
	if got := NewSettlementManager().GetAttestation(db, id); got == nil || got.Status != FillReversed {
		t.Fatalf("the reversal did not persist: %+v", got)
	}
}

// TestZzmpOrderIDAndSymbolEncodingsAreDeterministic pins the two derivations the ledger
// keys on: the same provider order id always yields the same 32-byte key (many runs,
// byte-identical), distinct ids never collide, and a symbol is left-aligned and padded.
func TestZzmpOrderIDAndSymbolEncodingsAreDeterministic(t *testing.T) {
	const provider = "b7f1c2d3-4e5a-6789-abcd-ef0123456789"
	first := OrderIDFromString(provider)
	for i := 0; i < 256; i++ {
		if got := OrderIDFromString(provider); got != first {
			t.Fatalf("OrderIDFromString is not deterministic on iteration %d: %x vs %x", i, got, first)
		}
	}
	if first == (([32]byte)(([32]byte{}))) {
		t.Fatal("OrderIDFromString returned the zero id")
	}
	seen := map[[32]byte]string{}
	for _, s := range []string{"", "a", "b", provider, provider + "0", "A", "aa"} {
		id := OrderIDFromString(s)
		if prev, dup := seen[id]; dup {
			t.Fatalf("OrderIDFromString collided: %q and %q", prev, s)
		}
		seen[id] = s
	}

	sym := SymbolToBytes32("AAPL")
	if string(sym[:4]) != "AAPL" {
		t.Fatalf("SymbolToBytes32 must left-align the symbol, got %x", sym)
	}
	for i := 4; i < 32; i++ {
		if sym[i] != 0 {
			t.Fatalf("SymbolToBytes32 must zero-pad, byte %d = %x", i, sym[i])
		}
	}
	// A symbol longer than 32 bytes is truncated rather than overflowing.
	long := SymbolToBytes32("0123456789ABCDEF0123456789ABCDEFOVERFLOW")
	if string(long[:32]) != "0123456789ABCDEF0123456789ABCDEF" {
		t.Fatalf("SymbolToBytes32 truncation: %x", long)
	}
	if SymbolToBytes32("AAPL") != SymbolToBytes32("AAPL") {
		t.Fatal("SymbolToBytes32 is not deterministic")
	}
}
