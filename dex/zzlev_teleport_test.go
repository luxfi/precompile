// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/luxfi/geth/common"
)

// zzlev_teleport_test.go covers dex/teleport.go — the cross-chain bridge and the
// omnichain router. A bridge's security properties are replay protection,
// signature verification, limit enforcement, pause, and authorization; each is
// asserted below against what the code actually does, and every place the code
// does NOT enforce one is pinned with a comment naming it as a reported finding.

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

var zzlToken = common.HexToAddress("0x7777777777777777777777777777777777777777")
var zzlRemote = common.HexToAddress("0x4444444444444444444444444444444444444444")
var zzlRecipient = common.HexToAddress("0x5555555555555555555555555555555555555555")

// zzlBridge builds a bridge with one supported token on ChainLux whose limits
// are wide enough that a test must opt in to hitting them.
func zzlBridge(t *testing.T, threshold uint32) *TeleportBridge {
	t.Helper()
	tb := NewTeleportBridge(threshold)
	huge := new(big.Int).Lsh(big.NewInt(1), 200)
	if err := tb.AddSupportedToken(ChainLux, zzlToken, zzlRemote, 18,
		huge, huge, big.NewInt(1)); err != nil {
		t.Fatalf("AddSupportedToken: %v", err)
	}
	return tb
}

// zzlE18 is n whole tokens at 18 decimals. Written this way because 1e19 and up
// overflow the int64 that big.NewInt takes.
func zzlE18(n int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(n), big.NewInt(1e18))
}

// zzlSigs returns n placeholder signatures. Their CONTENT is never examined by
// the bridge — see TestZzlTeleportSignaturesAreCountedNotVerified.
func zzlSigs(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte{byte(i + 1)}
	}
	return out
}

// zzlInitiated runs a teleport up to the requested status and returns its id.
func zzlInitiated(t *testing.T, tb *TeleportBridge, amount *big.Int) [32]byte {
	t.Helper()
	req, err := tb.InitiateTeleport(zzlOwner, ChainETH, zzlRecipient, zzlToken, amount, ChainLux)
	if err != nil {
		t.Fatalf("InitiateTeleport: %v", err)
	}
	return req.TeleportID
}

// ---------------------------------------------------------------------------
// construction and chain support
// ---------------------------------------------------------------------------

func TestZzlTeleportBridgeDefaults(t *testing.T) {
	tb := NewTeleportBridge(3)
	if tb.Threshold != 3 {
		t.Fatalf("threshold = %d, want 3", tb.Threshold)
	}
	if tb.FeeRate != 30 {
		t.Fatalf("fee rate = %d bps, want 30", tb.FeeRate)
	}
	if tb.TotalFees.Sign() != 0 {
		t.Fatal("a new bridge starts with collected fees")
	}
	if len(tb.Operators) != 0 || len(tb.PendingTeleports) != 0 || len(tb.CompletedTeleports) != 0 {
		t.Fatal("a new bridge starts non-empty")
	}
	// The fee floor must not exceed the ceiling, or every fee would be
	// simultaneously clamped in both directions.
	if tb.MinFee.Cmp(tb.MaxFee) > 0 {
		t.Fatalf("MinFee %s > MaxFee %s", tb.MinFee, tb.MaxFee)
	}
	if tb.MinFee.Sign() <= 0 {
		t.Fatalf("MinFee = %s, want positive", tb.MinFee)
	}
}

func TestZzlTeleportChainSupportIsExactlyTheKnownSet(t *testing.T) {
	tb := NewTeleportBridge(1)
	supported := []uint32{ChainLux, ChainHanzo, ChainZoo, ChainETH, ChainArb,
		ChainOP, ChainBase, ChainPoly, ChainBSC, ChainAvax}
	for _, c := range supported {
		if !tb.isChainSupported(c) {
			t.Fatalf("chain %d reported unsupported", c)
		}
	}
	// Nothing outside the set is accepted — including zero, the max uint32, and
	// values adjacent to real chain ids.
	for _, c := range []uint32{0, 2, 9, 11, 55, 57, 136, 138, 8452, 8454, 99999, 1 << 31, ^uint32(0)} {
		if tb.isChainSupported(c) {
			t.Fatalf("chain %d reported supported", c)
		}
	}
	// An unsupported destination is refused before anything else happens.
	tbFull := zzlBridge(t, 1)
	if _, err := tbFull.InitiateTeleport(zzlOwner, 12345, zzlRecipient, zzlToken,
		big.NewInt(1e18), ChainLux); !errors.Is(err, ErrInvalidChainID) {
		t.Fatalf("unsupported destination err = %v, want ErrInvalidChainID", err)
	}
	if len(tbFull.PendingTeleports) != 0 {
		t.Fatal("a chain-refused teleport was recorded")
	}
}

func TestZzlTeleportTokenRegistrationAndLookup(t *testing.T) {
	tb := NewTeleportBridge(1)
	// Nothing is registered on any chain yet.
	if tb.getTokenConfig(ChainLux, zzlToken) != nil {
		t.Fatal("an unregistered chain returned a token config")
	}
	if err := tb.AddSupportedToken(ChainLux, zzlToken, zzlRemote, 18,
		big.NewInt(1000), big.NewInt(100), big.NewInt(10)); err != nil {
		t.Fatalf("AddSupportedToken: %v", err)
	}
	cfg := tb.getTokenConfig(ChainLux, zzlToken)
	if cfg == nil {
		t.Fatal("the registered token is not retrievable")
	}
	if cfg.LocalAddress != zzlToken || cfg.RemoteAddress != zzlRemote || cfg.ChainID != ChainLux {
		t.Fatal("the token config does not carry its registration fields")
	}
	if cfg.Decimals != 18 {
		t.Fatalf("decimals = %d, want 18", cfg.Decimals)
	}
	// A token starts unpaused with nothing locked or minted.
	if cfg.IsPaused {
		t.Fatal("a newly registered token starts paused")
	}
	if cfg.TotalLocked.Sign() != 0 || cfg.TotalMinted.Sign() != 0 {
		t.Fatal("a newly registered token starts with a balance")
	}
	// Registration is scoped to its chain: the same address on another chain is
	// a different token and is not implicitly registered.
	if tb.getTokenConfig(ChainETH, zzlToken) != nil {
		t.Fatal("registering on one chain registered the token on another")
	}
	// A different token on the same chain is also absent.
	if tb.getTokenConfig(ChainLux, zzlRemote) != nil {
		t.Fatal("an unregistered token on a registered chain returned a config")
	}
	// Re-registering replaces the entry rather than duplicating it.
	if err := tb.AddSupportedToken(ChainLux, zzlToken, zzlRecipient, 6,
		big.NewInt(1), big.NewInt(1), big.NewInt(1)); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if len(tb.SupportedTokens[ChainLux]) != 1 {
		t.Fatalf("%d entries after re-registering, want 1", len(tb.SupportedTokens[ChainLux]))
	}
	if tb.getTokenConfig(ChainLux, zzlToken).Decimals != 6 {
		t.Fatal("re-registration did not replace the config")
	}
}

// ---------------------------------------------------------------------------
// fees
// ---------------------------------------------------------------------------

func TestZzlTeleportFeeIsClampedBetweenMinAndMax(t *testing.T) {
	tb := NewTeleportBridge(1)

	// In the middle of the range the fee is the plain basis-point cut.
	mid := big.NewInt(1e18)
	want := new(big.Int).Mul(mid, big.NewInt(int64(tb.FeeRate)))
	want.Div(want, big.NewInt(10000))
	if got := tb.calculateFee(mid); got.Cmp(want) != 0 {
		t.Fatalf("fee on %s = %s, want amount*%d/10000 = %s", mid, got, tb.FeeRate, want)
	}
	// Below the floor the fee is the floor.
	if got := tb.calculateFee(big.NewInt(1)); got.Cmp(tb.MinFee) != 0 {
		t.Fatalf("fee on 1 = %s, want the floor %s", got, tb.MinFee)
	}
	// Above the ceiling the fee is the ceiling.
	huge := new(big.Int).Mul(tb.MaxFee, big.NewInt(1_000_000))
	if got := tb.calculateFee(huge); got.Cmp(tb.MaxFee) != 0 {
		t.Fatalf("fee on %s = %s, want the ceiling %s", huge, got, tb.MaxFee)
	}
	// The clamps do not alias the bridge's own fields: mutating the returned
	// value must not move MinFee or MaxFee.
	lo := tb.calculateFee(big.NewInt(1))
	lo.SetInt64(0)
	if tb.MinFee.Sign() == 0 {
		t.Fatal("calculateFee returned a live reference to MinFee")
	}
	hi := tb.calculateFee(huge)
	hi.SetInt64(0)
	if tb.MaxFee.Sign() == 0 {
		t.Fatal("calculateFee returned a live reference to MaxFee")
	}
	// The fee is monotone non-decreasing in the amount.
	prev := tb.calculateFee(big.NewInt(0))
	for _, a := range []*big.Int{
		big.NewInt(1), big.NewInt(1e15), big.NewInt(1e16),
		big.NewInt(1e17), zzlE18(1), zzlE18(10), zzlE18(100_000),
	} {
		cur := tb.calculateFee(a)
		if cur.Cmp(prev) < 0 {
			t.Fatalf("fee fell as the amount rose at %s: %s -> %s", a, prev, cur)
		}
		prev = cur
	}
}

func TestZzlTeleportFeeRoundsDownInTheUsersFavour(t *testing.T) {
	// The basis-point cut floors, so the bridge always takes at most its stated
	// rate and never more. Above the floor this means the rounding runs in the
	// USER's favour, against the bridge — the safe direction for a user but a
	// per-transfer shortfall for the operator.
	tb := NewTeleportBridge(1)
	// An amount whose 30bps cut has a remainder: 1e18+1 -> 3000000000000001/1.
	amt := new(big.Int).Add(big.NewInt(1e18), big.NewInt(1))
	exact := new(big.Int).Mul(amt, big.NewInt(30))
	fee := tb.calculateFee(amt)
	scaled := new(big.Int).Mul(fee, big.NewInt(10000))
	if scaled.Cmp(exact) > 0 {
		t.Fatalf("fee %s exceeds the exact 30bps of %s", fee, amt)
	}
	// Confirm it is a strict floor for at least one amount with a remainder.
	found := false
	for i := int64(1); i <= 400; i++ {
		a := new(big.Int).Add(big.NewInt(1e18), big.NewInt(i))
		f := tb.calculateFee(a)
		e := new(big.Int).Mul(a, big.NewInt(30))
		if new(big.Int).Mul(f, big.NewInt(10000)).Cmp(e) < 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no amount in the sweep produced a rounded-down fee; the rounding changed")
	}
}

// DEFECT (reported, HIGH): the fee floor is applied unconditionally, so for any
// amount below MinFee the fee EXCEEDS the amount being transferred. The bridge
// records a NEGATIVE net amount, decrements the token's locked balance, and
// credits itself a fee larger than anything it received.
func TestZzlTeleportFeeCanExceedTheTransferredAmount(t *testing.T) {
	tb := zzlBridge(t, 1) // minAmount is 1, so tiny transfers are admissible
	cfg := tb.getTokenConfig(ChainLux, zzlToken)

	tiny := big.NewInt(1)
	fee := tb.calculateFee(tiny)
	if fee.Cmp(tiny) <= 0 {
		t.Fatalf("fee %s on an amount of %s is not larger; the floor was removed — "+
			"update the reported finding", fee, tiny)
	}

	req, err := tb.InitiateTeleport(zzlOwner, ChainETH, zzlRecipient, zzlToken, tiny, ChainLux)
	if err != nil {
		t.Fatalf("tiny teleport was refused (%v); an amount-vs-fee check was added", err)
	}
	if req.Amount.Sign() >= 0 {
		t.Fatalf("recorded net amount = %s, want negative", req.Amount)
	}
	if req.Amount.Cmp(new(big.Int).Sub(tiny, fee)) != 0 {
		t.Fatalf("net = %s, want amount - fee = %s", req.Amount, new(big.Int).Sub(tiny, fee))
	}
	// The token's locked balance went NEGATIVE: the bridge believes it owes less
	// than nothing on this asset.
	if cfg.TotalLocked.Sign() >= 0 {
		t.Fatalf("TotalLocked = %s, want negative", cfg.TotalLocked)
	}
	// And it booked a fee larger than the entire transfer.
	if tb.TotalFees.Cmp(tiny) <= 0 {
		t.Fatalf("collected fees %s do not exceed the %s transferred", tb.TotalFees, tiny)
	}
}

// ---------------------------------------------------------------------------
// InitiateTeleport: limits and pause
// ---------------------------------------------------------------------------

func TestZzlTeleportInitiateRefusals(t *testing.T) {
	tb := NewTeleportBridge(1)
	if err := tb.AddSupportedToken(ChainLux, zzlToken, zzlRemote, 18,
		zzlE18(1000), zzlE18(10), zzlE18(1)); err != nil {
		t.Fatalf("AddSupportedToken: %v", err)
	}

	// An unregistered token on a supported chain.
	if _, err := tb.InitiateTeleport(zzlOwner, ChainETH, zzlRecipient, zzlRemote,
		big.NewInt(1e18), ChainLux); !errors.Is(err, ErrTokenNotSupported) {
		t.Fatalf("unregistered token err = %v, want ErrTokenNotSupported", err)
	}
	// A source chain with no registrations at all.
	if _, err := tb.InitiateTeleport(zzlOwner, ChainETH, zzlRecipient, zzlToken,
		big.NewInt(1e18), ChainZoo); !errors.Is(err, ErrTokenNotSupported) {
		t.Fatalf("unregistered source chain err = %v, want ErrTokenNotSupported", err)
	}

	// The minimum is inclusive: one below is refused, exactly the minimum is not.
	below := big.NewInt(1e18 - 1)
	if _, err := tb.InitiateTeleport(zzlOwner, ChainETH, zzlRecipient, zzlToken,
		below, ChainLux); !errors.Is(err, ErrBelowMinimum) {
		t.Fatalf("one below the minimum err = %v, want ErrBelowMinimum", err)
	}
	if _, err := tb.InitiateTeleport(zzlOwner, ChainETH, zzlRecipient, zzlToken,
		big.NewInt(1e18), ChainLux); err != nil {
		t.Fatalf("exactly the minimum was refused: %v", err)
	}

	// The single-transaction cap is inclusive too: exactly the cap passes, one
	// above is refused.
	if _, err := tb.InitiateTeleport(zzlOwner, ChainETH, zzlRecipient, zzlToken,
		zzlE18(10), ChainLux); err != nil {
		t.Fatalf("exactly the single-tx cap was refused: %v", err)
	}
	over := new(big.Int).Add(zzlE18(10), big.NewInt(1))
	pendingBefore := len(tb.PendingTeleports)
	if _, err := tb.InitiateTeleport(zzlOwner, ChainETH, zzlRecipient, zzlToken,
		over, ChainLux); !errors.Is(err, ErrExceedsLimit) {
		t.Fatalf("one above the cap err = %v, want ErrExceedsLimit", err)
	}
	if len(tb.PendingTeleports) != pendingBefore {
		t.Fatal("a cap-refused teleport was recorded")
	}
	// A zero amount is refused by the minimum check.
	if _, err := tb.InitiateTeleport(zzlOwner, ChainETH, zzlRecipient, zzlToken,
		big.NewInt(0), ChainLux); !errors.Is(err, ErrBelowMinimum) {
		t.Fatalf("zero amount err = %v, want ErrBelowMinimum", err)
	}
}

func TestZzlTeleportPausedTokenIsRefusedAndUnpauseRestoresIt(t *testing.T) {
	tb := zzlBridge(t, 1)
	amt := big.NewInt(1e18)

	if err := tb.PauseToken(ChainLux, zzlToken); err != nil {
		t.Fatalf("PauseToken: %v", err)
	}
	if !tb.getTokenConfig(ChainLux, zzlToken).IsPaused {
		t.Fatal("PauseToken did not set the flag")
	}
	if _, err := tb.InitiateTeleport(zzlOwner, ChainETH, zzlRecipient, zzlToken,
		amt, ChainLux); !errors.Is(err, ErrTokenNotSupported) {
		t.Fatalf("paused token err = %v, want ErrTokenNotSupported", err)
	}
	if len(tb.PendingTeleports) != 0 {
		t.Fatal("a paused-token teleport was recorded")
	}
	// Unpausing restores service exactly.
	if err := tb.UnpauseToken(ChainLux, zzlToken); err != nil {
		t.Fatalf("UnpauseToken: %v", err)
	}
	if tb.getTokenConfig(ChainLux, zzlToken).IsPaused {
		t.Fatal("UnpauseToken did not clear the flag")
	}
	if _, err := tb.InitiateTeleport(zzlOwner, ChainETH, zzlRecipient, zzlToken, amt, ChainLux); err != nil {
		t.Fatalf("after unpausing: %v", err)
	}
	// Pausing an unknown token or chain is refused rather than silently ignored.
	if err := tb.PauseToken(ChainLux, zzlRecipient); !errors.Is(err, ErrTokenNotSupported) {
		t.Fatalf("pause unknown token err = %v, want ErrTokenNotSupported", err)
	}
	if err := tb.UnpauseToken(ChainZoo, zzlToken); !errors.Is(err, ErrTokenNotSupported) {
		t.Fatalf("unpause unknown chain err = %v, want ErrTokenNotSupported", err)
	}
}

// DEFECT (reported, HIGH): BridgedToken carries a DailyLimit that nothing ever
// reads. Only MinAmount and SingleTxLimit are enforced, so a caller can drain
// any multiple of the daily cap by splitting it into transfers that each sit
// under the per-transaction cap.
func TestZzlTeleportDailyLimitIsNeverEnforced(t *testing.T) {
	tb := NewTeleportBridge(1)
	// A daily cap of 10 units and a per-transaction cap of 5.
	daily := zzlE18(10)
	if err := tb.AddSupportedToken(ChainLux, zzlToken, zzlRemote, 18,
		daily, zzlE18(5), big.NewInt(1)); err != nil {
		t.Fatalf("AddSupportedToken: %v", err)
	}

	// Twenty transfers of 5 units is ten times the daily cap. Every one lands.
	moved := big.NewInt(0)
	for i := 0; i < 20; i++ {
		req, err := tb.InitiateTeleport(zzlOwner, ChainETH, zzlRecipient, zzlToken,
			zzlE18(5), ChainLux)
		if err != nil {
			t.Fatalf("transfer %d of 20 was refused (%v); a daily cap is now enforced — "+
				"update the reported finding", i, err)
		}
		moved.Add(moved, req.Amount)
	}
	if moved.Cmp(daily) <= 0 {
		t.Fatalf("moved %s, which is within the daily cap %s; the fixture is not exercising it",
			moved, daily)
	}
	if len(tb.PendingTeleports) != 20 {
		t.Fatalf("%d pending teleports, want 20", len(tb.PendingTeleports))
	}
	// The token's own accounting confirms the overflow.
	if tb.getTokenConfig(ChainLux, zzlToken).TotalLocked.Cmp(daily) <= 0 {
		t.Fatal("TotalLocked stayed within the daily cap")
	}
}

func TestZzlTeleportInitiateRecordsAConsistentRequest(t *testing.T) {
	tb := zzlBridge(t, 1)
	cfg := tb.getTokenConfig(ChainLux, zzlToken)
	amt := big.NewInt(1e18)
	fee := tb.calculateFee(amt)

	req, err := tb.InitiateTeleport(zzlOwner, ChainETH, zzlRecipient, zzlToken, amt, ChainLux)
	if err != nil {
		t.Fatalf("InitiateTeleport: %v", err)
	}
	if req.Sender != zzlOwner || req.Recipient != zzlRecipient || req.Token != zzlToken {
		t.Fatal("the request does not carry its parties")
	}
	if req.SourceChain != ChainLux || req.DestChain != ChainETH {
		t.Fatalf("chains = %d -> %d, want %d -> %d", req.SourceChain, req.DestChain, ChainLux, ChainETH)
	}
	if req.Status != TeleportPending {
		t.Fatalf("status = %d, want TeleportPending", req.Status)
	}
	// Conservation: what is recorded plus what is charged equals what was sent.
	if new(big.Int).Add(req.Amount, fee).Cmp(amt) != 0 {
		t.Fatalf("net %s + fee %s != sent %s", req.Amount, fee, amt)
	}
	// The locked balance moved by exactly the net amount, and fees by the fee.
	if cfg.TotalLocked.Cmp(req.Amount) != 0 {
		t.Fatalf("TotalLocked = %s, want the net %s", cfg.TotalLocked, req.Amount)
	}
	if tb.TotalFees.Cmp(fee) != 0 {
		t.Fatalf("TotalFees = %s, want %s", tb.TotalFees, fee)
	}
	// It is filed under its id and reachable by status lookup.
	if tb.PendingTeleports[req.TeleportID] != req {
		t.Fatal("the request is not filed under its id")
	}
	st, err := tb.GetTeleportStatus(req.TeleportID)
	if err != nil {
		t.Fatalf("GetTeleportStatus: %v", err)
	}
	if st != TeleportPending {
		t.Fatalf("status = %d, want TeleportPending", st)
	}
	// A second transfer accumulates rather than overwriting.
	if _, err := tb.InitiateTeleport(zzlOwner, ChainETH, zzlRecipient, zzlToken, amt, ChainLux); err != nil {
		t.Fatalf("second InitiateTeleport: %v", err)
	}
	if len(tb.PendingTeleports) != 2 {
		t.Fatalf("%d pending, want 2", len(tb.PendingTeleports))
	}
	if tb.TotalFees.Cmp(new(big.Int).Mul(fee, big.NewInt(2))) != 0 {
		t.Fatalf("TotalFees = %s, want twice %s", tb.TotalFees, fee)
	}
}

func TestZzlTeleportIDIsDeterministicAndFieldSensitive(t *testing.T) {
	tb := NewTeleportBridge(1)
	base := func() [32]byte {
		return tb.generateTeleportID(zzlOwner, ChainETH, zzlRecipient, zzlToken, big.NewInt(1e18), 7)
	}
	if base() != base() {
		t.Fatal("generateTeleportID is not deterministic")
	}
	// Every input participates: changing any one of them changes the id.
	for _, tc := range []struct {
		name string
		got  [32]byte
	}{
		{"sender", tb.generateTeleportID(zzlOther, ChainETH, zzlRecipient, zzlToken, big.NewInt(1e18), 7)},
		{"dest chain", tb.generateTeleportID(zzlOwner, ChainZoo, zzlRecipient, zzlToken, big.NewInt(1e18), 7)},
		{"recipient", tb.generateTeleportID(zzlOwner, ChainETH, zzlOther, zzlToken, big.NewInt(1e18), 7)},
		{"token", tb.generateTeleportID(zzlOwner, ChainETH, zzlRecipient, zzlRemote, big.NewInt(1e18), 7)},
		{"amount", tb.generateTeleportID(zzlOwner, ChainETH, zzlRecipient, zzlToken, big.NewInt(1e18+1), 7)},
		{"nonce", tb.generateTeleportID(zzlOwner, ChainETH, zzlRecipient, zzlToken, big.NewInt(1e18), 8)},
	} {
		if tc.got == base() {
			t.Fatalf("changing the %s did not change the teleport id", tc.name)
		}
	}
	// Two teleports with identical parameters get different ids because the
	// nonce is the wall clock in nanoseconds, so ErrDuplicateTeleportID is not
	// reachable through InitiateTeleport (reported as an uncovered branch).
	tbFull := zzlBridge(t, 1)
	a := zzlInitiated(t, tbFull, big.NewInt(1e18))
	b := zzlInitiated(t, tbFull, big.NewInt(1e18))
	if a == b {
		t.Fatal("two identical teleports collided on one id")
	}
}

// ---------------------------------------------------------------------------
// state machine: burn, complete, cancel
// ---------------------------------------------------------------------------

func TestZzlTeleportBurnRequiresPendingAndIsIdempotentlyRefused(t *testing.T) {
	tb := zzlBridge(t, 1)

	if err := tb.BurnForTeleport([32]byte{0xFF}); !errors.Is(err, ErrTeleportNotFound) {
		t.Fatalf("unknown id err = %v, want ErrTeleportNotFound", err)
	}
	id := zzlInitiated(t, tb, big.NewInt(1e18))
	if err := tb.BurnForTeleport(id); err != nil {
		t.Fatalf("BurnForTeleport: %v", err)
	}
	if st, _ := tb.GetTeleportStatus(id); st != TeleportBurned {
		t.Fatalf("status = %d, want TeleportBurned", st)
	}
	// Burning twice is refused: the state machine only moves forward.
	if err := tb.BurnForTeleport(id); !errors.Is(err, ErrInvalidTeleportState) {
		t.Fatalf("second burn err = %v, want ErrInvalidTeleportState", err)
	}
	if st, _ := tb.GetTeleportStatus(id); st != TeleportBurned {
		t.Fatalf("status = %d after a refused second burn, want TeleportBurned", st)
	}
}

func TestZzlTeleportCompleteRequiresBurnedState(t *testing.T) {
	tb := zzlBridge(t, 2)

	if err := tb.CompleteTeleport([32]byte{0xFF}, []byte("m"), zzlSigs(2)); !errors.Is(err, ErrTeleportNotFound) {
		t.Fatalf("unknown id err = %v, want ErrTeleportNotFound", err)
	}
	// A pending (unburned) teleport cannot be completed: minting before the
	// source-chain burn would create tokens on both sides.
	id := zzlInitiated(t, tb, big.NewInt(1e18))
	if err := tb.CompleteTeleport(id, []byte("m"), zzlSigs(2)); !errors.Is(err, ErrInvalidTeleportState) {
		t.Fatalf("completing an unburned teleport err = %v, want ErrInvalidTeleportState", err)
	}
	if tb.CompletedTeleports[id] {
		t.Fatal("a refused completion marked the teleport complete")
	}
	if st, _ := tb.GetTeleportStatus(id); st != TeleportPending {
		t.Fatalf("status = %d, want it left at TeleportPending", st)
	}
}

func TestZzlTeleportCompleteEnforcesTheSignatureThreshold(t *testing.T) {
	const threshold = 3
	tb := zzlBridge(t, threshold)
	id := zzlInitiated(t, tb, big.NewInt(1e18))
	if err := tb.BurnForTeleport(id); err != nil {
		t.Fatalf("burn: %v", err)
	}

	// One below the threshold is refused; exactly the threshold passes. That is
	// the boundary that stops a minority of operators from minting.
	if err := tb.CompleteTeleport(id, []byte("m"), zzlSigs(threshold-1)); !errors.Is(err, ErrInsufficientSignatures) {
		t.Fatalf("%d signatures err = %v, want ErrInsufficientSignatures", threshold-1, err)
	}
	if tb.CompletedTeleports[id] {
		t.Fatal("an under-signed completion went through")
	}
	if err := tb.CompleteTeleport(id, []byte("m"), zzlSigs(threshold)); err != nil {
		t.Fatalf("exactly %d signatures: %v", threshold, err)
	}
	// Zero signatures against a non-zero threshold is refused.
	tb2 := zzlBridge(t, 1)
	id2 := zzlInitiated(t, tb2, big.NewInt(1e18))
	if err := tb2.BurnForTeleport(id2); err != nil {
		t.Fatalf("burn: %v", err)
	}
	if err := tb2.CompleteTeleport(id2, []byte("m"), nil); !errors.Is(err, ErrInsufficientSignatures) {
		t.Fatalf("nil signatures err = %v, want ErrInsufficientSignatures", err)
	}
}

// CRITICAL FINDING (reported): verifyWarpMessage is `len(message) > 0`. It does
// not verify anything — not the signatures, not the teleport id it is handed,
// not a source. Any non-empty byte string authorises a mint. The signature
// slice is only COUNTED; its contents are never examined either. On a live
// bridge this is an unlimited mint for anyone who can call CompleteTeleport.
func TestZzlTeleportWarpVerificationAcceptsAnyNonEmptyMessage(t *testing.T) {
	tb := zzlBridge(t, 1)
	id := zzlInitiated(t, tb, big.NewInt(1e18))

	// Every one of these is accepted as a valid Warp proof of `id`.
	for _, msg := range [][]byte{
		{0x00},
		[]byte("not a warp message"),
		[]byte("\x00\x00\x00\x00"),
		make([]byte, 4096),
	} {
		if !tb.verifyWarpMessage(msg, id) {
			t.Fatalf("verifyWarpMessage rejected %d bytes; real verification was added — "+
				"update the reported finding", len(msg))
		}
	}
	// It is not even a function of the teleport id: a message "for" one id
	// verifies against a completely different one.
	if !tb.verifyWarpMessage([]byte("x"), [32]byte{0xAB, 0xCD}) {
		t.Fatal("verifyWarpMessage became id-sensitive")
	}
	// The ONLY rejected input is the empty message.
	if tb.verifyWarpMessage(nil, id) {
		t.Fatal("verifyWarpMessage accepted an empty message")
	}
	if tb.verifyWarpMessage([]byte{}, id) {
		t.Fatal("verifyWarpMessage accepted a zero-length message")
	}

	// End to end: a forged message mints, and an empty one is the only refusal.
	if err := tb.BurnForTeleport(id); err != nil {
		t.Fatalf("burn: %v", err)
	}
	if err := tb.CompleteTeleport(id, nil, zzlSigs(1)); !errors.Is(err, ErrInvalidWarpSignature) {
		t.Fatalf("empty warp message err = %v, want ErrInvalidWarpSignature", err)
	}
	if err := tb.CompleteTeleport(id, []byte("forged"), zzlSigs(1)); err != nil {
		t.Fatalf("a forged warp message was rejected (%v); verification was added", err)
	}
	if !tb.CompletedTeleports[id] {
		t.Fatal("the forged completion did not mint")
	}
}

func TestZzlTeleportSignaturesAreCountedNotVerified(t *testing.T) {
	// The threshold counts entries in the slice. Empty, identical and garbage
	// signatures all satisfy it, so N copies of one byte pass a 3-of-N policy.
	tb := zzlBridge(t, 3)
	id := zzlInitiated(t, tb, big.NewInt(1e18))
	if err := tb.BurnForTeleport(id); err != nil {
		t.Fatalf("burn: %v", err)
	}
	identical := [][]byte{{0x01}, {0x01}, {0x01}}
	if err := tb.CompleteTeleport(id, []byte("m"), identical); err != nil {
		t.Fatalf("three identical signatures were rejected (%v); content checking was added — "+
			"update the reported finding", err)
	}

	// Even three empty slices count.
	tb2 := zzlBridge(t, 3)
	id2 := zzlInitiated(t, tb2, big.NewInt(1e18))
	if err := tb2.BurnForTeleport(id2); err != nil {
		t.Fatalf("burn: %v", err)
	}
	if err := tb2.CompleteTeleport(id2, []byte("m"), [][]byte{nil, nil, nil}); err != nil {
		t.Fatalf("three empty signatures were rejected (%v)", err)
	}
}

func TestZzlTeleportCompletionIsReplayProof(t *testing.T) {
	tb := zzlBridge(t, 1)
	id := zzlInitiated(t, tb, big.NewInt(1e18))
	if err := tb.BurnForTeleport(id); err != nil {
		t.Fatalf("burn: %v", err)
	}
	if err := tb.CompleteTeleport(id, []byte("m"), zzlSigs(1)); err != nil {
		t.Fatalf("first completion: %v", err)
	}
	// The completed teleport is recorded and removed from the pending set.
	if !tb.CompletedTeleports[id] {
		t.Fatal("the completion was not recorded")
	}
	if tb.PendingTeleports[id] != nil {
		t.Fatal("the completed teleport is still pending")
	}
	if st, err := tb.GetTeleportStatus(id); err != nil || st != TeleportMinted {
		t.Fatalf("status = %d err = %v, want TeleportMinted", st, err)
	}

	// The same id can never complete twice — not with the same proof, not with
	// a different one, not with more signatures.
	for _, tc := range []struct {
		name string
		msg  []byte
		sigs [][]byte
	}{
		{"the same proof", []byte("m"), zzlSigs(1)},
		{"a different proof", []byte("other"), zzlSigs(1)},
		{"far more signatures", []byte("m"), zzlSigs(50)},
	} {
		if err := tb.CompleteTeleport(id, tc.msg, tc.sigs); !errors.Is(err, ErrTeleportNotFound) {
			t.Fatalf("replay with %s: err = %v, want ErrTeleportNotFound", tc.name, err)
		}
	}
	// It stays exactly one completion, and it is still reported as minted.
	if len(tb.CompletedTeleports) != 1 {
		t.Fatalf("%d completions recorded, want 1", len(tb.CompletedTeleports))
	}
	if st, _ := tb.GetTeleportStatus(id); st != TeleportMinted {
		t.Fatalf("status after replay attempts = %d, want TeleportMinted", st)
	}
	// A completed teleport can no longer be burned or cancelled either.
	if err := tb.BurnForTeleport(id); !errors.Is(err, ErrTeleportNotFound) {
		t.Fatalf("burning a completed teleport err = %v, want ErrTeleportNotFound", err)
	}
	if err := tb.CancelTeleport(zzlOwner, id); !errors.Is(err, ErrTeleportNotFound) {
		t.Fatalf("cancelling a completed teleport err = %v, want ErrTeleportNotFound", err)
	}
}

func TestZzlTeleportCancelIsSenderOnlyAndPendingOnly(t *testing.T) {
	tb := zzlBridge(t, 1)
	cfg := tb.getTokenConfig(ChainLux, zzlToken)

	if err := tb.CancelTeleport(zzlOwner, [32]byte{0xFF}); !errors.Is(err, ErrTeleportNotFound) {
		t.Fatalf("unknown id err = %v, want ErrTeleportNotFound", err)
	}

	id := zzlInitiated(t, tb, big.NewInt(1e18))
	locked := new(big.Int).Set(cfg.TotalLocked)

	// Only the sender may cancel. Anyone else is refused and nothing moves.
	if err := tb.CancelTeleport(zzlOther, id); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cancel by a stranger err = %v, want ErrUnauthorized", err)
	}
	if tb.PendingTeleports[id] == nil {
		t.Fatal("an unauthorized cancel removed the teleport")
	}
	if cfg.TotalLocked.Cmp(locked) != 0 {
		t.Fatal("an unauthorized cancel moved the locked balance")
	}
	// The recipient is not the sender either.
	if err := tb.CancelTeleport(zzlRecipient, id); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cancel by the recipient err = %v, want ErrUnauthorized", err)
	}

	// The sender can, and the locked balance is returned exactly.
	if err := tb.CancelTeleport(zzlOwner, id); err != nil {
		t.Fatalf("cancel by the sender: %v", err)
	}
	if tb.PendingTeleports[id] != nil {
		t.Fatal("the cancelled teleport is still pending")
	}
	if cfg.TotalLocked.Sign() != 0 {
		t.Fatalf("TotalLocked = %s after cancelling the only teleport, want 0", cfg.TotalLocked)
	}
	// Cancelling twice is refused.
	if err := tb.CancelTeleport(zzlOwner, id); !errors.Is(err, ErrTeleportNotFound) {
		t.Fatalf("second cancel err = %v, want ErrTeleportNotFound", err)
	}

	// Once burned, a teleport can no longer be cancelled — otherwise the sender
	// could reclaim tokens that are already being minted on the far side.
	id2 := zzlInitiated(t, tb, big.NewInt(1e18))
	if err := tb.BurnForTeleport(id2); err != nil {
		t.Fatalf("burn: %v", err)
	}
	lockedAfterBurn := new(big.Int).Set(cfg.TotalLocked)
	if err := tb.CancelTeleport(zzlOwner, id2); !errors.Is(err, ErrCannotCancel) {
		t.Fatalf("cancel after burn err = %v, want ErrCannotCancel", err)
	}
	if cfg.TotalLocked.Cmp(lockedAfterBurn) != 0 {
		t.Fatal("a refused cancel returned the locked balance")
	}
	if tb.PendingTeleports[id2] == nil {
		t.Fatal("a refused cancel removed the teleport")
	}
}

// DEFECT (reported): cancelling refunds the NET amount to TotalLocked but the
// fee, which was taken out of the sender's transfer at initiation, stays in
// TotalFees. A cancelled teleport therefore costs the sender the full fee for
// a transfer that never happened.
func TestZzlTeleportCancelDoesNotRefundTheFee(t *testing.T) {
	tb := zzlBridge(t, 1)
	amt := big.NewInt(1e18)
	fee := tb.calculateFee(amt)

	id := zzlInitiated(t, tb, amt)
	if tb.TotalFees.Cmp(fee) != 0 {
		t.Fatalf("TotalFees = %s, want %s", tb.TotalFees, fee)
	}
	if err := tb.CancelTeleport(zzlOwner, id); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if tb.TotalFees.Sign() == 0 {
		t.Fatal("the fee was refunded on cancel; a refund was added — update the finding")
	}
	if tb.TotalFees.Cmp(fee) != 0 {
		t.Fatalf("TotalFees = %s after cancel, want the fee %s retained", tb.TotalFees, fee)
	}
}

func TestZzlTeleportStatusOfAnUnknownIDIsAnError(t *testing.T) {
	tb := zzlBridge(t, 1)
	st, err := tb.GetTeleportStatus([32]byte{0x99})
	if !errors.Is(err, ErrTeleportNotFound) {
		t.Fatalf("unknown id err = %v, want ErrTeleportNotFound", err)
	}
	if st != 0 {
		t.Fatalf("status = %d on an error, want the zero value", st)
	}
}

// DEFECT (reported, HIGH): the bridge has an Operators list and a Threshold but
// NOTHING consults the list. AddOperator, AddSupportedToken, PauseToken and
// UnpauseToken take no caller at all, so there is no authorization to perform.
// Anyone who can reach these entry points can register a token, unpause a
// halted one, or appoint themselves an operator.
func TestZzlTeleportAdminActionsHaveNoAuthorization(t *testing.T) {
	tb := zzlBridge(t, 3)

	// The operator set is write-only: appending is unrestricted and duplicates
	// are accepted, because nothing reads it.
	if len(tb.Operators) != 0 {
		t.Fatal("a new bridge starts with operators")
	}
	tb.AddOperator(zzlOther)
	tb.AddOperator(zzlOther)
	tb.AddOperator(zzlRecipient)
	if len(tb.Operators) != 3 {
		t.Fatalf("%d operators, want 3 (duplicates are not rejected)", len(tb.Operators))
	}

	// Pausing is an emergency control, yet an empty operator set does not stop
	// it and a populated one does not gate it.
	if err := tb.PauseToken(ChainLux, zzlToken); err != nil {
		t.Fatalf("PauseToken: %v", err)
	}
	if err := tb.UnpauseToken(ChainLux, zzlToken); err != nil {
		t.Fatalf("UnpauseToken by a non-operator: %v", err)
	}
	if tb.getTokenConfig(ChainLux, zzlToken).IsPaused {
		t.Fatal("the token is still paused")
	}

	// Registering a brand-new token on a fresh bridge with NO operators at all
	// also succeeds, which is the sharpest form of the finding.
	bare := NewTeleportBridge(5)
	if len(bare.Operators) != 0 {
		t.Fatal("fixture: the bare bridge has operators")
	}
	if err := bare.AddSupportedToken(ChainLux, zzlToken, zzlRemote, 18,
		big.NewInt(1), big.NewInt(1), big.NewInt(1)); err != nil {
		t.Fatalf("AddSupportedToken on an operator-less bridge: %v", err)
	}
	if bare.getTokenConfig(ChainLux, zzlToken) == nil {
		t.Fatal("the token was not registered")
	}
}

// ---------------------------------------------------------------------------
// OmnichainRouter
// ---------------------------------------------------------------------------

func TestZzlRouterAddRouteAndLookup(t *testing.T) {
	or := NewOmnichainRouter(zzlBridge(t, 1))

	if or.getRoute(ChainLux, ChainETH) != nil {
		t.Fatal("an empty router returned a route")
	}
	if _, err := or.GetBestRoute(ChainLux, ChainETH, zzlToken, big.NewInt(1)); !errors.Is(err, ErrNoRouteFound) {
		t.Fatalf("empty router err = %v, want ErrNoRouteFound", err)
	}

	if err := or.AddRoute(ChainLux, ChainETH, 50, big.NewInt(1000)); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	r := or.getRoute(ChainLux, ChainETH)
	if r == nil {
		t.Fatal("the added route is not retrievable")
	}
	if r.SourceChain != ChainLux || r.DestChain != ChainETH || r.Fee != 50 {
		t.Fatal("the route does not carry its parameters")
	}
	if !r.IsActive {
		t.Fatal("a new route starts inactive")
	}
	if r.UsedToday.Sign() != 0 {
		t.Fatal("a new route starts with usage")
	}
	// Routes are directional: the reverse is a separate entry.
	if or.getRoute(ChainETH, ChainLux) != nil {
		t.Fatal("adding a route also created its reverse")
	}
	// Adding a second destination from the same source does not disturb the first.
	if err := or.AddRoute(ChainLux, ChainZoo, 10, big.NewInt(5)); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	if or.getRoute(ChainLux, ChainETH) != r {
		t.Fatal("adding a second route replaced the first")
	}
}

func TestZzlRouterBestRouteRespectsCapacityAndActivity(t *testing.T) {
	or := NewOmnichainRouter(zzlBridge(t, 1))
	if err := or.AddRoute(ChainLux, ChainETH, 50, big.NewInt(1000)); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	r := or.getRoute(ChainLux, ChainETH)

	// Exactly the remaining capacity is routable; one unit more is not.
	if _, err := or.GetBestRoute(ChainLux, ChainETH, zzlToken, big.NewInt(1000)); err != nil {
		t.Fatalf("routing exactly the capacity: %v", err)
	}
	if _, err := or.GetBestRoute(ChainLux, ChainETH, zzlToken, big.NewInt(1001)); !errors.Is(err, ErrNoRouteFound) {
		t.Fatalf("routing one over capacity err = %v, want ErrNoRouteFound", err)
	}
	// Consuming capacity narrows what remains, at the same boundary.
	r.UsedToday = big.NewInt(400)
	if _, err := or.GetBestRoute(ChainLux, ChainETH, zzlToken, big.NewInt(600)); err != nil {
		t.Fatalf("routing the exact remainder: %v", err)
	}
	if _, err := or.GetBestRoute(ChainLux, ChainETH, zzlToken, big.NewInt(601)); !errors.Is(err, ErrNoRouteFound) {
		t.Fatalf("routing one over the remainder err = %v, want ErrNoRouteFound", err)
	}
	// A deactivated route is not used even with capacity to spare.
	r.UsedToday = big.NewInt(0)
	r.IsActive = false
	if _, err := or.GetBestRoute(ChainLux, ChainETH, zzlToken, big.NewInt(1)); !errors.Is(err, ErrNoRouteFound) {
		t.Fatalf("inactive route err = %v, want ErrNoRouteFound", err)
	}
}

// DEFECT (reported): when the direct route is out of capacity the router falls
// through to a two-hop search and returns the FIRST hop without checking its
// capacity — and that first hop can be the very route that was just rejected.
// The capacity limit is therefore advisory.
func TestZzlRouterMultiHopFallbackBypassesCapacity(t *testing.T) {
	or := NewOmnichainRouter(zzlBridge(t, 1))
	// A direct Lux->ETH route with tiny capacity, plus a Lux->Zoo->ETH pair.
	if err := or.AddRoute(ChainLux, ChainETH, 0, big.NewInt(1)); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	if err := or.AddRoute(ChainLux, ChainZoo, 0, big.NewInt(1)); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	if err := or.AddRoute(ChainZoo, ChainETH, 0, big.NewInt(1)); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}

	// An amount far beyond every route's capacity still finds a route.
	huge := big.NewInt(1_000_000)
	got, err := or.GetBestRoute(ChainLux, ChainETH, zzlToken, huge)
	if err != nil {
		t.Fatalf("over-capacity routing was refused (%v); the two-hop path now checks "+
			"capacity — update the reported finding", err)
	}
	if got == nil {
		t.Fatal("GetBestRoute returned a nil route with a nil error")
	}
	// The returned hop cannot carry the amount it was selected for.
	remaining := new(big.Int).Sub(got.MaxCapacity, got.UsedToday)
	if remaining.Cmp(huge) >= 0 {
		t.Fatalf("the returned route has %s of capacity for a %s transfer; the fixture is "+
			"not exercising the bypass", remaining, huge)
	}
	// The intermediate hop is skipped when it IS the destination, so a lone
	// direct route out of capacity still fails.
	solo := NewOmnichainRouter(zzlBridge(t, 1))
	if err := solo.AddRoute(ChainLux, ChainETH, 0, big.NewInt(1)); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	if _, err := solo.GetBestRoute(ChainLux, ChainETH, zzlToken, huge); !errors.Is(err, ErrNoRouteFound) {
		t.Fatalf("a lone over-capacity route err = %v, want ErrNoRouteFound", err)
	}
	// A first hop with no matching second hop also fails.
	dead := NewOmnichainRouter(zzlBridge(t, 1))
	if err := dead.AddRoute(ChainLux, ChainETH, 0, big.NewInt(1)); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	if err := dead.AddRoute(ChainLux, ChainZoo, 0, big.NewInt(1)); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	if _, err := dead.GetBestRoute(ChainLux, ChainETH, zzlToken, huge); !errors.Is(err, ErrNoRouteFound) {
		t.Fatalf("a dead-end first hop err = %v, want ErrNoRouteFound", err)
	}
	// An inactive second hop is likewise not usable.
	inactive := NewOmnichainRouter(zzlBridge(t, 1))
	for _, r := range [][3]uint32{{ChainLux, ChainETH, 0}, {ChainLux, ChainZoo, 0}, {ChainZoo, ChainETH, 0}} {
		if err := inactive.AddRoute(r[0], r[1], r[2], big.NewInt(1)); err != nil {
			t.Fatalf("AddRoute: %v", err)
		}
	}
	inactive.getRoute(ChainZoo, ChainETH).IsActive = false
	if _, err := inactive.GetBestRoute(ChainLux, ChainETH, zzlToken, huge); !errors.Is(err, ErrNoRouteFound) {
		t.Fatalf("an inactive second hop err = %v, want ErrNoRouteFound", err)
	}
}

func TestZzlRouterDailyLimitsResetOnlyAfterTwentyFourHours(t *testing.T) {
	or := NewOmnichainRouter(zzlBridge(t, 1))
	if err := or.AddRoute(ChainLux, ChainETH, 0, big.NewInt(1000)); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	r := or.getRoute(ChainLux, ChainETH)
	r.UsedToday = big.NewInt(900)

	// A freshly created route is not reset: the window has not elapsed.
	or.ResetDailyLimits()
	if r.UsedToday.Cmp(big.NewInt(900)) != 0 {
		t.Fatalf("usage = %s, want it left at 900 inside the window", r.UsedToday)
	}
	// Exactly 24h is not enough either — the comparison is strictly greater.
	r.LastReset = time.Now().Unix() - 86400
	or.ResetDailyLimits()
	if r.UsedToday.Cmp(big.NewInt(900)) != 0 {
		t.Fatalf("usage = %s, want it left at 900 at exactly 24h", r.UsedToday)
	}
	// One second past 24h resets both the usage and the clock.
	before := time.Now().Unix()
	r.LastReset = before - 86401
	or.ResetDailyLimits()
	if r.UsedToday.Sign() != 0 {
		t.Fatalf("usage = %s after the window elapsed, want 0", r.UsedToday)
	}
	if r.LastReset < before {
		t.Fatalf("LastReset = %d, want it advanced to at least %d", r.LastReset, before)
	}
	// Capacity is genuinely restored afterwards.
	if _, err := or.GetBestRoute(ChainLux, ChainETH, zzlToken, big.NewInt(1000)); err != nil {
		t.Fatalf("full capacity after a reset: %v", err)
	}
	// The reset walks every source chain, not just the first.
	if err := or.AddRoute(ChainZoo, ChainETH, 0, big.NewInt(10)); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	r2 := or.getRoute(ChainZoo, ChainETH)
	r2.UsedToday = big.NewInt(10)
	r2.LastReset = time.Now().Unix() - 86401
	r.UsedToday = big.NewInt(5)
	r.LastReset = time.Now().Unix() - 86401
	or.ResetDailyLimits()
	if r.UsedToday.Sign() != 0 || r2.UsedToday.Sign() != 0 {
		t.Fatalf("reset missed a route: %s / %s", r.UsedToday, r2.UsedToday)
	}
}

// DEFECT (reported, HIGH): RouteTransfer takes the router's write lock and then
// calls GetBestRoute, which takes a read lock on the same non-reentrant
// sync.RWMutex. The call can never return. Every routed transfer deadlocks, and
// the parked writer blocks every other router operation forever.
func TestZzlRouterRouteTransferDeadlocks(t *testing.T) {
	or := NewOmnichainRouter(zzlBridge(t, 1))
	if err := or.AddRoute(ChainLux, ChainETH, 50, big.NewInt(1_000_000)); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}

	done := make(chan struct{})
	go func() {
		// This call never returns; the goroutine stays parked for the rest of
		// the run. It holds only this router, which no other test uses.
		_, _ = or.RouteTransfer(zzlOwner, ChainETH, zzlRecipient, zzlToken,
			big.NewInt(1e18), ChainLux)
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("RouteTransfer returned; the lock reentrancy was fixed — update the " +
			"reported finding and cover the routing arithmetic")
	case <-time.After(2 * time.Second):
	}

	// The router is now wedged: even a plain read cannot acquire the lock.
	readDone := make(chan struct{})
	go func() {
		_, _ = or.GetBestRoute(ChainLux, ChainETH, zzlToken, big.NewInt(1))
		close(readDone)
	}()
	select {
	case <-readDone:
		t.Fatal("a read succeeded while RouteTransfer held the write lock")
	case <-time.After(time.Second):
	}
}
