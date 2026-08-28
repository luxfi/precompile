// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
)

// zzmop_seed_test.go covers settle_seed.go — the operator-funding surface for the two
// settlement pots a D->C credit draws on (the swap rail's seamReserve and the LP rail's
// committedPositions). Three properties are load-bearing:
//
//   - AUTHORIZATION: only the per-network governance controller may seed; an unset
//     controller is fail-CLOSED (no default key to abuse).
//   - CONSERVATION: a seed is backed by REAL delivered value — a native seed that
//     carried no msg.value credits nothing, and an ERC-20 seed that under-delivers
//     refuses. The pot never rises without value behind it.
//   - BINDING: a fee credit names an OPEN position and its OWN locked asset; it raises
//     the pot, the record and the owner reserve by the SAME amount, so the per-owner
//     committed bound stays exact.

// zzmpPlainState is an AccessibleState WITHOUT the AtomicState capability — the
// single-chain / unwired host. Every governance-gated and atomic op must fail closed
// against it rather than fall back to a default authority.
type zzmpPlainState struct{ inner *nativeAtomicState }

func (s *zzmpPlainState) GetStateDB() contract.StateDB                     { return s.inner.GetStateDB() }
func (s *zzmpPlainState) GetBlockContext() contract.BlockContext           { return s.inner.GetBlockContext() }
func (s *zzmpPlainState) GetConsensusContext() context.Context             { return context.Background() }
func (s *zzmpPlainState) GetChainConfig() precompileconfig.ChainConfig     { return nil }
func (s *zzmpPlainState) GetPrecompileEnv() contract.PrecompileEnvironment { return nil }

var _ contract.AccessibleState = (*zzmpPlainState)(nil)

// zzmpPlain wraps a harness's state so it presents ONLY AccessibleState.
func zzmpPlain(h *settleHarness) *zzmpPlainState { return &zzmpPlainState{inner: h.state} }

// zzmpCreditFeeData builds creditPositionFee(bytes32 positionID, address asset, uint256 amount).
func zzmpCreditFeeData(positionID [32]byte, asset common.Address, amount *big.Int) []byte {
	data := make([]byte, 96)
	copy(data[0:32], positionID[:])
	copy(data[44:64], asset.Bytes())
	if amount != nil && amount.Sign() > 0 {
		amount.FillBytes(data[64:96])
	}
	return data
}

// ---------------------------------------------------------------------------
// seedSeamReserve
// ---------------------------------------------------------------------------

func TestZzmpSeedRefusesUnauthorizedAndUnconfiguredGovernance(t *testing.T) {
	h := newSettleHarness(t)
	body := zzmpAssetAmountData(common.Address{}, big.NewInt(100))
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(100))

	// A non-governance caller is refused even with the value delivered.
	if _, _, err := zzmpRun(h, h.caller, SelectorSeedSeamReserve, body, 5_000_000, false); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("seed by a non-governance caller: want ErrUnauthorized, got %v", err)
	}
	if got := loadSeamReserve(zzmpDB(h), h.inAssetID()); got.Sign() != 0 {
		t.Fatalf("an unauthorized seed credited the pot: %s", got)
	}
	if _, _, err := zzmpRun(h, h.caller, SelectorCreditPositionFee, zzmpCreditFeeData([32]byte{1}, common.Address{}, big.NewInt(1)), 5_000_000, false); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("creditPositionFee by a non-governance caller: want ErrUnauthorized, got %v", err)
	}

	// An UNCONFIGURED governance controller is fail-closed for EVERY caller, including
	// the zero address itself — there is no default key.
	saved := h.state.governance
	h.state.governance = common.Address{}
	for _, caller := range []common.Address{h.caller, saved, {}} {
		if _, _, err := zzmpRun(h, caller, SelectorSeedSeamReserve, body, 5_000_000, false); !errors.Is(err, ErrSettleNoGovernance) {
			t.Fatalf("seed with no governance controller (caller %s): want ErrSettleNoGovernance, got %v", caller.Hex(), err)
		}
		if _, _, err := zzmpRun(h, caller, SelectorCreditPositionFee, zzmpCreditFeeData([32]byte{1}, common.Address{}, big.NewInt(1)), 5_000_000, false); !errors.Is(err, ErrSettleNoGovernance) {
			t.Fatalf("creditPositionFee with no governance controller: want ErrSettleNoGovernance, got %v", err)
		}
	}
	h.state.governance = saved

	// A host with NO atomic capability at all is fail-closed the same way.
	if _, _, err := h.c.Run(zzmpPlain(h), h.operator(), poolManagerAddr9999, prependSelector(SelectorSeedSeamReserve, body), 5_000_000, false); !errors.Is(err, ErrSettleNoGovernance) {
		t.Fatalf("seed with no AtomicState: want ErrSettleNoGovernance, got %v", err)
	}
	if _, _, err := h.c.Run(zzmpPlain(h), h.operator(), poolManagerAddr9999, prependSelector(SelectorCreditPositionFee, zzmpCreditFeeData([32]byte{1}, common.Address{}, big.NewInt(1))), 5_000_000, false); !errors.Is(err, ErrSettleNoGovernance) {
		t.Fatalf("creditPositionFee with no AtomicState: want ErrSettleNoGovernance, got %v", err)
	}
}

func TestZzmpSeedRefusesReadOnlyOutOfGasShortInputAndZeroAmount(t *testing.T) {
	h := newSettleHarness(t)
	good := zzmpAssetAmountData(common.Address{}, big.NewInt(10))

	if _, gasLeft, err := zzmpRun(h, h.operator(), SelectorSeedSeamReserve, good, 5_000_000, true); err == nil {
		t.Fatal("read-only seed must be refused")
	} else if gasLeft != 5_000_000 {
		t.Fatalf("read-only refusal must charge no gas, got %d", gasLeft)
	}
	if _, gasLeft, err := zzmpRun(h, h.operator(), SelectorSeedSeamReserve, good, gasSeedReserve-1, false); err == nil {
		t.Fatal("seed under gasSeedReserve must be refused")
	} else if gasLeft != 0 {
		t.Fatalf("out-of-gas refusal must consume the supply, got %d", gasLeft)
	}
	for n := 0; n < 64; n++ {
		n := n
		zzmpNoPanic(t, "seed truncated body", func() {
			if _, _, err := zzmpRun(h, h.operator(), SelectorSeedSeamReserve, good[:n], 5_000_000, false); !errors.Is(err, ErrSeedShortInput) {
				t.Errorf("seed with a %d-byte body: want ErrSeedShortInput, got %v", n, err)
			}
		})
	}
	// A zero amount cannot open a pot credit (a value==0 seed must not be a no-op success).
	if _, _, err := zzmpRun(h, h.operator(), SelectorSeedSeamReserve, zzmpAssetAmountData(common.Address{}, big.NewInt(0)), 5_000_000, false); !errors.Is(err, ErrSeedBadAmount) {
		t.Fatalf("zero-amount seed: want ErrSeedBadAmount, got %v", err)
	}

	// Same three refusals on the fee-credit selector.
	fee := zzmpCreditFeeData([32]byte{7}, common.Address{}, big.NewInt(10))
	if _, gasLeft, err := zzmpRun(h, h.operator(), SelectorCreditPositionFee, fee, 5_000_000, true); err == nil {
		t.Fatal("read-only creditPositionFee must be refused")
	} else if gasLeft != 5_000_000 {
		t.Fatalf("read-only refusal must charge no gas, got %d", gasLeft)
	}
	if _, gasLeft, err := zzmpRun(h, h.operator(), SelectorCreditPositionFee, fee, gasSeedReserve-1, false); err == nil {
		t.Fatal("creditPositionFee under gasSeedReserve must be refused")
	} else if gasLeft != 0 {
		t.Fatalf("out-of-gas refusal must consume the supply, got %d", gasLeft)
	}
	for n := 0; n < 96; n++ {
		n := n
		zzmpNoPanic(t, "creditPositionFee truncated body", func() {
			if _, _, err := zzmpRun(h, h.operator(), SelectorCreditPositionFee, fee[:n], 5_000_000, false); !errors.Is(err, ErrSeedShortInput) {
				t.Errorf("creditPositionFee with a %d-byte body: want ErrSeedShortInput, got %v", n, err)
			}
		})
	}
	if _, _, err := zzmpRun(h, h.operator(), SelectorCreditPositionFee, zzmpCreditFeeData([32]byte{7}, common.Address{}, big.NewInt(0)), 5_000_000, false); !errors.Is(err, ErrSeedBadAmount) {
		t.Fatalf("zero-amount fee credit: want ErrSeedBadAmount, got %v", err)
	}
}

// TestZzmpSeedNativeRequiresDeliveredValue pins the seed's conservation gate: the pot
// may only rise by value the CALL delivered, measured against ALL THREE tracked pots.
func TestZzmpSeedNativeRequiresDeliveredValue(t *testing.T) {
	h := newSettleHarness(t)
	aid := h.inAssetID()
	db := zzmpDB(h)

	// No delivered value -> refused, pot untouched.
	if _, _, err := zzmpRun(h, h.operator(), SelectorSeedSeamReserve, zzmpAssetAmountData(common.Address{}, big.NewInt(500)), 5_000_000, false); !errors.Is(err, ErrSeedUndelivered) {
		t.Fatalf("undelivered native seed: want ErrSeedUndelivered, got %v", err)
	}
	if got := loadSeamReserve(db, aid); got.Sign() != 0 {
		t.Fatalf("a refused seed credited seamReserve: %s", got)
	}

	// Under-delivery (asked 500, carried 499) is refused too.
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(499))
	if _, _, err := zzmpRun(h, h.operator(), SelectorSeedSeamReserve, zzmpAssetAmountData(common.Address{}, big.NewInt(500)), 5_000_000, false); !errors.Is(err, ErrSeedUndelivered) {
		t.Fatalf("short native seed: want ErrSeedUndelivered, got %v", err)
	}

	// Exact delivery credits exactly the delivered amount.
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(1))
	out, _, err := zzmpRun(h, h.operator(), SelectorSeedSeamReserve, zzmpAssetAmountData(common.Address{}, big.NewInt(500)), 5_000_000, false)
	if err != nil {
		t.Fatalf("funded seed: %v", err)
	}
	if got := new(big.Int).SetBytes(out).Int64(); got != 500 {
		t.Fatalf("seed returned %d, want 500", got)
	}
	if got := loadSeamReserve(db, aid); got.Int64() != 500 {
		t.Fatalf("seamReserve after seed: want 500, got %s", got)
	}

	// THE DOUBLE-COUNT ATTACK: a second seed of the same 500 with NO new value must
	// refuse, because the already-credited pot is subtracted from the real balance.
	if _, _, err := zzmpRun(h, h.operator(), SelectorSeedSeamReserve, zzmpAssetAmountData(common.Address{}, big.NewInt(500)), 5_000_000, false); !errors.Is(err, ErrSeedUndelivered) {
		t.Fatalf("second value-free seed over the same native: want ErrSeedUndelivered, got %v", err)
	}
	if got := loadSeamReserve(db, aid); got.Int64() != 500 {
		t.Fatalf("seamReserve was double-credited: want 500, got %s", got)
	}
	// Conservation: real vault balance == Σ tracked pots.
	tracked := new(big.Int).Add(loadSettleVault(db, aid), loadSeamReserve(db, aid))
	tracked.Add(tracked, loadCommittedPositions(db, aid))
	if got := h.state.stateDB.GetBalance(poolManagerAddr9999).ToBig(); got.Cmp(tracked) != 0 {
		t.Fatalf("vault-account invariant broken: real=%s tracked=%s", got, tracked)
	}
}

// TestZzmpSeedNativeCreditsTheDeliveredAmountNotTheRequested pins the documented
// over-send rule: a native seed credits what the call actually CARRIED, so an
// over-send becomes real backing (conservation-preserving — it is the operator's own
// value) and can never credit more than was delivered.
func TestZzmpSeedNativeCreditsTheDeliveredAmountNotTheRequested(t *testing.T) {
	h := newSettleHarness(t)
	aid := h.inAssetID()
	db := zzmpDB(h)

	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(750)) // carried 750, asks for 500
	out, _, err := zzmpRun(h, h.operator(), SelectorSeedSeamReserve, zzmpAssetAmountData(common.Address{}, big.NewInt(500)), 5_000_000, false)
	if err != nil {
		t.Fatalf("over-sent seed: %v", err)
	}
	if got := new(big.Int).SetBytes(out).Int64(); got != 750 {
		t.Fatalf("over-sent seed credited %d — the DELIVERED 750 is the backing", got)
	}
	if got := loadSeamReserve(db, aid); got.Int64() != 750 {
		t.Fatalf("seamReserve: want 750, got %s", got)
	}
	// The pot never exceeds the vault's real holding.
	if got := h.state.stateDB.GetBalance(poolManagerAddr9999).Uint64(); got != 750 {
		t.Fatalf("real vault balance: want 750, got %d", got)
	}
}

// TestZzmpSeedNativeCountsAllThreePots proves the tracked baseline is the SUM of the
// three pots, not just settleVault: a depositor's funds already in settleVault must not
// be re-counted as an operator seed.
func TestZzmpSeedNativeCountsAllThreePots(t *testing.T) {
	h := newSettleHarness(t)
	aid := h.inAssetID()
	db := zzmpDB(h)

	// A depositor's 800 sits in settleVault, backed by real native.
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(800))
	if _, _, err := zzmpRun(h, h.caller, SelectorDeposit, zzmpAssetAmountData(common.Address{}, big.NewInt(800)), 5_000_000, false); err != nil {
		t.Fatalf("deposit: %v", err)
	}
	// The operator now tries to "seed" 800 without delivering any value: the depositor's
	// native is already tracked, so nothing was delivered.
	if _, _, err := zzmpRun(h, h.operator(), SelectorSeedSeamReserve, zzmpAssetAmountData(common.Address{}, big.NewInt(800)), 5_000_000, false); !errors.Is(err, ErrSeedUndelivered) {
		t.Fatalf("seed over a depositor's tracked native: want ErrSeedUndelivered, got %v", err)
	}
	if got := loadDepositorClaim(db, h.caller, aid); got.Int64() != 800 {
		t.Fatalf("the depositor's claim changed: want 800, got %s", got)
	}
	if got := loadSeamReserve(db, aid); got.Sign() != 0 {
		t.Fatalf("seamReserve took a depositor's funds: %s", got)
	}
}

func TestZzmpSeedRefusesReentrantEntry(t *testing.T) {
	h := newSettleHarness(t)
	zzmpDB(h).SetState(poolManagerAddr9999, custodyGuardKey9999, common.Hash{31: 1})
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(100))

	if _, _, err := zzmpRun(h, h.operator(), SelectorSeedSeamReserve, zzmpAssetAmountData(common.Address{}, big.NewInt(100)), 5_000_000, false); !errors.Is(err, ErrCustodyReentrant) {
		t.Fatalf("re-entered seed: want ErrCustodyReentrant, got %v", err)
	}
	if _, _, err := zzmpRun(h, h.operator(), SelectorCreditPositionFee, zzmpCreditFeeData([32]byte{9}, common.Address{}, big.NewInt(100)), 5_000_000, false); !errors.Is(err, ErrCustodyReentrant) {
		t.Fatalf("re-entered creditPositionFee: want ErrCustodyReentrant, got %v", err)
	}
}

func TestZzmpSeedERC20MovesRealTokenValue(t *testing.T) {
	h := newSettleHarness(t)
	token := h.outToken()
	aid := h.outAssetID()
	db := zzmpDB(h)

	h.wrapper().mintTestToken(token, h.operator(), big.NewInt(2_000))
	out, _, err := zzmpRun(h, h.operator(), SelectorSeedSeamReserve, zzmpAssetAmountData(token, big.NewInt(1_200)), 5_000_000, false)
	if err != nil {
		t.Fatalf("erc20 seed: %v", err)
	}
	if got := new(big.Int).SetBytes(out).Int64(); got != 1_200 {
		t.Fatalf("erc20 seed returned %d, want 1200", got)
	}
	if got := loadSeamReserve(db, aid); got.Int64() != 1_200 {
		t.Fatalf("seamReserve: want 1200, got %s", got)
	}
	if got := h.wrapper().TokenBalanceOf(token, poolManagerAddr9999); got.Int64() != 1_200 {
		t.Fatalf("vault token holding: want 1200, got %s", got)
	}
	if got := h.wrapper().TokenBalanceOf(token, h.operator()); got.Int64() != 800 {
		t.Fatalf("operator token balance: want 800, got %s", got)
	}

	// An under-delivering token is refused (fail-secure: never an unbacked pot credit).
	h.state.stateDB.feeOnTransferBps = 250
	if _, _, err := zzmpRun(h, h.operator(), SelectorSeedSeamReserve, zzmpAssetAmountData(token, big.NewInt(400)), 5_000_000, false); !errors.Is(err, ErrERC20UnderDelivered) {
		t.Fatalf("under-delivering erc20 seed: want ErrERC20UnderDelivered, got %v", err)
	}
	h.state.stateDB.feeOnTransferBps = 0
	// An operator with no tokens left cannot seed.
	if _, _, err := zzmpRun(h, h.operator(), SelectorSeedSeamReserve, zzmpAssetAmountData(token, big.NewInt(10_000)), 5_000_000, false); !errors.Is(err, ErrERC20TransferFailed) {
		t.Fatalf("unfunded erc20 seed: want ErrERC20TransferFailed, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// creditPositionFee
// ---------------------------------------------------------------------------

func TestZzmpCreditPositionFeeRequiresAnOpenPositionInItsOwnAsset(t *testing.T) {
	h := newSettleHarness(t)
	db := zzmpDB(h)

	// An unknown position id names nothing.
	if _, _, err := zzmpRun(h, h.operator(), SelectorCreditPositionFee, zzmpCreditFeeData([32]byte{0xAB}, common.Address{}, big.NewInt(100)), 5_000_000, false); !errors.Is(err, ErrFeeNoPosition) {
		t.Fatalf("fee credit to an unknown position: want ErrFeeNoPosition, got %v", err)
	}

	// A CLOSED (cancelled) position is terminal and takes no more fees.
	closed := [32]byte{0xC0}
	storeRestingOrder(db, closed, RestingOrder{
		Owner: h.caller, LockedAsset: h.inAssetID(), LockedAmt: big.NewInt(0), Status: OrderStatusCancelled,
	})
	if _, _, err := zzmpRun(h, h.operator(), SelectorCreditPositionFee, zzmpCreditFeeData(closed, common.Address{}, big.NewInt(100)), 5_000_000, false); !errors.Is(err, ErrFeeNoPosition) {
		t.Fatalf("fee credit to a closed position: want ErrFeeNoPosition, got %v", err)
	}

	// An OPEN position takes fees only in ITS OWN locked asset.
	open := [32]byte{0x0B}
	storeRestingOrder(db, open, RestingOrder{
		Owner: h.caller, LockedAsset: h.inAssetID(), LockedAmt: big.NewInt(500), Status: OrderStatusOpen,
	})
	storeLockedReserve(db, h.caller, h.inAssetID(), big.NewInt(500))
	if _, _, err := zzmpRun(h, h.operator(), SelectorCreditPositionFee, zzmpCreditFeeData(open, h.outToken(), big.NewInt(100)), 5_000_000, false); !errors.Is(err, ErrFeeNoPosition) {
		t.Fatalf("fee credit in a FOREIGN asset: want ErrFeeNoPosition, got %v", err)
	}
	if got := loadRestingOrder(db, open).LockedAmt; got.Int64() != 500 {
		t.Fatalf("a refused fee credit changed the record: want 500, got %s", got)
	}

	// The honest credit raises the POT, the RECORD and the OWNER RESERVE by the SAME
	// amount — the per-owner committed bound stays exact.
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(100)) // host frame delivered msg.value
	out, _, err := zzmpRun(h, h.operator(), SelectorCreditPositionFee, zzmpCreditFeeData(open, common.Address{}, big.NewInt(100)), 5_000_000, false)
	if err != nil {
		t.Fatalf("fee credit: %v", err)
	}
	if got := new(big.Int).SetBytes(out).Int64(); got != 100 {
		t.Fatalf("fee credit returned %d, want 100", got)
	}
	if got := loadCommittedPositions(db, h.inAssetID()); got.Int64() != 100 {
		t.Fatalf("committedPositions: want 100, got %s", got)
	}
	if got := loadRestingOrder(db, open).LockedAmt; got.Int64() != 600 {
		t.Fatalf("record LockedAmt: want 600, got %s", got)
	}
	if got := loadLockedReserve(db, h.caller, h.inAssetID()); got.Int64() != 600 {
		t.Fatalf("owner locked reserve: want 600, got %s", got)
	}

	// And a CLOSING position (a withdraw already requested) still takes fees.
	closing := [32]byte{0xC1}
	storeRestingOrder(db, closing, RestingOrder{
		Owner: h.caller, LockedAsset: h.inAssetID(), LockedAmt: big.NewInt(10), Status: OrderStatusClosing,
	})
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(7))
	if _, _, err := zzmpRun(h, h.operator(), SelectorCreditPositionFee, zzmpCreditFeeData(closing, common.Address{}, big.NewInt(7)), 5_000_000, false); err != nil {
		t.Fatalf("fee credit to a CLOSING position must be allowed, got %v", err)
	}
	if got := loadRestingOrder(db, closing).LockedAmt; got.Int64() != 17 {
		t.Fatalf("closing record LockedAmt: want 17, got %s", got)
	}
}

// TestZzmpCreditPositionFeeNativeRequiresDeliveredValue pins that a fee credit is
// value-backed exactly like a seed: no delivered native, no credit.
func TestZzmpCreditPositionFeeNativeRequiresDeliveredValue(t *testing.T) {
	h := newSettleHarness(t)
	db := zzmpDB(h)
	pos := [32]byte{0x0F}
	storeRestingOrder(db, pos, RestingOrder{
		Owner: h.caller, LockedAsset: h.inAssetID(), LockedAmt: big.NewInt(100), Status: OrderStatusOpen,
	})

	if _, _, err := zzmpRun(h, h.operator(), SelectorCreditPositionFee, zzmpCreditFeeData(pos, common.Address{}, big.NewInt(50)), 5_000_000, false); !errors.Is(err, ErrSeedUndelivered) {
		t.Fatalf("undelivered native fee credit: want ErrSeedUndelivered, got %v", err)
	}
	if got := loadRestingOrder(db, pos).LockedAmt; got.Int64() != 100 {
		t.Fatalf("a refused fee credit raised the record: want 100, got %s", got)
	}
	if got := loadCommittedPositions(db, h.inAssetID()); got.Sign() != 0 {
		t.Fatalf("a refused fee credit raised the pot: %s", got)
	}
}

func TestZzmpCreditPositionFeeERC20MovesRealTokenValue(t *testing.T) {
	h := newSettleHarness(t)
	db := zzmpDB(h)
	token := h.outToken()
	aid := h.outAssetID()

	pos := [32]byte{0xE2}
	storeRestingOrder(db, pos, RestingOrder{
		Owner: h.caller, LockedAsset: aid, LockedAmt: big.NewInt(300), Status: OrderStatusOpen,
	})
	storeLockedReserve(db, h.caller, aid, big.NewInt(300))
	h.wrapper().mintTestToken(token, h.operator(), big.NewInt(90))

	if _, _, err := zzmpRun(h, h.operator(), SelectorCreditPositionFee, zzmpCreditFeeData(pos, token, big.NewInt(90)), 5_000_000, false); err != nil {
		t.Fatalf("erc20 fee credit: %v", err)
	}
	if got := loadRestingOrder(db, pos).LockedAmt; got.Int64() != 390 {
		t.Fatalf("record LockedAmt: want 390, got %s", got)
	}
	if got := loadCommittedPositions(db, aid); got.Int64() != 90 {
		t.Fatalf("committedPositions: want 90, got %s", got)
	}
	if got := loadLockedReserve(db, h.caller, aid); got.Int64() != 390 {
		t.Fatalf("owner reserve: want 390, got %s", got)
	}
	if got := h.wrapper().TokenBalanceOf(token, poolManagerAddr9999); got.Int64() != 90 {
		t.Fatalf("vault token holding: want 90, got %s", got)
	}
}

// ---------------------------------------------------------------------------
// receiveOperatorValue / decodeAssetAmount, called directly
// ---------------------------------------------------------------------------

// TestZzmpReceiveOperatorValueRefusesWithoutAnERC20Vault covers the fail-closed ERC-20
// branch by handing receiveOperatorValue a StateDB with NO vault capability, and pins
// that a `record` failure aborts the receive rather than being swallowed.
func TestZzmpReceiveOperatorValueRefusesWithoutAnERC20Vault(t *testing.T) {
	plain := NewMockStateDB() // implements dex.StateDB, but is no erc20Vault
	token := common.HexToAddress("0x00000000000000000000000000000000000000FF")
	asset := Currency{Address: token}
	aid := assetID(asset)

	if _, err := receiveOperatorValue(plain, common.Address{}, asset, aid, big.NewInt(10), func(*big.Int) error { return nil }); !errors.Is(err, ErrSettleERC20Vault) {
		t.Fatalf("erc20 receive with no vault: want ErrSettleERC20Vault, got %v", err)
	}

	// A native amount that does not fit uint256 can never be moved as balance, so the
	// receive refuses instead of truncating it.
	huge := new(big.Int).Lsh(big.NewInt(1), 300)
	if _, err := receiveOperatorValue(plain, common.Address{}, Currency{}, [32]byte{}, huge, func(*big.Int) error {
		t.Fatal("record must not run for an out-of-range native amount")
		return nil
	}); !errors.Is(err, ErrSeedBadAmount) {
		t.Fatalf("out-of-uint256 native receive: want ErrSeedBadAmount, got %v", err)
	}

	// A failing `record` (Phase A) aborts BEFORE the terminal pull, on both legs.
	boom := errors.New("zzmp record refused")
	h := newSettleHarness(t)
	h.wrapper().mintTestToken(token, h.operator(), big.NewInt(100))
	if _, err := receiveOperatorValue(zzmpDB(h), h.operator(), asset, aid, big.NewInt(10), func(*big.Int) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("erc20 receive with a failing record: want the record error, got %v", err)
	}
	if got := h.wrapper().TokenBalanceOf(token, poolManagerAddr9999); got.Sign() != 0 {
		t.Fatalf("a record failure still pulled %s of the token", got)
	}
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(10))
	if _, err := receiveOperatorValue(zzmpDB(h), h.operator(), Currency{}, [32]byte{}, big.NewInt(10), func(*big.Int) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("native receive with a failing record: want the record error, got %v", err)
	}
}

// TestZzmpDecodeAssetAmountRefusesEveryMalformedWidth feeds every prefix of a valid
// 2-word body plus an out-of-uint256 amount.
func TestZzmpDecodeAssetAmountRefusesEveryMalformedWidth(t *testing.T) {
	good := zzmpAssetAmountData(common.HexToAddress("0x0000000000000000000000000000000000000042"), big.NewInt(7))
	for n := 0; n < 64; n++ {
		if _, _, err := decodeAssetAmount(good[:n]); !errors.Is(err, ErrSeedShortInput) {
			t.Fatalf("decodeAssetAmount(%d bytes): want ErrSeedShortInput, got %v", n, err)
		}
	}
	asset, amount, err := decodeAssetAmount(good)
	if err != nil {
		t.Fatalf("decodeAssetAmount(valid): %v", err)
	}
	if asset.Address != common.HexToAddress("0x0000000000000000000000000000000000000042") || amount.Int64() != 7 {
		t.Fatalf("decodeAssetAmount(valid) = %s/%s", asset.Address.Hex(), amount)
	}
	// Trailing bytes beyond the two words are ignored, not a refusal.
	if _, _, err := decodeAssetAmount(append(append([]byte{}, good...), 0xFF)); err != nil {
		t.Fatalf("decodeAssetAmount with a longer body: %v", err)
	}
	// Zero amount refused.
	if _, _, err := decodeAssetAmount(zzmpAssetAmountData(common.Address{}, big.NewInt(0))); !errors.Is(err, ErrSeedBadAmount) {
		t.Fatalf("decodeAssetAmount(0): want ErrSeedBadAmount, got %v", err)
	}
}
