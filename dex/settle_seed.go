// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// settle_seed.go is the PRODUCTION operator-funding surface for the two settlement
// pots a D->C credit draws on — the swap rail's seamReserve and the LP rail's
// committedPositions — replacing the test-only fundVaultOut / seedCommittedNative
// helpers with real, operator-gated, value-backed selectors (FIX-4 / the LP fee
// analog).
//
// WHY A SEED IS NEEDED (the liveness gap FIX-4 closes): a swap-rail D->C settlement
// credits the taker out of seamReserve[assetOut] (creditSettlementOutput). seamReserve
// is funded by the tokenIn legs of OPPOSING-direction intents (an A->B taker locks A
// into seamReserve[A], funding a later B->A taker's A-out). So a BALANCED two-sided
// taker flow self-funds: every asset a taker receives was locked by an opposing taker.
// But the FIRST matched swap of an output asset — or a persistently imbalanced market
// — has no opposing lock yet, so seamReserve[assetOut] is empty and the first fill
// would revert ErrNativeSettleUnbacked. The operator seeds the counterparty backing
// once at market bring-up; thereafter opposing flow sustains it. This selector is the
// real (not test-only) path for that seed, gated to the protocolFeeController.
//
// CONSERVATION: a seed moves REAL value INTO the 0x9999 vault (native via the host
// call frame's msg.value, observed-delta-checked exactly like deposit; ERC-20 via the
// vault transferFrom observed delta) and records it in the target pot, so the
// vault-account invariant (realHolding == settleVault + makerLockedVault + seamReserve
// + committedPositions) is preserved — the seed is backed by deposited value, never a
// bookkeeping mint. A seed is NOT withdrawable as a depositor claim; it is the
// operator's committed counterparty/fee backing for that rail.

const gasSeedReserve uint64 = 30_000

var (
	// SelectorSeedSeamReserve funds the SWAP rail's seamReserve[asset] (operator
	// counterparty backing): seedSeamReserve(address asset, uint256 amount). Gated to
	// the protocolFeeController.
	SelectorSeedSeamReserve uint32 // seedSeamReserve(address,uint256)
	// SelectorCreditPositionFee credits an LP position's earned fees into BOTH the
	// position record's withdrawable backing and the LP rail's committedPositions pot:
	// creditPositionFee(bytes32 positionID, address asset, uint256 amount). It is the
	// keeper's per-owner reflection of fees the D-Chain CLOB credited a maker, so the
	// LP can collect principal+fees while the per-owner committed bound (FIX-2) still
	// holds (fees raise THIS owner's record, never the shared pot's principal slice).
	// Gated to the protocolFeeController.
	SelectorCreditPositionFee uint32 // creditPositionFee(bytes32,address,uint256)
)

var (
	ErrSeedShortInput  = errors.New("dex: seed input too short")
	ErrSeedBadAmount   = errors.New("dex: seed amount out of range")
	ErrSeedUndelivered = errors.New("dex: native seed requires msg.value == amount (value not delivered this call)")
	ErrFeeNoPosition   = errors.New("dex: creditPositionFee names no open/closing position")
)

// runSeedSeamReserve funds seamReserve[asset] from operator-delivered value. Native:
// observed-delta (the host frame moved msg.value into 0x9999; delivered = realBal −
// Σpots), exactly the deposit discipline so a value==0 seed delivers 0 and reverts.
// ERC-20: transferFrom observed delta. Gated to the per-network DEX governance
// controller (governanceController), resolved from the runtime AtomicState — never a
// hardcoded key; fail-closed when no governance controller is configured.
func (s *SettleContract) runSeedSeamReserve(
	state contract.AccessibleState, caller common.Address, input []byte, gas uint64, readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, gas, errors.New("dex: cannot seed in read-only mode")
	}
	if gas < gasSeedReserve {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := gas - gasSeedReserve
	gov, gerr := governanceController(state)
	if gerr != nil {
		return nil, gasLeft, gerr
	}
	if caller != gov {
		return nil, gasLeft, ErrUnauthorized
	}
	asset, amount, perr := decodeAssetAmount(input)
	if perr != nil {
		return nil, gasLeft, perr
	}
	stateDB := newPoolStateAdapter(state)
	if !enterCustodyKV(stateDB) {
		return nil, gasLeft, ErrCustodyReentrant
	}
	defer exitCustodyKV(stateDB)

	aid := assetID(asset)
	// PHASE A (record) credits seamReserve BEFORE the terminal ERC-20 pull, so the seed's
	// accounting is never dropped by the geth nested-call host bug.
	delivered, derr := receiveOperatorValue(stateDB, caller, asset, aid, amount, func(amt *big.Int) error {
		storeSeamReserve(stateDB, aid, new(big.Int).Add(loadSeamReserve(stateDB, aid), amt))
		return nil
	})
	if derr != nil {
		return nil, gasLeft, derr
	}
	out := make([]byte, 32)
	delivered.FillBytes(out)
	return out, gasLeft, nil
}

// runCreditPositionFee credits an LP position's earned fees: it receives operator
// value into the vault, adds it to committedPositions[asset] (the LP-rail pot backing
// the collect), raises the NAMED position record's LockedAmt and the owner's per-asset
// committed reserve by the same amount. So a maker's withdrawable rises with the fees
// the D-Chain credited them, the per-owner committed bound stays exact (a collect can
// still only pull up to THIS owner's record), and conservation holds (the fee credit
// is backed by deposited value). Gated to the per-network DEX governance controller
// (governanceController), resolved from the runtime AtomicState — never a hardcoded
// key; fail-closed when no governance controller is configured.
func (s *SettleContract) runCreditPositionFee(
	state contract.AccessibleState, caller common.Address, input []byte, gas uint64, readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, gas, errors.New("dex: cannot credit fees in read-only mode")
	}
	if gas < gasSeedReserve {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := gas - gasSeedReserve
	gov, gerr := governanceController(state)
	if gerr != nil {
		return nil, gasLeft, gerr
	}
	if caller != gov {
		return nil, gasLeft, ErrUnauthorized
	}
	if len(input) < 96 {
		return nil, gasLeft, ErrSeedShortInput
	}
	var positionID [32]byte
	copy(positionID[:], input[0:32])
	asset := Currency{Address: common.BytesToAddress(input[44:64])}
	amount := new(big.Int).SetBytes(input[64:96])
	if amount.Sign() <= 0 || !isWord(amount) {
		return nil, gasLeft, ErrSeedBadAmount
	}
	stateDB := newPoolStateAdapter(state)
	if !enterCustodyKV(stateDB) {
		return nil, gasLeft, ErrCustodyReentrant
	}
	defer exitCustodyKV(stateDB)

	order := loadRestingOrder(stateDB, positionID)
	if order.Status != OrderStatusOpen && order.Status != OrderStatusClosing {
		return nil, gasLeft, ErrFeeNoPosition
	}
	aid := assetID(asset)
	if aid != order.LockedAsset {
		return nil, gasLeft, ErrFeeNoPosition // fees credit the position's own locked asset.
	}
	// PHASE A (record): back the collect BEFORE the terminal ERC-20 pull — the pot, the
	// record's withdrawable, and the owner reserve all rise by the credited fee, keeping
	// committedPositions == Σ live records' LockedAmt and the per-owner bound exact. Recording
	// before the transfer is the geth nested-call fund-loss fix (the prior order dropped these
	// writes for an ERC-20 fee credit).
	delivered, derr := receiveOperatorValue(stateDB, caller, asset, aid, amount, func(amt *big.Int) error {
		storeCommittedPositions(stateDB, aid, new(big.Int).Add(loadCommittedPositions(stateDB, aid), amt))
		order.LockedAmt = new(big.Int).Add(order.LockedAmt, amt)
		storeRestingOrder(stateDB, positionID, order)
		storeLockedReserve(stateDB, order.Owner, aid,
			new(big.Int).Add(loadLockedReserve(stateDB, order.Owner, aid), amt))
		return nil
	})
	if derr != nil {
		return nil, gasLeft, derr
	}
	out := make([]byte, 32)
	delivered.FillBytes(out)
	return out, gasLeft, nil
}

// receiveOperatorValue moves operator-delivered value INTO the 0x9999 vault and records it in
// the target pot via `record` using the NATIVE-ZAP two-phase discipline (the geth nested-call
// fund-loss fix): the pot write (Phase A, via `record`) happens BEFORE the ERC-20 transferFrom
// (Phase B, terminal), so the host bug cannot drop the seed's accounting (which it did — the
// ERC-20 seed moved the token but lost the seamReserve/committedPositions credit => a stranded,
// liveness-ineffective seed).
//
//   - NATIVE: observed-delta read (the host frame already moved msg.value into 0x9999; delivered
//     = realBal − Σ tracked pots), no nested call, so `record(delivered)` is Phase A and safe.
//     A value==0 seed delivers 0 and reverts; an over-send is captured as real backing.
//   - ERC-20: `record(requested)` runs in Phase A, then the single transferFrom is the terminal
//     effect and asserts the vault received at least `requested` (under-delivery reverts the
//     whole frame, the recorded pot write included — never an unbacked seed credit).
//
// Returns the recorded amount (delivered for native, requested for ERC-20).
func receiveOperatorValue(stateDB StateDB, caller common.Address, asset Currency, aid [32]byte, amount *big.Int, record func(*big.Int) error) (*big.Int, error) {
	if isNativeAsset(aid) {
		if _, of := uint256.FromBig(amount); of {
			return nil, ErrSeedBadAmount
		}
		// deliveredNative (native_zap.go) is the one answer to how much native this call
		// carried: the vault's real balance less every pot already accounted for.
		delivered := deliveredNative(stateDB, aid)
		if delivered.Sign() < 0 || delivered.Cmp(amount) < 0 {
			return nil, ErrSeedUndelivered
		}
		if err := record(delivered); err != nil {
			return nil, err
		}
		return delivered, nil
	}
	vault, ok := stateDBERC20(stateDB)
	if !ok {
		return nil, ErrSettleERC20Vault
	}
	// PHASE A — record the REQUESTED amount in the target pot, BEFORE the terminal pull.
	if err := record(amount); err != nil {
		return nil, err
	}
	// PHASE B — terminal transferFrom; revert (rolling back `record`) on under-delivery.
	if err := pullERC20Terminal(vault, asset.Address, caller, amount); err != nil {
		return nil, err
	}
	return amount, nil
}

// decodeAssetAmount reads (address asset, uint256 amount) from a 2-word calldata
// (the deposit/seed shape). The asset is the right-20-bytes of word 0.
func decodeAssetAmount(input []byte) (Currency, *big.Int, error) {
	if len(input) < 64 {
		return Currency{}, nil, ErrSeedShortInput
	}
	asset := Currency{Address: common.BytesToAddress(input[12:32])}
	amount := new(big.Int).SetBytes(input[32:64])
	if amount.Sign() <= 0 || !isWord(amount) {
		return Currency{}, nil, ErrSeedBadAmount
	}
	return asset, amount, nil
}
