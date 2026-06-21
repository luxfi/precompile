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
// ERC-20: transferFrom observed delta. protocolFeeController-gated.
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
	if caller != s.protocolFeeController {
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
	delivered, derr := receiveOperatorValue(stateDB, caller, asset, aid, amount)
	if derr != nil {
		return nil, gasLeft, derr
	}
	storeSeamReserve(stateDB, aid, new(big.Int).Add(loadSeamReserve(stateDB, aid), delivered))
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
// is backed by deposited value). protocolFeeController-gated.
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
	if caller != s.protocolFeeController {
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
	delivered, derr := receiveOperatorValue(stateDB, caller, asset, aid, amount)
	if derr != nil {
		return nil, gasLeft, derr
	}
	// Back the collect: the pot, the record's withdrawable, and the owner reserve all
	// rise by the delivered fee — keeping committedPositions == Σ live records'
	// LockedAmt and the per-owner bound exact.
	storeCommittedPositions(stateDB, aid, new(big.Int).Add(loadCommittedPositions(stateDB, aid), delivered))
	order.LockedAmt = new(big.Int).Add(order.LockedAmt, delivered)
	storeRestingOrder(stateDB, positionID, order)
	storeLockedReserve(stateDB, order.Owner, aid,
		new(big.Int).Add(loadLockedReserve(stateDB, order.Owner, aid), delivered))
	out := make([]byte, 32)
	delivered.FillBytes(out)
	return out, gasLeft, nil
}

// receiveOperatorValue moves operator-delivered value INTO the 0x9999 vault and
// returns the amount that ACTUALLY arrived. Native uses the observed-delta discipline
// (the host frame already moved msg.value into 0x9999; delivered = realBal − Σ tracked
// pots), so a value==0 seed delivers 0 and the caller reverts on the unbacked check.
// ERC-20 uses the vault transferFrom observed delta (fee-on-transfer safe). It does NOT
// itself touch any pot — the caller records the delivered value in the target pot,
// keeping the vault-account invariant intact.
func receiveOperatorValue(stateDB StateDB, caller common.Address, asset Currency, aid [32]byte, amount *big.Int) (*big.Int, error) {
	if isNativeAsset(aid) {
		if _, of := uint256.FromBig(amount); of {
			return nil, ErrSeedBadAmount
		}
		// delivered = realBal − (settleVault + makerLockedVault + seamReserve +
		// committedPositions): the native this call carried, since every native-moving
		// path keeps the four pots in lock-step with the vault's real native balance.
		realBal := stateDB.GetBalance(poolManagerAddr9999).ToBig()
		tracked := new(big.Int).Add(loadSettleVault(stateDB, aid), loadMakerLockedVault(stateDB, aid))
		tracked.Add(tracked, loadSeamReserve(stateDB, aid))
		tracked.Add(tracked, loadCommittedPositions(stateDB, aid))
		delivered := new(big.Int).Sub(realBal, tracked)
		if delivered.Sign() < 0 || delivered.Cmp(amount) < 0 {
			return nil, ErrSeedUndelivered
		}
		// Return what ACTUALLY arrived, not the requested amount — symmetric with the
		// ERC-20 branch's observed delta below. The caller records this in the target
		// pot, so an operator over-send is captured as real backing instead of stranded
		// (keeps the four pots tracking the vault's real balance; realHolding >= Σ pots
		// always holds, and == in the normal seed flow).
		return delivered, nil
	}
	vault, ok := stateDBERC20(stateDB)
	if !ok {
		return nil, ErrSettleERC20Vault
	}
	delta, err := safeTransferTokenFrom(vault, asset.Address, caller, poolManagerAddr9999, amount)
	if err != nil {
		return nil, err
	}
	return delta, nil
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
