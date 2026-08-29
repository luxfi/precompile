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

// ---------------------------------------------------------------------------
// creditPositionFee
// ---------------------------------------------------------------------------

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
