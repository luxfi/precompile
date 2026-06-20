// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"

	"github.com/luxfi/geth/common"
)

// halt9999.go is the MULTI-LAYER HALT for the 0x9999 settlement path. Authority
// is the protocolFeeController (governance), the SAME authority that gates the
// existing pauseDEX/freezePool controls — one authority, not a new one.
//
// Halt state is DURABLE, consensus-shared StateDB read STRAIGHT from state on
// every settle (never cached in a process field). This is the RED V6 invariant
// the existing pause path relies on: if a halt-set tx reverts, its StateDB write
// reverts with it and the next call reads the un-halted value, so a reverted halt
// can never wedge the DEX permanently. A halted swap reverts cleanly with NO
// partial state (EVM revert rolls back every prior SetState/balance change).
//
// SAFE DEFAULT: halting stops NEW swaps but NEVER strands funds — withdraw /
// balanceOf / cancel / settle remain callable so escrowed value can always exit.
// The withdraw path lives on the deprecated-but-forwarding custody selectors and
// is intentionally NOT gated by the swap halt.

// Halt layers (each an independent key; checked in order, cheapest scope first).
var (
	haltGlobalKey          = makeStorageKey([]byte(settleStateNamespace+"h.glb"), []byte{})
	haltMarketPrefix       = []byte(settleStateNamespace + "h.mkt")
	haltAssetPrefix        = []byte(settleStateNamespace + "h.ast")
	haltReceiptTypePrefix  = []byte(settleStateNamespace + "h.crt")
	haltValidatorSetPrefix = []byte(settleStateNamespace + "h.vst")
)

// Halt errors (each a clean revert reason).
var (
	ErrDEXHalted        = errors.New("dex: settlement halted (global)")
	ErrMarketHalted     = errors.New("dex: settlement halted for this market")
	ErrAssetHalted      = errors.New("dex: settlement halted for this asset")
	ErrCertTypeDisabled = errors.New("dex: settlement disabled for this certificate type")
	ErrVSetHalted       = errors.New("dex: settlement halted for this validator set")
)

// haltSet is the non-zero sentinel a halt slot holds when active. Any non-zero
// value means halted; we write a fixed 1 for clarity.
var haltSet = common.Hash{31: 1}

func isHalted(stateDB stateKV, key common.Hash) bool {
	return stateDB.GetState(poolManagerAddr9999, key) != (common.Hash{})
}

// checkHalt is the single, ordered halt gate the settle handler calls before any
// crypto or value movement. Returns the FIRST applicable halt error, or nil.
func checkHalt(stateDB stateKV, r *DFillReceiptV1, cert *BLSCert) error {
	if isHalted(stateDB, haltGlobalKey) {
		return ErrDEXHalted
	}
	// MARKET halt keys on the POOL identity (r.PoolKeyHash), NOT the free-form
	// r.MarketID. PoolKeyHash is validated == key.ID() in BindToSwap and is the SAME
	// id SetHaltMarket callers, the registry, analytics, and StateView all use — so
	// the kill switch addresses exactly the market operators halt. Keying on the
	// attacker-supplied MarketID would let a compromised market dodge the halt by
	// emitting receipts whose MarketID != its pool id (it controls that field).
	if isHalted(stateDB, makeStorageKey(haltMarketPrefix, r.PoolKeyHash[:])) {
		return ErrMarketHalted
	}
	if isHalted(stateDB, makeStorageKey(haltAssetPrefix, r.TokenInAssetID[:])) ||
		isHalted(stateDB, makeStorageKey(haltAssetPrefix, r.TokenOutAssetID[:])) {
		return ErrAssetHalted
	}
	if isHalted(stateDB, makeStorageKey(haltReceiptTypePrefix, []byte{byte(r.CertType)})) {
		return ErrCertTypeDisabled
	}
	if isHalted(stateDB, makeStorageKey(haltValidatorSetPrefix, cert.ValidatorSetID[:])) {
		return ErrVSetHalted
	}
	return nil
}

// --- Governance setters (protocolFeeController-gated; the caller checks authority).

// SetHaltGlobal halts/unhalts all new settlement.
func SetHaltGlobal(stateDB stateKV, on bool) { setHalt(stateDB, haltGlobalKey, on) }

// SetHaltMarket halts/unhalts settlement for one market (poolKeyHash / marketID).
func SetHaltMarket(stateDB stateKV, marketID [32]byte, on bool) {
	setHalt(stateDB, makeStorageKey(haltMarketPrefix, marketID[:]), on)
}

// SetHaltAsset halts/unhalts settlement touching one asset (injective AssetID).
func SetHaltAsset(stateDB stateKV, assetID [32]byte, on bool) {
	setHalt(stateDB, makeStorageKey(haltAssetPrefix, assetID[:]), on)
}

// SetHaltReceiptType disables/enables settlement for one certType (e.g. retire a
// scheme during a cert upgrade).
func SetHaltReceiptType(stateDB stateKV, ct CertType, on bool) {
	setHalt(stateDB, makeStorageKey(haltReceiptTypePrefix, []byte{byte(ct)}), on)
}

// SetHaltValidatorSet halts/unhalts settlement certified by one validator set
// (e.g. a compromised/rotated set).
func SetHaltValidatorSet(stateDB stateKV, validatorSetID [32]byte, on bool) {
	setHalt(stateDB, makeStorageKey(haltValidatorSetPrefix, validatorSetID[:]), on)
}

func setHalt(stateDB stateKV, key common.Hash, on bool) {
	if on {
		stateDB.SetState(poolManagerAddr9999, key, haltSet)
	} else {
		stateDB.SetState(poolManagerAddr9999, key, common.Hash{})
	}
}
