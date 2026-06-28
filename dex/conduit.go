// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/precompile/contract"
)

// conduit.go is the LP-311 STATELESS 0x9999 CONDUIT — the decomplected money path that
// dissolves the empty-account reaping hazard at its cause.
//
// ── THE INVARIANT (LP-311 §5, the gate to live) ─────────────────────────────────────
// The conduit writes ZERO durable storage to its OWN (0x9999) account. Its only state
// mutations are:
//
//	(a) the conduit's NATIVE balance       — escrow of native LUX (makes 0x9999 non-empty
//	                                          only WHILE native value is held; reaped clean
//	                                          when it returns to zero).
//	(b) the TOKEN contract's trie          — escrow of an ERC-20 (balanceOf(token,0x9999));
//	                                          another account's storage, never reaped with
//	                                          0x9999.
//	(c) the HOST atomic-staging account     — the cross-domain C->D / D->C objects, staged
//	                                          via contract.AtomicStager into the HOST's own
//	                                          NON-EMPTY account (the host atomic backend),
//	                                          NEVER 0x9999's account.
//	(d) an EIP-1153 TRANSIENT reentrancy guard — txn-scoped, journaled, never persisted.
//
// No persistent SetState(0x9999, …) survives the transaction. Therefore an ERC-20-only
// deposit leaves 0x9999 EMPTY (nonce==0 ∧ balance==0 ∧ codeHash==∅), and geth's
// Finalise(deleteEmptyObjects=true) reaping that empty account is a NO-OP: there is no
// own-storage to lose, the ERC-20 escrow sits in the token's trie, and the claim on it is
// a D-Chain ledger row. The nonce marker (ensureVaultAccountPersists) is unnecessary and
// is not used on this path.
//
// ── THE LEDGER LIVES ON D (one venue) ───────────────────────────────────────────────
// The conduit holds NO order book and NO accounting ledger. A deposit escrows the asset
// and forwards a C->D Credit object; the D-Chain venue (dex/pkg/dchain) credits the
// owner's balance: row. A swap escrows the input and forwards an Order; the venue matches
// (matcher-at-Verify, the carry-fills SYNC primitive in chains/dexvm) and exports a D->C
// settlement object the conduit consumes to release escrow. Conservation reduces to ONE
// inequality the host atomic seam enforces: Σ escrow(asset) ≥ Σ D-backed-releasable(asset).
//
// ── TRANSPORT-BLIND (LP-311 §2.4) ───────────────────────────────────────────────────
// The conduit never branches on whether the venue is same-network (AtomicTransport,
// synchronous carry-fills) or cross-network (WarpTransport, asynchronous). It escrows,
// forwards an intent, and applies the fill the venue produced — the host's AtomicStager
// is the one orthogonal transport seam.

var (
	// ErrConduitNoStager is the fail-closed refusal when the host wired no atomic-staging
	// backend (single-chain dev / a non-atomic harness). The conduit NEVER fabricates value
	// or falls back to writing its own (reapable) storage — it reverts.
	ErrConduitNoStager = errors.New("dex: stateless conduit requires the host atomic staging backend (AtomicStager) — fail-closed")
	// ErrConduitNoDPeer is the fail-closed refusal when no D-Chain (dexvm) peer is resolved
	// on this network (the "D" alias does not resolve). The on-ramp is honestly closed until
	// the venue exists; the conduit never guesses a peer.
	ErrConduitNoDPeer = errors.New("dex: stateless conduit requires a resolved D-Chain peer — fail-closed")
	// ErrConduitBadObject is the refusal when a D->C settlement object fails its value-bind
	// (wrong width, wrong rail, or zero amount). A corrupt/garbage record is never credited.
	ErrConduitBadObject = errors.New("dex: conduit D->C settlement object failed value-bind (rail/width/amount)")
	// ErrConduitNoFill is returned when no D->C settlement object is present for the
	// reference yet (the fill has not landed on the async path). The conduit releases nothing.
	ErrConduitNoFill = errors.New("dex: conduit found no D->C settlement object for the reference")
)

// conduitSeam bundles the host atomic capabilities the stateless conduit resolves once per
// call. It is the ONLY outward dependency of the conduit (LP-311's one orthogonal transport).
type conduitSeam struct {
	stager    contract.AtomicStager
	dChainID  ids.ID
	networkID uint32
	cChainID  ids.ID
}

// resolveConduitSeam type-asserts the host atomic capabilities off the AccessibleState and
// resolves the D-Chain peer, or fails CLOSED. It NEVER returns a usable seam when the host
// did not wire shared-memory staging or no D peer exists — so a conduit op on such a host
// reverts rather than touch its own storage or fabricate a fill.
func resolveConduitSeam(state contract.AccessibleState) (conduitSeam, error) {
	at, ok := state.(contract.AtomicState)
	if !ok {
		return conduitSeam{}, ErrConduitNoStager
	}
	stager, ok := state.(contract.AtomicStager)
	if !ok {
		return conduitSeam{}, ErrConduitNoStager
	}
	d := at.DChainID()
	if d == ids.Empty {
		return conduitSeam{}, ErrConduitNoDPeer
	}
	return conduitSeam{
		stager:    stager,
		dChainID:  d,
		networkID: at.NetworkID(),
		cChainID:  at.CChainID(),
	}, nil
}

// conduitForwardCredit escrows `amount` of `asset` from `caller` and forwards a C->D Credit
// object to the D-Chain venue. It is the conduit's deposit primitive and the EXACT shape of
// the live ERC-20 fund-strand bug (an ERC-20 deposit on an empty 0x9999) — done WITHOUT a
// single 0x9999 storage write.
//
// Discipline (two-phase, no 0x9999 self-write ever follows a nested call):
//   - PHASE A (no nested calls): stage the C->D object into the HOST staging account
//     (revert-safe EVM state) and move NATIVE value via balance ops. A reverted tx discards
//     the staged object atomically with the rolled-back escrow (no orphan C->D object).
//   - PHASE B (terminal, ERC-20 only): pull the token as the frame's LAST external effect,
//     asserting delivered ≥ amount (fee-on-transfer fail-secure). Nothing writes 0x9999
//     storage after it.
//
// Returns the deterministic intent id the venue's import consumes (DeriveIntentID, injective
// over the full identity). ZERO durable 0x9999 storage write.
func conduitForwardCredit(
	state contract.AccessibleState,
	seam conduitSeam,
	caller common.Address,
	asset Currency,
	amount uint64,
	marketID [32]byte,
	nonce uint64,
) (ids.ID, error) {
	if amount == 0 {
		return ids.Empty, ErrNativeBadAmount
	}
	aid := assetID(asset)
	// The escrow legs use the dex.StateDB adapter (native balance ops + the ERC-20 Call
	// seam). The conduit NEVER SetState's 0x9999 through it, so the adapter's nonce-marker
	// choke point (poolStateAdapter.SetState, module.go) is never reached on this path.
	stateDB := newPoolStateAdapter(state)

	// Native fail-fast: refuse an underfunded escrow BEFORE staging anything, so an unbacked
	// deposit stages no C->D object even absent the EVM revert (defense in depth).
	if isNativeAsset(aid) && stateDB.GetBalance(caller).Cmp(uint256.NewInt(amount)) < 0 {
		return ids.Empty, ErrNativeFundsShort
	}

	intentID := DeriveIntentID(seam.networkID, seam.cChainID, seam.dChainID, caller, aid, amount, marketID, nonce)

	// PHASE A — stage the C->D credit object in the HOST account (NOT 0x9999). The venue's
	// executeImport binds the recorded (rail=railSwap, owner=caller, asset=aid, amount) and
	// credits caller's balance: row. spent is 0 on the C->D leg (encodeAtomicObject).
	obj := encodeAtomicObject(railSwap, caller, aid, amount)
	if err := seam.stager.StageExport(seam.dChainID, intentID, obj); err != nil {
		return ids.Empty, err
	}

	if isNativeAsset(aid) {
		// Native escrow is a Phase-A balance op (no nested call): 0x9999's native balance
		// rises (non-empty while held), no storage written.
		if err := moveNativeIntoVault(stateDB, caller, amount); err != nil {
			return ids.Empty, err
		}
		return intentID, nil
	}

	// PHASE B — terminal ERC-20 pull into the token's trie (escrow). NO 0x9999 storage write
	// follows; 0x9999 stays EMPTY (reap-immune by construction).
	vault, ok := stateDBERC20(stateDB)
	if !ok {
		return ids.Empty, ErrNativeERC20Vault
	}
	if err := pullERC20Terminal(vault, asset.Address, caller, new(big.Int).SetUint64(amount)); err != nil {
		return ids.Empty, err
	}
	return intentID, nil
}

// conduitApplyRelease consumes a D->C settlement object by `ref`, value-binds it to the
// RECORDED (rail, owner, asset, amount) — never to what the caller declares — and releases
// escrow OUT to the bound owner. It is the conduit's fill/withdraw release primitive.
//
// Exactly-once: ConsumeImport reads the object from shared memory and stages a revert-safe
// Remove; a re-consume of the same key finds nothing (found=false). A tx that reverts after
// the consume discards the staged Remove, so the object is NOT consumed and no value is lost.
//
// `tokenFor` resolves the asset id to its ERC-20 contract address for a non-native release
// (native releases need no resolver). ZERO durable 0x9999 storage write.
func conduitApplyRelease(
	state contract.AccessibleState,
	seam conduitSeam,
	ref ids.ID,
	tokenFor func(asset [32]byte) (common.Address, bool),
) (owner common.Address, released uint64, err error) {
	obj, found, cerr := seam.stager.ConsumeImport(seam.dChainID, ref)
	if cerr != nil {
		return common.Address{}, 0, cerr
	}
	if !found {
		return common.Address{}, 0, ErrConduitNoFill
	}
	rail, boundOwner, aid, amount, _, ok := decodeAtomicObject(obj)
	if !ok || rail != railSwap || amount == 0 {
		return common.Address{}, 0, ErrConduitBadObject
	}
	// dex.StateDB adapter for the escrow-out leg; the conduit never SetState's 0x9999 here.
	stateDB := newPoolStateAdapter(state)

	if isNativeAsset(aid) {
		// Native release: vault native balance -> owner. The underflow guard in
		// moveNativeOutOfVault is defense-in-depth (a precompile SubBalance is uint256-modular).
		if err := moveNativeOutOfVault(stateDB, boundOwner, amount); err != nil {
			return common.Address{}, 0, err
		}
		return boundOwner, amount, nil
	}
	tokenAddr, ok := tokenFor(aid)
	if !ok {
		return common.Address{}, 0, ErrConduitBadObject
	}
	vault, ok := stateDBERC20(stateDB)
	if !ok {
		return common.Address{}, 0, ErrNativeERC20Vault
	}
	if err := pushERC20Terminal(vault, tokenAddr, boundOwner, new(big.Int).SetUint64(amount)); err != nil {
		return common.Address{}, 0, err
	}
	return boundOwner, amount, nil
}
