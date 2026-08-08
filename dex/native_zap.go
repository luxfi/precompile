// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
)

// native_zap.go is the NATIVE-ZAP value-settlement core: the two-phase discipline that
// DISSOLVES the geth nested-call / dropped-write host bug for the 0x9999 money path.
//
// ── THE BUG (proven live, ERC-20 leg only) ──────────────────────────────────────────
// When 0x9999 makes a NESTED geth EVM Call — an ERC-20 transferFrom / transfer / balanceOf
// into or out of the vault, made through the precompile execution environment's Call — the
// precompile's SUBSEQUENT writes to its OWN 0x9999 storage are DROPPED at commit (the nested
// frame's snapshot/journal swallows the caller-precompile's later same-StateDB writes). So a
// deposit that did `transferFrom THEN storeSeamReserve` moved the token (balanceOf(0x9999)
// rose to 6000) yet lost the accounting (custody stayed 0) ⇒ stranded funds, zero fill.
// The NATIVE path has no nested call, so it ALWAYS persisted; the trigger is exclusively the
// ERC-20 leg's mid-frame env.Call. (Host root-cause is a separate geth-host concern — the
// owner's directive is to DISSOLVE the trigger here, not patch geth.)
//
// ── THE DISSOLUTION (two phases, never re-enter the EVM mid-precompile) ──────────────
// Every value-moving 0x9999 handler is structured so NO 0x9999 self-write EVER follows a
// nested EVM Call:
//
//	PHASE A — ACCOUNTING (zero nested calls): record ALL 0x9999 state — the seam / committed
//	  reserve, the dexcore ledger, order / settlement records, atomic staging, logs — AND
//	  move NATIVE value (SubBalance/AddBalance are plain journal writes, never nested calls).
//	  Every write here precedes any nested call, so none can be dropped.
//
//	PHASE B — SETTLEMENT (terminal, ERC-20 only): perform the ERC-20 transferFrom / transfer
//	  as the frame's LAST external effects. Nothing writes 0x9999 storage after them, so there
//	  is nothing for the host bug to drop. A revert in Phase B (e.g. an under-delivering fee-
//	  on-transfer token) rolls the WHOLE frame back — the Phase-A accounting included — so the
//	  two phases commit ALL-OR-NOTHING.
//
// ── CONSERVATION WITHOUT A POST-TRANSFER CREDIT ─────────────────────────────────────
// The prior code credited the OBSERVED transfer delta (balanceOf after − before) to be fee-
// on-transfer safe. That REQUIRES a self-write AFTER the transfer (to record the measured
// delta) — exactly the dropped write. So this model instead credits the REQUESTED amount in
// Phase A and, in Phase B, ASSERTS the vault received at least that much (pullERC20Terminal's
// delivered ≥ amount check). A fee-on-transfer / rebasing-down / under-delivering token
// therefore REVERTS (fail-secure: never under-credited, never over-credited) rather than
// silently routing a partial. The check is a pure REVERT condition — it writes nothing — so
// it stays in Phase B without reintroducing the bug. Standard ERC-20s (delivered == amount)
// settle unchanged. Rebasing-UP between the transfer and the check leaves the surplus as a
// vault donation (safe; the credit is still the requested amount).

// ─────────────────── THE ROOT-CAUSE FIX: keep the 0x9999 vault non-empty ───────────────────
//
// The live ERC-20 fund-strand is EIP-158 EMPTY-ACCOUNT REAPING, NOT a nested-call journal
// anomaly (proven by a real-*state.StateDB probe matrix: a NON-nested single 0x9999 storage
// write is ALSO dropped when 0x9999 is empty + deleteEmptyObjects=true; and it is PRESERVED
// when 0x9999 carries a nonce marker, when it is funded, or when EIP-158 is off — the
// discriminator is the empty account, never the nested call). geth's Finalise(deleteEmpty-
// Objects=true) deletes any account that is empty (nonce==0 && balance==0 && code==∅) AND ALL
// of its storage. An ERC-20 deposit credits 0x9999 the TOKEN (the token contract's storage),
// leaving 0x9999's OWN account empty (zero native balance/nonce/code), so the custody /
// dexcore / halt slots written on 0x9999 are reaped at end-of-tx ⇒ custody=0 while the
// token sits in the vault. A NATIVE deposit credits 0x9999's native balance (non-empty), which
// is exactly why native persisted and ERC-20 did not.
//
// ensureVaultAccountPersists bumps the 0x9999 vault's nonce to 1 (once) so it is permanently
// NON-EMPTY from its first mutation — surviving Finalise on EVERY network with ZERO config (no
// genesis re-mark, no re-launch; a live chain self-heals on the next 0x9999 mutation). The bump
// is deterministic (identical on every validator) and inert (0x9999 is a precompile dispatched
// by address; a nonce never participates in its execution and a CALL never increments it).

// nonceMarker is the OPTIONAL capability to read/bump an account nonce. The production geth-
// backed adapter implements it (poolStateAdapter); a minimal test StateDB that models NO empty-
// account reaping need not, and the marker is then a safe no-op (there is nothing to reap).
type nonceMarker interface {
	GetNonce(addr common.Address) uint64
	SetNonce(addr common.Address, nonce uint64)
}

// ensureVaultAccountPersists makes the 0x9999 vault account NON-EMPTY (nonce >= 1) so EIP-158
// Finalise(deleteEmptyObjects=true) cannot reap it together with its storage. It is the single
// root-cause fix for the ERC-20 fund-strand; the value handlers call it before writing any
// 0x9999 state. Idempotent (only bumps a zero nonce) and reverted with the tx like any write.
func ensureVaultAccountPersists(stateDB StateDB) {
	m, ok := stateDB.(nonceMarker)
	if !ok {
		return // host models no empty-account reaping (a minimal mock) — nothing to protect.
	}
	if m.GetNonce(poolManagerAddr9999) == 0 {
		m.SetNonce(poolManagerAddr9999, 1)
	}
}

// ErrERC20UnderDelivered is the fail-secure refusal when an ERC-20 deposit/lock's terminal
// transferFrom delivered LESS than the requested amount into the 0x9999 vault (a fee-on-
// transfer / rebasing-down / non-conforming token). The frame reverts, rolling back the
// Phase-A accounting that optimistically recorded the requested amount — so the vault is
// never credited value it did not receive. This is the conservation guard that replaces the
// old observed-delta credit, now that the credit must precede the transfer (the bug fix).
var ErrERC20UnderDelivered = errors.New("dex: ERC-20 transfer delivered less than requested into the 0x9999 vault (fee-on-transfer / under-delivery refused, fail-secure)")

// ─────────────────────────── PHASE A: native value moves ───────────────────────────
// SubBalance/AddBalance journal the move with NO nested EVM call, so these are safe to
// interleave with the other 0x9999 accounting writes (Phase A). Native value NEVER moves
// through a nested call, so it is never subject to the dropped-write bug.

// moveNativeIntoVault debits `amount` native LUX from `caller` into the 0x9999 vault. Fails
// (frame reverts) if the caller's balance is short. Phase-A op (no nested call).
func moveNativeIntoVault(stateDB StateDB, caller common.Address, amount uint64) error {
	u := uint256.NewInt(amount)
	if stateDB.GetBalance(caller).Cmp(u) < 0 {
		return ErrNativeFundsShort
	}
	stateDB.SubBalance(caller, u)
	stateDB.AddBalance(poolManagerAddr9999, u)
	return nil
}

// moveNativeOutOfVault releases `amount` native LUX from the 0x9999 vault to `recipient`.
// The caller MUST have already decremented the asset's reserve accounting (recordCustodyOut), which bounds amount to the vault's real holding; the underflow
// guard here is defense-in-depth (SubBalance is uint256-modular from a precompile and would
// otherwise wrap rather than revert). Phase-A op (no nested call).
func moveNativeOutOfVault(stateDB StateDB, recipient common.Address, amount uint64) error {
	u := uint256.NewInt(amount)
	if stateDB.GetBalance(poolManagerAddr9999).Cmp(u) < 0 {
		return ErrCustodyUnbacked
	}
	stateDB.SubBalance(poolManagerAddr9999, u)
	stateDB.AddBalance(recipient, u)
	return nil
}

// ─────────────────────────── PHASE A: reserve accounting ────────────────────────────
// Pure 0x9999 storage writes (never nested calls). The matching value movement is a
// separate Phase-A (native) or Phase-B (ERC-20) settle.

// recordCustodyIn credits custody[asset] by amount — value entering the funding
// rail's pot on its way to D.
func recordCustodyIn(stateDB stateKV, assetID [32]byte, amount uint64) {
	before := loadCustody(stateDB, assetID)
	storeCustody(stateDB, assetID, new(big.Int).Add(before, new(big.Int).SetUint64(amount)))
}

// recordCustodyOut debits custody[asset] by amount, refusing (NO MINT, NO RAID) if
// the rail's own pot cannot back it. This is the C-side conservation floor: a credit
// can only ever pay out value C is already holding on D's behalf, never a depositor's
// claim or a maker's reserve. Callable on its own so a handler records the release
// BEFORE the terminal payout.
func recordCustodyOut(stateDB stateKV, assetID [32]byte, amount uint64) error {
	held := loadCustody(stateDB, assetID)
	amt := new(big.Int).SetUint64(amount)
	if held.Cmp(amt) < 0 {
		return ErrCustodyUnbacked
	}
	storeCustody(stateDB, assetID, new(big.Int).Sub(held, amt))
	return nil
}

// ─────────────────────── PHASE B: ERC-20 terminal settlements ───────────────────────
// The ONLY nested EVM calls. Nothing 0x9999 writes after them, so the host bug has nothing
// to drop. These perform ZERO writes to 0x9999 storage.

// pullERC20Terminal moves `amount` of `token` from `from` into the 0x9999 vault as a
// TERMINAL frame effect, then ASSERTS the vault actually received at least `amount`
// (delivered = balanceOf(vault) after − before). An under-delivering token (fee-on-transfer
// / rebasing-down) makes it return ErrERC20UnderDelivered and the frame reverts — the
// conservation guard that lets Phase A credit the requested amount up front. The two
// balanceOf reads and the transferFrom are nested EVM calls; NONE writes 0x9999 storage.
// `amount` is the full ERC-20 uint256 domain (a settle-reserve deposit can exceed uint64).
func pullERC20Terminal(vault erc20Vault, token, from common.Address, amount *big.Int) error {
	before := vault.TokenBalanceOf(token, poolManagerAddr9999)
	if err := vault.TransferTokenFrom(token, from, poolManagerAddr9999, amount); err != nil {
		return fmt.Errorf("%w: %v", ErrERC20TransferFailed, err)
	}
	after := vault.TokenBalanceOf(token, poolManagerAddr9999)
	if new(big.Int).Sub(after, before).Cmp(amount) < 0 {
		return ErrERC20UnderDelivered
	}
	return nil
}

// pushERC20Terminal moves `amount` of `token` from the 0x9999 vault to `to` as a TERMINAL
// frame effect (OpenZeppelin SafeERC20 semantics). The caller MUST have already debited the
// asset's reserve accounting (recordCustodyOut) so this can never
// pay out unbacked value. Zero 0x9999 storage writes.
func pushERC20Terminal(vault erc20Vault, token, to common.Address, amount *big.Int) error {
	return safeTransferTokenTo(vault, token, to, amount)
}

// ───────────────────── composed two-phase input-lock helpers ────────────────────────

// lockAsset is the Phase-A-then-Phase-B input lock for the funding rail's export
// leg. It (A) credits custody and runs `record` — the caller's OWN 0x9999 accounting
// (claim staging, event) — so EVERY 0x9999 write is done BEFORE any nested call, then
// (B) settles the asset IN: native via balance ops, ERC-20 via the single TERMINAL
// transferFrom. Returns the amount locked (== requested; an ERC-20 under-delivery
// reverts the whole frame, `record` included). `record` may be nil and runs before
// the terminal pull, so its writes are never dropped.
//
// This is the ONE structural fix for the lock family: the transferFrom is the frame's
// terminal external effect with ALL 0x9999 accounting written before it.
func lockAsset(stateDB StateDB, caller common.Address, assetID [32]byte, assetAddr common.Address, amount uint64, record func() error) (uint64, error) {
	if amount == 0 {
		return 0, ErrNativeBadAmount
	}
	// Native fail-fast: refuse an underfunded lock BEFORE writing ANY 0x9999 accounting, so an
	// unbacked lock records nothing and stages nothing even absent the EVM revert (defense in
	// depth, not a reliance on rollback). ERC-20 under-delivery is caught by the terminal pull's
	// delivered>=amount guard (+ the EVM revert), since allowance/balance cannot be pre-read.
	if isNativeAsset(assetID) && stateDB.GetBalance(caller).Cmp(uint256.NewInt(amount)) < 0 {
		return 0, ErrNativeFundsShort
	}
	// PHASE A — accounting (no nested calls).
	recordCustodyIn(stateDB, assetID, amount)
	if record != nil {
		if err := record(); err != nil {
			return 0, err
		}
	}
	if isNativeAsset(assetID) {
		// Native value move is a plain balance op (Phase A) — no nested call.
		if err := moveNativeIntoVault(stateDB, caller, amount); err != nil {
			return 0, err
		}
		return amount, nil
	}
	// PHASE B — terminal ERC-20 pull (nothing writes 0x9999 after this).
	vault, ok := stateDBERC20(stateDB)
	if !ok {
		return 0, ErrNativeERC20Vault
	}
	if err := pullERC20Terminal(vault, assetAddr, caller, new(big.Int).SetUint64(amount)); err != nil {
		return 0, err
	}
	return amount, nil
}
