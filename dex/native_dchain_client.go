// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/precompile/contract"
)

// native_dchain_client.go is the C side of the C<->D funding rail. Two methods, one
// job each, and neither knows what the value is for.
//
//   - Export FUNDS D: it debits the caller's C value into custody and stages a C->D
//     claim naming the beneficiary. It returns a claim id — never a fill, never an
//     order. D is funded ONLY by consuming that claim.
//   - Import CREDITS C: it consumes a D->C claim exactly once (replay-rejected,
//     value-bound to the RECORDED object, source-chain-bound) and credits the claim's
//     beneficiary out of custody. A C balance is credited ONLY along this path.
//
// MOVE ONCE, TRADE MANY. Between the two, D owns the value outright: an order is a
// D-local transaction against the beneficiary's own D account, a match is a D-local
// balance movement, and a cancel is a D-local unreserve. None of them reaches this
// file, which is why a million trades cost zero crossings.
//
// WHAT C ENFORCES vs WHAT D ENFORCES. C enforces, with no trust in D: the object bytes
// are the recorded ones (proven at Block.Verify, settle_import.go), the claim is
// consumed exactly once, the credit equals the RECORDED amount and pays the RECORDED
// beneficiary, and custody must already back it (no mint, no raid). D enforces the
// other half: an export debits a real balance and refuses an over-debit, so C can
// never be asked to credit more than D held.
//
// THAT IS THE WHOLE SAFETY MODEL, and it is the same one every shared-memory import
// uses. It replaced a per-order cap, a deadline and a slippage floor, which bounded a
// hostile export in terms of the taker's ORDER — facts that do not exist on a funding
// rail, and which is exactly why the order had to ride the object for them to be
// checkable at all.
//
// CONSENSUS-SAFETY: every method is a pure deterministic function of (input, StateDB,
// tx-carried bytes) — no live cross-chain read, so a transaction replays
// byte-identically forever.

// NativeDChainClient moves value across the C<->D boundary via primary-network
// shared memory. It holds NO mutable state of its own (custody and the consumed set
// live in StateDB); it is a stateless set of operations over the host capabilities
// passed at call time.
type NativeDChainClient struct {
	// brand is the user-facing identity for error/log strings (white-label).
	brand string
}

// NewNativeDChainClient constructs the native C<->D client. brand defaults to the
// OSS "Lux DEX" identity; a tenant surface passes its own.
func NewNativeDChainClient(brand string) *NativeDChainClient {
	if brand == "" {
		brand = "Lux DEX"
	}
	return &NativeDChainClient{brand: brand}
}

// Brand identifies the client in logs / error wrapping (Engine surface).
func (c *NativeDChainClient) Brand() string { return c.brand }

var (
	ErrNativeNoAtomicMemory = errors.New("dex: cross-chain memory unavailable (single-chain dev / rail closed)")
	ErrNativeBadAmount      = errors.New("dex: funding amount out of range")
	ErrNativeFundsShort     = errors.New("dex: sender has insufficient balance to fund the C->D claim")
	ErrNativeERC20Vault     = errors.New("dex: ERC-20 transfer requires an erc20Vault-capable StateDB")
	ErrExportReplay         = errors.New("dex: C->D claim id already written (replay)")
	ErrImportReplay         = errors.New("dex: D->C claim already consumed (replay)")
	ErrImportAsset          = errors.New("dex: D->C claim asset does not match the claim")
	ErrImportBeneficiary    = errors.New("dex: D->C claim beneficiary does not match the recipient")
	ErrImportAmount         = errors.New("dex: D->C claim moves no value")
	// ErrCustodyUnbacked: custody cannot back the credited amount. The conservation
	// floor — no mint, and no raid on the depositor or maker pots.
	ErrCustodyUnbacked = errors.New("dex: custody cannot back the D->C credit (no mint, no raid)")
)

// Transfer is what a C-side caller asks the rail to move.
type Transfer struct {
	// Owner is the C account debited (the tx caller). It funds the crossing.
	Owner common.Address
	// Beneficiary is the account credited on D. It defaults to Owner; naming a
	// different one is how Alice funds Bob, and it is what makes delivery on the far
	// side permissionless — handing over the claim can only ever credit this account.
	Beneficiary common.Address
	// Asset is the full injective AssetID moved (native = all-zero).
	Asset [32]byte
	// AssetAddr is the ERC-20 token for the C-side lock (address(0) for native).
	AssetAddr common.Address
	// Amount is the integer asset unit count.
	Amount uint64
}

// Export debits the caller's C value into custody and stages a C->D claim. It returns
// the claim id (== the object's shared-memory key). It creates NO order: what the
// beneficiary does with the value once it lands is a D-local decision, taken by their
// own D transactions.
//
// ORDERING (lock -> derive id -> replay-check -> stage). The C value is debited into
// custody FIRST and the claim's amount is what was ACTUALLY locked, so D can never be
// funded beyond what C removed. The replay guard runs inside the lock's Phase-A
// record callback, before the terminal asset pull, so a duplicate id reverts the whole
// frame — the lock included — rather than leaving a half-written crossing.
//
// The claim is STAGED, not applied. A direct shared-memory Apply commits outside the
// EVM revert scope, so a tx reverting after it would leave a C->D claim with no
// backing C debit — a mint. Staging into StateDB is revert-aware; the host flushes
// staged writes at BLOCK ACCEPT (native_staging.go).
func (c *NativeDChainClient) Export(
	state contract.AccessibleState,
	atomicState contract.AtomicState,
	t Transfer,
) (claimID ids.ID, locked uint64, err error) {
	if atomicState.AtomicMemory() == nil {
		return ids.Empty, 0, ErrNativeNoAtomicMemory
	}
	if t.Amount == 0 {
		return ids.Empty, 0, ErrNativeBadAmount
	}
	beneficiary := t.Beneficiary
	if beneficiary == (common.Address{}) {
		beneficiary = t.Owner
	}

	// The D peer is the D-Chain on the primary network. The claim is keyed by claimID
	// and written under the D chain's partition. The host resolves the D-Chain id at
	// runtime from the chain topology; a network with no D-Chain yields ids.Empty and
	// the rail stays closed (no mint).
	cChainID := atomicState.CChainID()
	dChainID := atomicState.DChainID()
	if dChainID == ids.Empty {
		return ids.Empty, 0, ErrNativeNoAtomicMemory
	}

	stateDB := newPoolStateAdapter(state)
	locked = t.Amount
	claimID = DeriveClaimID(cChainID, dChainID, atomicState.TxID(), atomicState.CallIndex())

	if _, lockErr := lockAsset(stateDB, t.Owner, t.Asset, t.AssetAddr, t.Amount, func() error {
		// Replay guard: the same claim id must not be written twice (a re-executed /
		// reorged C tx). Durable, consensus-shared (StateDB), before the staging.
		if isClaimWritten(stateDB, claimID) {
			return ErrExportReplay
		}
		markClaimWritten(stateDB, claimID, state.GetBlockContext().Number().Uint64())
		stageAtomicPut(stateDB, dChainID, claimID, encodeClaim(beneficiary, t.Asset, locked))
		emitExportEvent(stateDB, claimID, dChainID, t.Owner, beneficiary, t.Asset, locked)
		return nil
	}); lockErr != nil {
		return ids.Empty, 0, lockErr
	}
	return claimID, locked, nil
}

// Claim is what an importing C tx declares it wants to consume. Every field is BOUND
// to the RECORDED object — a mismatch reverts. The transaction cannot invent value: it
// only names which committed claim to consume and the beneficiary it must already
// credit.
type Claim struct {
	// ID is the claim's shared-memory key on the source chain.
	ID ids.ID
	// Asset is the claimed asset — MUST equal the object's asset.
	Asset [32]byte
	// Beneficiary is the claimed payee — MUST equal the object's beneficiary.
	Beneficiary common.Address
	// Object is the claim's BYTES, carried by the transaction exactly as D wrote them.
	// It is the AUTHORITATIVE value: the credit is this object's amount, never a
	// number the transaction states separately. Execution binds to these bytes WITHOUT
	// reading shared memory, so the transaction replays byte-identically forever; the
	// host proves the bytes are the recorded object at Block.Verify (settle_import.go),
	// where a forgery rejects the block instead of diverging a receipt.
	Object []byte
}

// Import consumes a D->C claim EXACTLY ONCE and credits its beneficiary out of
// custody. This is the sole C-credit path.
//
//  1. BIND to the object the TRANSACTION carried, and DECLARE the consumption into the
//     receipt so the host can authenticate it at Verify.
//  2. BIND the credit to the RECORDED value — asset == claimed, beneficiary ==
//     claimed — so a transaction cannot consume someone else's claim or re-denominate
//     it.
//  3. REPLAY guard: reject an already-consumed claim id.
//  4. MARK consumed (CEI) BEFORE moving value, and STAGE the shared-memory Remove.
//  5. CREDIT from custody as the frame's terminal effect (no mint — custody must
//     already back it).
//
// A "live matcher answer" cannot drive this: there is no parameter for an amount; the
// credit is the RECORDED object's amount, and a forged object kills the block.
func (c *NativeDChainClient) Import(
	state contract.AccessibleState,
	atomicState contract.AtomicState,
	cl Claim,
) (credited uint64, err error) {
	if atomicState.AtomicMemory() == nil {
		return 0, ErrNativeNoAtomicMemory
	}
	dChainID := atomicState.DChainID()
	if dChainID == ids.Empty {
		return 0, ErrNativeNoAtomicMemory
	}
	stateDB := newPoolStateAdapter(state)

	// (1) BIND the carried bytes + DECLARE the consumption into the receipt.
	recBeneficiary, recAsset, recAmount, berr := bindImportObject(stateDB, dChainID, cl.ID, cl.Object)
	if berr != nil {
		return 0, berr
	}

	// (2) BIND the credit to the OBJECT's value (authoritative, not declared).
	if recAsset != cl.Asset {
		return 0, ErrImportAsset
	}
	if recBeneficiary != cl.Beneficiary {
		return 0, ErrImportBeneficiary
	}

	// (3) REPLAY guard: one-time consumption, durable + consensus-shared.
	if isClaimConsumed(stateDB, cl.ID) {
		return 0, ErrImportReplay
	}

	// (4) MARK consumed and STAGE the Remove BEFORE the terminal credit. Both are pure
	// 0x9999 writes; the EVM revert rolls them back together with a failed credit, and
	// doing them first is what stops the geth nested-call host from dropping them.
	// We do NOT Apply here — a direct Apply commits outside the EVM revert scope, so a
	// post-Apply revert would consume the object while the credit rolled back (value
	// LOSS). Staging is revert-aware and flushed at block accept.
	markClaimConsumed(stateDB, cl.ID, state.GetBlockContext().Number().Uint64())
	stageAtomicRemove(stateDB, dChainID, cl.ID)

	// (5) CREDIT from custody as the frame's TERMINAL effect.
	if cerr := creditAsset(stateDB, recBeneficiary, recAsset, recAmount); cerr != nil {
		return 0, cerr
	}
	return recAmount, nil
}

// --- DChainClient interface conformance (the on-ramp seam). --------------------
//
// The narrow DChainClient methods (context-only) are the migration surface; the
// native value-moving work needs the host capabilities (StateDB + AtomicState)
// the V4 handler holds, so those are the methods above. The interface methods here
// keep the seam satisfiable for code paths that hold only a context — they refuse
// rather than move value without the host capabilities (fail-secure).

var _ Engine = (*NativeDChainClient)(nil)

// Initialize / Swap / ModifyLiquidity / Donate / Quote: the Engine surface the
// PoolManager calls. The native seam routes value through the 0x9999 handler
// (SettleSwap) using the methods above, NOT through a synchronous Engine.Swap
// (which forks). So the Engine methods here are the closed-on-ramp refusal: a node
// must use the 0x9999 native settle path, not the deprecated synchronous surface.
func (c *NativeDChainClient) Initialize(_ *big.Int) (int24, error) {
	return 0, ErrDChainUnavailable
}

func (c *NativeDChainClient) Swap(_ *PoolState, _ common.Address, _ SwapParams) (BalanceDelta, error) {
	// A synchronous in-block fill via a live query forks consensus (the whole reason
	// for the async atomic model). The native path is SettleSwap's two-phase order/
	// settlement; this synchronous surface is never the value path.
	return ZeroBalanceDelta(), ErrDChainUnavailable
}

func (c *NativeDChainClient) ModifyLiquidity(_ *PoolState, _ common.Address, _ ModifyLiquidityParams) (BalanceDelta, BalanceDelta, error) {
	return ZeroBalanceDelta(), ZeroBalanceDelta(), ErrDChainUnavailable
}

func (c *NativeDChainClient) Donate(_ *PoolState, _, _ *big.Int) (BalanceDelta, error) {
	return ZeroBalanceDelta(), ErrDChainUnavailable
}

func (c *NativeDChainClient) Quote(_ *Pool, _ *big.Int, _ bool) *big.Int {
	return big.NewInt(0)
}

// --- C-side value movement -----------------------------------------------------
//
// The export LOCK is lockAsset (native_zap.go) — the two-phase input lock that
// records custody before the terminal ERC-20 pull. The import CREDIT is creditAsset
// below (recordCustodyOut + terminal payout). One of each, for one rail.

// creditAsset releases amount of an asset from CUSTODY to the beneficiary — NO MINT
// (the rail's own pot must already hold it), NO RAID (the credit is checked against
// custody[a], never the depositor settleVault or the maker makerLockedVault). Native
// via SubBalance(0x9999)/AddBalance; ERC-20 via the vault transfer.
//
// The ERC-20 transfer token is DERIVED from the recorded asset id
// (assetAddress(assetID)) INSIDE this function — it does not trust a token address the
// caller passes. assetID is the consumed claim's asset (the value custody is
// denominated in) and assetAddress is its injective inverse, so the token credited is
// provably the one custody was debited for.
func creditAsset(stateDB StateDB, beneficiary common.Address, assetID [32]byte, amount uint64) error {
	// PHASE A — debit custody (the conservation floor: NO MINT, NO RAID). Pure 0x9999
	// write, no nested call.
	if err := recordCustodyOut(stateDB, assetID, amount); err != nil {
		return err
	}
	if isNativeAsset(assetID) {
		// Native release is a plain balance op (Phase A) — no nested call.
		return moveNativeOutOfVault(stateDB, beneficiary, amount)
	}
	// PHASE B — terminal ERC-20 transfer. Nothing writes 0x9999 storage after this.
	vault, ok := stateDBERC20(stateDB)
	if !ok {
		return ErrNativeERC20Vault
	}
	return pushERC20Terminal(vault, assetAddress(assetID), beneficiary, new(big.Int).SetUint64(amount))
}
