// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// erc20_custody_test.go exercises the ERC-20 D<->C custody rail end-to-end against
// the faithful in-memory token double (erc20_vault_test.go). It proves the rail
// REUSES the native primitives — vault lock/release + ZAP relay + (txHash,asset,
// amount) idempotency — with the ONE substitution that the locked asset is the
// token's own balance (moved via transferFrom/transfer), credited by the OBSERVED
// delta. The hard invariants:
//   - deposit credits the OBSERVED transfer delta, never the requested amount
//     (fee-on-transfer safe);
//   - withdraw releases exactly the realized burn and refuses a vault underflow;
//   - per-token conservation: token.balanceOf(0x9010) == Σ ledger(token);
//   - native (address(0)) and ERC-20 ops never confuse or dedup each other;
//   - settlement is via transferFrom/transfer ONLY — never a balance-slot poke.

// Realistic token addresses (keccak-derived shape). The D-Chain asset key is the
// FULL 32-byte injective id (assetID left-pads the 20-byte address into 32 bytes),
// so EVERY distinct address — including any with leading-zero bytes — maps to a
// distinct id that never collides with native LUX (address(0) -> all-zero id) or
// another token. These mirror real ERC-20 shapes. See TestAssetIDInjective for the
// injectivity proof that closes the old 8-byte-fold collision class.
var (
	lusdAddr = common.HexToAddress("0xA0b86991C6218B36c1d19D4a2e9Eb0cE3606EB48") // standard 18-dec token (LUSD/USDC-style)
	fotAddr  = common.HexToAddress("0xF0E1d2C3b4A5968778695A4B3c2D1e0F00112233") // fee-on-transfer token
)

// vaultLedgerOf reads the precompile's per-token vault holdings (0x9010's own state).
func vaultLedgerOf(sdb *tokenStateDB, token common.Address) uint64 {
	return loadVaultLedger(sdb, token).Uint64()
}

// erc20Curr wraps a token address as a Currency.
func erc20Curr(addr common.Address) Currency { return Currency{Address: addr} }

// assertPerTokenConservation pins token.balanceOf(0x9010) == precompile vault ledger
// for `token`. (The D-Chain available/locked sums live in the fakeCLOB ledger; this
// checks the C-Chain side of the invariant — the real token in the vault equals the
// precompile's recorded backing, which the D-Chain claims are matched against.)
func assertPerTokenConservation(t *testing.T, sdb *tokenStateDB, reg *mockTokenRegistry, token common.Address) {
	t.Helper()
	tok := reg.get(token)
	vaultReal := tok.balanceOf(poolManagerAddr).Uint64()
	ledger := vaultLedgerOf(sdb, token)
	if vaultReal != ledger {
		t.Fatalf("per-token conservation broken for %x: token.balanceOf(0x9010)=%d != vault ledger=%d", token[:4], vaultReal, ledger)
	}
}

// --- DEPOSIT: standard token, observed delta == requested ---
func TestERC20_Deposit_StandardToken_CreditsObservedDelta(t *testing.T) {
	pm, f, sdb, reg, caller := custodyPMToken(t, 0)
	lusd := newMockToken(0) // standard, no fee
	reg.register(lusdAddr, lusd)

	const dep = uint64(250)
	lusd.mint(caller, 1000)
	lusd.approve(caller, poolManagerAddr, dep) // caller grants 0x9010 the allowance

	if err := pm.Deposit(sdb, caller, erc20Curr(lusdAddr), new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	// Caller's token balance dropped by exactly dep (no fee).
	if got := lusd.balanceOf(caller).Uint64(); got != 1000-dep {
		t.Fatalf("caller token balance = %d, want %d", got, 1000-dep)
	}
	// The vault physically holds dep of the token (moved via transferFrom).
	if got := lusd.balanceOf(poolManagerAddr).Uint64(); got != dep {
		t.Fatalf("vault token balance = %d, want %d", got, dep)
	}
	// D-Chain available credited exactly the observed delta (== dep here).
	if got := fakeAvail(f, caller, erc20Curr(lusdAddr)); got != dep {
		t.Fatalf("D-Chain available = %d, want %d", got, dep)
	}
	// Settlement used transferFrom (exactly 1 genuine move). The "no slot poke"
	// guarantee is STRUCTURAL — the precompile reaches the token only through the
	// erc20Vault seam (TokenBalanceOf/TransferTokenFrom/TransferTokenTo), which has
	// NO balance-write method — so the move-count is the load-bearing assertion.
	if lusd.transfers != 1 {
		t.Fatalf("token transfers = %d, want 1 (transferFrom)", lusd.transfers)
	}
	assertPerTokenConservation(t, sdb, reg, lusdAddr)
}

// --- DEPOSIT: fee-on-transfer token — credit the OBSERVED (post-fee) delta ---
//
// THE SHARPEST EDGE: a fee-on-transfer token delivers LESS than `amount` to the
// vault. The D-Chain must be credited the OBSERVED delta, NOT the requested amount,
// or it mints an unbacked claim. Conservation must hold against the real (post-fee)
// vault balance.
func TestERC20_Deposit_FeeOnTransfer_CreditsObservedNotRequested(t *testing.T) {
	pm, f, sdb, reg, caller := custodyPMToken(t, 0)
	const feeBps = uint64(100) // 1% fee
	fot := newMockToken(feeBps)
	reg.register(fotAddr, fot)

	const req = uint64(1000)
	fot.mint(caller, 5000)
	fot.approve(caller, poolManagerAddr, req)

	if err := pm.Deposit(sdb, caller, erc20Curr(fotAddr), new(big.Int).SetUint64(req)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	// Recipient (vault) observed delta = req - 1% = 990. THAT is what must be credited.
	const wantDelta = uint64(990)
	if got := fot.balanceOf(poolManagerAddr).Uint64(); got != wantDelta {
		t.Fatalf("vault token balance = %d, want %d (post-fee observed delta)", got, wantDelta)
	}
	// D-Chain credited the OBSERVED delta (990), NOT the requested 1000.
	if got := fakeAvail(f, caller, erc20Curr(fotAddr)); got != wantDelta {
		t.Fatalf("D-Chain available = %d, want %d (OBSERVED delta, NOT requested %d)", got, wantDelta, req)
	}
	if got := fakeAvail(f, caller, erc20Curr(fotAddr)); got == req {
		t.Fatalf("D-Chain credited the REQUESTED amount %d — unbacked mint (must credit observed)", req)
	}
	// Caller debited the full requested amount (the fee is real cost to the caller).
	if got := fot.balanceOf(caller).Uint64(); got != 5000-req {
		t.Fatalf("caller token balance = %d, want %d", got, 5000-req)
	}
	// Conservation holds against the POST-FEE vault balance.
	if got := vaultLedgerOf(sdb, fotAddr); got != wantDelta {
		t.Fatalf("vault ledger = %d, want %d (tracks observed delta)", got, wantDelta)
	}
	assertPerTokenConservation(t, sdb, reg, fotAddr)
}

// --- WITHDRAW: burn D-Chain, transfer token out of the vault ---
func TestERC20_Withdraw_BurnsLedgerAndReleasesToken(t *testing.T) {
	pm, f, sdb, reg, caller := custodyPMToken(t, 0)
	lusd := newMockToken(0)
	reg.register(lusdAddr, lusd)

	const dep = uint64(400)
	lusd.mint(caller, 1000)
	lusd.approve(caller, poolManagerAddr, dep)
	if err := pm.Deposit(sdb, caller, erc20Curr(lusdAddr), new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	// Distinct tx for the withdraw (a genuinely different custody op).
	sdb.setTxHash(common.HexToHash("0x1111000000000000000000000000000000000000000000000000000000001111"))
	const wd = uint64(150)
	realized, err := pm.Withdraw(sdb, caller, erc20Curr(lusdAddr), new(big.Int).SetUint64(wd))
	if err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	if realized.Uint64() != wd {
		t.Fatalf("realized = %d, want %d", realized.Uint64(), wd)
	}
	// Token transferred from the vault back to the caller.
	if got := lusd.balanceOf(caller).Uint64(); got != 1000-dep+wd {
		t.Fatalf("caller token balance = %d, want %d", got, 1000-dep+wd)
	}
	if got := lusd.balanceOf(poolManagerAddr).Uint64(); got != dep-wd {
		t.Fatalf("vault token balance = %d, want %d", got, dep-wd)
	}
	// D-Chain available burned by the realized amount.
	if got := fakeAvail(f, caller, erc20Curr(lusdAddr)); got != dep-wd {
		t.Fatalf("D-Chain available = %d, want %d", got, dep-wd)
	}
	assertPerTokenConservation(t, sdb, reg, lusdAddr)
}

// --- WITHDRAW: vault-underflow refusal (vaultBalanceOf < realized) ---
//
// The ERC-20 analog of releaseNativeFromVault's underflow guard: if the vault's
// recorded holdings for the token are below the realized burn, the release is
// refused (defense in depth — never pay out a token the vault does not hold).
func TestERC20_Withdraw_RefusesVaultUnderflow(t *testing.T) {
	pm, _, sdb, reg, caller := custodyPMToken(t, 0)
	lusd := newMockToken(0)
	reg.register(lusdAddr, lusd)

	const dep = uint64(300)
	lusd.mint(caller, 1000)
	lusd.approve(caller, poolManagerAddr, dep)
	if err := pm.Deposit(sdb, caller, erc20Curr(lusdAddr), new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	// Corrupt the vault ledger DOWN to simulate the invariant breach the guard
	// defends against (the D-Chain would say `dep` available, but the vault holds
	// less). The withdraw must REFUSE rather than overdraw the vault.
	storeVaultLedger(sdb, lusdAddr, new(big.Int).SetUint64(50)) // < dep

	sdb.setTxHash(common.HexToHash("0x2222000000000000000000000000000000000000000000000000000000002222"))
	_, err := pm.Withdraw(sdb, caller, erc20Curr(lusdAddr), new(big.Int).SetUint64(dep))
	if !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("underflow withdraw err = %v, want ErrInsufficientBalance", err)
	}
	// The vault ledger is untouched by the refused withdraw (we set it to 50).
	if got := vaultLedgerOf(sdb, lusdAddr); got != 50 {
		t.Fatalf("vault ledger = %d after refused withdraw, want 50 (no debit)", got)
	}
}

// --- PER-TOKEN CONSERVATION across deposit -> trade -> withdraw ---
//
// A full custody cycle for one token, with a resting-order place in the middle (the
// no-reserve gate: a place moves D-Chain available->locked but NEVER touches the
// vault). token.balanceOf(0x9010) == vault ledger at every step.
func TestERC20_Conservation_DepositTradeWithdrawCycle(t *testing.T) {
	pm, f, sdb, reg, caller := custodyPMToken(t, 0)
	lusd := newMockToken(0)
	reg.register(lusdAddr, lusd)

	const dep = uint64(1000)
	lusd.mint(caller, 5000)
	lusd.approve(caller, poolManagerAddr, dep)
	if err := pm.Deposit(sdb, caller, erc20Curr(lusdAddr), new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	vaultAfterDeposit := lusd.balanceOf(poolManagerAddr).Uint64()
	if vaultAfterDeposit != dep {
		t.Fatalf("vault after deposit = %d, want %d", vaultAfterDeposit, dep)
	}
	assertPerTokenConservation(t, sdb, reg, lusdAddr)

	// Place a resting order in an ERC-20/quote market (the D-Chain locks available;
	// the vault is UNCHANGED — no native/token reserve backs a resting order).
	// quoteAddr (0xFF..) > lusdAddr (0xA0..), so currency0=lusd, currency1=quote (sorted).
	quoteAddr := common.HexToAddress("0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF")
	key := PoolKey{
		Currency0: erc20Curr(lusdAddr),
		Currency1: erc20Curr(quoteAddr),
		Fee:       3000, TickSpacing: 60,
	}
	if _, err := pm.Initialize(sdb, key, new(big.Int).Set(Q96), nil); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	var salt [32]byte
	salt[31] = 9
	if _, _, err := pm.ModifyLiquidity(sdb, caller, key, ModifyLiquidityParams{
		TickLower: -60, TickUpper: 60, LiquidityDelta: big.NewInt(10), Salt: salt,
	}, nil); err != nil {
		t.Fatalf("ModifyLiquidity place: %v", err)
	}
	// THE GATE: the vault token balance is UNCHANGED by the place.
	if got := lusd.balanceOf(poolManagerAddr).Uint64(); got != vaultAfterDeposit {
		t.Fatalf("vault changed by place: %d -> %d (NO reserve must back a resting order)", vaultAfterDeposit, got)
	}
	assertPerTokenConservation(t, sdb, reg, lusdAddr)

	// Withdraw the full deposit back out (distinct tx).
	sdb.setTxHash(common.HexToHash("0x3333000000000000000000000000000000000000000000000000000000003333"))
	realized, err := pm.Withdraw(sdb, caller, erc20Curr(lusdAddr), new(big.Int).SetUint64(dep))
	if err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	if realized.Uint64() != dep {
		t.Fatalf("realized = %d, want %d", realized.Uint64(), dep)
	}
	// Conservation: caller whole again, vault empty, ledger zero.
	if got := lusd.balanceOf(caller).Uint64(); got != 5000 {
		t.Fatalf("caller token balance = %d after full cycle, want 5000 (conserved)", got)
	}
	if got := lusd.balanceOf(poolManagerAddr).Uint64(); got != 0 {
		t.Fatalf("vault token balance = %d after full cycle, want 0", got)
	}
	_ = f
	assertPerTokenConservation(t, sdb, reg, lusdAddr)
}

// --- CROSS-ASSET ISOLATION: native (address(0)) and ERC-20 do NOT confuse/dedup ---
//
// A native deposit and an ERC-20 deposit by the same caller in the same tx context
// must be DISTINCT: distinct idempotency bindings (custodyBindKey folds the asset
// address) AND distinct D-Chain ledger keys (assetID maps native->all-zero id,
// ERC-20->its 20-byte address embedded injectively in 32 bytes). Neither dedups
// against the other.
func TestERC20_CrossAssetIsolation_NativeAndTokenDistinct(t *testing.T) {
	pm, f, sdb, reg, caller := custodyPMToken(t, 1000)
	lusd := newMockToken(0)
	reg.register(lusdAddr, lusd)

	const amt = uint64(200)

	// Native deposit: EVM pre-moves msg.value into the vault.
	sdb.SubBalance(caller, mustU256(amt))
	sdb.AddBalance(poolManagerAddr, mustU256(amt))
	if err := pm.Deposit(sdb, caller, NativeCurrency, new(big.Int).SetUint64(amt)); err != nil {
		t.Fatalf("native Deposit: %v", err)
	}

	// ERC-20 deposit of the SAME amount by the SAME caller in the SAME tx context.
	// If the asset were not part of the identity, this would dedup against the native
	// deposit (the bug). It must instead be a fresh, distinct credit.
	lusd.mint(caller, 1000)
	lusd.approve(caller, poolManagerAddr, amt)
	if err := pm.Deposit(sdb, caller, erc20Curr(lusdAddr), new(big.Int).SetUint64(amt)); err != nil {
		t.Fatalf("erc20 Deposit: %v", err)
	}

	// Both credited SEPARATELY, each under its own asset handle.
	if got := fakeAvail(f, caller, NativeCurrency); got != amt {
		t.Fatalf("native D-Chain available = %d, want %d (not consumed by token dedup)", got, amt)
	}
	if got := fakeAvail(f, caller, erc20Curr(lusdAddr)); got != amt {
		t.Fatalf("token D-Chain available = %d, want %d (not deduped against native)", got, amt)
	}
	// The two ledger keys are genuinely distinct (native all-zero id != token id).
	if assetID(NativeCurrency) == assetID(erc20Curr(lusdAddr)) {
		t.Fatalf("native and token share an asset id — cross-asset isolation broken")
	}
	// Vault holds BOTH: native wei AND the token, independently.
	if got := vaultBal(sdb.txStateDB); got != amt {
		t.Fatalf("native vault wei = %d, want %d", got, amt)
	}
	if got := lusd.balanceOf(poolManagerAddr).Uint64(); got != amt {
		t.Fatalf("token vault balance = %d, want %d", got, amt)
	}
	assertPerTokenConservation(t, sdb, reg, lusdAddr)
}

// --- LUSD-style standard token settles via transferFrom/transfer, NOT a slot poke ---
//
// The exact failure Michael flagged: autoSettle's balance-slot WRITE broke a
// standard 18-decimal token. This rail moves value ONLY through the token's own
// transferFrom/transfer (which the mock counts), never by writing balanceOf slots —
// and structurally CANNOT write them, since the erc20Vault seam exposes no
// balance-write method. A full deposit+withdraw round-trips with transfers counted.
func TestERC20_LUSDStyle_SettlesViaTransfer_NoSlotPoke(t *testing.T) {
	pm, _, sdb, reg, caller := custodyPMToken(t, 0)
	lusd := newMockToken(0) // standard ERC-20 layout
	reg.register(lusdAddr, lusd)

	const dep = uint64(777)
	lusd.mint(caller, 1000)
	lusd.approve(caller, poolManagerAddr, dep)
	if err := pm.Deposit(sdb, caller, erc20Curr(lusdAddr), new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	sdb.setTxHash(common.HexToHash("0x4444000000000000000000000000000000000000000000000000000000004444"))
	if _, err := pm.Withdraw(sdb, caller, erc20Curr(lusdAddr), new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}

	// Exactly two genuine moves: transferFrom (deposit) + transfer (withdraw). The
	// precompile NEVER poked balanceOf slots — it CANNOT: the erc20Vault seam exposes
	// no balance-write method, so the only paths to the token are these counted
	// transfers (the structural "no slot poke" guarantee Michael's autoSettle bug
	// violated). The move-count is the load-bearing assertion.
	if lusd.transfers != 2 {
		t.Fatalf("token transfers = %d, want 2 (transferFrom + transfer)", lusd.transfers)
	}
	// Round-tripped whole.
	if got := lusd.balanceOf(caller).Uint64(); got != 1000 {
		t.Fatalf("caller token balance = %d after round-trip, want 1000", got)
	}
	assertPerTokenConservation(t, sdb, reg, lusdAddr)
}

// --- OZ-SAFE FAILURE: a reverting transfer aborts the deposit, no mint ---
func TestERC20_Deposit_RevertingTransfer_NoMint(t *testing.T) {
	pm, f, sdb, reg, caller := custodyPMToken(t, 0)
	bad := newMockToken(0)
	bad.revertTransfer = true
	reg.register(lusdAddr, bad)

	bad.mint(caller, 1000)
	bad.approve(caller, poolManagerAddr, 100)
	err := pm.Deposit(sdb, caller, erc20Curr(lusdAddr), big.NewInt(100))
	if !errors.Is(err, ErrERC20TransferFailed) {
		t.Fatalf("reverting deposit err = %v, want ErrERC20TransferFailed", err)
	}
	if got := fakeAvail(f, caller, erc20Curr(lusdAddr)); got != 0 {
		t.Fatalf("D-Chain available = %d after reverted deposit, want 0 (no mint)", got)
	}
	if got := vaultLedgerOf(sdb, lusdAddr); got != 0 {
		t.Fatalf("vault ledger = %d after reverted deposit, want 0", got)
	}
}

// --- OZ-SAFE FAILURE: a false-returning transfer aborts the deposit, no mint ---
func TestERC20_Deposit_FalseReturningTransfer_NoMint(t *testing.T) {
	pm, f, sdb, reg, caller := custodyPMToken(t, 0)
	bad := newMockToken(0)
	bad.returnsFalse = true
	reg.register(lusdAddr, bad)

	bad.mint(caller, 1000)
	bad.approve(caller, poolManagerAddr, 100)
	err := pm.Deposit(sdb, caller, erc20Curr(lusdAddr), big.NewInt(100))
	if !errors.Is(err, ErrERC20TransferFailed) {
		t.Fatalf("false-return deposit err = %v, want ErrERC20TransferFailed", err)
	}
	if got := fakeAvail(f, caller, erc20Curr(lusdAddr)); got != 0 {
		t.Fatalf("D-Chain available = %d after false-return deposit, want 0 (no mint)", got)
	}
}

// --- DEPOSIT IDEMPOTENCY: replaying the SAME ERC-20 deposit tx pulls ONCE ---
func TestERC20_Deposit_ReplayPullsOnce(t *testing.T) {
	pm, f, sdb, reg, caller := custodyPMToken(t, 0)
	lusd := newMockToken(0)
	reg.register(lusdAddr, lusd)

	const dep = uint64(300)
	lusd.mint(caller, 1000)
	lusd.approve(caller, poolManagerAddr, dep) // allowance for ONE pull only
	if err := pm.Deposit(sdb, caller, erc20Curr(lusdAddr), new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("Deposit#1: %v", err)
	}
	// Replay the identical tx (same txHash). The binding must short-circuit BEFORE a
	// second transferFrom — which would also fail on the now-zero allowance, but the
	// binding must catch it first so the result is a clean no-op.
	if err := pm.Deposit(sdb, caller, erc20Curr(lusdAddr), new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("Deposit#2 (replay): %v", err)
	}
	if got := fakeAvail(f, caller, erc20Curr(lusdAddr)); got != dep {
		t.Fatalf("D-Chain available after replay = %d, want %d (credited once)", got, dep)
	}
	if lusd.transfers != 1 {
		t.Fatalf("token transfers after replay = %d, want 1 (pulled once)", lusd.transfers)
	}
	assertPerTokenConservation(t, sdb, reg, lusdAddr)
}

// --- uint64 LEDGER BOUNDARY: a deposit delta beyond uint64 is REFUSED, not truncated ---
//
// The D-Chain ledger keys balances by uint64. A deposit whose OBSERVED delta exceeds
// 2^64-1 cannot be credited 1:1, so the rail REFUSES rather than truncating (a
// truncated credit would strand the untracked remainder in the vault). This pins the
// no-silent-loss behavior AND documents the cap: ~1.8e19 base units (~18 tokens at
// 18 decimals) — a real D-Chain-ledger constraint surfaced sharply by high-decimal
// ERC-20s. The transferFrom must NOT leave tokens stranded: on refusal the tx
// reverts, undoing the pull (same revert-safety as native).
func TestERC20_Deposit_ExceedsUint64Ledger_RefusedNotTruncated(t *testing.T) {
	pm, f, sdb, reg, caller := custodyPMToken(t, 0)
	lusd := newMockToken(0)
	reg.register(lusdAddr, lusd)

	// 2^64 (one past uint64 max).
	over := new(big.Int).Lsh(big.NewInt(1), 64)
	lusd.mintBig(caller, new(big.Int).Mul(over, big.NewInt(2)))
	lusd.approveBig(caller, poolManagerAddr, over)

	err := pm.Deposit(sdb, caller, erc20Curr(lusdAddr), over)
	if !errors.Is(err, ErrInvalidAmount) {
		t.Fatalf("over-uint64 deposit err = %v, want ErrInvalidAmount", err)
	}
	// No D-Chain credit recorded.
	if got := fakeAvail(f, caller, erc20Curr(lusdAddr)); got != 0 {
		t.Fatalf("D-Chain available = %d after refused over-cap deposit, want 0", got)
	}
	// NOTE: the in-memory double does not model EVM tx revert, so the mock's
	// transferFrom moved tokens into the vault before the uint64 check rejected. In
	// production the precompile error reverts the whole tx, undoing the transferFrom
	// (identical to native's lockNativeIntoVault->relay-fail revert path). The vault
	// LEDGER (the precompile's own state) was NOT updated past the check, so the
	// precompile records no backing for an uncredited deposit.
	if got := vaultLedgerOf(sdb, lusdAddr); got != 0 {
		t.Fatalf("vault ledger = %d after refused over-cap deposit, want 0 (no backing recorded)", got)
	}
}

// --- DONATION DOES NOT BREAK SAFETY: balanceOf(vault) >= Σ ledger ---
//
// The production conservation invariant is balanceOf(0x9010) >= Σ vault ledger: a
// direct ERC-20 transfer to 0x9010 OUTSIDE the deposit path ADDS unaccounted tokens
// (a donation) but NEVER subtracts backing. The withdraw guard checks the precompile
// LEDGER (not balanceOf), so a donation can never be over-released; the donated
// tokens are simply stuck (no D-Chain claim). This proves a donation cannot mint a
// D-Chain claim and cannot break the withdraw underflow guard.
func TestERC20_Donation_DoesNotMintOrUnderflow(t *testing.T) {
	pm, f, sdb, reg, caller := custodyPMToken(t, 0)
	lusd := newMockToken(0)
	reg.register(lusdAddr, lusd)

	const dep = uint64(500)
	lusd.mint(caller, 2000)
	lusd.approve(caller, poolManagerAddr, dep)
	if err := pm.Deposit(sdb, caller, erc20Curr(lusdAddr), new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	// DONATION: someone transfers tokens directly to the vault, bypassing deposit.
	// (Modeled as a direct credit to the vault's token balance — NOT a precompile op.)
	lusd.credit(poolManagerAddr, big.NewInt(777))

	// balanceOf(vault) is now dep+777, but the ledger is still dep (donation unaccounted).
	if got := lusd.balanceOf(poolManagerAddr).Uint64(); got != dep+777 {
		t.Fatalf("vault token balance = %d, want %d (deposit + donation)", got, dep+777)
	}
	if got := vaultLedgerOf(sdb, lusdAddr); got != dep {
		t.Fatalf("vault ledger = %d, want %d (donation NOT counted as backing)", got, dep)
	}
	// The donation did NOT mint a D-Chain claim — available is still just the deposit.
	if got := fakeAvail(f, caller, erc20Curr(lusdAddr)); got != dep {
		t.Fatalf("D-Chain available = %d, want %d (donation does not mint)", got, dep)
	}
	// The PRODUCTION invariant balanceOf(vault) >= ledger holds (strictly > here).
	if lusd.balanceOf(poolManagerAddr).Cmp(loadVaultLedger(sdb, lusdAddr)) < 0 {
		t.Fatalf("invariant breach: balanceOf(vault) < ledger")
	}

	// A withdraw can release UP TO the ledger (dep), never the donated surplus.
	sdb.setTxHash(common.HexToHash("0x5555000000000000000000000000000000000000000000000000000000005555"))
	realized, err := pm.Withdraw(sdb, caller, erc20Curr(lusdAddr), new(big.Int).SetUint64(dep))
	if err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	if realized.Uint64() != dep {
		t.Fatalf("realized = %d, want %d (clamped to ledger-backed claim)", realized.Uint64(), dep)
	}
	// After releasing the full deposit, the donated 777 remains stuck in the vault
	// (safe — no claim against it), ledger back to 0.
	if got := vaultLedgerOf(sdb, lusdAddr); got != 0 {
		t.Fatalf("vault ledger = %d after full withdraw, want 0", got)
	}
	if got := lusd.balanceOf(poolManagerAddr).Uint64(); got != 777 {
		t.Fatalf("vault token balance = %d after full withdraw, want 777 (donation stuck, not drained)", got)
	}
}

// --- WITHOUT A LIVE Call SURFACE: deposit fails-secure (no unbacked mint) ---
//
// poolStateAdapter's erc20Vault binding refuses when the execution environment does
// not expose a Call surface (GetPrecompileEnv()==nil through the current bridge).
// This pins the fail-secure behavior of the PRODUCTION adapter (distinct from the
// in-memory test double, which always has the capability): a token balance reads 0
// and a transfer errors, so the deposit refuses rather than minting unbacked.
func TestERC20_PoolStateAdapter_NoCallSurface_FailsSecure(t *testing.T) {
	a := &poolStateAdapter{stateDB: nil, blockNumber: 1, accessibleState: nil}
	if got := a.TokenBalanceOf(lusdAddr, lusdAddr); got.Sign() != 0 {
		t.Fatalf("TokenBalanceOf with no env = %v, want 0", got)
	}
	if err := a.TransferTokenFrom(lusdAddr, lusdAddr, poolManagerAddr, big.NewInt(1)); !errors.Is(err, ErrERC20VaultUnavailable) {
		t.Fatalf("TransferTokenFrom with no env = %v, want ErrERC20VaultUnavailable", err)
	}
	if err := a.TransferTokenTo(lusdAddr, lusdAddr, big.NewInt(1)); !errors.Is(err, ErrERC20VaultUnavailable) {
		t.Fatalf("TransferTokenTo with no env = %v, want ErrERC20VaultUnavailable", err)
	}
}
