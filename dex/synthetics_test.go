// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
)

// Test helpers
var (
	testYieldToken     = common.HexToAddress("0x1111111111111111111111111111111111111111")
	testSyntheticToken = common.HexToAddress("0x2222222222222222222222222222222222222222")
	testUser1          = common.HexToAddress("0x3333333333333333333333333333333333333333")
	testUser2          = common.HexToAddress("0x4444444444444444444444444444444444444444")
	testUnderlying     = Currency{Address: common.HexToAddress("0x5555555555555555555555555555555555555555")}
)

// Helper to create large big.Int values
func bigInt(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 10)
	return n
}

// Helper to set balance
func setBalance(stateDB *MockStateDB, addr common.Address, amount *big.Int) {
	u256, _ := uint256.FromBig(amount)
	stateDB.balances[addr] = u256
}

// =========================================================================
// Alchemist Tests
// =========================================================================

func TestAlchemist_NewAlchemist(t *testing.T) {
	pm := NewPoolManager()
	alchemist := NewAlchemist(pm)

	if alchemist == nil {
		t.Fatal("NewAlchemist returned nil")
	}
	if alchemist.yieldTokens == nil {
		t.Fatal("yieldTokens map not initialized")
	}
	if alchemist.synthetics == nil {
		t.Fatal("synthetics map not initialized")
	}
	if alchemist.accounts == nil {
		t.Fatal("accounts map not initialized")
	}
}

func TestAlchemist_AddYieldToken(t *testing.T) {
	pm := NewPoolManager()
	alchemist := NewAlchemist(pm)
	stateDB := NewMockStateDB()

	// Add yield token
	yieldPerBlock := bigInt("1000000000000000") // 0.001 per block
	err := alchemist.AddYieldToken(stateDB, testYieldToken, testUnderlying, yieldPerBlock)
	if err != nil {
		t.Fatalf("AddYieldToken failed: %v", err)
	}

	// Verify it was added
	yt := alchemist.yieldTokens[testYieldToken]
	if yt == nil {
		t.Fatal("yield token not found in map")
	}
	if !yt.IsActive {
		t.Fatal("yield token should be active")
	}
	if yt.YieldPerBlock.Cmp(yieldPerBlock) != 0 {
		t.Fatal("yield per block mismatch")
	}

	// Try adding same token again - should fail
	err = alchemist.AddYieldToken(stateDB, testYieldToken, testUnderlying, yieldPerBlock)
	if err == nil {
		t.Fatal("adding duplicate yield token should fail")
	}
}

func TestAlchemist_AddSyntheticToken(t *testing.T) {
	pm := NewPoolManager()
	alchemist := NewAlchemist(pm)
	stateDB := NewMockStateDB()

	// Add synthetic token
	debtCeiling := bigInt("1000000000000000000000000") // 1M tokens
	err := alchemist.AddSyntheticToken(stateDB, testSyntheticToken, testUnderlying, debtCeiling)
	if err != nil {
		t.Fatalf("AddSyntheticToken failed: %v", err)
	}

	// Verify it was added
	st := alchemist.synthetics[testSyntheticToken]
	if st == nil {
		t.Fatal("synthetic token not found in map")
	}
	if st.DebtCeiling.Cmp(debtCeiling) != 0 {
		t.Fatal("debt ceiling mismatch")
	}
}

func TestAlchemist_Deposit(t *testing.T) {
	pm := NewPoolManager()
	alchemist := NewAlchemist(pm)
	stateDB := NewMockStateDB()

	// Setup
	yieldPerBlock := bigInt("1000000000000000")
	alchemist.AddYieldToken(stateDB, testYieldToken, testUnderlying, yieldPerBlock)

	// Give user some balance
	setBalance(stateDB, testUser1, bigInt("1000000000000000000000")) // 1000 tokens

	// Deposit
	depositAmount := bigInt("100000000000000000000") // 100 tokens
	err := alchemist.Deposit(stateDB, testUser1, testYieldToken, depositAmount)
	if err != nil {
		t.Fatalf("Deposit failed: %v", err)
	}

	// Check account
	account := alchemist.GetAccount(stateDB, testUser1, testYieldToken)
	if account == nil {
		t.Fatal("account not created")
	}
	if account.Collateral.Cmp(depositAmount) != 0 {
		t.Fatalf("collateral mismatch: got %s, want %s", account.Collateral, depositAmount)
	}
	if account.Debt.Sign() != 0 {
		t.Fatal("debt should be zero")
	}

	// Check yield token total deposited
	yt := alchemist.yieldTokens[testYieldToken]
	if yt.TotalDeposited.Cmp(depositAmount) != 0 {
		t.Fatal("total deposited mismatch")
	}
}

func TestAlchemist_Mint_MaxLTV(t *testing.T) {
	pm := NewPoolManager()
	alchemist := NewAlchemist(pm)
	stateDB := NewMockStateDB()

	// Setup
	yieldPerBlock := bigInt("1000000000000000")
	debtCeiling := bigInt("1000000000000000000000000")
	alchemist.AddYieldToken(stateDB, testYieldToken, testUnderlying, yieldPerBlock)
	alchemist.AddSyntheticToken(stateDB, testSyntheticToken, testUnderlying, debtCeiling)

	// Deposit collateral
	setBalance(stateDB, testUser1, bigInt("1000000000000000000000"))
	depositAmount := bigInt("100000000000000000000") // 100 tokens
	alchemist.Deposit(stateDB, testUser1, testYieldToken, depositAmount)

	// Calculate max mintable (90% of collateral)
	maxMintable := new(big.Int).Mul(depositAmount, big.NewInt(MaxLTV))
	maxMintable.Div(maxMintable, big.NewInt(LTVPrecision))

	// Mint at max LTV
	err := alchemist.Mint(stateDB, testUser1, testYieldToken, testSyntheticToken, maxMintable)
	if err != nil {
		t.Fatalf("Mint at max LTV failed: %v", err)
	}

	// Check account
	account := alchemist.GetAccount(stateDB, testUser1, testYieldToken)
	if account.Debt.Cmp(maxMintable) != 0 {
		t.Fatalf("debt mismatch: got %s, want %s", account.Debt, maxMintable)
	}

	// Verify LTV is 90%
	ltv := alchemist.GetLTV(stateDB, testUser1, testYieldToken)
	if ltv.Int64() != MaxLTV {
		t.Fatalf("LTV mismatch: got %d, want %d", ltv.Int64(), MaxLTV)
	}

	// Try to mint more - should fail
	err = alchemist.Mint(stateDB, testUser1, testYieldToken, testSyntheticToken, big.NewInt(1))
	if err != ErrMaxLTVExceeded {
		t.Fatalf("expected ErrMaxLTVExceeded, got %v", err)
	}
}

func TestAlchemist_Burn(t *testing.T) {
	pm := NewPoolManager()
	alchemist := NewAlchemist(pm)
	stateDB := NewMockStateDB()

	// Setup
	yieldPerBlock := bigInt("1000000000000000")
	debtCeiling := bigInt("1000000000000000000000000")
	alchemist.AddYieldToken(stateDB, testYieldToken, testUnderlying, yieldPerBlock)
	alchemist.AddSyntheticToken(stateDB, testSyntheticToken, testUnderlying, debtCeiling)

	// Deposit and mint
	setBalance(stateDB, testUser1, bigInt("1000000000000000000000"))
	depositAmount := bigInt("100000000000000000000")
	alchemist.Deposit(stateDB, testUser1, testYieldToken, depositAmount)

	mintAmount := bigInt("50000000000000000000") // 50 tokens (50% LTV)
	alchemist.Mint(stateDB, testUser1, testYieldToken, testSyntheticToken, mintAmount)

	// Get initial debt
	account := alchemist.GetAccount(stateDB, testUser1, testYieldToken)
	initialDebt := new(big.Int).Set(account.Debt)

	// Burn half
	burnAmount := bigInt("20000000000000000000") // 20 tokens
	err := alchemist.Burn(stateDB, testUser1, testYieldToken, testSyntheticToken, burnAmount)
	if err != nil {
		t.Fatalf("Burn failed: %v", err)
	}

	// Check debt reduced (accounting for burn fee)
	account = alchemist.GetAccount(stateDB, testUser1, testYieldToken)
	// BurnFee is 10, divisor is 1,000,000 (6 decimal precision)
	fee := new(big.Int).Mul(burnAmount, big.NewInt(10))
	fee.Div(fee, big.NewInt(1_000_000))
	debtReduction := new(big.Int).Sub(burnAmount, fee)
	expectedDebt := new(big.Int).Sub(initialDebt, debtReduction)

	if account.Debt.Cmp(expectedDebt) != 0 {
		t.Fatalf("debt not reduced properly: expected %v, got %v", expectedDebt, account.Debt)
	}
}

func TestAlchemist_Withdraw_WithDebt(t *testing.T) {
	pm := NewPoolManager()
	alchemist := NewAlchemist(pm)
	stateDB := NewMockStateDB()

	// Setup
	yieldPerBlock := bigInt("1000000000000000")
	debtCeiling := bigInt("1000000000000000000000000")
	alchemist.AddYieldToken(stateDB, testYieldToken, testUnderlying, yieldPerBlock)
	alchemist.AddSyntheticToken(stateDB, testSyntheticToken, testUnderlying, debtCeiling)

	// Deposit and mint at 50% LTV
	setBalance(stateDB, testUser1, bigInt("1000000000000000000000"))
	depositAmount := bigInt("100000000000000000000") // 100 tokens
	alchemist.Deposit(stateDB, testUser1, testYieldToken, depositAmount)

	mintAmount := bigInt("50000000000000000000") // 50 tokens (50% LTV)
	alchemist.Mint(stateDB, testUser1, testYieldToken, testSyntheticToken, mintAmount)

	// Try to withdraw too much (would breach 90% LTV)
	// With 50 debt and 90% max LTV, need at least 55.56 collateral
	// So can withdraw at most ~44.44 tokens
	withdrawAmount := bigInt("50000000000000000000") // 50 tokens - should fail
	err := alchemist.Withdraw(stateDB, testUser1, testYieldToken, withdrawAmount)
	if err != ErrMaxLTVExceeded {
		t.Fatalf("expected ErrMaxLTVExceeded, got %v", err)
	}

	// Withdraw smaller amount (should succeed)
	withdrawAmount = bigInt("40000000000000000000") // 40 tokens
	err = alchemist.Withdraw(stateDB, testUser1, testYieldToken, withdrawAmount)
	if err != nil {
		t.Fatalf("small withdraw failed: %v", err)
	}

	// Verify collateral reduced
	account := alchemist.GetAccount(stateDB, testUser1, testYieldToken)
	expectedCollateral := new(big.Int).Sub(depositAmount, withdrawAmount)
	if account.Collateral.Cmp(expectedCollateral) != 0 {
		t.Fatalf("collateral mismatch: got %s, want %s", account.Collateral, expectedCollateral)
	}
}

func TestAlchemist_GetMaxMintable(t *testing.T) {
	pm := NewPoolManager()
	alchemist := NewAlchemist(pm)
	stateDB := NewMockStateDB()

	// Setup
	yieldPerBlock := bigInt("1000000000000000")
	debtCeiling := bigInt("1000000000000000000000000")
	alchemist.AddYieldToken(stateDB, testYieldToken, testUnderlying, yieldPerBlock)
	alchemist.AddSyntheticToken(stateDB, testSyntheticToken, testUnderlying, debtCeiling)

	// Deposit
	setBalance(stateDB, testUser1, bigInt("1000000000000000000000"))
	depositAmount := bigInt("100000000000000000000") // 100 tokens
	alchemist.Deposit(stateDB, testUser1, testYieldToken, depositAmount)

	// Check max mintable = 90% of collateral
	maxMintable := alchemist.GetMaxMintable(stateDB, testUser1, testYieldToken)
	expected := new(big.Int).Mul(depositAmount, big.NewInt(MaxLTV))
	expected.Div(expected, big.NewInt(LTVPrecision))

	if maxMintable.Cmp(expected) != 0 {
		t.Fatalf("max mintable mismatch: got %s, want %s", maxMintable, expected)
	}

	// Mint some
	mintAmount := bigInt("50000000000000000000")
	alchemist.Mint(stateDB, testUser1, testYieldToken, testSyntheticToken, mintAmount)

	// Check max mintable reduced
	maxMintable = alchemist.GetMaxMintable(stateDB, testUser1, testYieldToken)
	expectedRemaining := new(big.Int).Sub(expected, mintAmount)
	if maxMintable.Cmp(expectedRemaining) != 0 {
		t.Fatalf("remaining mintable mismatch: got %s, want %s", maxMintable, expectedRemaining)
	}
}

func TestAlchemist_GetTimeToRepayment(t *testing.T) {
	pm := NewPoolManager()
	alchemist := NewAlchemist(pm)
	stateDB := NewMockStateDB()

	// Setup with known yield rate
	yieldPerBlock := bigInt("1000000000000000") // 0.001 per block per unit
	debtCeiling := bigInt("1000000000000000000000000")
	alchemist.AddYieldToken(stateDB, testYieldToken, testUnderlying, yieldPerBlock)
	alchemist.AddSyntheticToken(stateDB, testSyntheticToken, testUnderlying, debtCeiling)

	// Deposit 100 tokens
	setBalance(stateDB, testUser1, bigInt("1000000000000000000000"))
	depositAmount := bigInt("100000000000000000000") // 100 tokens
	alchemist.Deposit(stateDB, testUser1, testYieldToken, depositAmount)

	// Mint 90 tokens (90% LTV)
	mintAmount := bigInt("90000000000000000000")
	alchemist.Mint(stateDB, testUser1, testYieldToken, testSyntheticToken, mintAmount)

	// Calculate expected time to repayment
	// Yield per block = collateral * yieldPerBlock / 1e18 = 100e18 * 1e15 / 1e18 = 1e17
	// Time = debt / yieldPerBlock = 90e18 / 1e17 = 900 blocks
	timeToRepay := alchemist.GetTimeToRepayment(stateDB, testUser1, testYieldToken)

	// Allow some tolerance for fees
	if timeToRepay < 800 || timeToRepay > 1000 {
		t.Fatalf("time to repayment unexpected: got %d blocks", timeToRepay)
	}
}

// =========================================================================
// Transmuter Tests
// =========================================================================

func TestTransmuter_NewTransmuter(t *testing.T) {
	pm := NewPoolManager()
	alchemist := NewAlchemist(pm)
	transmuter := NewTransmuter(alchemist)

	if transmuter == nil {
		t.Fatal("NewTransmuter returned nil")
	}
	if transmuter.states == nil {
		t.Fatal("states map not initialized")
	}
	if transmuter.stakes == nil {
		t.Fatal("stakes map not initialized")
	}
}

func TestTransmuter_InitializeTransmuter(t *testing.T) {
	pm := NewPoolManager()
	alchemist := NewAlchemist(pm)
	transmuter := NewTransmuter(alchemist)
	stateDB := NewMockStateDB()

	err := transmuter.InitializeTransmuter(stateDB, testSyntheticToken, testUnderlying)
	if err != nil {
		t.Fatalf("InitializeTransmuter failed: %v", err)
	}

	state := transmuter.GetTransmuterState(testSyntheticToken)
	if state == nil {
		t.Fatal("transmuter state not found")
	}
	if state.SyntheticToken != testSyntheticToken {
		t.Fatal("synthetic token mismatch")
	}
	if state.ExchangeBuffer.Sign() != 0 {
		t.Fatal("exchange buffer should start at 0")
	}
}

func TestTransmuter_Stake(t *testing.T) {
	pm := NewPoolManager()
	alchemist := NewAlchemist(pm)
	transmuter := NewTransmuter(alchemist)
	stateDB := NewMockStateDB()

	// Setup
	transmuter.InitializeTransmuter(stateDB, testSyntheticToken, testUnderlying)
	setBalance(stateDB, testUser1, bigInt("1000000000000000000000"))

	// Stake
	stakeAmount := bigInt("100000000000000000000")
	err := transmuter.Stake(stateDB, testUser1, testSyntheticToken, stakeAmount)
	if err != nil {
		t.Fatalf("Stake failed: %v", err)
	}

	// Check stake
	stake := transmuter.GetStake(stateDB, testUser1, testSyntheticToken)
	if stake == nil {
		t.Fatal("stake not found")
	}
	if stake.StakedAmount.Cmp(stakeAmount) != 0 {
		t.Fatalf("staked amount mismatch: got %s, want %s", stake.StakedAmount, stakeAmount)
	}

	// Check total staked
	state := transmuter.GetTransmuterState(testSyntheticToken)
	if state.TotalStaked.Cmp(stakeAmount) != 0 {
		t.Fatal("total staked mismatch")
	}
}

func TestTransmuter_Deposit_And_Claim(t *testing.T) {
	pm := NewPoolManager()
	alchemist := NewAlchemist(pm)
	transmuter := NewTransmuter(alchemist)
	stateDB := NewMockStateDB()

	// Setup
	transmuter.InitializeTransmuter(stateDB, testSyntheticToken, testUnderlying)
	setBalance(stateDB, testUser1, bigInt("1000000000000000000000"))
	setBalance(stateDB, transmuterAddr, bigInt("1000000000000000000000")) // Give transmuter some underlying

	// User stakes synthetic
	stakeAmount := bigInt("100000000000000000000")
	transmuter.Stake(stateDB, testUser1, testSyntheticToken, stakeAmount)

	// Deposit underlying into transmuter (simulating yield flow)
	depositAmount := bigInt("50000000000000000000") // 50% of staked
	transmuter.Deposit(stateDB, testSyntheticToken, depositAmount)

	// Check claimable
	claimable := transmuter.GetClaimable(stateDB, testUser1, testSyntheticToken)
	if claimable.Cmp(depositAmount) != 0 {
		t.Fatalf("claimable mismatch: got %s, want %s", claimable, depositAmount)
	}

	// Claim
	claimed, err := transmuter.Claim(stateDB, testUser1, testSyntheticToken)
	if err != nil {
		t.Fatalf("Claim failed: %v", err)
	}
	if claimed.Cmp(depositAmount) != 0 {
		t.Fatalf("claimed amount mismatch: got %s, want %s", claimed, depositAmount)
	}

	// Check stake reduced (synthetics converted)
	stake := transmuter.GetStake(stateDB, testUser1, testSyntheticToken)
	expectedRemaining := new(big.Int).Sub(stakeAmount, depositAmount)
	if stake.StakedAmount.Cmp(expectedRemaining) != 0 {
		t.Fatalf("remaining stake mismatch: got %s, want %s", stake.StakedAmount, expectedRemaining)
	}
}

func TestTransmuter_Unstake(t *testing.T) {
	pm := NewPoolManager()
	alchemist := NewAlchemist(pm)
	transmuter := NewTransmuter(alchemist)
	stateDB := NewMockStateDB()

	// Setup
	transmuter.InitializeTransmuter(stateDB, testSyntheticToken, testUnderlying)
	setBalance(stateDB, testUser1, bigInt("1000000000000000000000"))

	// Stake
	stakeAmount := bigInt("100000000000000000000")
	transmuter.Stake(stateDB, testUser1, testSyntheticToken, stakeAmount)

	// Unstake half
	unstakeAmount := bigInt("50000000000000000000")
	err := transmuter.Unstake(stateDB, testUser1, testSyntheticToken, unstakeAmount)
	if err != nil {
		t.Fatalf("Unstake failed: %v", err)
	}

	// Check remaining stake
	stake := transmuter.GetStake(stateDB, testUser1, testSyntheticToken)
	expectedRemaining := new(big.Int).Sub(stakeAmount, unstakeAmount)
	if stake.StakedAmount.Cmp(expectedRemaining) != 0 {
		t.Fatalf("remaining stake mismatch: got %s, want %s", stake.StakedAmount, expectedRemaining)
	}
}

func TestTransmuter_MultipleStakers(t *testing.T) {
	pm := NewPoolManager()
	alchemist := NewAlchemist(pm)
	transmuter := NewTransmuter(alchemist)
	stateDB := NewMockStateDB()

	// Setup
	transmuter.InitializeTransmuter(stateDB, testSyntheticToken, testUnderlying)
	setBalance(stateDB, testUser1, bigInt("1000000000000000000000"))
	setBalance(stateDB, testUser2, bigInt("1000000000000000000000"))
	setBalance(stateDB, transmuterAddr, bigInt("1000000000000000000000"))

	// User1 stakes 100
	user1Stake := bigInt("100000000000000000000")
	transmuter.Stake(stateDB, testUser1, testSyntheticToken, user1Stake)

	// User2 stakes 200
	user2Stake := bigInt("200000000000000000000")
	transmuter.Stake(stateDB, testUser2, testSyntheticToken, user2Stake)

	// Deposit 150 underlying (should split proportionally)
	depositAmount := bigInt("150000000000000000000")
	transmuter.Deposit(stateDB, testSyntheticToken, depositAmount)

	// User1 should get 1/3 = 50
	// User2 should get 2/3 = 100
	claimable1 := transmuter.GetClaimable(stateDB, testUser1, testSyntheticToken)
	claimable2 := transmuter.GetClaimable(stateDB, testUser2, testSyntheticToken)

	expectedUser1 := bigInt("50000000000000000000")
	expectedUser2 := bigInt("100000000000000000000")

	if claimable1.Cmp(expectedUser1) != 0 {
		t.Fatalf("user1 claimable mismatch: got %s, want %s", claimable1, expectedUser1)
	}
	if claimable2.Cmp(expectedUser2) != 0 {
		t.Fatalf("user2 claimable mismatch: got %s, want %s", claimable2, expectedUser2)
	}
}

// =========================================================================
// Integration Tests
// =========================================================================

func TestAlchemist_FullFlow(t *testing.T) {
	pm := NewPoolManager()
	alchemist := NewAlchemist(pm)
	transmuter := NewTransmuter(alchemist)
	stateDB := NewMockStateDB()

	// Setup tokens
	yieldPerBlock := bigInt("1000000000000000")
	debtCeiling := bigInt("1000000000000000000000000")
	alchemist.AddYieldToken(stateDB, testYieldToken, testUnderlying, yieldPerBlock)
	alchemist.AddSyntheticToken(stateDB, testSyntheticToken, testUnderlying, debtCeiling)
	transmuter.InitializeTransmuter(stateDB, testSyntheticToken, testUnderlying)

	// User deposits LP tokens
	setBalance(stateDB, testUser1, bigInt("1000000000000000000000"))
	depositAmount := bigInt("100000000000000000000")
	alchemist.Deposit(stateDB, testUser1, testYieldToken, depositAmount)

	// User mints synthetic at 90% LTV
	maxMint := alchemist.GetMaxMintable(stateDB, testUser1, testYieldToken)
	alchemist.Mint(stateDB, testUser1, testYieldToken, testSyntheticToken, maxMint)

	// Verify position
	account := alchemist.GetAccount(stateDB, testUser1, testYieldToken)
	if account.Debt.Cmp(maxMint) != 0 {
		t.Fatal("debt should equal minted amount")
	}

	ltv := alchemist.GetLTV(stateDB, testUser1, testYieldToken)
	if ltv.Int64() != MaxLTV {
		t.Fatalf("LTV should be 90%%, got %d", ltv.Int64())
	}

	// User can use synthetics (e.g., stake in transmuter)
	transmuter.Stake(stateDB, testUser1, testSyntheticToken, maxMint)

	// Verify synthetics are staked
	stake := transmuter.GetStake(stateDB, testUser1, testSyntheticToken)
	if stake.StakedAmount.Sign() == 0 {
		t.Fatal("no synthetics staked")
	}

	t.Logf("Full flow completed:")
	t.Logf("  Deposited: %s yield tokens", depositAmount)
	t.Logf("  Minted: %s synthetics (90%% LTV)", maxMint)
	t.Logf("  Staked in transmuter: %s", stake.StakedAmount)
}

// =========================================================================
// Benchmark Tests
// =========================================================================

func BenchmarkAlchemist_Deposit(b *testing.B) {
	pm := NewPoolManager()
	alchemist := NewAlchemist(pm)
	stateDB := NewMockStateDB()

	yieldPerBlock := bigInt("1000000000000000")
	alchemist.AddYieldToken(stateDB, testYieldToken, testUnderlying, yieldPerBlock)
	depositAmount := bigInt("1000000000000000000")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Use different users to avoid harvest overhead
		user := common.BigToAddress(big.NewInt(int64(i)))
		setBalance(stateDB, user, bigInt("1000000000000000000000000000000"))
		alchemist.Deposit(stateDB, user, testYieldToken, depositAmount)
	}
}

func BenchmarkAlchemist_Mint(b *testing.B) {
	pm := NewPoolManager()
	alchemist := NewAlchemist(pm)
	stateDB := NewMockStateDB()

	yieldPerBlock := bigInt("1000000000000000")
	debtCeiling := bigInt("1000000000000000000000000000000")
	alchemist.AddYieldToken(stateDB, testYieldToken, testUnderlying, yieldPerBlock)
	alchemist.AddSyntheticToken(stateDB, testSyntheticToken, testUnderlying, debtCeiling)

	// Pre-deposit for many users
	depositAmount := bigInt("100000000000000000000")
	mintAmount := bigInt("50000000000000000000")
	for i := 0; i < b.N; i++ {
		user := common.BigToAddress(big.NewInt(int64(i)))
		setBalance(stateDB, user, bigInt("1000000000000000000000000000000"))
		alchemist.Deposit(stateDB, user, testYieldToken, depositAmount)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		user := common.BigToAddress(big.NewInt(int64(i)))
		alchemist.Mint(stateDB, user, testYieldToken, testSyntheticToken, mintAmount)
	}
}

func BenchmarkTransmuter_Stake(b *testing.B) {
	pm := NewPoolManager()
	alchemist := NewAlchemist(pm)
	transmuter := NewTransmuter(alchemist)
	stateDB := NewMockStateDB()

	transmuter.InitializeTransmuter(stateDB, testSyntheticToken, testUnderlying)
	stakeAmount := bigInt("1000000000000000000")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		user := common.BigToAddress(big.NewInt(int64(i)))
		setBalance(stateDB, user, bigInt("1000000000000000000000000000000"))
		transmuter.Stake(stateDB, user, testSyntheticToken, stakeAmount)
	}
}
