// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"sync"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/zeebo/blake3"
)

// Precompile address as bytes
var transmuterAddr = common.HexToAddress(TransmuterAddress)

// Storage key prefixes for Transmuter state
var (
	transmuterStatePrefix  = []byte("xmut/state")
	transmuterStakePrefix  = []byte("xmut/stake")
	transmuterQueuePrefix  = []byte("xmut/queue")
)

// Transmuter allows conversion of synthetic tokens back to underlying assets
// Based on Alchemix's Transmuter design:
// 1. Users stake synthetic tokens (e.g., luxUSD) in the transmuter
// 2. As underlying flows in (from yield harvesting), staked synthetics convert
// 3. Users can claim their proportional share of underlying
//
// This provides an exit mechanism from synthetics without market selling
type Transmuter struct {
	mu sync.RWMutex

	// Transmuter state per synthetic token
	states map[common.Address]*TransmuterState

	// User stakes (keyed by synthetic + user)
	stakes map[[32]byte]*TransmuterStake

	// Reference to Alchemist for yield flow
	alchemist *Alchemist
}

// TransmuterStake represents a user's stake in the transmuter
type TransmuterStake struct {
	Owner           common.Address
	SyntheticToken  common.Address
	StakedAmount    *big.Int       // Amount of synthetic staked
	UnclaimedAmount *big.Int       // Underlying available to claim
	LastUpdateIndex *big.Int       // Index at last update (for pro-rata)
}

// NewTransmuter creates a new Transmuter instance
func NewTransmuter(alchemist *Alchemist) *Transmuter {
	return &Transmuter{
		states:    make(map[common.Address]*TransmuterState),
		stakes:    make(map[[32]byte]*TransmuterStake),
		alchemist: alchemist,
	}
}

// stakeKey generates unique key for user stake
func stakeKey(synthetic common.Address, owner common.Address) [32]byte {
	h := blake3.New()
	h.Write(synthetic.Bytes())
	h.Write(owner.Bytes())
	var key [32]byte
	h.Digest().Read(key[:])
	return key
}

// =========================================================================
// Admin Functions
// =========================================================================

// InitializeTransmuter sets up a transmuter for a synthetic token
func (t *Transmuter) InitializeTransmuter(
	stateDB StateDB,
	syntheticToken common.Address,
	underlyingAsset Currency,
) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, exists := t.states[syntheticToken]; exists {
		return ErrSyntheticNotRegistered
	}

	state := &TransmuterState{
		SyntheticToken:  syntheticToken,
		UnderlyingAsset: underlyingAsset,
		ExchangeBuffer:  big.NewInt(0),
		TotalStaked:     big.NewInt(0),
		ExchangeRate:    new(big.Int).Set(Q96), // 1:1 initial rate
	}

	t.states[syntheticToken] = state
	t.saveState(stateDB, state)

	return nil
}

// =========================================================================
// Core Transmuter Operations
// =========================================================================

// Stake stakes synthetic tokens for transmutation
// Staked synthetics will be converted to underlying as yield flows in
func (t *Transmuter) Stake(
	stateDB StateDB,
	owner common.Address,
	syntheticToken common.Address,
	amount *big.Int,
) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	state, exists := t.states[syntheticToken]
	if !exists {
		return ErrSyntheticNotRegistered
	}

	if amount.Sign() <= 0 {
		return ErrInvalidPositionSize
	}

	// Get or create stake
	key := stakeKey(syntheticToken, owner)
	stake := t.getStake(stateDB, key)
	if stake == nil {
		stake = &TransmuterStake{
			Owner:           owner,
			SyntheticToken:  syntheticToken,
			StakedAmount:    big.NewInt(0),
			UnclaimedAmount: big.NewInt(0),
			LastUpdateIndex: new(big.Int).Set(state.ExchangeRate),
		}
	}

	// Update stake's unclaimed amount based on exchange rate change
	t.updateStakeUnclaimed(stake, state)

	// Transfer synthetic tokens from user
	t.transferSynthetic(stateDB, syntheticToken, owner, transmuterAddr, amount)

	// Update stake
	stake.StakedAmount = new(big.Int).Add(stake.StakedAmount, amount)
	stake.LastUpdateIndex = new(big.Int).Set(state.ExchangeRate)

	// Update total staked
	state.TotalStaked = new(big.Int).Add(state.TotalStaked, amount)

	// Save state
	t.saveStake(stateDB, key, stake)
	t.saveState(stateDB, state)

	return nil
}

// Unstake removes synthetic tokens from transmutation queue
// Only unexchanged (remaining) synthetics can be unstaked
func (t *Transmuter) Unstake(
	stateDB StateDB,
	owner common.Address,
	syntheticToken common.Address,
	amount *big.Int,
) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	state, exists := t.states[syntheticToken]
	if !exists {
		return ErrSyntheticNotRegistered
	}

	key := stakeKey(syntheticToken, owner)
	stake := t.getStake(stateDB, key)
	if stake == nil || stake.StakedAmount.Sign() == 0 {
		return ErrInvalidPositionSize
	}

	// Update unclaimed first
	t.updateStakeUnclaimed(stake, state)

	// Check unstake amount
	if amount.Cmp(stake.StakedAmount) > 0 {
		amount = new(big.Int).Set(stake.StakedAmount)
	}

	// Update stake
	stake.StakedAmount = new(big.Int).Sub(stake.StakedAmount, amount)

	// Update total staked
	state.TotalStaked = new(big.Int).Sub(state.TotalStaked, amount)

	// Transfer synthetic tokens back to user
	t.transferSynthetic(stateDB, syntheticToken, transmuterAddr, owner, amount)

	// Save state
	t.saveStake(stateDB, key, stake)
	t.saveState(stateDB, state)

	return nil
}

// Claim claims converted underlying tokens
// Returns the amount of underlying claimed
func (t *Transmuter) Claim(
	stateDB StateDB,
	owner common.Address,
	syntheticToken common.Address,
) (*big.Int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	state, exists := t.states[syntheticToken]
	if !exists {
		return nil, ErrSyntheticNotRegistered
	}

	key := stakeKey(syntheticToken, owner)
	stake := t.getStake(stateDB, key)
	if stake == nil {
		return nil, ErrTransmuterEmpty
	}

	// Update unclaimed
	t.updateStakeUnclaimed(stake, state)

	claimAmount := new(big.Int).Set(stake.UnclaimedAmount)
	if claimAmount.Sign() == 0 {
		return big.NewInt(0), nil
	}

	// Check buffer has enough
	if claimAmount.Cmp(state.ExchangeBuffer) > 0 {
		claimAmount = new(big.Int).Set(state.ExchangeBuffer)
	}

	// Update state
	stake.UnclaimedAmount = new(big.Int).Sub(stake.UnclaimedAmount, claimAmount)
	state.ExchangeBuffer = new(big.Int).Sub(state.ExchangeBuffer, claimAmount)

	// Transfer underlying to user
	t.transferUnderlying(stateDB, state.UnderlyingAsset, transmuterAddr, owner, claimAmount)

	// Save state
	t.saveStake(stateDB, key, stake)
	t.saveState(stateDB, state)

	return claimAmount, nil
}

// Deposit deposits underlying tokens into the transmuter buffer
// Called by Alchemist when harvesting yield for debt repayment overflow
func (t *Transmuter) Deposit(
	stateDB StateDB,
	syntheticToken common.Address,
	underlyingAmount *big.Int,
) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	state, exists := t.states[syntheticToken]
	if !exists {
		return ErrSyntheticNotRegistered
	}

	if underlyingAmount.Sign() <= 0 {
		return nil
	}

	// Add to exchange buffer
	state.ExchangeBuffer = new(big.Int).Add(state.ExchangeBuffer, underlyingAmount)

	// Update exchange rate if there are stakers
	if state.TotalStaked.Sign() > 0 {
		// exchangeRate increases as underlying flows in
		// newRate = oldRate + (underlyingAmount * Q96 / totalStaked)
		rateIncrease := new(big.Int).Mul(underlyingAmount, Q96)
		rateIncrease.Div(rateIncrease, state.TotalStaked)
		state.ExchangeRate = new(big.Int).Add(state.ExchangeRate, rateIncrease)
	}

	t.saveState(stateDB, state)

	return nil
}

// =========================================================================
// View Functions
// =========================================================================

// GetStake returns a user's stake information
func (t *Transmuter) GetStake(
	stateDB StateDB,
	owner common.Address,
	syntheticToken common.Address,
) *TransmuterStake {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key := stakeKey(syntheticToken, owner)
	return t.getStake(stateDB, key)
}

// GetTransmuterState returns the transmuter state for a synthetic
func (t *Transmuter) GetTransmuterState(
	syntheticToken common.Address,
) *TransmuterState {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.states[syntheticToken]
}

// GetClaimable returns the amount of underlying a user can claim
func (t *Transmuter) GetClaimable(
	stateDB StateDB,
	owner common.Address,
	syntheticToken common.Address,
) *big.Int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	state, exists := t.states[syntheticToken]
	if !exists {
		return big.NewInt(0)
	}

	key := stakeKey(syntheticToken, owner)
	stake := t.getStake(stateDB, key)
	if stake == nil {
		return big.NewInt(0)
	}

	// Calculate current unclaimed
	unclaimed := new(big.Int).Set(stake.UnclaimedAmount)

	// Add newly accrued based on exchange rate change
	if stake.StakedAmount.Sign() > 0 {
		rateDiff := new(big.Int).Sub(state.ExchangeRate, stake.LastUpdateIndex)
		if rateDiff.Sign() > 0 {
			newUnclaimed := new(big.Int).Mul(stake.StakedAmount, rateDiff)
			newUnclaimed.Div(newUnclaimed, Q96)
			unclaimed.Add(unclaimed, newUnclaimed)
		}
	}

	// Cap at available buffer
	if unclaimed.Cmp(state.ExchangeBuffer) > 0 {
		return new(big.Int).Set(state.ExchangeBuffer)
	}

	return unclaimed
}

// GetExchangeRate returns the current exchange rate
func (t *Transmuter) GetExchangeRate(syntheticToken common.Address) *big.Int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	state, exists := t.states[syntheticToken]
	if !exists {
		return new(big.Int).Set(Q96)
	}

	return new(big.Int).Set(state.ExchangeRate)
}

// =========================================================================
// Internal Functions
// =========================================================================

// updateStakeUnclaimed updates a stake's unclaimed amount based on exchange rate
func (t *Transmuter) updateStakeUnclaimed(stake *TransmuterStake, state *TransmuterState) {
	if stake.StakedAmount.Sign() == 0 {
		return
	}

	// Calculate newly accrued based on exchange rate change
	rateDiff := new(big.Int).Sub(state.ExchangeRate, stake.LastUpdateIndex)
	if rateDiff.Sign() <= 0 {
		return
	}

	// newUnclaimed = stakedAmount * rateDiff / Q96
	newUnclaimed := new(big.Int).Mul(stake.StakedAmount, rateDiff)
	newUnclaimed.Div(newUnclaimed, Q96)

	stake.UnclaimedAmount = new(big.Int).Add(stake.UnclaimedAmount, newUnclaimed)

	// Reduce staked amount by converted amount (synthetics are "burned" as they convert)
	if newUnclaimed.Cmp(stake.StakedAmount) >= 0 {
		stake.StakedAmount = big.NewInt(0)
	} else {
		stake.StakedAmount = new(big.Int).Sub(stake.StakedAmount, newUnclaimed)
	}

	stake.LastUpdateIndex = new(big.Int).Set(state.ExchangeRate)
}

// =========================================================================
// Storage Management
// =========================================================================

func (t *Transmuter) getStake(stateDB StateDB, key [32]byte) *TransmuterStake {
	if stake, ok := t.stakes[key]; ok {
		return stake
	}

	// Load from state (simplified)
	storageKey := makeStorageKey(transmuterStakePrefix, key[:])
	data := stateDB.GetState(transmuterAddr, storageKey)
	if data == (common.Hash{}) {
		return nil
	}

	stake := &TransmuterStake{
		StakedAmount:    big.NewInt(0).SetBytes(data[:16]),
		UnclaimedAmount: big.NewInt(0).SetBytes(data[16:]),
		LastUpdateIndex: new(big.Int).Set(Q96),
	}
	t.stakes[key] = stake
	return stake
}

func (t *Transmuter) saveStake(stateDB StateDB, key [32]byte, stake *TransmuterStake) {
	t.stakes[key] = stake

	storageKey := makeStorageKey(transmuterStakePrefix, key[:])
	var data common.Hash
	stakedBytes := stake.StakedAmount.Bytes()
	unclaimedBytes := stake.UnclaimedAmount.Bytes()
	copy(data[:16], stakedBytes)
	copy(data[16:], unclaimedBytes)
	stateDB.SetState(transmuterAddr, storageKey, data)
}

func (t *Transmuter) saveState(stateDB StateDB, state *TransmuterState) {
	t.states[state.SyntheticToken] = state

	// In production, would serialize full struct to state
	storageKey := makeStorageKey(transmuterStatePrefix, state.SyntheticToken.Bytes())
	var data common.Hash
	bufferBytes := state.ExchangeBuffer.Bytes()
	totalBytes := state.TotalStaked.Bytes()
	copy(data[:16], bufferBytes)
	copy(data[16:], totalBytes)
	stateDB.SetState(transmuterAddr, storageKey, data)
}

// Token transfer helpers
func (t *Transmuter) transferSynthetic(stateDB StateDB, token common.Address, from, to common.Address, amount *big.Int) {
	amountU256, _ := uint256.FromBig(amount)
	stateDB.SubBalance(from, amountU256)
	stateDB.AddBalance(to, amountU256)
}

func (t *Transmuter) transferUnderlying(stateDB StateDB, currency Currency, from, to common.Address, amount *big.Int) {
	amountU256, _ := uint256.FromBig(amount)
	stateDB.SubBalance(from, amountU256)
	stateDB.AddBalance(to, amountU256)
}
