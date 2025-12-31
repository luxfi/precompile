// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridge

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/luxfi/geth/common"
)

// BridgeGateway is the main bridge interface for cross-chain transfers
// This precompile at 0x0440 handles bridge initiation and completion
type BridgeGateway struct {
	// State
	Requests       map[[32]byte]*BridgeRequest
	Nonces         map[common.Address]uint64 // Per-address nonces
	SupportedTokens map[common.Address]*BridgedToken
	SupportedChains map[uint32]bool

	// Liquidity pools
	Pools map[uint32]map[common.Address]*LiquidityPool // ChainID -> Token -> Pool

	// Signer set (interface to B-Chain)
	SignerSet *SignerSet

	// Configuration
	Config  *BridgeFeeConfig
	Enabled bool
	Paused  bool

	mu sync.RWMutex
}

// NewBridgeGateway creates a new bridge gateway
func NewBridgeGateway() *BridgeGateway {
	gw := &BridgeGateway{
		Requests:        make(map[[32]byte]*BridgeRequest),
		Nonces:          make(map[common.Address]uint64),
		SupportedTokens: make(map[common.Address]*BridgedToken),
		SupportedChains: make(map[uint32]bool),
		Pools:           make(map[uint32]map[common.Address]*LiquidityPool),
		SignerSet:       &SignerSet{
			Signers:   make([]*SignerInfo, 0),
			Waitlist:  make([][20]byte, 0),
			Threshold: 67, // 2/3 default
		},
		Config: &BridgeFeeConfig{
			BaseFee:      big.NewInt(1e15),               // 0.001 token
			PercentFee:   30,                              // 0.3%
			MinFee:       big.NewInt(1e15),               // 0.001 token
			MaxFee:       new(big.Int).Mul(big.NewInt(1e18), big.NewInt(100)), // 100 tokens
			LiquidityFee: 20,                              // 0.2% to LPs
			ProtocolFee:  10,                              // 0.1% protocol
		},
		Enabled: true,
		Paused:  false,
	}

	// Initialize supported chains
	gw.initSupportedChains()

	return gw
}

func (gw *BridgeGateway) initSupportedChains() {
	// Lux ecosystem
	gw.SupportedChains[ChainLux] = true
	gw.SupportedChains[ChainLuxTest] = true
	gw.SupportedChains[ChainHanzo] = true
	gw.SupportedChains[ChainHanzoTest] = true
	gw.SupportedChains[ChainZoo] = true
	gw.SupportedChains[ChainZooTest] = true
	gw.SupportedChains[ChainSPC] = true
	gw.SupportedChains[ChainSPCTest] = true

	// External chains
	gw.SupportedChains[ChainEthereum] = true
	gw.SupportedChains[ChainArbitrum] = true
	gw.SupportedChains[ChainOptimism] = true
	gw.SupportedChains[ChainBase] = true
	gw.SupportedChains[ChainPolygon] = true
	gw.SupportedChains[ChainBSC] = true
	gw.SupportedChains[ChainAvalanche] = true
}

// InitiateBridge starts a cross-chain transfer
func (gw *BridgeGateway) InitiateBridge(
	sender common.Address,
	recipient common.Address,
	token common.Address,
	amount *big.Int,
	sourceChain uint32,
	destChain uint32,
	deadline uint64,
	data []byte,
) (*BridgeRequest, error) {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	// Validations
	if !gw.Enabled || gw.Paused {
		return nil, ErrBridgeDisabled
	}

	if !gw.SupportedChains[destChain] {
		return nil, ErrChainNotSupported
	}

	// Check token is supported
	tokenInfo := gw.SupportedTokens[token]
	if tokenInfo == nil || !tokenInfo.Enabled {
		return nil, ErrTokenNotSupported
	}

	// Check amount limits
	if amount.Cmp(tokenInfo.MinBridge) < 0 {
		return nil, ErrAmountTooLow
	}
	if tokenInfo.MaxBridge.Sign() > 0 && amount.Cmp(tokenInfo.MaxBridge) > 0 {
		return nil, ErrAmountTooHigh
	}

	// Check daily limit
	gw.resetDailyLimitIfNeeded(tokenInfo)
	newTotal := new(big.Int).Add(tokenInfo.BridgedToday, amount)
	if tokenInfo.DailyLimit.Sign() > 0 && newTotal.Cmp(tokenInfo.DailyLimit) > 0 {
		return nil, ErrDailyLimitExceeded
	}

	// Check liquidity on destination chain
	pool := gw.getPool(destChain, token)
	if pool == nil || pool.Available.Cmp(amount) < 0 {
		return nil, ErrInsufficientLiquidity
	}

	// Generate request ID
	nonce := gw.Nonces[sender]
	gw.Nonces[sender] = nonce + 1

	requestID := gw.generateRequestID(sender, recipient, token, amount, sourceChain, destChain, nonce)

	// Calculate fee
	fee := gw.calculateFee(amount)

	// Create request
	request := &BridgeRequest{
		ID:          requestID,
		Sender:      sender,
		Recipient:   recipient,
		Token:       token,
		Amount:      new(big.Int).Sub(amount, fee), // Amount after fee
		SourceChain: sourceChain,
		DestChain:   destChain,
		Nonce:       nonce,
		Deadline:    deadline,
		Data:        data,
		Status:      StatusPending,
		Signatures:  make([][]byte, 0),
		CreatedAt:   uint64(time.Now().Unix()),
	}

	// Update state
	gw.Requests[requestID] = request
	tokenInfo.BridgedToday.Add(tokenInfo.BridgedToday, amount)

	// Reserve liquidity on destination
	pool.Available.Sub(pool.Available, request.Amount)

	return request, nil
}

// CompleteBridge completes a bridge on the destination chain
func (gw *BridgeGateway) CompleteBridge(
	requestID [32]byte,
	signatures [][]byte,
) error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	request := gw.Requests[requestID]
	if request == nil {
		return ErrRequestNotFound
	}

	if request.Status == StatusCompleted {
		return ErrRequestAlreadyDone
	}

	if request.Deadline > 0 && uint64(time.Now().Unix()) > request.Deadline {
		request.Status = StatusExpired
		return ErrRequestExpired
	}

	// Verify signatures meet threshold
	if uint32(len(signatures)) < gw.getThreshold() {
		return ErrSignatureThreshold
	}

	// Verify each signature
	message := gw.encodeMessage(request)
	for _, sig := range signatures {
		if !gw.verifySignature(message, sig) {
			return ErrInvalidSignature
		}
	}

	// Mark completed
	request.Status = StatusCompleted
	request.Signatures = signatures
	request.CompletedAt = uint64(time.Now().Unix())

	return nil
}

// GetRequest returns a bridge request by ID
func (gw *BridgeGateway) GetRequest(requestID [32]byte) (*BridgeRequest, error) {
	gw.mu.RLock()
	defer gw.mu.RUnlock()

	request := gw.Requests[requestID]
	if request == nil {
		return nil, ErrRequestNotFound
	}

	return request, nil
}

// RefundExpired refunds an expired bridge request
func (gw *BridgeGateway) RefundExpired(requestID [32]byte) error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	request := gw.Requests[requestID]
	if request == nil {
		return ErrRequestNotFound
	}

	if request.Status == StatusCompleted || request.Status == StatusRefunded {
		return ErrRequestAlreadyDone
	}

	if request.Deadline > 0 && uint64(time.Now().Unix()) <= request.Deadline {
		return errors.New("request not yet expired")
	}

	// Return liquidity to pool
	pool := gw.getPool(request.DestChain, request.Token)
	if pool != nil {
		pool.Available.Add(pool.Available, request.Amount)
	}

	request.Status = StatusRefunded
	return nil
}

// AddLiquidity adds liquidity to a bridge pool
func (gw *BridgeGateway) AddLiquidity(
	provider common.Address,
	token common.Address,
	chainID uint32,
	amount *big.Int,
) (*LPPosition, error) {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	if !gw.SupportedChains[chainID] {
		return nil, ErrChainNotSupported
	}

	pool := gw.getOrCreatePool(chainID, token)

	// Calculate share ratio
	var shareRatio *big.Int
	if pool.TotalLiq.Sign() == 0 {
		shareRatio = new(big.Int).Mul(amount, big.NewInt(1e18))
	} else {
		shareRatio = new(big.Int).Mul(amount, big.NewInt(1e18))
		shareRatio.Div(shareRatio, pool.TotalLiq)
	}

	// Update or create position
	position := pool.Providers[provider]
	if position == nil {
		position = &LPPosition{
			Provider:    provider,
			Amount:      big.NewInt(0),
			ShareRatio:  big.NewInt(0),
			DepositTime: uint64(time.Now().Unix()),
			PendingFees: big.NewInt(0),
		}
		pool.Providers[provider] = position
	}

	position.Amount.Add(position.Amount, amount)
	position.ShareRatio.Add(position.ShareRatio, shareRatio)

	// Update pool totals
	pool.TotalLiq.Add(pool.TotalLiq, amount)
	pool.Available.Add(pool.Available, amount)

	return position, nil
}

// RemoveLiquidity removes liquidity from a bridge pool
func (gw *BridgeGateway) RemoveLiquidity(
	provider common.Address,
	token common.Address,
	chainID uint32,
	amount *big.Int,
) (*big.Int, error) {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	pool := gw.getPool(chainID, token)
	if pool == nil {
		return nil, ErrInsufficientLiquidity
	}

	position := pool.Providers[provider]
	if position == nil || position.Amount.Cmp(amount) < 0 {
		return nil, ErrInsufficientLiquidity
	}

	if pool.Available.Cmp(amount) < 0 {
		return nil, errors.New("liquidity currently in use")
	}

	// Calculate fees earned
	fees := gw.calculateLPFees(pool, position)

	// Update position
	position.Amount.Sub(position.Amount, amount)
	if position.Amount.Sign() == 0 {
		delete(pool.Providers, provider)
	}

	// Update pool totals
	pool.TotalLiq.Sub(pool.TotalLiq, amount)
	pool.Available.Sub(pool.Available, amount)

	// Return amount + fees
	total := new(big.Int).Add(amount, fees)
	return total, nil
}

// RegisterToken registers a new token for bridging
func (gw *BridgeGateway) RegisterToken(
	localAddress common.Address,
	decimals uint8,
	symbol string,
	name string,
	minBridge *big.Int,
	maxBridge *big.Int,
	dailyLimit *big.Int,
) error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	if gw.SupportedTokens[localAddress] != nil {
		return errors.New("token already registered")
	}

	gw.SupportedTokens[localAddress] = &BridgedToken{
		LocalAddress:  localAddress,
		RemoteAddress: make(map[uint32]common.Address),
		Decimals:      decimals,
		Symbol:        symbol,
		Name:          name,
		MinBridge:     minBridge,
		MaxBridge:     maxBridge,
		DailyLimit:    dailyLimit,
		BridgedToday:  big.NewInt(0),
		LastReset:     uint64(time.Now().Unix()),
		Enabled:       true,
	}

	return nil
}

// Helper functions

func (gw *BridgeGateway) generateRequestID(
	sender, recipient common.Address,
	token common.Address,
	amount *big.Int,
	sourceChain, destChain uint32,
	nonce uint64,
) [32]byte {
	data := append(sender.Bytes(), recipient.Bytes()...)
	data = append(data, token.Bytes()...)
	data = append(data, amount.Bytes()...)
	data = append(data, big.NewInt(int64(sourceChain)).Bytes()...)
	data = append(data, big.NewInt(int64(destChain)).Bytes()...)
	data = append(data, big.NewInt(int64(nonce)).Bytes()...)
	return sha256.Sum256(data)
}

func (gw *BridgeGateway) calculateFee(amount *big.Int) *big.Int {
	// Percent fee
	fee := new(big.Int).Mul(amount, big.NewInt(int64(gw.Config.PercentFee)))
	fee.Div(fee, big.NewInt(10000))

	// Add base fee
	fee.Add(fee, gw.Config.BaseFee)

	// Apply min/max
	if fee.Cmp(gw.Config.MinFee) < 0 {
		fee.Set(gw.Config.MinFee)
	}
	if gw.Config.MaxFee.Sign() > 0 && fee.Cmp(gw.Config.MaxFee) > 0 {
		fee.Set(gw.Config.MaxFee)
	}

	return fee
}

func (gw *BridgeGateway) getPool(chainID uint32, token common.Address) *LiquidityPool {
	chainPools := gw.Pools[chainID]
	if chainPools == nil {
		return nil
	}
	return chainPools[token]
}

func (gw *BridgeGateway) getOrCreatePool(chainID uint32, token common.Address) *LiquidityPool {
	if gw.Pools[chainID] == nil {
		gw.Pools[chainID] = make(map[common.Address]*LiquidityPool)
	}

	pool := gw.Pools[chainID][token]
	if pool == nil {
		pool = &LiquidityPool{
			Token:     token,
			ChainID:   chainID,
			TotalLiq:  big.NewInt(0),
			Available: big.NewInt(0),
			Providers: make(map[common.Address]*LPPosition),
			FeeRate:   gw.Config.LiquidityFee,
			TotalFees: big.NewInt(0),
		}
		gw.Pools[chainID][token] = pool
	}

	return pool
}

func (gw *BridgeGateway) resetDailyLimitIfNeeded(token *BridgedToken) {
	now := uint64(time.Now().Unix())
	daySeconds := uint64(86400)
	if now-token.LastReset >= daySeconds {
		token.BridgedToday = big.NewInt(0)
		token.LastReset = now
	}
}

func (gw *BridgeGateway) getThreshold() uint32 {
	if gw.SignerSet == nil || len(gw.SignerSet.Signers) == 0 {
		return 1
	}
	// 2/3 + 1 of active signers
	return (uint32(len(gw.SignerSet.Signers)) * 2 / 3) + 1
}

func (gw *BridgeGateway) encodeMessage(request *BridgeRequest) []byte {
	msg := &BridgeMessage{
		Version:     1,
		MessageType: MsgTypeTransfer,
		SourceChain: request.SourceChain,
		DestChain:   request.DestChain,
		Nonce:       request.Nonce,
		Sender:      request.Sender,
		Recipient:   request.Recipient,
		Token:       request.Token,
		Amount:      request.Amount,
		Data:        request.Data,
		Timestamp:   request.CreatedAt,
	}

	// Encode message (simplified - would use proper encoding)
	data := []byte{msg.Version, msg.MessageType}
	data = append(data, big.NewInt(int64(msg.SourceChain)).Bytes()...)
	data = append(data, big.NewInt(int64(msg.DestChain)).Bytes()...)
	data = append(data, big.NewInt(int64(msg.Nonce)).Bytes()...)
	data = append(data, msg.Sender.Bytes()...)
	data = append(data, msg.Recipient.Bytes()...)
	data = append(data, msg.Token.Bytes()...)
	data = append(data, msg.Amount.Bytes()...)
	data = append(data, msg.Data...)

	return data
}

func (gw *BridgeGateway) verifySignature(message []byte, signature []byte) bool {
	// In production, verify against signer set public keys
	// This would call into B-Chain's MPC verification
	return len(signature) > 0
}

func (gw *BridgeGateway) calculateLPFees(pool *LiquidityPool, position *LPPosition) *big.Int {
	if pool.TotalFees.Sign() == 0 || position.ShareRatio.Sign() == 0 {
		return big.NewInt(0)
	}

	// fees = totalFees * shareRatio / 1e18
	fees := new(big.Int).Mul(pool.TotalFees, position.ShareRatio)
	fees.Div(fees, big.NewInt(1e18))

	return fees
}
