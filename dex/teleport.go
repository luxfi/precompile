// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/luxfi/geth/common"
	"github.com/zeebo/blake3"
)

// TeleportBridge manages cross-chain transfers
// Address: 0x0440
type TeleportBridge struct {
	// Pending teleports indexed by ID
	PendingTeleports map[[32]byte]*TeleportRequest

	// Completed teleports (for replay protection)
	CompletedTeleports map[[32]byte]bool

	// Supported tokens per chain
	SupportedTokens map[uint32]map[common.Address]*BridgedToken

	// Bridge operators (for MPC signing)
	Operators []common.Address
	Threshold uint32 // Required signatures

	// Fee configuration
	FeeRate uint32 // Basis points
	MinFee  *big.Int
	MaxFee  *big.Int

	// Liquidity pools per chain/token
	Liquidity map[uint32]map[common.Address]*big.Int

	// Statistics
	TotalBridged map[common.Address]*big.Int
	TotalFees    *big.Int

	mu sync.RWMutex
}

// BridgedToken represents a token that can be bridged
type BridgedToken struct {
	LocalAddress  common.Address // Address on this chain
	RemoteAddress common.Address // Address on remote chain
	ChainID       uint32
	Decimals      uint8
	DailyLimit    *big.Int // Maximum per 24h
	SingleTxLimit *big.Int // Maximum per transaction
	MinAmount     *big.Int // Minimum transfer amount
	IsPaused      bool
	TotalLocked   *big.Int // Total locked on this side
	TotalMinted   *big.Int // Total minted (for wrapped tokens)
}

// OmnichainRouter handles multi-chain liquidity routing
// Address: 0x0441
type OmnichainRouter struct {
	Bridge *TeleportBridge
	Routes map[uint32]map[uint32]*Route // srcChain -> dstChain -> Route
	Pools  map[uint32]*ChainPool        // chainID -> pool
	mu     sync.RWMutex
}

// Route represents a path between two chains
type Route struct {
	SourceChain uint32
	DestChain   uint32
	Fee         uint32 // Additional routing fee (basis points)
	IsActive    bool
	MaxCapacity *big.Int // Maximum daily capacity
	UsedToday   *big.Int
	LastReset   int64 // Unix timestamp
}

// ChainPool represents liquidity available on a chain
type ChainPool struct {
	ChainID       uint32
	Tokens        map[common.Address]*big.Int // Token -> liquidity
	TotalValueUSD *big.Int
}

// NewTeleportBridge creates a new cross-chain bridge
func NewTeleportBridge(threshold uint32) *TeleportBridge {
	return &TeleportBridge{
		PendingTeleports:   make(map[[32]byte]*TeleportRequest),
		CompletedTeleports: make(map[[32]byte]bool),
		SupportedTokens:    make(map[uint32]map[common.Address]*BridgedToken),
		Operators:          make([]common.Address, 0),
		Threshold:          threshold,
		FeeRate:            30,                                                   // 0.3%
		MinFee:             big.NewInt(1e15),                                     // 0.001 tokens
		MaxFee:             new(big.Int).Mul(big.NewInt(1e10), big.NewInt(1e10)), // 100 tokens (1e20)
		Liquidity:          make(map[uint32]map[common.Address]*big.Int),
		TotalBridged:       make(map[common.Address]*big.Int),
		TotalFees:          big.NewInt(0),
	}
}

// InitiateTeleport starts a cross-chain transfer
func (tb *TeleportBridge) InitiateTeleport(
	sender common.Address,
	destChain uint32,
	recipient common.Address,
	token common.Address,
	amount *big.Int,
	sourceChain uint32,
) (*TeleportRequest, error) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// Validate destination chain
	if !tb.isChainSupported(destChain) {
		return nil, ErrInvalidChainID
	}

	// Validate token
	tokenConfig := tb.getTokenConfig(sourceChain, token)
	if tokenConfig == nil || tokenConfig.IsPaused {
		return nil, ErrTokenNotSupported
	}

	// Check limits
	if amount.Cmp(tokenConfig.MinAmount) < 0 {
		return nil, ErrBelowMinimum
	}
	if amount.Cmp(tokenConfig.SingleTxLimit) > 0 {
		return nil, ErrExceedsLimit
	}

	// Calculate fee
	fee := tb.calculateFee(amount)

	// Net amount after fee
	netAmount := new(big.Int).Sub(amount, fee)

	// Generate teleport ID
	teleportID := tb.generateTeleportID(sender, destChain, recipient, token, amount, time.Now().UnixNano())

	// Check for duplicate
	if _, exists := tb.PendingTeleports[teleportID]; exists {
		return nil, ErrDuplicateTeleportID
	}
	if tb.CompletedTeleports[teleportID] {
		return nil, ErrDuplicateTeleportID
	}

	request := &TeleportRequest{
		TeleportID:  teleportID,
		SourceChain: sourceChain,
		DestChain:   destChain,
		Sender:      sender,
		Recipient:   recipient,
		Token:       token,
		Amount:      netAmount,
		Timestamp:   time.Now().Unix(),
		Status:      TeleportPending,
	}

	tb.PendingTeleports[teleportID] = request

	// Update token locked amount
	tokenConfig.TotalLocked.Add(tokenConfig.TotalLocked, netAmount)

	// Collect fee
	tb.TotalFees.Add(tb.TotalFees, fee)

	return request, nil
}

// CompleteTeleport completes a cross-chain transfer (called on destination chain)
func (tb *TeleportBridge) CompleteTeleport(
	teleportID [32]byte,
	warpMessage []byte, // Warp message with signatures
	signatures [][]byte,
) error {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	request := tb.PendingTeleports[teleportID]
	if request == nil {
		return ErrTeleportNotFound
	}

	if request.Status != TeleportBurned {
		return ErrInvalidTeleportState
	}

	// Verify signatures (simplified - in production use Warp verification)
	if uint32(len(signatures)) < tb.Threshold {
		return ErrInsufficientSignatures
	}

	// Verify warp message (in production, call Warp precompile)
	if !tb.verifyWarpMessage(warpMessage, teleportID) {
		return ErrInvalidWarpSignature
	}

	// Mark as validated
	request.Status = TeleportValidated

	// In production, this would trigger minting on dest chain
	request.Status = TeleportMinted
	tb.CompletedTeleports[teleportID] = true
	delete(tb.PendingTeleports, teleportID)

	return nil
}

// BurnForTeleport burns tokens on source chain (called after InitiateTeleport)
func (tb *TeleportBridge) BurnForTeleport(teleportID [32]byte) error {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	request := tb.PendingTeleports[teleportID]
	if request == nil {
		return ErrTeleportNotFound
	}

	if request.Status != TeleportPending {
		return ErrInvalidTeleportState
	}

	// Burn tokens (in production, interact with ERC20)
	// This would be verified by Warp message

	request.Status = TeleportBurned
	return nil
}

// CancelTeleport cancels a pending teleport (only by sender, before burn)
func (tb *TeleportBridge) CancelTeleport(sender common.Address, teleportID [32]byte) error {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	request := tb.PendingTeleports[teleportID]
	if request == nil {
		return ErrTeleportNotFound
	}

	if request.Sender != sender {
		return ErrUnauthorized
	}

	if request.Status != TeleportPending {
		return ErrCannotCancel
	}

	// Restore locked tokens
	tokenConfig := tb.getTokenConfig(request.SourceChain, request.Token)
	if tokenConfig != nil {
		tokenConfig.TotalLocked.Sub(tokenConfig.TotalLocked, request.Amount)
	}

	delete(tb.PendingTeleports, teleportID)
	return nil
}

// GetTeleportStatus returns the status of a teleport
func (tb *TeleportBridge) GetTeleportStatus(teleportID [32]byte) (TeleportStatus, error) {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	if tb.CompletedTeleports[teleportID] {
		return TeleportMinted, nil
	}

	request := tb.PendingTeleports[teleportID]
	if request == nil {
		return 0, ErrTeleportNotFound
	}

	return request.Status, nil
}

// AddSupportedToken adds a token to the bridge
func (tb *TeleportBridge) AddSupportedToken(
	chainID uint32,
	localAddr common.Address,
	remoteAddr common.Address,
	decimals uint8,
	dailyLimit *big.Int,
	singleTxLimit *big.Int,
	minAmount *big.Int,
) error {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	if tb.SupportedTokens[chainID] == nil {
		tb.SupportedTokens[chainID] = make(map[common.Address]*BridgedToken)
	}

	tb.SupportedTokens[chainID][localAddr] = &BridgedToken{
		LocalAddress:  localAddr,
		RemoteAddress: remoteAddr,
		ChainID:       chainID,
		Decimals:      decimals,
		DailyLimit:    dailyLimit,
		SingleTxLimit: singleTxLimit,
		MinAmount:     minAmount,
		IsPaused:      false,
		TotalLocked:   big.NewInt(0),
		TotalMinted:   big.NewInt(0),
	}

	return nil
}

// PauseToken pauses bridging for a token
func (tb *TeleportBridge) PauseToken(chainID uint32, token common.Address) error {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	config := tb.getTokenConfig(chainID, token)
	if config == nil {
		return ErrTokenNotSupported
	}

	config.IsPaused = true
	return nil
}

// UnpauseToken resumes bridging for a token
func (tb *TeleportBridge) UnpauseToken(chainID uint32, token common.Address) error {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	config := tb.getTokenConfig(chainID, token)
	if config == nil {
		return ErrTokenNotSupported
	}

	config.IsPaused = false
	return nil
}

// AddOperator adds a bridge operator
func (tb *TeleportBridge) AddOperator(operator common.Address) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.Operators = append(tb.Operators, operator)
}

// Helper functions

func (tb *TeleportBridge) isChainSupported(chainID uint32) bool {
	switch chainID {
	case ChainLux, ChainHanzo, ChainZoo, ChainETH, ChainArb, ChainOP, ChainBase, ChainPoly, ChainBSC, ChainAvax:
		return true
	default:
		return false
	}
}

func (tb *TeleportBridge) getTokenConfig(chainID uint32, token common.Address) *BridgedToken {
	chainTokens := tb.SupportedTokens[chainID]
	if chainTokens == nil {
		return nil
	}
	return chainTokens[token]
}

func (tb *TeleportBridge) calculateFee(amount *big.Int) *big.Int {
	fee := new(big.Int).Mul(amount, big.NewInt(int64(tb.FeeRate)))
	fee.Div(fee, big.NewInt(10000))

	if fee.Cmp(tb.MinFee) < 0 {
		return new(big.Int).Set(tb.MinFee)
	}
	if fee.Cmp(tb.MaxFee) > 0 {
		return new(big.Int).Set(tb.MaxFee)
	}
	return fee
}

func (tb *TeleportBridge) generateTeleportID(
	sender common.Address,
	destChain uint32,
	recipient common.Address,
	token common.Address,
	amount *big.Int,
	nonce int64,
) [32]byte {
	hasher := blake3.New()
	hasher.Write(sender[:])
	hasher.Write([]byte{byte(destChain >> 24), byte(destChain >> 16), byte(destChain >> 8), byte(destChain)})
	hasher.Write(recipient[:])
	hasher.Write(token[:])
	hasher.Write(amount.Bytes())
	hasher.Write([]byte{byte(nonce >> 56), byte(nonce >> 48), byte(nonce >> 40), byte(nonce >> 32),
		byte(nonce >> 24), byte(nonce >> 16), byte(nonce >> 8), byte(nonce)})

	var id [32]byte
	copy(id[:], hasher.Sum(nil))
	return id
}

func (tb *TeleportBridge) verifyWarpMessage(message []byte, teleportID [32]byte) bool {
	// In production, this would call the Warp precompile to verify
	// For now, just check message is non-empty
	return len(message) > 0
}

// NewOmnichainRouter creates a new multi-chain router
func NewOmnichainRouter(bridge *TeleportBridge) *OmnichainRouter {
	return &OmnichainRouter{
		Bridge: bridge,
		Routes: make(map[uint32]map[uint32]*Route),
		Pools:  make(map[uint32]*ChainPool),
	}
}

// AddRoute adds a route between two chains
func (or *OmnichainRouter) AddRoute(srcChain, dstChain uint32, fee uint32, maxCapacity *big.Int) error {
	or.mu.Lock()
	defer or.mu.Unlock()

	if or.Routes[srcChain] == nil {
		or.Routes[srcChain] = make(map[uint32]*Route)
	}

	or.Routes[srcChain][dstChain] = &Route{
		SourceChain: srcChain,
		DestChain:   dstChain,
		Fee:         fee,
		IsActive:    true,
		MaxCapacity: maxCapacity,
		UsedToday:   big.NewInt(0),
		LastReset:   time.Now().Unix(),
	}

	return nil
}

// GetBestRoute finds the optimal route for a transfer
func (or *OmnichainRouter) GetBestRoute(
	srcChain, dstChain uint32,
	token common.Address,
	amount *big.Int,
) (*Route, error) {
	or.mu.RLock()
	defer or.mu.RUnlock()

	// Direct route
	directRoute := or.getRoute(srcChain, dstChain)
	if directRoute != nil && directRoute.IsActive {
		// Check capacity
		remaining := new(big.Int).Sub(directRoute.MaxCapacity, directRoute.UsedToday)
		if remaining.Cmp(amount) >= 0 {
			return directRoute, nil
		}
	}

	// Look for multi-hop routes (simplified - just 2 hops)
	for intermediateChain := range or.Routes[srcChain] {
		if intermediateChain == dstChain {
			continue
		}

		route1 := or.getRoute(srcChain, intermediateChain)
		route2 := or.getRoute(intermediateChain, dstChain)

		if route1 != nil && route2 != nil && route1.IsActive && route2.IsActive {
			// Found a 2-hop route
			// In production, would calculate combined fee and return composite route
			return route1, nil // Simplified
		}
	}

	return nil, ErrNoRouteFound
}

// RouteTransfer executes a routed transfer
func (or *OmnichainRouter) RouteTransfer(
	sender common.Address,
	dstChain uint32,
	recipient common.Address,
	token common.Address,
	amount *big.Int,
	srcChain uint32,
) (*TeleportRequest, error) {
	or.mu.Lock()
	defer or.mu.Unlock()

	route, err := or.GetBestRoute(srcChain, dstChain, token, amount)
	if err != nil {
		return nil, err
	}

	// Calculate routing fee
	routingFee := new(big.Int).Mul(amount, big.NewInt(int64(route.Fee)))
	routingFee.Div(routingFee, big.NewInt(10000))

	netAmount := new(big.Int).Sub(amount, routingFee)

	// Update route capacity
	route.UsedToday.Add(route.UsedToday, amount)

	// Initiate teleport
	return or.Bridge.InitiateTeleport(sender, dstChain, recipient, token, netAmount, srcChain)
}

// ResetDailyLimits resets daily capacity limits (should be called daily)
func (or *OmnichainRouter) ResetDailyLimits() {
	or.mu.Lock()
	defer or.mu.Unlock()

	now := time.Now().Unix()
	for _, chainRoutes := range or.Routes {
		for _, route := range chainRoutes {
			// Reset if more than 24 hours since last reset
			if now-route.LastReset > 86400 {
				route.UsedToday = big.NewInt(0)
				route.LastReset = now
			}
		}
	}
}

func (or *OmnichainRouter) getRoute(src, dst uint32) *Route {
	if or.Routes[src] == nil {
		return nil
	}
	return or.Routes[src][dst]
}

// Additional errors for teleport (others in types.go)
var (
	ErrTokenNotSupported      = errors.New("token not supported for bridging")
	ErrBelowMinimum           = errors.New("amount below minimum")
	ErrExceedsLimit           = errors.New("amount exceeds limit")
	ErrTeleportNotFound       = errors.New("teleport not found")
	ErrInvalidTeleportState   = errors.New("invalid teleport state")
	ErrInsufficientSignatures = errors.New("insufficient signatures")
	ErrCannotCancel           = errors.New("cannot cancel teleport in current state")
	ErrNoRouteFound           = errors.New("no route found")
)
