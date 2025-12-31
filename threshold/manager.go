// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import (
	"context"
	"crypto/sha256"
	"math/big"
	"sync"
	"time"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/threshold/pkg/party"
)

// ThresholdManager provides the interface to T-Chain threshold operations
// This is the main precompile at 0x0800 that coordinates threshold cryptography
type ThresholdManager struct {
	// Key storage
	Keys map[[32]byte]*ThresholdKey

	// Request tracking
	KeygenRequests  map[[32]byte]*KeygenRequest
	SignRequests    map[[32]byte]*SigningRequest
	RefreshRequests map[[32]byte]*RefreshRequest
	ReshareRequests map[[32]byte]*ReshareRequest

	// Real threshold client for executing MPC protocols
	client *ThresholdClient

	// T-Chain connection (in production, cross-chain calls)
	TChainEndpoint string

	// Configuration
	DefaultThreshold uint32
	SignTimeout      time.Duration
	KeygenTimeout    time.Duration
	MaxKeysPerOwner  int

	mu sync.RWMutex
}

// NewThresholdManager creates a new threshold manager
func NewThresholdManager() *ThresholdManager {
	return &ThresholdManager{
		Keys:             make(map[[32]byte]*ThresholdKey),
		KeygenRequests:   make(map[[32]byte]*KeygenRequest),
		SignRequests:     make(map[[32]byte]*SigningRequest),
		RefreshRequests:  make(map[[32]byte]*RefreshRequest),
		ReshareRequests:  make(map[[32]byte]*ReshareRequest),
		client:           NewThresholdClient(),
		DefaultThreshold: 2,
		SignTimeout:      5 * time.Minute,
		KeygenTimeout:    10 * time.Minute,
		MaxKeysPerOwner:  100,
	}
}

// Close cleans up resources
func (tm *ThresholdManager) Close() {
	if tm.client != nil {
		tm.client.Close()
	}
}

// RequestKeygen initiates distributed key generation
func (tm *ThresholdManager) RequestKeygen(
	requester common.Address,
	protocol Protocol,
	keyType KeyType,
	threshold uint32,
	totalParties uint32,
	participants [][20]byte,
) ([32]byte, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Validate parameters
	if err := tm.validateKeygenParams(protocol, keyType, threshold, totalParties); err != nil {
		return [32]byte{}, err
	}

	if len(participants) != int(totalParties) {
		return [32]byte{}, ErrInvalidPartyCount
	}

	// Generate request ID
	now := uint64(time.Now().Unix())
	requestData := append(requester.Bytes(), byte(protocol), byte(keyType))
	requestData = append(requestData, big.NewInt(int64(now)).Bytes()...)
	requestID := sha256.Sum256(requestData)

	request := &KeygenRequest{
		RequestID:    requestID,
		Protocol:     protocol,
		KeyType:      keyType,
		Threshold:    threshold,
		TotalParties: totalParties,
		Requester:    requester,
		RequestedAt:  now,
		ExpiresAt:    now + uint64(tm.KeygenTimeout.Seconds()),
		Status:       KeygenStatusPending,
		Participants: participants,
	}

	tm.KeygenRequests[requestID] = request

	// In production, send to T-Chain to initiate DKG
	go tm.initiateKeygen(request)

	return requestID, nil
}

// RequestSignature requests a threshold signature
func (tm *ThresholdManager) RequestSignature(
	requester common.Address,
	keyID [32]byte,
	messageHash [32]byte,
) ([32]byte, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Get key and validate
	key := tm.Keys[keyID]
	if key == nil {
		return [32]byte{}, ErrKeyNotFound
	}

	if err := tm.validateKeyForSigning(key, requester); err != nil {
		return [32]byte{}, err
	}

	// Check daily limit
	tm.resetDailyLimitIfNeeded(key)
	if key.Permissions.MaxSignsPerDay > 0 &&
		key.Permissions.SignsToday >= key.Permissions.MaxSignsPerDay {
		return [32]byte{}, ErrSigningLimitExceeded
	}

	// Generate request ID
	now := uint64(time.Now().Unix())
	requestData := append(keyID[:], messageHash[:]...)
	requestData = append(requestData, big.NewInt(int64(now)).Bytes()...)
	requestID := sha256.Sum256(requestData)

	request := &SigningRequest{
		RequestID:   requestID,
		KeyID:       keyID,
		MessageHash: messageHash,
		Requester:   requester,
		RequestedAt: now,
		ExpiresAt:   now + uint64(tm.SignTimeout.Seconds()),
		Status:      SignStatusPending,
		PartialSigs: make([][]byte, 0),
	}

	tm.SignRequests[requestID] = request
	key.Permissions.SignsToday++

	// In production, send to T-Chain to initiate signing
	go tm.initiateSigning(request, key)

	return requestID, nil
}

// GetSignature retrieves a completed signature
func (tm *ThresholdManager) GetSignature(requestID [32]byte) ([]byte, SigningStatus, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	request := tm.SignRequests[requestID]
	if request == nil {
		return nil, 0, ErrRequestNotFound
	}

	return request.Signature, request.Status, nil
}

// RequestRefresh initiates key share refresh (proactive security)
func (tm *ThresholdManager) RequestRefresh(
	requester common.Address,
	keyID [32]byte,
) ([32]byte, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	key := tm.Keys[keyID]
	if key == nil {
		return [32]byte{}, ErrKeyNotFound
	}

	if key.Status != KeyStatusActive {
		return [32]byte{}, ErrKeyBusy
	}

	if key.Owner != requester {
		return [32]byte{}, ErrUnauthorized
	}

	// Generate request ID
	now := uint64(time.Now().Unix())
	requestData := append(keyID[:], requester.Bytes()...)
	requestData = append(requestData, big.NewInt(int64(now)).Bytes()...)
	requestID := sha256.Sum256(requestData)

	request := &RefreshRequest{
		RequestID:   requestID,
		KeyID:       keyID,
		Requester:   requester,
		RequestedAt: now,
		Status:      RefreshStatusPending,
	}

	tm.RefreshRequests[requestID] = request
	key.Status = KeyStatusRefreshing

	// In production, send to T-Chain
	go tm.initiateRefresh(request, key)

	return requestID, nil
}

// RequestReshare initiates key resharing to new parties
func (tm *ThresholdManager) RequestReshare(
	requester common.Address,
	keyID [32]byte,
	newThreshold uint32,
	newParties [][20]byte,
) ([32]byte, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	key := tm.Keys[keyID]
	if key == nil {
		return [32]byte{}, ErrKeyNotFound
	}

	if key.Status != KeyStatusActive {
		return [32]byte{}, ErrKeyBusy
	}

	if key.Owner != requester {
		return [32]byte{}, ErrUnauthorized
	}

	if newThreshold >= uint32(len(newParties)) {
		return [32]byte{}, ErrInvalidThreshold
	}

	// Generate request ID
	now := uint64(time.Now().Unix())
	requestData := append(keyID[:], requester.Bytes()...)
	requestData = append(requestData, big.NewInt(int64(now)).Bytes()...)
	requestID := sha256.Sum256(requestData)

	request := &ReshareRequest{
		RequestID:    requestID,
		KeyID:        keyID,
		NewThreshold: newThreshold,
		NewParties:   newParties,
		Requester:    requester,
		RequestedAt:  now,
		Status:       ReshareStatusPending,
	}

	tm.ReshareRequests[requestID] = request
	key.Status = KeyStatusResharing

	// In production, send to T-Chain
	go tm.initiateReshare(request, key)

	return requestID, nil
}

// GetKey returns key information
func (tm *ThresholdManager) GetKey(keyID [32]byte) (*ThresholdKey, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	key := tm.Keys[keyID]
	if key == nil {
		return nil, ErrKeyNotFound
	}

	return key, nil
}

// GetPublicKey returns the public key for a threshold key
func (tm *ThresholdManager) GetPublicKey(keyID [32]byte) ([]byte, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	key := tm.Keys[keyID]
	if key == nil {
		return nil, ErrKeyNotFound
	}

	return key.PublicKey, nil
}

// GetAddress returns the EVM address derived from a threshold key
func (tm *ThresholdManager) GetAddress(keyID [32]byte) (common.Address, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	key := tm.Keys[keyID]
	if key == nil {
		return common.Address{}, ErrKeyNotFound
	}

	if key.KeyType != KeyTypeSecp256k1 {
		return common.Address{}, ErrInvalidKeyType
	}

	return key.Address, nil
}

// VerifySignature verifies a threshold signature
func (tm *ThresholdManager) VerifySignature(
	keyID [32]byte,
	messageHash [32]byte,
	signature []byte,
) (*VerificationResult, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	key := tm.Keys[keyID]
	if key == nil {
		return nil, ErrKeyNotFound
	}

	// In production, verify using the appropriate scheme
	valid := tm.verifyWithProtocol(key, messageHash, signature)

	return &VerificationResult{
		Valid:       valid,
		SignerKeyID: keyID,
		MessageHash: messageHash,
		Protocol:    key.Protocol,
		KeyType:     key.KeyType,
	}, nil
}

// RevokeKey revokes a threshold key
func (tm *ThresholdManager) RevokeKey(requester common.Address, keyID [32]byte) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	key := tm.Keys[keyID]
	if key == nil {
		return ErrKeyNotFound
	}

	if key.Owner != requester {
		return ErrUnauthorized
	}

	key.Status = KeyStatusRevoked
	return nil
}

// AddSigner adds an authorized signer to a key
func (tm *ThresholdManager) AddSigner(
	owner common.Address,
	keyID [32]byte,
	signer common.Address,
) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	key := tm.Keys[keyID]
	if key == nil {
		return ErrKeyNotFound
	}

	if key.Owner != owner {
		return ErrUnauthorized
	}

	// Check not already added
	for _, s := range key.Permissions.AllowedSigners {
		if s == signer {
			return nil // Already added
		}
	}

	key.Permissions.AllowedSigners = append(key.Permissions.AllowedSigners, signer)
	return nil
}

// RemoveSigner removes an authorized signer from a key
func (tm *ThresholdManager) RemoveSigner(
	owner common.Address,
	keyID [32]byte,
	signer common.Address,
) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	key := tm.Keys[keyID]
	if key == nil {
		return ErrKeyNotFound
	}

	if key.Owner != owner {
		return ErrUnauthorized
	}

	newSigners := make([]common.Address, 0)
	for _, s := range key.Permissions.AllowedSigners {
		if s != signer {
			newSigners = append(newSigners, s)
		}
	}
	key.Permissions.AllowedSigners = newSigners

	return nil
}

// Helper functions

func (tm *ThresholdManager) validateKeygenParams(
	protocol Protocol,
	keyType KeyType,
	threshold uint32,
	totalParties uint32,
) error {
	// Validate protocol
	switch protocol {
	case ProtocolLSS, ProtocolFROST, ProtocolCGGMP21, ProtocolRingtail:
		// Valid
	default:
		return ErrInvalidProtocol
	}

	// Validate key type for protocol
	switch protocol {
	case ProtocolFROST:
		if keyType != KeyTypeSecp256k1 && keyType != KeyTypeEd25519 {
			return ErrInvalidKeyType
		}
	case ProtocolCGGMP21:
		if keyType != KeyTypeSecp256k1 {
			return ErrInvalidKeyType
		}
	case ProtocolRingtail:
		if keyType != KeyTypeRingtail {
			return ErrInvalidKeyType
		}
	}

	// Validate threshold
	if threshold == 0 || threshold >= totalParties {
		return ErrInvalidThreshold
	}

	if totalParties > MaxParties {
		return ErrInvalidPartyCount
	}

	return nil
}

func (tm *ThresholdManager) validateKeyForSigning(key *ThresholdKey, requester common.Address) error {
	if key.Status != KeyStatusActive {
		switch key.Status {
		case KeyStatusExpired:
			return ErrKeyExpired
		case KeyStatusRevoked:
			return ErrKeyRevoked
		default:
			return ErrKeyBusy
		}
	}

	// Check expiry
	if key.ExpiresAt > 0 && uint64(time.Now().Unix()) > key.ExpiresAt {
		key.Status = KeyStatusExpired
		return ErrKeyExpired
	}

	// Check authorization
	if key.Owner == requester {
		return nil
	}

	for _, signer := range key.Permissions.AllowedSigners {
		if signer == requester {
			return nil
		}
	}

	return ErrUnauthorized
}

func (tm *ThresholdManager) resetDailyLimitIfNeeded(key *ThresholdKey) {
	today := uint64(time.Now().Unix() / 86400)
	if key.Permissions.LastResetDay < today {
		key.Permissions.SignsToday = 0
		key.Permissions.LastResetDay = today
	}
}

func (tm *ThresholdManager) initiateKeygen(request *KeygenRequest) {
	// Execute real DKG protocol using threshold client
	ctx, cancel := context.WithTimeout(context.Background(), tm.KeygenTimeout)
	defer cancel()

	// Convert participant addresses to party IDs
	participants := partyIDsFromAddresses(request.Participants)
	selfID := participants[0] // First participant is self in this context

	result, err := tm.client.ExecuteKeygen(
		ctx,
		request.Protocol,
		request.KeyType,
		int(request.Threshold),
		participants,
		selfID,
	)

	tm.mu.Lock()
	defer tm.mu.Unlock()

	if err != nil {
		request.Status = KeygenStatusFailed
		return
	}

	// Complete keygen with results
	tm.completeKeygenInternal(request, result.KeyID, result.PublicKey, result.Address)
}

func (tm *ThresholdManager) initiateSigning(request *SigningRequest, key *ThresholdKey) {
	// Execute real threshold signing protocol
	ctx, cancel := context.WithTimeout(context.Background(), tm.SignTimeout)
	defer cancel()

	// Generate signer party IDs from key participants
	// In production, this would come from the authorized signers list
	signers := make([]party.ID, 0, key.Threshold+1)
	for i, addr := range key.Permissions.AllowedSigners {
		if uint32(i) >= key.Threshold+1 {
			break
		}
		signers = append(signers, participantAddressToPartyID([20]byte(addr)))
	}
	// Add owner as signer if not enough
	if len(signers) < int(key.Threshold)+1 {
		signers = append(signers, participantAddressToPartyID([20]byte(key.Owner)))
	}

	selfID := signers[0]

	result, err := tm.client.ExecuteSigning(
		ctx,
		request.KeyID,
		key.Protocol,
		request.MessageHash,
		signers,
		selfID,
	)

	tm.mu.Lock()
	defer tm.mu.Unlock()

	if err != nil {
		request.Status = SignStatusFailed
		return
	}

	// Complete signing with results
	request.Signature = result.Signature
	request.Status = SignStatusComplete
}

func (tm *ThresholdManager) initiateRefresh(request *RefreshRequest, key *ThresholdKey) {
	// Execute real key refresh protocol
	ctx, cancel := context.WithTimeout(context.Background(), tm.KeygenTimeout)
	defer cancel()

	// Get participants from key
	participants := make([]party.ID, 0, key.TotalParties)
	for i, addr := range key.Permissions.AllowedSigners {
		if uint32(i) >= key.TotalParties {
			break
		}
		participants = append(participants, participantAddressToPartyID([20]byte(addr)))
	}
	// Ensure we have enough participants
	if len(participants) < int(key.TotalParties) {
		participants = append(participants, participantAddressToPartyID([20]byte(key.Owner)))
	}

	selfID := participants[0]

	err := tm.client.ExecuteRefresh(
		ctx,
		request.KeyID,
		key.Protocol,
		participants,
		selfID,
	)

	tm.mu.Lock()
	defer tm.mu.Unlock()

	if err != nil {
		request.Status = RefreshStatusFailed
		key.Status = KeyStatusActive // Reset status on failure
		return
	}

	// Update key metadata
	key.Generation++
	key.LastRefresh = uint64(time.Now().Unix())
	key.Status = KeyStatusActive
	request.Status = RefreshStatusComplete
}

func (tm *ThresholdManager) initiateReshare(request *ReshareRequest, key *ThresholdKey) {
	// Execute real key resharing protocol
	ctx, cancel := context.WithTimeout(context.Background(), tm.KeygenTimeout)
	defer cancel()

	// Convert new party addresses to party IDs
	newParticipants := partyIDsFromAddresses(request.NewParties)
	selfID := newParticipants[0]

	newKeyID, err := tm.client.ExecuteReshare(
		ctx,
		request.KeyID,
		key.Protocol,
		newParticipants,
		int(request.NewThreshold),
		selfID,
	)

	tm.mu.Lock()
	defer tm.mu.Unlock()

	if err != nil {
		request.Status = ReshareStatusFailed
		key.Status = KeyStatusActive // Reset status on failure
		return
	}

	// Update key with new parameters
	key.KeyID = newKeyID
	key.Threshold = request.NewThreshold
	key.TotalParties = uint32(len(request.NewParties))
	key.Generation++
	key.LastRefresh = uint64(time.Now().Unix())
	key.Status = KeyStatusActive
	request.Status = ReshareStatusComplete

	// Re-register key under new ID if changed
	if newKeyID != request.KeyID {
		delete(tm.Keys, request.KeyID)
		tm.Keys[newKeyID] = key
	}
}

func (tm *ThresholdManager) verifyWithProtocol(
	key *ThresholdKey,
	messageHash [32]byte,
	signature []byte,
) bool {
	// Use real threshold client for verification
	valid, err := tm.client.VerifySignature(
		key.KeyID,
		key.Protocol,
		messageHash,
		signature,
	)
	if err != nil {
		return false
	}
	return valid
}

// completeKeygenInternal creates the key without locking (called from initiateKeygen which holds lock)
func (tm *ThresholdManager) completeKeygenInternal(
	request *KeygenRequest,
	keyID [32]byte,
	publicKey []byte,
	address common.Address,
) {
	now := uint64(time.Now().Unix())
	key := &ThresholdKey{
		KeyID:        keyID,
		Protocol:     request.Protocol,
		KeyType:      request.KeyType,
		PublicKey:    publicKey,
		Address:      address,
		Threshold:    request.Threshold,
		TotalParties: request.TotalParties,
		Generation:   1,
		CreatedAt:    now,
		LastRefresh:  now,
		ExpiresAt:    now + DefaultKeyExpiry,
		Status:       KeyStatusActive,
		Owner:        request.Requester,
		Permissions: KeyPermissions{
			Owner:          request.Requester,
			AllowedSigners: make([]common.Address, 0),
			AllowedChains:  make([]uint32, 0),
			MaxSignsPerDay: 10000, // Default limit
		},
	}

	tm.Keys[keyID] = key
	request.Status = KeygenStatusComplete
	request.ResultKeyID = keyID
}

// CompleteKeygen is called when keygen completes on T-Chain (external callback)
func (tm *ThresholdManager) CompleteKeygen(
	requestID [32]byte,
	keyID [32]byte,
	publicKey []byte,
	address common.Address,
) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	request := tm.KeygenRequests[requestID]
	if request == nil {
		return ErrRequestNotFound
	}

	tm.completeKeygenInternal(request, keyID, publicKey, address)
	return nil
}

// CompleteSigning is called when signing completes on T-Chain
func (tm *ThresholdManager) CompleteSigning(
	requestID [32]byte,
	signature []byte,
) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	request := tm.SignRequests[requestID]
	if request == nil {
		return ErrRequestNotFound
	}

	request.Signature = signature
	request.Status = SignStatusComplete

	return nil
}
