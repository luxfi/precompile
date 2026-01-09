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

// BridgeSigner provides the interface to B-Chain MPC signing
// This precompile at 0x0445 allows EVM contracts to request MPC signatures
type BridgeSigner struct {
	// Signer set management
	SignerSet    *SignerSet
	PendingSigns map[[32]byte]*SigningSession

	// B-Chain connection (in production, would be cross-chain call)
	BChainEndpoint string

	// Configuration
	SignTimeout     time.Duration
	MaxPendingSigns int

	mu sync.RWMutex
}

// SigningSession represents an active signing request
type SigningSession struct {
	SessionID    [32]byte
	MessageHash  [32]byte
	RequestedBy  common.Address
	RequestedAt  uint64
	ExpiresAt    uint64
	Status       SigningStatus
	Signatures   map[[20]byte][]byte // NodeID -> signature
	FinalSig     []byte              // Combined threshold signature
	CallbackAddr common.Address      // Contract to call when done
	CallbackData []byte              // Data for callback
}

// SigningStatus represents the status of a signing session
type SigningStatus uint8

const (
	SigningPending SigningStatus = iota
	SigningInProgress
	SigningComplete
	SigningFailed
	SigningExpired
)

// NewBridgeSigner creates a new bridge signer interface
func NewBridgeSigner() *BridgeSigner {
	return &BridgeSigner{
		SignerSet: &SignerSet{
			Signers:   make([]*SignerInfo, 0),
			Waitlist:  make([][20]byte, 0),
			Threshold: 67,
		},
		PendingSigns:    make(map[[32]byte]*SigningSession),
		SignTimeout:     5 * time.Minute,
		MaxPendingSigns: 1000,
	}
}

// RequestSignature requests an MPC signature from the signer set
func (bs *BridgeSigner) RequestSignature(
	requester common.Address,
	messageHash [32]byte,
	callbackAddr common.Address,
	callbackData []byte,
) ([32]byte, error) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if len(bs.PendingSigns) >= bs.MaxPendingSigns {
		return [32]byte{}, errors.New("too many pending signing requests")
	}

	if len(bs.SignerSet.Signers) == 0 {
		return [32]byte{}, errors.New("no active signers")
	}

	// Generate session ID
	now := uint64(time.Now().Unix())
	sessionData := append(messageHash[:], requester.Bytes()...)
	sessionData = append(sessionData, big.NewInt(int64(now)).Bytes()...)
	sessionID := sha256.Sum256(sessionData)

	session := &SigningSession{
		SessionID:    sessionID,
		MessageHash:  messageHash,
		RequestedBy:  requester,
		RequestedAt:  now,
		ExpiresAt:    now + uint64(bs.SignTimeout.Seconds()),
		Status:       SigningPending,
		Signatures:   make(map[[20]byte][]byte),
		CallbackAddr: callbackAddr,
		CallbackData: callbackData,
	}

	bs.PendingSigns[sessionID] = session

	// In production, this would send a message to B-Chain
	// to initiate MPC signing protocol
	go bs.initiateSigningProtocol(session)

	return sessionID, nil
}

// GetSignature retrieves a completed signature
func (bs *BridgeSigner) GetSignature(sessionID [32]byte) ([]byte, SigningStatus, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	session := bs.PendingSigns[sessionID]
	if session == nil {
		return nil, 0, errors.New("signing session not found")
	}

	return session.FinalSig, session.Status, nil
}

// SubmitPartialSignature allows a signer to submit their signature share
func (bs *BridgeSigner) SubmitPartialSignature(
	sessionID [32]byte,
	signerNodeID [20]byte,
	signature []byte,
) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	session := bs.PendingSigns[sessionID]
	if session == nil {
		return errors.New("signing session not found")
	}

	if session.Status != SigningPending && session.Status != SigningInProgress {
		return errors.New("signing session not accepting signatures")
	}

	if uint64(time.Now().Unix()) > session.ExpiresAt {
		session.Status = SigningExpired
		return errors.New("signing session expired")
	}

	// Verify signer is in the active set
	if !bs.isActiveSigner(signerNodeID) {
		return ErrUnauthorizedSigner
	}

	// Store partial signature
	session.Signatures[signerNodeID] = signature
	session.Status = SigningInProgress

	// Check if we have enough signatures
	threshold := bs.getThreshold()
	if uint32(len(session.Signatures)) >= threshold {
		// Combine signatures
		finalSig, err := bs.combineSignatures(session)
		if err != nil {
			session.Status = SigningFailed
			return err
		}

		session.FinalSig = finalSig
		session.Status = SigningComplete

		// Execute callback if specified
		if session.CallbackAddr != (common.Address{}) {
			go bs.executeCallback(session)
		}
	}

	return nil
}

// GetSignerSet returns the current signer set information
func (bs *BridgeSigner) GetSignerSet() (*SignerSet, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	return bs.SignerSet, nil
}

// GetPublicKey returns the combined threshold public key
func (bs *BridgeSigner) GetPublicKey() ([]byte, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	if bs.SignerSet == nil || len(bs.SignerSet.PublicKey) == 0 {
		return nil, errors.New("no public key available")
	}

	return bs.SignerSet.PublicKey, nil
}

// RegisterSigner registers a new signer (implements LP-333 opt-in model)
func (bs *BridgeSigner) RegisterSigner(
	nodeID [20]byte,
	evmAddress common.Address,
	publicKeyShare []byte,
	bond *big.Int,
) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	// Check minimum bond
	if bond.Cmp(MinSignerBond) < 0 {
		return ErrInsufficientBond
	}

	// Check if already a signer
	for _, signer := range bs.SignerSet.Signers {
		if signer.NodeID == nodeID {
			return ErrAlreadySigner
		}
	}

	signer := &SignerInfo{
		NodeID:     nodeID,
		Address:    evmAddress,
		PublicKey:  publicKeyShare,
		Bond:       bond,
		JoinedAt:   uint64(time.Now().Unix()),
		LastActive: uint64(time.Now().Unix()),
		SignCount:  0,
		SlashCount: 0,
		Status:     SignerActive,
	}

	// First 100 validators join without reshare (LP-333)
	if len(bs.SignerSet.Signers) < MaxSigners {
		bs.SignerSet.Signers = append(bs.SignerSet.Signers, signer)
		bs.updateThreshold()
	} else {
		// Add to waitlist
		signer.Status = SignerWaitlist
		bs.SignerSet.Waitlist = append(bs.SignerSet.Waitlist, nodeID)
	}

	return nil
}

// RemoveSigner removes a signer from the set
func (bs *BridgeSigner) RemoveSigner(nodeID [20]byte) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	found := false
	newSigners := make([]*SignerInfo, 0, len(bs.SignerSet.Signers))

	for _, signer := range bs.SignerSet.Signers {
		if signer.NodeID != nodeID {
			newSigners = append(newSigners, signer)
		} else {
			found = true
		}
	}

	if !found {
		return ErrSignerNotFound
	}

	bs.SignerSet.Signers = newSigners
	bs.updateThreshold()

	// Promote from waitlist if available
	if len(bs.SignerSet.Waitlist) > 0 {
		// This would trigger a reshare in production
		bs.SignerSet.Epoch++
		bs.SignerSet.LastReshare = uint64(time.Now().Unix())
	}

	return nil
}

// SlashSigner reduces a signer's bond due to misbehavior
func (bs *BridgeSigner) SlashSigner(nodeID [20]byte, slashPercent uint32) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	for _, signer := range bs.SignerSet.Signers {
		if signer.NodeID == nodeID {
			// Calculate slash amount
			slashAmount := new(big.Int).Mul(signer.Bond, big.NewInt(int64(slashPercent)))
			slashAmount.Div(slashAmount, big.NewInt(100))

			// Reduce bond
			signer.Bond.Sub(signer.Bond, slashAmount)
			signer.SlashCount++

			// Remove if bond drops below minimum
			if signer.Bond.Cmp(MinSignerBond) < 0 {
				signer.Status = SignerSlashed
				return bs.RemoveSigner(nodeID)
			}

			return nil
		}
	}

	return ErrSignerNotFound
}

// Helper functions

func (bs *BridgeSigner) isActiveSigner(nodeID [20]byte) bool {
	for _, signer := range bs.SignerSet.Signers {
		if signer.NodeID == nodeID && signer.Status == SignerActive {
			return true
		}
	}
	return false
}

func (bs *BridgeSigner) getThreshold() uint32 {
	if len(bs.SignerSet.Signers) == 0 {
		return 1
	}
	// 2/3 + 1 of active signers
	return (uint32(len(bs.SignerSet.Signers)) * 2 / 3) + 1
}

func (bs *BridgeSigner) updateThreshold() {
	bs.SignerSet.Threshold = bs.getThreshold()
}

func (bs *BridgeSigner) initiateSigningProtocol(session *SigningSession) {
	// In production, this would:
	// 1. Send a cross-chain message to B-Chain
	// 2. B-Chain's MPC coordinator would initiate threshold signing
	// 3. Signers would submit their shares
	// 4. Combined signature would be returned

	// For now, this is a placeholder
	// The actual implementation would use Warp messaging
}

func (bs *BridgeSigner) combineSignatures(session *SigningSession) ([]byte, error) {
	// In production, this would use threshold signature combination
	// For FROST/CGGMP21/Ringtail depending on the key type

	// Placeholder: concatenate signatures
	var combined []byte
	for _, sig := range session.Signatures {
		combined = append(combined, sig...)
	}

	return combined, nil
}

func (bs *BridgeSigner) executeCallback(session *SigningSession) {
	// In production, this would call the callback contract
	// with the signature result
}

// VerifyThresholdSignature verifies a threshold signature against the public key
func (bs *BridgeSigner) VerifyThresholdSignature(
	messageHash [32]byte,
	signature []byte,
) (bool, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	if len(bs.SignerSet.PublicKey) == 0 {
		return false, errors.New("no public key available")
	}

	// In production, verify using the appropriate threshold scheme
	// This would call into lux/threshold package
	return len(signature) > 0, nil
}
