// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"sync"

	"github.com/luxfi/geth/common"
	"github.com/zeebo/blake3"
)

// Precompile address LP-9090 LXSettle
const LXSettlementAddress = "0x0000000000000000000000000000000000009090"

var settlementAddr = common.HexToAddress(LXSettlementAddress)

// Gas costs for Settlement operations
const (
	GasFillAttestation uint64 = 30_000 // Record a broker fill attestation
	GasFillChallenge uint64 = 50_000 // Challenge an attestation (reversal)
	GasFillFinalize  uint64 = 20_000 // Finalize after fraud window
	GasFillQuery     uint64 = 5_000  // Query attestation state
	GasFillSetAdmin  uint64 = 25_000 // Set attester or ceiling (governance)
)

// FillStatus tracks the lifecycle of a fill attestation.
type FillStatus uint8

const (
	FillPending   FillStatus = iota // Attested, within fraud window
	FillFinalized                   // Fraud window expired, attestation final
	FillReversed                    // Challenged and reversed (tokens burned)
)

// DefaultFraudWindowBlocks is ~3 days at 1 block/second.
// Covers T+2 ACH settlement plus 1 day buffer.
const DefaultFraudWindowBlocks uint64 = 259_200

// Settlement records a broker fill for on-chain auditing and fraud proofs.
type Settlement struct {
	OrderID   [32]byte       // Unique broker order identifier (blake3 of provider order ID)
	Symbol    [32]byte       // Asset symbol (e.g., "AAPL", "BTC", "ETH")
	Amount    *big.Int       // Number of shares/units filled
	Price     *big.Int       // Fill price in USD (18 decimals)
	User      common.Address // Recipient of minted tokens
	Attester  common.Address // Address that submitted the attestation
	Timestamp uint64         // Broker fill timestamp (unix seconds)
	Block     uint64         // Block at which attestation was recorded
	Status    FillStatus     // Current lifecycle status
}

// Storage key prefixes for Settlement state
var (
	fillAttestPrefix   = []byte("fill_attestation/attest/")  // per-order attestation
	fillConfigPrefix   = []byte("fill_attestation/config/")  // global config
	fillAttesterKey    = []byte("fill_attestation/attester")  // authorized attester address
	fillCeilingKey     = []byte("fill_attestation/ceiling")   // max outstanding USD value
	fillOutstandingKey = []byte("fill_attestation/outstanding") // current outstanding USD
	fillFraudWindowKey = []byte("fill_attestation/fraud_window") // fraud window in blocks
)

// Errors
var (
	ErrUnauthorizedAttester    = errors.New("caller is not the authorized attester")
	ErrDuplicateAttestation    = errors.New("attestation already exists for this order")
	ErrAttestationNotFound     = errors.New("attestation not found")
	ErrAttestationFinalized    = errors.New("attestation already finalized")
	ErrAttestationReversed     = errors.New("attestation already reversed")
	ErrFraudWindowActive       = errors.New("fraud window has not expired")
	ErrPrefundCeilingExceeded  = errors.New("outstanding attestations exceed prefund ceiling")
	ErrInvalidReversalProof    = errors.New("reversal proof is invalid")
	ErrInvalidAttestationParam = errors.New("invalid attestation parameter")
)

// SettlementManager manages on-chain fill attestations.
//
// Security model:
//   - Only the registered attester (ATS MPC wallet) can create attestations.
//   - Attestations enter Pending state with a fraud window (~3 days).
//   - During the window, a challenger can submit a reversal proof to burn tokens.
//   - After the window, anyone can call finalize() to mark as final.
//   - A prefund ceiling limits total outstanding (unfinalized) attestation value.
type SettlementManager struct {
	mu sync.RWMutex

	// In-memory cache of attestations (keyed by OrderID)
	attestations map[[32]byte]*Settlement
}

// NewSettlementManager creates a new manager instance.
func NewSettlementManager() *SettlementManager {
	return &SettlementManager{
		attestations: make(map[[32]byte]*Settlement),
	}
}

// OrderIDFromString computes a deterministic 32-byte order ID from a provider
// order ID string (e.g., Alpaca order UUID).
func OrderIDFromString(providerOrderID string) [32]byte {
	h := blake3.New()
	h.Write([]byte(providerOrderID))
	var id [32]byte
	h.Digest().Read(id[:])
	return id
}

// SymbolToBytes32 converts a symbol string to a fixed 32-byte array.
func SymbolToBytes32(symbol string) [32]byte {
	var b [32]byte
	copy(b[:], []byte(symbol))
	return b
}

// --------------------------------------------------------------------------
// Core Operations
// --------------------------------------------------------------------------

// Attest records a broker fill attestation on-chain.
//
// Only callable by the registered attester. Checks:
//   - Caller is the authorized attester
//   - Order ID is not already attested
//   - Outstanding value does not exceed prefund ceiling
//   - Amount and price are positive
func (m *SettlementManager) Attest(
	stateDB StateDB,
	caller common.Address,
	orderID [32]byte,
	symbol [32]byte,
	amount *big.Int,
	price *big.Int,
	user common.Address,
	timestamp uint64,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Verify caller is authorized attester
	attester := m.getAttester(stateDB)
	if attester == (common.Address{}) {
		return ErrUnauthorizedAttester
	}
	if caller != attester {
		return ErrUnauthorizedAttester
	}

	// Validate parameters
	if amount == nil || amount.Sign() <= 0 {
		return ErrInvalidAttestationParam
	}
	if price == nil || price.Sign() <= 0 {
		return ErrInvalidAttestationParam
	}
	if user == (common.Address{}) {
		return ErrInvalidAttestationParam
	}

	// Check for duplicate
	if existing := m.getAttestation(stateDB, orderID); existing != nil {
		return ErrDuplicateAttestation
	}

	// Check prefund ceiling
	// fillValue = amount * price (both in 18-decimal USD units)
	fillValue := new(big.Int).Mul(amount, price)

	outstanding := m.getOutstanding(stateDB)
	ceiling := m.getCeiling(stateDB)
	if ceiling.Sign() > 0 {
		newOutstanding := new(big.Int).Add(outstanding, fillValue)
		if newOutstanding.Cmp(ceiling) > 0 {
			return ErrPrefundCeilingExceeded
		}
	}

	// Record attestation
	currentBlock := m.getCurrentBlock(stateDB)
	attestation := &Settlement{
		OrderID:   orderID,
		Symbol:    symbol,
		Amount:    new(big.Int).Set(amount),
		Price:     new(big.Int).Set(price),
		User:      user,
		Attester:  caller,
		Timestamp: timestamp,
		Block:     currentBlock,
		Status:    FillPending,
	}

	// Update outstanding
	m.setOutstanding(stateDB, new(big.Int).Add(outstanding, fillValue))

	// Save
	m.saveAttestation(stateDB, attestation)

	return nil
}

// Challenge marks an attestation as reversed due to a broker fill reversal.
//
// Callable by anyone with CHALLENGER_ROLE (in practice, the ATS reconciler).
// The reversalProof is opaque bytes -- in production this would contain the
// Alpaca reversal confirmation signed by the attester or a quorum.
//
// On success, the caller is responsible for triggering the corresponding
// LXLiquid.burn() in the same transaction.
func (m *SettlementManager) Challenge(
	stateDB StateDB,
	caller common.Address,
	orderID [32]byte,
	reversalProof []byte,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	attestation := m.getAttestation(stateDB, orderID)
	if attestation == nil {
		return ErrAttestationNotFound
	}

	if attestation.Status == FillFinalized {
		return ErrAttestationFinalized
	}
	if attestation.Status == FillReversed {
		return ErrAttestationReversed
	}

	// Verify caller is authorized (attester can also challenge)
	attester := m.getAttester(stateDB)
	if caller != attester {
		return ErrUnauthorizedAttester
	}

	// Verify reversal proof is non-empty (actual verification is application-specific)
	if len(reversalProof) == 0 {
		return ErrInvalidReversalProof
	}

	// Mark as reversed
	attestation.Status = FillReversed
	m.saveAttestation(stateDB, attestation)

	// Reduce outstanding
	fillValue := new(big.Int).Mul(attestation.Amount, attestation.Price)
	outstanding := m.getOutstanding(stateDB)
	newOutstanding := new(big.Int).Sub(outstanding, fillValue)
	if newOutstanding.Sign() < 0 {
		newOutstanding = big.NewInt(0)
	}
	m.setOutstanding(stateDB, newOutstanding)

	return nil
}

// Finalize marks an attestation as final after the fraud window expires.
//
// Callable by anyone. The attestation must be in Pending state and the
// fraud window must have elapsed.
func (m *SettlementManager) Finalize(
	stateDB StateDB,
	orderID [32]byte,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	attestation := m.getAttestation(stateDB, orderID)
	if attestation == nil {
		return ErrAttestationNotFound
	}

	if attestation.Status == FillFinalized {
		return ErrAttestationFinalized
	}
	if attestation.Status == FillReversed {
		return ErrAttestationReversed
	}

	// Check fraud window
	currentBlock := m.getCurrentBlock(stateDB)
	fraudWindow := m.getFraudWindow(stateDB)
	if currentBlock < attestation.Block+fraudWindow {
		return ErrFraudWindowActive
	}

	// Finalize
	attestation.Status = FillFinalized
	m.saveAttestation(stateDB, attestation)

	// Reduce outstanding (finalized attestations are fully settled)
	fillValue := new(big.Int).Mul(attestation.Amount, attestation.Price)
	outstanding := m.getOutstanding(stateDB)
	newOutstanding := new(big.Int).Sub(outstanding, fillValue)
	if newOutstanding.Sign() < 0 {
		newOutstanding = big.NewInt(0)
	}
	m.setOutstanding(stateDB, newOutstanding)

	return nil
}

// --------------------------------------------------------------------------
// View Functions
// --------------------------------------------------------------------------

// GetAttestation returns the attestation for an order ID, or nil if not found.
func (m *SettlementManager) GetAttestation(
	stateDB StateDB,
	orderID [32]byte,
) *Settlement {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.getAttestation(stateDB, orderID)
}

// GetOutstanding returns the current outstanding unfinalized attestation value.
func (m *SettlementManager) GetOutstanding(stateDB StateDB) *big.Int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.getOutstanding(stateDB)
}

// GetCeiling returns the prefund ceiling.
func (m *SettlementManager) GetCeiling(stateDB StateDB) *big.Int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.getCeiling(stateDB)
}

// --------------------------------------------------------------------------
// Admin Functions (governance)
// --------------------------------------------------------------------------

// SetAttester sets the authorized attester address.
// In production, this should be behind a timelock or multi-sig.
func (m *SettlementManager) SetAttester(
	stateDB StateDB,
	caller common.Address,
	newAttester common.Address,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// First attester can be set by anyone (genesis initialization).
	// Subsequent changes require the current attester.
	current := m.getAttester(stateDB)
	if current != (common.Address{}) && caller != current {
		return ErrUnauthorizedAttester
	}

	storageKey := makeStorageKey(fillConfigPrefix, fillAttesterKey)
	var data common.Hash
	copy(data[12:], newAttester.Bytes())
	stateDB.SetState(settlementAddr, storageKey, data)

	return nil
}

// SetCeiling sets the prefund ceiling (max outstanding USD value).
func (m *SettlementManager) SetCeiling(
	stateDB StateDB,
	caller common.Address,
	ceiling *big.Int,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	attester := m.getAttester(stateDB)
	if caller != attester {
		return ErrUnauthorizedAttester
	}

	storageKey := makeStorageKey(fillConfigPrefix, fillCeilingKey)
	var data common.Hash
	ceilingBytes := ceiling.Bytes()
	copy(data[32-len(ceilingBytes):], ceilingBytes)
	stateDB.SetState(settlementAddr, storageKey, data)

	return nil
}

// SetFraudWindow sets the fraud window in blocks.
func (m *SettlementManager) SetFraudWindow(
	stateDB StateDB,
	caller common.Address,
	blocks uint64,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	attester := m.getAttester(stateDB)
	if caller != attester {
		return ErrUnauthorizedAttester
	}

	storageKey := makeStorageKey(fillConfigPrefix, fillFraudWindowKey)
	var data common.Hash
	blocksBig := new(big.Int).SetUint64(blocks)
	blockBytes := blocksBig.Bytes()
	copy(data[32-len(blockBytes):], blockBytes)
	stateDB.SetState(settlementAddr, storageKey, data)

	// Write sentinel to indicate fraud window has been explicitly set
	sentinelKey := makeStorageKey(fillConfigPrefix, []byte("fraud_window_set"))
	var sentinel common.Hash
	sentinel[31] = 1
	stateDB.SetState(settlementAddr, sentinelKey, sentinel)

	return nil
}

// --------------------------------------------------------------------------
// Internal State Management
// --------------------------------------------------------------------------

func (m *SettlementManager) getAttester(stateDB StateDB) common.Address {
	storageKey := makeStorageKey(fillConfigPrefix, fillAttesterKey)
	data := stateDB.GetState(settlementAddr, storageKey)
	if data == (common.Hash{}) {
		return common.Address{}
	}
	return common.BytesToAddress(data[12:])
}

func (m *SettlementManager) getCeiling(stateDB StateDB) *big.Int {
	storageKey := makeStorageKey(fillConfigPrefix, fillCeilingKey)
	data := stateDB.GetState(settlementAddr, storageKey)
	return new(big.Int).SetBytes(data[:])
}

func (m *SettlementManager) getOutstanding(stateDB StateDB) *big.Int {
	storageKey := makeStorageKey(fillConfigPrefix, fillOutstandingKey)
	data := stateDB.GetState(settlementAddr, storageKey)
	return new(big.Int).SetBytes(data[:])
}

func (m *SettlementManager) setOutstanding(stateDB StateDB, value *big.Int) {
	storageKey := makeStorageKey(fillConfigPrefix, fillOutstandingKey)
	var data common.Hash
	valueBytes := value.Bytes()
	copy(data[32-len(valueBytes):], valueBytes)
	stateDB.SetState(settlementAddr, storageKey, data)
}

func (m *SettlementManager) getFraudWindow(stateDB StateDB) uint64 {
	// Check if fraud window has been explicitly set by looking at a sentinel key.
	// If not set, return the default. If set (even to 0), return the stored value.
	sentinelKey := makeStorageKey(fillConfigPrefix, []byte("fraud_window_set"))
	sentinel := stateDB.GetState(settlementAddr, sentinelKey)
	if sentinel == (common.Hash{}) {
		return DefaultFraudWindowBlocks
	}
	storageKey := makeStorageKey(fillConfigPrefix, fillFraudWindowKey)
	data := stateDB.GetState(settlementAddr, storageKey)
	return new(big.Int).SetBytes(data[:]).Uint64()
}

func (m *SettlementManager) getCurrentBlock(stateDB StateDB) uint64 {
	blockKey := makeStorageKey(fillConfigPrefix, []byte("block"))
	blockHash := stateDB.GetState(settlementAddr, blockKey)
	if blockHash == (common.Hash{}) {
		return 1
	}
	return new(big.Int).SetBytes(blockHash[:]).Uint64()
}

func (m *SettlementManager) getAttestation(stateDB StateDB, orderID [32]byte) *Settlement {
	if att, ok := m.attestations[orderID]; ok {
		return att
	}

	storageKey := makeStorageKey(fillAttestPrefix, orderID[:])
	data := stateDB.GetState(settlementAddr, storageKey)
	if data == (common.Hash{}) {
		return nil
	}

	// Attestation exists -- load full state from multiple storage slots.
	// Slot 0: status (1 byte) + timestamp (8 bytes) + block (8 bytes)
	// Remaining fields stored in subsequent slots keyed by orderID + offset.
	att := &Settlement{
		OrderID: orderID,
		Status:  FillStatus(data[0]),
	}

	// Load timestamp and block from packed slot 0
	att.Timestamp = new(big.Int).SetBytes(data[1:9]).Uint64()
	att.Block = new(big.Int).SetBytes(data[9:17]).Uint64()

	// Slot 1: amount (32 bytes)
	amountKey := makeStorageKey(fillAttestPrefix, append(orderID[:], byte(1)))
	amountData := stateDB.GetState(settlementAddr, amountKey)
	att.Amount = new(big.Int).SetBytes(amountData[:])

	// Slot 2: price (32 bytes)
	priceKey := makeStorageKey(fillAttestPrefix, append(orderID[:], byte(2)))
	priceData := stateDB.GetState(settlementAddr, priceKey)
	att.Price = new(big.Int).SetBytes(priceData[:])

	// Slot 3: user address (20 bytes) + attester address (first 12 bytes)
	addrKey := makeStorageKey(fillAttestPrefix, append(orderID[:], byte(3)))
	addrData := stateDB.GetState(settlementAddr, addrKey)
	att.User = common.BytesToAddress(addrData[12:])

	// Slot 4: attester address (20 bytes) + symbol (first 12 bytes)
	attesterKey := makeStorageKey(fillAttestPrefix, append(orderID[:], byte(4)))
	attesterData := stateDB.GetState(settlementAddr, attesterKey)
	att.Attester = common.BytesToAddress(attesterData[12:])

	// Slot 5: symbol (32 bytes)
	symbolKey := makeStorageKey(fillAttestPrefix, append(orderID[:], byte(5)))
	symbolData := stateDB.GetState(settlementAddr, symbolKey)
	copy(att.Symbol[:], symbolData[:])

	m.attestations[orderID] = att
	return att
}

func (m *SettlementManager) saveAttestation(stateDB StateDB, att *Settlement) {
	m.attestations[att.OrderID] = att

	// Slot 0: status (1 byte) + timestamp (8 bytes) + block (8 bytes)
	var slot0 common.Hash
	slot0[0] = byte(att.Status)
	tsBig := new(big.Int).SetUint64(att.Timestamp)
	tsBytes := tsBig.Bytes()
	copy(slot0[9-len(tsBytes):9], tsBytes)
	blkBig := new(big.Int).SetUint64(att.Block)
	blkBytes := blkBig.Bytes()
	copy(slot0[17-len(blkBytes):17], blkBytes)
	storageKey := makeStorageKey(fillAttestPrefix, att.OrderID[:])
	stateDB.SetState(settlementAddr, storageKey, slot0)

	// Slot 1: amount
	var slot1 common.Hash
	amountBytes := att.Amount.Bytes()
	copy(slot1[32-len(amountBytes):], amountBytes)
	amountKey := makeStorageKey(fillAttestPrefix, append(att.OrderID[:], byte(1)))
	stateDB.SetState(settlementAddr, amountKey, slot1)

	// Slot 2: price
	var slot2 common.Hash
	priceBytes := att.Price.Bytes()
	copy(slot2[32-len(priceBytes):], priceBytes)
	priceKey := makeStorageKey(fillAttestPrefix, append(att.OrderID[:], byte(2)))
	stateDB.SetState(settlementAddr, priceKey, slot2)

	// Slot 3: user address
	var slot3 common.Hash
	copy(slot3[12:], att.User.Bytes())
	addrKey := makeStorageKey(fillAttestPrefix, append(att.OrderID[:], byte(3)))
	stateDB.SetState(settlementAddr, addrKey, slot3)

	// Slot 4: attester address
	var slot4 common.Hash
	copy(slot4[12:], att.Attester.Bytes())
	attesterKey := makeStorageKey(fillAttestPrefix, append(att.OrderID[:], byte(4)))
	stateDB.SetState(settlementAddr, attesterKey, slot4)

	// Slot 5: symbol
	var slot5 common.Hash
	copy(slot5[:], att.Symbol[:])
	symbolKey := makeStorageKey(fillAttestPrefix, append(att.OrderID[:], byte(5)))
	stateDB.SetState(settlementAddr, symbolKey, slot5)
}
