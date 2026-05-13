// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

// Package bridge — registrar precompile at 0x0446.
//
// The registrar is the governance write-path that mutates the on-chain bridge
// Registry. It exposes five selectors:
//
//	0x01 RegisterChain(chain_id, name, evm, gateway_at)
//	0x02 UnregisterChain(chain_id)
//	0x03 SetGateway(chain_id, gateway_at)
//	0x04 GetCount() -> uint64
//	0x05 GetChain(idx) -> (chain_id, name, evm, gateway_at)
//
// Writes go through M-of-N ECDSA multisig — the registrar refuses to mutate
// state unless the supplied signatures cover threshold-many operators of the
// canonical governance set. Reads are unauthenticated (state-only, gas-cheap).
//
// Storage layout
//
//   - Registry rows live at the bridge gateway address (see registry_state.go).
//     The registrar writes to those same slots — exactly one canonical layout.
//   - The operator set and threshold live at the registrar's own address under
//     the "lux.bridge.gov" prefix so other precompiles can read it.
//
// Signature payload
//
//	keccak256("lux.bridge.registrar.v1" || selector(1) || abi_args)
//
// where abi_args is the same byte slice the EVM hands the selector.
package bridge

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"

	"github.com/luxfi/precompile/contract"
)

// ContractRegistrarAddress is the canonical 20-byte address of the registrar
// precompile. The address is the "0x0446" sibling of the bridge gateway
// (0x0440) in the DEX/Bridge reserved range 0x0400-0x04FF.
var ContractRegistrarAddress = common.HexToAddress(
	"0x0400000000000000000000000000000000000046",
)

// BridgeGatewayCanonicalAddress is the address where the registry rows live —
// the bridge gateway precompile, 0x0440 in the same range. The registrar
// reads and writes those slots; it does not maintain a parallel registry.
var BridgeGatewayCanonicalAddress = common.HexToAddress(
	"0x0400000000000000000000000000000000000040",
)

// DomainSeparator is the prefix bound into the multisig payload. The EVM-side
// caller (off-chain signer) MUST keccak the same bytes in the same order:
//
//	keccak256(DomainSeparator || selector || abi.encodePacked(args))
const DomainSeparator = "lux.bridge.registrar.v1"

// Selectors. First byte of input; remaining bytes are big-endian ABI args.
const (
	SelectorRegisterChain   byte = 0x01
	SelectorUnregisterChain byte = 0x02
	SelectorSetGateway      byte = 0x03
	SelectorGetCount        byte = 0x04
	SelectorGetChain        byte = 0x05
)

// Gas costs — pinned, no dynamic component.
const (
	GasRegisterChain   uint64 = 60_000 // 3 SSTOREs to fresh slots
	GasUnregisterChain uint64 = 30_000 // 3 SSTOREs to zero + bookkeeping
	GasSetGateway      uint64 = 22_000 // 1 SSTORE
	GasGetCount        uint64 = 700    // 1 SLOAD
	GasGetChain        uint64 = 2_400  // 3 SLOADs
)

// Errors.
var (
	ErrRegistrarInputTooShort  = errors.New("registrar: input too short")
	ErrRegistrarUnknownSelector = errors.New("registrar: unknown selector")
	ErrRegistrarReadOnly       = errors.New("registrar: write in read-only mode")
	ErrAlreadyRegistered       = errors.New("registrar: chain already registered")
	ErrNotRegistered           = errors.New("registrar: chain not registered")
	ErrIndexOutOfRange         = errors.New("registrar: index out of range")
	ErrUnauthorized            = errors.New("registrar: threshold not met")
	ErrInvalidSignatureBytes   = errors.New("registrar: invalid signature bytes")
	ErrDuplicateSigner         = errors.New("registrar: duplicate signer in signature set")
	ErrChainNameTooLong        = errors.New("registrar: chain name exceeds max length")
)

// ABI arg sizes for RegisterChain.
const (
	argChainIDSize   = 4  // uint32 BE
	argNameLenSize   = 1  // uint8: length-prefix for name (<=32)
	argEVMFlagSize   = 1  // uint8: 0 virtual, 1 EVM
	argAddressSize   = 20 // common.Address
	argSigLen        = 65 // r(32) || s(32) || v(1)
	maxChainNameSize = 32
)

// registrarPrecompile is the singleton 0x0446 stateful contract.
type registrarPrecompile struct{}

// RegistrarPrecompile is the singleton exposed to the module registry.
var RegistrarPrecompile contract.StatefulPrecompiledContract = &registrarPrecompile{}

// Run dispatches on the leading 1-byte selector. The packed encoding mirrors
// what the off-chain signer hashes — there is exactly one wire layout per
// selector and the registrar IS that layout.
func (p *registrarPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if len(input) < 1 {
		return nil, suppliedGas, ErrRegistrarInputTooShort
	}
	sel := input[0]
	args := input[1:]
	state := accessibleState.GetStateDB()

	switch sel {
	case SelectorRegisterChain:
		return p.runRegisterChain(state, sel, args, suppliedGas, readOnly)
	case SelectorUnregisterChain:
		return p.runUnregisterChain(state, sel, args, suppliedGas, readOnly)
	case SelectorSetGateway:
		return p.runSetGateway(state, sel, args, suppliedGas, readOnly)
	case SelectorGetCount:
		return p.runGetCount(state, suppliedGas)
	case SelectorGetChain:
		return p.runGetChain(state, args, suppliedGas)
	default:
		return nil, suppliedGas, ErrRegistrarUnknownSelector
	}
}

// runRegisterChain — selector 0x01.
//
// args = chain_id(4) || name_len(1) || name(name_len) || evm(1) || gateway_at(20)
//
//	|| sig_count(1) || sig0(65) || ... || sigN(65)
func (p *registrarPrecompile) runRegisterChain(
	state contract.StateDB,
	sel byte,
	args []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, ErrRegistrarReadOnly
	}
	remaining, err := contract.DeductGas(suppliedGas, GasRegisterChain)
	if err != nil {
		return nil, 0, err
	}

	id, name, evm, gw, payload, sigs, err := decodeRegisterChainArgs(args)
	if err != nil {
		return nil, remaining, err
	}

	if err := verifyMultisig(state, sel, payload, sigs); err != nil {
		return nil, remaining, err
	}

	r := &stateRegistry{state: state, addr: BridgeGatewayCanonicalAddress}
	if _, ok := r.Get(id); ok {
		return nil, remaining, ErrAlreadyRegistered
	}

	idx := r.count()
	hdrKey, nameKey, _ := slotRow(idx)
	hdr, nm := packRow(Chain{ID: id, Name: name, EVM: evm, GatewayAt: gw})
	state.SetState(BridgeGatewayCanonicalAddress, hdrKey, hdr)
	state.SetState(BridgeGatewayCanonicalAddress, nameKey, nm)

	var cnt common.Hash
	binary.BigEndian.PutUint64(cnt[24:], idx+1)
	state.SetState(BridgeGatewayCanonicalAddress, slotCount(), cnt)

	return encodeU64(idx), remaining, nil
}

// runUnregisterChain — selector 0x02.
//
// args = chain_id(4) || sig_count(1) || sig0(65) || ... || sigN(65)
//
// Compaction: zero the row, swap-with-last to keep the slice dense, decrement
// count. The slot scheme assumes contiguous indices, so we maintain that
// invariant.
func (p *registrarPrecompile) runUnregisterChain(
	state contract.StateDB,
	sel byte,
	args []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, ErrRegistrarReadOnly
	}
	remaining, err := contract.DeductGas(suppliedGas, GasUnregisterChain)
	if err != nil {
		return nil, 0, err
	}

	id, payload, sigs, err := decodeUnregisterChainArgs(args)
	if err != nil {
		return nil, remaining, err
	}

	if err := verifyMultisig(state, sel, payload, sigs); err != nil {
		return nil, remaining, err
	}

	r := &stateRegistry{state: state, addr: BridgeGatewayCanonicalAddress}
	n := r.count()
	idx, found := indexOf(r, id, n)
	if !found {
		return nil, remaining, ErrNotRegistered
	}

	last := n - 1
	if idx != last {
		// Move last row's data into the slot we're vacating.
		lastHdrKey, lastNameKey, _ := slotRow(last)
		hdr := state.GetState(BridgeGatewayCanonicalAddress, lastHdrKey)
		nm := state.GetState(BridgeGatewayCanonicalAddress, lastNameKey)

		dstHdrKey, dstNameKey, _ := slotRow(idx)
		state.SetState(BridgeGatewayCanonicalAddress, dstHdrKey, hdr)
		state.SetState(BridgeGatewayCanonicalAddress, dstNameKey, nm)
	}

	// Zero the (now duplicate or stale) trailing slot.
	zeroHdrKey, zeroNameKey, zeroResKey := slotRow(last)
	var zero common.Hash
	state.SetState(BridgeGatewayCanonicalAddress, zeroHdrKey, zero)
	state.SetState(BridgeGatewayCanonicalAddress, zeroNameKey, zero)
	state.SetState(BridgeGatewayCanonicalAddress, zeroResKey, zero)

	var cnt common.Hash
	binary.BigEndian.PutUint64(cnt[24:], last)
	state.SetState(BridgeGatewayCanonicalAddress, slotCount(), cnt)

	return encodeU64(idx), remaining, nil
}

// runSetGateway — selector 0x03.
//
// args = chain_id(4) || gateway_at(20) || sig_count(1) || sigs(65 each)
func (p *registrarPrecompile) runSetGateway(
	state contract.StateDB,
	sel byte,
	args []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, ErrRegistrarReadOnly
	}
	remaining, err := contract.DeductGas(suppliedGas, GasSetGateway)
	if err != nil {
		return nil, 0, err
	}

	id, gw, payload, sigs, err := decodeSetGatewayArgs(args)
	if err != nil {
		return nil, remaining, err
	}

	if err := verifyMultisig(state, sel, payload, sigs); err != nil {
		return nil, remaining, err
	}

	r := &stateRegistry{state: state, addr: BridgeGatewayCanonicalAddress}
	n := r.count()
	idx, found := indexOf(r, id, n)
	if !found {
		return nil, remaining, ErrNotRegistered
	}

	// Patch the gateway field in word 0 (bytes 5..24). Preserve the rest.
	hdrKey, _, _ := slotRow(idx)
	hdr := state.GetState(BridgeGatewayCanonicalAddress, hdrKey)
	copy(hdr[5:25], gw.Bytes())
	state.SetState(BridgeGatewayCanonicalAddress, hdrKey, hdr)

	return encodeU64(idx), remaining, nil
}

// runGetCount — selector 0x04. Read-only, no signature required.
func (p *registrarPrecompile) runGetCount(
	state contract.StateDB,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	remaining, err := contract.DeductGas(suppliedGas, GasGetCount)
	if err != nil {
		return nil, 0, err
	}
	r := &stateRegistry{state: state, addr: BridgeGatewayCanonicalAddress}
	return encodeU64(r.count()), remaining, nil
}

// runGetChain — selector 0x05.
//
// args = idx(8 bytes, big-endian uint64)
//
// returns chain_id(4) || name_len(1) || name(name_len) || evm(1) || gateway_at(20)
func (p *registrarPrecompile) runGetChain(
	state contract.StateDB,
	args []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	remaining, err := contract.DeductGas(suppliedGas, GasGetChain)
	if err != nil {
		return nil, 0, err
	}
	if len(args) < 8 {
		return nil, remaining, ErrRegistrarInputTooShort
	}
	idx := binary.BigEndian.Uint64(args[:8])

	r := &stateRegistry{state: state, addr: BridgeGatewayCanonicalAddress}
	n := r.count()
	if idx >= n {
		return nil, remaining, ErrIndexOutOfRange
	}
	c := r.row(idx)
	return encodeChain(c), remaining, nil
}

// --- Argument decoders -------------------------------------------------------

// decodeRegisterChainArgs returns the parsed payload and the signed-payload
// bytes (everything up to but not including sig_count).
func decodeRegisterChainArgs(args []byte) (
	id ChainID,
	name string,
	evm bool,
	gw common.Address,
	signedPayload []byte,
	sigs [][]byte,
	err error,
) {
	if len(args) < argChainIDSize+argNameLenSize {
		err = ErrRegistrarInputTooShort
		return
	}
	id = ChainID(binary.BigEndian.Uint32(args[0:4]))
	nameLen := int(args[4])
	if nameLen > maxChainNameSize {
		err = ErrChainNameTooLong
		return
	}
	off := 5 + nameLen
	if len(args) < off+argEVMFlagSize+argAddressSize {
		err = ErrRegistrarInputTooShort
		return
	}
	name = string(args[5:off])
	evm = args[off] == 0x01
	off++
	gw = common.BytesToAddress(args[off : off+argAddressSize])
	off += argAddressSize

	signedPayload = append([]byte(nil), args[:off]...)

	sigs, err = decodeSigs(args[off:])
	return
}

func decodeUnregisterChainArgs(args []byte) (
	id ChainID,
	signedPayload []byte,
	sigs [][]byte,
	err error,
) {
	if len(args) < argChainIDSize {
		err = ErrRegistrarInputTooShort
		return
	}
	id = ChainID(binary.BigEndian.Uint32(args[0:4]))
	signedPayload = append([]byte(nil), args[:argChainIDSize]...)
	sigs, err = decodeSigs(args[argChainIDSize:])
	return
}

func decodeSetGatewayArgs(args []byte) (
	id ChainID,
	gw common.Address,
	signedPayload []byte,
	sigs [][]byte,
	err error,
) {
	const headerLen = argChainIDSize + argAddressSize
	if len(args) < headerLen {
		err = ErrRegistrarInputTooShort
		return
	}
	id = ChainID(binary.BigEndian.Uint32(args[0:4]))
	gw = common.BytesToAddress(args[4 : 4+argAddressSize])
	signedPayload = append([]byte(nil), args[:headerLen]...)
	sigs, err = decodeSigs(args[headerLen:])
	return
}

// decodeSigs reads sig_count(1) || sigs(65 each).
func decodeSigs(b []byte) ([][]byte, error) {
	if len(b) < 1 {
		return nil, ErrRegistrarInputTooShort
	}
	n := int(b[0])
	expected := 1 + n*argSigLen
	if len(b) < expected {
		return nil, ErrRegistrarInputTooShort
	}
	sigs := make([][]byte, n)
	for i := 0; i < n; i++ {
		off := 1 + i*argSigLen
		sigs[i] = b[off : off+argSigLen]
	}
	return sigs, nil
}

// --- Multisig verification ---------------------------------------------------

// verifyMultisig checks that at least Threshold operators of the canonical
// governance set signed keccak256(DomainSeparator || sel || payload).
func verifyMultisig(state contract.StateDB, sel byte, payload []byte, sigs [][]byte) error {
	digest := registrarDigest(sel, payload)
	operators, threshold, err := loadGovernance(state)
	if err != nil {
		return err
	}
	opSet := make(map[common.Address]bool, len(operators))
	for _, op := range operators {
		opSet[op] = true
	}

	seen := make(map[common.Address]bool, len(sigs))
	valid := uint32(0)
	for _, sig := range sigs {
		if len(sig) != argSigLen {
			return ErrInvalidSignatureBytes
		}
		pub, err := crypto.Ecrecover(digest, sig)
		if err != nil {
			// One bad signature shouldn't allow the rest to count — fail closed.
			return ErrInvalidSignatureBytes
		}
		// Drop the 0x04 prefix and keccak the remaining 64 bytes to derive the
		// EVM address.
		if len(pub) != 65 {
			return ErrInvalidSignatureBytes
		}
		addr := common.BytesToAddress(crypto.Keccak256(pub[1:])[12:])
		if !opSet[addr] {
			continue
		}
		if seen[addr] {
			return ErrDuplicateSigner
		}
		seen[addr] = true
		valid++
		if valid >= threshold {
			return nil
		}
	}
	return ErrUnauthorized
}

// registrarDigest computes the canonical signing digest. The off-chain signer
// MUST produce the same bytes — keep this function and its callers in lock-step.
func registrarDigest(sel byte, payload []byte) []byte {
	buf := make([]byte, 0, len(DomainSeparator)+1+len(payload))
	buf = append(buf, []byte(DomainSeparator)...)
	buf = append(buf, sel)
	buf = append(buf, payload...)
	return crypto.Keccak256(buf)
}

// --- Encoders ----------------------------------------------------------------

func encodeU64(v uint64) []byte {
	var h common.Hash
	binary.BigEndian.PutUint64(h[24:], v)
	return h[:]
}

// encodeChain packs a row for GetChain replies. Compact wire format:
//
//	chain_id(4) || name_len(1) || name(name_len) || evm(1) || gateway_at(20)
func encodeChain(c Chain) []byte {
	name := []byte(c.Name)
	if len(name) > maxChainNameSize {
		name = name[:maxChainNameSize]
	}
	out := make([]byte, 0, 4+1+len(name)+1+20)
	var idBuf [4]byte
	binary.BigEndian.PutUint32(idBuf[:], uint32(c.ID))
	out = append(out, idBuf[:]...)
	out = append(out, byte(len(name)))
	out = append(out, name...)
	if c.EVM {
		out = append(out, 0x01)
	} else {
		out = append(out, 0x00)
	}
	out = append(out, c.GatewayAt.Bytes()...)
	return out
}

// indexOf scans the registry for id. The state-backed registry doesn't keep an
// id->index map (rows are 3-word slots, not addressable by chain id), so we
// resolve by linear scan — bounded by chain count, which is small.
func indexOf(r *stateRegistry, id ChainID, n uint64) (uint64, bool) {
	for i := uint64(0); i < n; i++ {
		if r.row(i).ID == id {
			return i, true
		}
	}
	return 0, false
}

// --- Governance state --------------------------------------------------------
//
// Slots at the registrar's own address (0x0446):
//
//	govSlot(0)            -> packed: threshold(uint32 BE in bytes 28..32) || count(uint32 BE in bytes 24..28)
//	govSlot(1 + i)        -> operator i (20-byte address right-aligned in bytes 12..32)
//
// Operators are seeded at deployment via SeedGovernance. Mutations to the
// operator set are out of scope for this registrar — a future governor
// precompile may rotate them, again as a single canonical layout.

var govBase = [24]byte{
	// fixed ASCII prefix "lux.bridge.gov" left-padded with zero bytes
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	'l', 'u', 'x', '.', 'b', 'r', 'i', 'd', 'g', 'e', '.', 'g', 'o', 'v',
}

func govSlot(offset uint64) common.Hash {
	var h common.Hash
	copy(h[:24], govBase[:])
	binary.BigEndian.PutUint64(h[24:], offset)
	return h
}

// SeedGovernance writes the operator set and threshold to the registrar's
// state. Idempotent: re-seeding the same configuration is a no-op. Different
// configuration overwrites — this is intended to be called once at deployment
// from the configurator, but tests may call it directly.
func SeedGovernance(state contract.StateDB, operators []common.Address, threshold uint32) error {
	if threshold == 0 || int(threshold) > len(operators) {
		return fmt.Errorf("registrar: invalid threshold %d for %d operators", threshold, len(operators))
	}
	if len(operators) > 1<<16 {
		return fmt.Errorf("registrar: too many operators: %d", len(operators))
	}

	var header common.Hash
	binary.BigEndian.PutUint32(header[24:28], uint32(len(operators)))
	binary.BigEndian.PutUint32(header[28:32], threshold)
	state.SetState(ContractRegistrarAddress, govSlot(0), header)

	for i, op := range operators {
		var slot common.Hash
		copy(slot[12:], op.Bytes())
		state.SetState(ContractRegistrarAddress, govSlot(uint64(i+1)), slot)
	}
	return nil
}

// loadGovernance reads the operator set and threshold from state.
func loadGovernance(state contract.StateDB) ([]common.Address, uint32, error) {
	header := state.GetState(ContractRegistrarAddress, govSlot(0))
	count := binary.BigEndian.Uint32(header[24:28])
	threshold := binary.BigEndian.Uint32(header[28:32])
	if count == 0 || threshold == 0 {
		return nil, 0, ErrUnauthorized
	}
	ops := make([]common.Address, count)
	for i := uint32(0); i < count; i++ {
		slot := state.GetState(ContractRegistrarAddress, govSlot(uint64(i+1)))
		ops[i] = common.BytesToAddress(slot[12:])
	}
	return ops, threshold, nil
}
