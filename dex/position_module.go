// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

// position_module.go is 0x9996 — the CLOB order-POSITION adapter.
//
// IT IS NOT AN ERC-721 NFT. There is no token, no tokenURI, no transfer, no
// approval. A "position" here is a maker's RESTING ORDER (settle_maker.go); this
// module is an ergonomic facade that maps Uniswap-position vocabulary
// (mint/increase/decrease/collect/burn) AND limit-order vocabulary
// (placeLimit/cancelLimit/modifyPosition) onto the ONE 0x9999 modifyLiquidity
// kernel.
//
// IT HOLDS NO CUSTODY OF ITS OWN. Every lifecycle op COMPOSES 0x9999: it builds a
// V4 modifyLiquidity call (+delta to open/increase, −delta to decrease/cancel/close)
// and routes it into SettlePrecompile.runSettleModifyLiquidity with the SAME caller
// and the SAME AccessibleState. So the reserve lock/unlock, the conservation
// invariant, the reentrancy guard, and the ownership check ALL live once at 0x9999;
// 0x9996 adds zero new value-moving code. Reads (positionsOf / positionInfo)
// enumerate the 0x9999 ownerOrders index deterministically.
//
// OWNERSHIP: cancel/decrease are bound by caller == order.owner. That check is
// enforced by the 0x9999 kernel (the orderID binds the owner; remove refuses when
// order.Owner != caller), so a cross-owner cancel reverts ErrMakerNotOwner — there
// is no way to cancel another account's order through this adapter.

var positionConfigKey = "dexPositionManagerConfig"

// PositionManagerContract is the 0x9996 adapter. It carries NO state — it routes to
// 0x9999. The singleton holds nothing.
type PositionManagerContract struct{}

var _ contract.StatefulPrecompiledContract = (*PositionManagerContract)(nil)

// PositionManagerPrecompile is the singleton 0x9996 contract.
var PositionManagerPrecompile = &PositionManagerContract{}

var positionManagerAddr = common.HexToAddress(DEXPositionManagerAddress)

// PositionManagerModule registers the 0x9996 adapter.
var PositionManagerModule = modules.Module{
	ConfigKey:    positionConfigKey,
	Address:      positionManagerAddr,
	Contract:     PositionManagerPrecompile,
	Configurator: &positionConfigurator{},
}

type positionConfigurator struct{}

// PositionManager selectors. The lifecycle ops share the V4 modifyLiquidity arg
// shape (PoolKey, tickLower, tickUpper, liquidity, salt) so the adapter can build a
// 0x9999 modifyLiquidity call from them directly.
var (
	SelectorPMMint              uint32 // mint/openPosition (ADD)
	SelectorPMOpenPosition      uint32
	SelectorPMIncreaseLiquidity uint32 // ADD
	SelectorPMDecreaseLiquidity uint32 // REMOVE
	SelectorPMCollect           uint32 // read (fees are D-authoritative)
	SelectorPMBurn              uint32 // REMOVE all (close)
	SelectorPMClosePosition     uint32
	SelectorPMPlaceLimit        uint32 // ADD (limit-order vocabulary)
	SelectorPMCancelLimit       uint32 // REMOVE
	SelectorPMModifyPosition    uint32 // ADD or REMOVE per signed delta
	SelectorPMPositionsOf       uint32 // read
	SelectorPMPositionInfo      uint32 // read
)

// pmLifecycleSig is the shared lifecycle ABI: (PoolKey, int24 tickLower, int24
// tickUpper, int256 liquidity, bytes32 salt, uint8 side). The side byte selects
// which asset the maker rests (bid=currency0, ask=currency1); the adapter folds it
// into the 0x9999 maker envelope.
const pmLifecycleSig = "((address,address,uint24,int24,address),int24,int24,int256,bytes32,uint8)"

func init() {
	SelectorPMMint = keccak4("mint" + pmLifecycleSig)
	SelectorPMOpenPosition = keccak4("openPosition" + pmLifecycleSig)
	SelectorPMIncreaseLiquidity = keccak4("increaseLiquidity" + pmLifecycleSig)
	SelectorPMDecreaseLiquidity = keccak4("decreaseLiquidity" + pmLifecycleSig)
	SelectorPMCollect = keccak4("collect" + pmLifecycleSig)
	SelectorPMBurn = keccak4("burn" + pmLifecycleSig)
	SelectorPMClosePosition = keccak4("closePosition" + pmLifecycleSig)
	SelectorPMPlaceLimit = keccak4("placeLimit" + pmLifecycleSig)
	SelectorPMCancelLimit = keccak4("cancelLimit" + pmLifecycleSig)
	SelectorPMModifyPosition = keccak4("modifyPosition" + pmLifecycleSig)
	SelectorPMPositionsOf = keccak4("positionsOf(address)")
	SelectorPMPositionInfo = keccak4("positionInfo(bytes32)")

	if err := modules.RegisterModule(PositionManagerModule); err != nil {
		panic(err)
	}
}

func (*positionConfigurator) MakeConfig() precompileconfig.Config { return &PositionManagerConfig{} }

func (c *positionConfigurator) Configure(
	_ precompileconfig.ChainConfig, _ precompileconfig.Config, _ contract.StateDB, _ contract.ConfigurationBlockContext,
) error {
	return nil // stateless adapter; the kernel at 0x9999 holds all state.
}

// PositionManagerConfig activates 0x9996 (no parameters — authority + custody live
// at 0x9999).
type PositionManagerConfig struct {
	precompileconfig.Upgrade
}

func (c *PositionManagerConfig) Key() string                                 { return positionConfigKey }
func (c *PositionManagerConfig) Timestamp() *uint64                          { return c.Upgrade.Timestamp() }
func (c *PositionManagerConfig) IsDisabled() bool                            { return c.Upgrade.Disable }
func (c *PositionManagerConfig) Verify(_ precompileconfig.ChainConfig) error { return nil }
func (c *PositionManagerConfig) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*PositionManagerConfig)
	return ok && c.Upgrade.Equal(&other.Upgrade)
}

const GasPositionRead uint64 = 1_500

var (
	ErrPMBadInput  = errors.New("dex: position-manager input too short")
	ErrPMZeroDelta = errors.New("dex: position-manager liquidity delta must be non-zero")
)

// Run dispatches 0x9996. Lifecycle ops route into the 0x9999 kernel; reads
// enumerate the ownerOrders index. The lifecycle ops are write ops (they invoke the
// kernel which writes 0x9999 state); reads are view.
func (p *PositionManagerContract) Run(
	state contract.AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool,
) ([]byte, uint64, error) {
	if len(input) < 4 {
		return nil, suppliedGas, errors.New("dex: position-manager input too short")
	}
	if state.GetBlockContext() == nil {
		return nil, suppliedGas, errors.New("dex: block context unavailable")
	}
	// CALL-only guard (same invariant as 0x9999): 0x9996 composes the 0x9999 kernel,
	// whose LP-commit ERC-20 leg (commitAssetIn -> pullERC20Terminal) moves
	// token value with the precompile self as msg.sender. geth binds self here as
	// `addr`; only DELEGATECALL makes addr != 0x9996 (CALL/CALLCODE both pass self =
	// 0x9996), which would commit ERC-20 liquidity as the WRONG msg.sender and break
	// the same conservation invariant. Reject it before any routing. See ErrSettleWrongContext.
	if addr != positionManagerAddr {
		return nil, suppliedGas, ErrSettleWrongContext
	}
	selector := uint32(input[0])<<24 | uint32(input[1])<<16 | uint32(input[2])<<8 | uint32(input[3])
	data := input[4:]

	switch selector {
	// ADD-delta lifecycle ops (open / increase / place a resting order).
	case SelectorPMMint, SelectorPMOpenPosition, SelectorPMIncreaseLiquidity, SelectorPMPlaceLimit:
		return p.routeLifecycle(state, caller, data, suppliedGas, readOnly, deltaSignPositive)

	// REMOVE-delta lifecycle ops (decrease / cancel / close — unlock + cancel).
	case SelectorPMDecreaseLiquidity, SelectorPMBurn, SelectorPMClosePosition, SelectorPMCancelLimit:
		return p.routeLifecycle(state, caller, data, suppliedGas, readOnly, deltaSignNegative)

	// modifyPosition: ADD or REMOVE per the signed delta the caller passes.
	case SelectorPMModifyPosition:
		return p.routeLifecycle(state, caller, data, suppliedGas, readOnly, deltaSignAny)

	// collect: accrued maker fees (and principal) are D-authoritative — the CLOB tracks
	// them in the maker's D-Chain balance. There is no C-side fee balance to sweep; the
	// value returns via a D->C atomic object the LP consumes through 0x9999
	// collectPosition. So 0x9996 collect REQUESTS the D-side fee export (emits the
	// collect routing event for the keeper to forward to D) and returns the position
	// id; the actual C credit lands when the LP/keeper calls collectPosition with the
	// resulting D->C object. Bound by caller == position owner.
	case SelectorPMCollect:
		return p.routeCollectRequest(state, caller, data, suppliedGas, readOnly)

	// Reads.
	case SelectorPMPositionsOf:
		return p.positionsOf(state, data, suppliedGas)
	case SelectorPMPositionInfo:
		return p.positionInfo(state, data, suppliedGas)

	default:
		return nil, suppliedGas, errors.New("dex: unknown 0x9996 position-manager selector")
	}
}

type deltaSign uint8

const (
	deltaSignPositive deltaSign = iota // force ADD (open/increase/place)
	deltaSignNegative                  // force REMOVE (decrease/cancel/close)
	deltaSignAny                       // use the caller's signed delta
)

// pmLifecycleArgs is the decoded shared lifecycle calldata.
type pmLifecycleArgs struct {
	key       PoolKey
	tickLower int24
	tickUpper int24
	delta     *big.Int
	salt      [32]byte
	side      MakerSide
}

// decodePMLifecycle decodes the shared lifecycle ABI:
//
//	[0:160]   PoolKey (5 slots)
//	[160:192] tickLower (int24, sign-extended)
//	[192:224] tickUpper (int24, sign-extended)
//	[224:256] liquidity (int256, signed)
//	[256:288] salt (bytes32)
//	[288:320] side (uint8 in the low byte)
func decodePMLifecycle(data []byte) (pmLifecycleArgs, error) {
	if len(data) < 320 {
		return pmLifecycleArgs{}, ErrPMBadInput
	}
	key, err := DecodePoolKey(data[:160])
	if err != nil {
		return pmLifecycleArgs{}, err
	}
	var a pmLifecycleArgs
	a.key = key
	a.tickLower = int24(decodeSigned256(data[160:192]).Int64())
	a.tickUpper = int24(decodeSigned256(data[192:224]).Int64())
	a.delta = decodeSigned256(data[224:256])
	copy(a.salt[:], data[256:288])
	if data[319] == byte(MakerSideAsk) {
		a.side = MakerSideAsk
	} else {
		a.side = MakerSideBid
	}
	return a, nil
}

// routeLifecycle is the SINGLE composition point: it decodes the lifecycle args,
// coerces the delta to the op's required sign, builds a V4 modifyLiquidity calldata
// (with the maker side envelope in hookData), and INVOKES the 0x9999 kernel with the
// SAME caller + state. No value-moving logic lives here — it all lives at 0x9999.
func (p *PositionManagerContract) routeLifecycle(
	state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool, sign deltaSign,
) ([]byte, uint64, error) {
	args, err := decodePMLifecycle(data)
	if err != nil {
		return nil, gas, err
	}
	if args.delta == nil || args.delta.Sign() == 0 {
		return nil, gas, ErrPMZeroDelta
	}
	// Coerce the delta to the op's required sign. open/increase/place => ADD (>0);
	// decrease/cancel/close => REMOVE (<0). modifyPosition keeps the caller's sign.
	delta := new(big.Int).Abs(args.delta)
	switch sign {
	case deltaSignPositive:
		// delta stays positive (ADD).
	case deltaSignNegative:
		delta = delta.Neg(delta) // REMOVE.
	case deltaSignAny:
		delta = args.delta // caller's signed value verbatim.
	}

	// Build the maker hookData envelope (tag + side byte) so the kernel rests the
	// intended asset side.
	hookData := []byte{makerEnvelopeTag[0], makerEnvelopeTag[1], makerEnvelopeTag[2], makerEnvelopeTag[3], byte(args.side)}

	// Build the V4 modifyLiquidity calldata (post-selector args) and route into the
	// 0x9999 kernel. This is genuine composition: the kernel is the ONLY place
	// reserve moves, ownership is checked, and the reentrancy guard is taken.
	kernelInput := buildModifyLiquidityArgs(args.key, args.tickLower, args.tickUpper, delta, args.salt, hookData)
	return SettlePrecompile.runSettleModifyLiquidity(state, caller, kernelInput, gas, readOnly)
}

// routeCollectRequest handles 0x9996 collect: it re-derives the position id from the
// lifecycle args, verifies the position exists and is owned by the caller, and emits
// the D->C collect routing event (for the keeper to make D export the LP's
// withdrawable principal + fees). It moves NO C value — the value returns when the LP
// consumes the resulting D->C object via 0x9999 collectPosition. The owner bind here
// is defense-in-depth; the value credit is bound again to the recorded object in
// Import, so a non-owner cannot collect another LP's funds.
func (p *PositionManagerContract) routeCollectRequest(
	state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, gas, ErrUnsupported // a collect request emits an event (a write); not a view.
	}
	if gas < GasPositionRead {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := gas - GasPositionRead
	args, err := decodePMLifecycle(data)
	if err != nil {
		return nil, gasLeft, err
	}
	poolID := args.key.ID()
	orderID := MakerOrderID(caller, poolID, args.salt, args.tickLower, args.tickUpper)
	stateDB := newPoolStateAdapter(state)
	order := loadRestingOrder(stateDB, orderID)
	// A collect names an existing position owned by the caller. None => nothing to
	// collect; a foreign owner => the orderID would differ (owner is folded in), so a
	// mismatch is already a missing record. Defense-in-depth owner compare too.
	if order.Status == OrderStatusNone || order.Owner != caller {
		return nil, gasLeft, ErrLPNoPosition
	}
	// Emit the collect routing event (reuse the native collect event — the keeper
	// forwards it to D to export the maker's withdrawable balance for this position).
	emitPositionCollecting(stateDB, ids.ID(orderID), poolID, caller)
	out := make([]byte, 32)
	copy(out, orderID[:])
	return out, gasLeft, nil
}

// positionsOf(owner) -> bytes32[] OPEN orderIDs. Deterministic enumeration via the
// 0x9999 ownerOrders index; skips CLOSED/CANCELLED (the design's "skip CLOSED").
func (p *PositionManagerContract) positionsOf(
	state contract.AccessibleState, data []byte, gas uint64,
) ([]byte, uint64, error) {
	if len(data) < 32 {
		return nil, gas, ErrPMBadInput
	}
	owner := common.BytesToAddress(data[12:32])
	rv := readOnlyView{state: state}
	ids := OwnerOrderIDs(rv, owner)
	cost := GasPositionRead * uint64(len(ids)+1)
	if gas < cost {
		return nil, 0, errors.New("dex: out of gas")
	}
	open := make([][32]byte, 0, len(ids))
	for _, id := range ids {
		if loadRestingOrder(rv, id).Status == OrderStatusOpen {
			open = append(open, id)
		}
	}
	return encodeBytes32Array(open), gas - cost, nil
}

// positionInfo(orderID) -> (owner, poolID, side, lockedAsset, lockedAmount,
// tickLower, tickUpper, status). Read of the 0x9999 resting-order record.
func (p *PositionManagerContract) positionInfo(
	state contract.AccessibleState, data []byte, gas uint64,
) ([]byte, uint64, error) {
	if gas < GasPositionRead {
		return nil, 0, errors.New("dex: out of gas")
	}
	if len(data) < 32 {
		return nil, gas - GasPositionRead, ErrPMBadInput
	}
	var orderID [32]byte
	copy(orderID[:], data[:32])
	o := loadRestingOrder(readOnlyView{state: state}, orderID)
	out := make([]byte, 32*8)
	copy(out[12:32], o.Owner.Bytes())
	copy(out[32:64], o.PoolID[:])
	out[95] = byte(o.Side)
	copy(out[96:128], o.LockedAsset[:])
	if o.LockedAmt != nil {
		o.LockedAmt.FillBytes(out[128:160])
	}
	copy(out[160:192], encodeInt24Word(o.TickLower))
	copy(out[192:224], encodeInt24Word(o.TickUpper))
	out[255] = byte(o.Status)
	return out, gas - GasPositionRead, nil
}

// buildModifyLiquidityArgs assembles the V4 modifyLiquidity post-selector calldata
// from its fields, with hookData ABI-appended (offset + length + padded data). The
// inverse of DecodeModifyLiquidityInput, so the kernel decodes exactly these args.
func buildModifyLiquidityArgs(key PoolKey, tickLower, tickUpper int24, delta *big.Int, salt [32]byte, hookData []byte) []byte {
	args := make([]byte, 288)
	copy(args[0:160], EncodePoolKeyABI(key))
	copy(args[160:192], encodeInt24Word(tickLower))
	copy(args[192:224], encodeInt24Word(tickUpper))
	copy(args[224:256], encodeSigned256(delta))
	copy(args[256:288], salt[:])
	// DecodeModifyLiquidityInput reads the hookData via decodeABIBytes(input, 288):
	// the word at byte 288 is the ABSOLUTE offset to the bytes' length word, then the
	// length, then the padded data. We append: offset(=320) | length | padded data.
	offsetWord := make([]byte, 32)
	putWordUint64(offsetWord[0:32], 320)
	lenWord := make([]byte, 32)
	putWordUint64(lenWord[0:32], uint64(len(hookData)))
	padded := make([]byte, (len(hookData)+31)/32*32)
	copy(padded, hookData)
	out := append(args, offsetWord...)
	out = append(out, lenWord...)
	out = append(out, padded...)
	return out
}

// encodeSigned256 encodes a signed big.Int as a 32-byte two's-complement word.
func encodeSigned256(v *big.Int) []byte {
	out := make([]byte, 32)
	if v == nil || v.Sign() == 0 {
		return out
	}
	if v.Sign() > 0 {
		v.FillBytes(out)
	} else {
		tc := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 256), v)
		tc.FillBytes(out)
	}
	return out
}
