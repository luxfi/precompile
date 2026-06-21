// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// LXSettleAddress is THE production DEX settlement precompile (LP-9999). It is
// the SOLE money path and the SOLE DEX precompile: every value-moving DEX call
// settles here via the native C<->D two-phase atomic seam. 0x9010 was removed;
// 0x9999 is the sole DEX precompile — there is exactly one money path and one
// replay namespace (dex.precompile.v1.9999.*), never two.
const LXSettleAddress = "0x0000000000000000000000000000000000009999"

// poolManagerAddr9999 is the 0x9999 settlement address as a common.Address. All
// 0x9999 native-seam state (the C->D intent set, the D->C settlement-consumed set,
// halt, config, per-asset vault) lives under this address; cross-chain atomic
// objects route to/from it.
var poolManagerAddr9999 = common.HexToAddress(LXSettleAddress)

// settleStateNamespace is the durable storage namespace prefix for 0x9999 state.
// Every storage key the settlement path writes derives from this so the money
// path's state is a single, auditable region: dex.precompile.v1.9999.*
const settleStateNamespace = "dex.precompile.v1.9999."

// keccak32 returns keccak256(b) as a [32]byte. The settlement path's commitments
// (swapParamsHash) use keccak to match PoolKey.ID() / swapParamsDigest, which the
// rest of the package already commits with keccak via crypto.Keccak256.
func keccak32(b []byte) [32]byte {
	var out [32]byte
	copy(out[:], crypto.Keccak256(b))
	return out
}

// stateKV is the MINIMAL key-value state surface the settlement metadata paths
// (halt, verifier registry, chain-identity config) need — just GetState/SetState,
// NO balance methods. Decomplecting this from the full StateDB (which braids in
// balance movement) lets these pure-metadata helpers accept the package's
// poolStateAdapter (used everywhere a swap/custody handler runs) without dragging
// in balances. It matches the package StateDB's GetState/SetState (SetState
// returns nothing — the adapter form), NOT the raw contract.StateDB (whose
// SetState returns the prior value). The value-MOVING settle path keeps the full
// StateDB (via the adapter) for balances.
type stateKV interface {
	GetState(addr common.Address, key common.Hash) common.Hash
	SetState(addr common.Address, key common.Hash, value common.Hash)
}
