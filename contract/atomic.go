// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package contract

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/chains/atomic"
)

// AtomicState is the OPTIONAL host capability a precompile type-asserts when it
// must move value across chains via the primary network's atomic shared memory —
// the same import/export shared-memory primitive platformvm and the dexvm use.
//
// It is intentionally NOT part of AccessibleState: the vast majority of
// precompiles never touch shared memory, and AccessibleState has many test/mock
// implementers. A precompile that needs it does:
//
//	atomicState, ok := accessibleState.(contract.AtomicState)
//
// and reverts cleanly when ok is false (the host did not wire a shared-memory
// capable runtime — single-chain dev / a non-atomic harness). The host's
// concrete AccessibleState (the EVM's accessibleStateAdapter, via the registry
// bridge) implements this by sourcing the runtime from the consensus context.
//
// THE INVARIANT THIS ENABLES (the DEX 0x9999 ship rule): a precompile can credit
// a local-chain balance from a cross-chain settlement ONLY by consuming a peer's
// atomic export object out of AtomicMemory() (Get + a Remove applied via Apply),
// and can fund a peer's chain ONLY by writing an atomic export object into
// AtomicMemory() (a Put applied via Apply). No value crosses without an atomic
// shared-memory object on the wire.
type AtomicState interface {
	// AtomicMemory returns this chain's atomic shared-memory handle, or nil when
	// the host wired no shared memory (single-chain dev). A nil return MUST make
	// the calling precompile revert rather than fabricate value.
	AtomicMemory() atomic.SharedMemory

	// NetworkID is the numeric network identifier (1=mainnet, 2=testnet, ...). It
	// scopes a cross-chain object's identity so an object minted on one network can
	// never be consumed on another.
	NetworkID() uint32

	// ChainID is THIS chain's id (the C-Chain / EVM chain executing the precompile).
	// It is the source chain id a C->D export object is keyed under and the
	// destination chain id a D->C settlement object names.
	ChainID() ids.ID

	// CChainID is the C-Chain id used as the cross-chain settlement peer's view of
	// this chain. On the C-Chain itself this equals ChainID(); it is surfaced
	// separately so the binding is explicit and survives chains that distinguish
	// the two.
	CChainID() ids.ID

	// TxID is the id of the transaction currently executing this precompile call.
	// Combined with CallIndex it makes a per-call cross-chain object id injective.
	TxID() ids.ID

	// CallIndex is this precompile invocation's index within the current tx
	// (0-based, monotonic). Two invocations in one tx get distinct indices so their
	// derived cross-chain object ids never collide.
	CallIndex() uint32
}
