// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package frost

import (
	"errors"
	"fmt"
	"sync"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/protocols/frost/sign"
)

var (
	// ContractFROSTVerifyAddress is the address of the FROST threshold signature precompile (Threshold Signatures range 0x0800)
	ContractFROSTVerifyAddress = common.HexToAddress("0x0800000000000000000000000000000000000002")

	// Singleton instance
	FROSTVerifyPrecompile = &frostVerifyPrecompile{}

	_ contract.StatefulPrecompiledContract = &frostVerifyPrecompile{}

	ErrInvalidInputLength  = contract.ErrInvalidInput
	ErrInvalidThreshold    = errors.New("invalid threshold: t must be > 0 and <= n")
	ErrInvalidPublicKey    = errors.New("invalid public key")
	ErrInvalidSignature    = errors.New("invalid signature")
	ErrSignatureVerifyFail = errors.New("signature verification failed")
)

const (
	// Gas costs for FROST threshold signature verification
	// FROST is more efficient than ECDSA threshold (CMP/CGGMP21)
	FROSTVerifyBaseGas      uint64 = 50_000 // Base cost for Schnorr verification
	FROSTVerifyPerSignerGas uint64 = 5_000  // Cost per signer in threshold

	// FROST uses 32-byte Schnorr signatures (Ed25519 or secp256k1)
	FROSTPublicKeySize   = 32 // Compressed public key
	FROSTSignatureSize   = 64 // Schnorr signature (R || s)
	FROSTMessageHashSize = 32 // SHA-256 message hash
	ThresholdSize        = 4  // uint32 threshold t
	TotalSignersSize     = 4  // uint32 total signers n

	// Minimum input size
	MinInputSize = ThresholdSize + TotalSignersSize + FROSTPublicKeySize + FROSTMessageHashSize + FROSTSignatureSize

	// MaxBilledSigners clamps the signer count read from calldata before it
	// is multiplied into the fee. `n` is attacker-chosen and the verifier
	// never consults it: verifySchnorrSignature is handed a fixed 32-byte
	// key, a fixed 32-byte hash and a fixed 64-byte signature, so the work
	// is the same for every declared n. Without the clamp a caller quotes an
	// arbitrary fee -- up to 2^32-1 signers -- for constant work. Matches the
	// clamp the sibling threshold precompiles apply.
	MaxBilledSigners uint32 = 1000
)

type frostVerifyPrecompile struct{}

// claim is one call's submission: the committee it names, and the Schnorr
// signature it asks to have checked against a key and a message hash.
type claim struct {
	threshold uint32
	signers   uint32
	key       []byte
	hash      []byte
	sig       []byte
}

// parse reads the wire format off calldata:
//
//	[0:4]    threshold t          (uint32, big-endian)
//	[4:8]    total signers n      (uint32, big-endian)
//	[8:40]   aggregated public key (32 bytes)
//	[40:72]  message hash          (32 bytes)
//	[72:136] Schnorr signature     (64 bytes: R || s)
//
// Every field is bounded by a contract.Cursor rather than by a slice
// expression, and the difference is not stylistic. A precompile's input is a
// window into EVM memory: opCall takes it with Memory.GetPtr, which returns
// the two-index slice m.store[off : off+size], and nothing on the path to Run
// copies it. So len is the size the caller declared and paid gas for, while
// cap is the rest of memory that same caller filled with MSTORE beforehand. A
// slice expression past len but within cap does not refuse -- it returns bytes
// the caller chose, and the verifier answers over material nobody declared.
// The cursor bounds every read against Len and caps what it hands back, so a
// field cannot be completed out of the next one or out of spare capacity.
// See contract/cursor.go.
//
// The format is fixed-size, so parse refuses exactly when the calldata holds
// fewer than MinInputSize bytes -- the same condition the hand-written length
// check tested, now enforced per field and not by a line that can be deleted.
//
// Trailing bytes are accepted. This format has always admitted them (it took
// len(input) >= MinInputSize, never ==), so parse reads its fields and stops
// rather than calling End. Whether to keep admitting them is a question about
// the wire format, not about the parser: padding lets one signature ride many
// distinct calldatas.
func parse(input []byte) (claim, error) {
	in := contract.Read(input)

	threshold, err := in.Uint32()
	if err != nil {
		return claim{}, err
	}
	signers, err := in.Uint32()
	if err != nil {
		return claim{}, err
	}
	key, err := in.Bytes(FROSTPublicKeySize)
	if err != nil {
		return claim{}, err
	}
	hash, err := in.Bytes(FROSTMessageHashSize)
	if err != nil {
		return claim{}, err
	}
	sig, err := in.Bytes(FROSTSignatureSize)
	if err != nil {
		return claim{}, err
	}
	return claim{threshold: threshold, signers: signers, key: key, hash: hash, sig: sig}, nil
}

// Address returns the address of the FROST verify precompile
func (p *frostVerifyPrecompile) Address() common.Address {
	return ContractFROSTVerifyAddress
}

// RequiredGas calculates the gas required for FROST verification
func (p *frostVerifyPrecompile) RequiredGas(input []byte) uint64 {
	return FROSTVerifyGasCost(input)
}

// FROSTVerifyGasCost calculates the gas cost for FROST verification.
//
// Calldata too short to carry a signer count is billed at base: parse refuses
// exactly below MinInputSize, which is the boundary this function has always
// priced at.
func FROSTVerifyGasCost(input []byte) uint64 {
	c, err := parse(input)
	if err != nil {
		return FROSTVerifyBaseGas
	}

	// Base cost + per-signer cost, on the clamped signer count.
	return FROSTVerifyBaseGas + (uint64(min(c.signers, MaxBilledSigners)) * FROSTVerifyPerSignerGas)
}

// Run implements the FROST threshold signature verification precompile
func (p *frostVerifyPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	// Calculate required gas
	gasCost := p.RequiredGas(input)
	remainingGas, err := contract.DeductGas(suppliedGas, gasCost)
	if err != nil {
		return nil, 0, err
	}

	// parse reads the fields through a contract.Cursor; see its doc comment
	// for why a slice expression is the wrong tool on calldata.
	c, err := parse(input)
	if err != nil {
		// parse refuses only by running out of calldata, and the deployed
		// error names both sizes, so keep that wording rather than the
		// cursor's.
		return nil, remainingGas, fmt.Errorf("%w: expected at least %d bytes, got %d",
			ErrInvalidInputLength, MinInputSize, len(input))
	}

	// Validate threshold
	if c.threshold == 0 || c.threshold > c.signers {
		return nil, remainingGas, ErrInvalidThreshold
	}

	// CPU is the single source of truth. FROST produces SCHNORR signatures;
	// the luxfi/accel SigECDSA kernel verifies a different equation entirely
	// (and mis-frames the 32-byte x-only key against its 33-byte ECDSA key
	// layout). A GPU "valid" for an ECDSA check does not imply a valid Schnorr
	// signature -- that was a wrong-primitive forgery surface and a CPU/GPU
	// consensus split. Re-introducing accel requires a Schnorr (secp256k1)
	// kernel proven byte-identical to verifySchnorrSignature.
	valid := verifySchnorrSignature(c.key, c.hash, c.sig)

	// Return result as 32-byte word (1 = valid, 0 = invalid)
	result := make([]byte, 32)
	if valid {
		result[31] = 1
	}

	return result, remainingGas, nil
}

// liftXCache caches decompressed public key points.
// LiftX (modular square root) is 80% of FROST verify cost — caching eliminates it
// for repeated verifications with the same key (which is every block from same validators).
var (
	liftXCache   = make(map[[32]byte]curve.Point)
	liftXCacheMu sync.RWMutex
)

// verifySchnorrSignature verifies a FROST Schnorr signature using the threshold library.
func verifySchnorrSignature(publicKey, messageHash, signature []byte) bool {
	if len(publicKey) != 32 || len(messageHash) != 32 || len(signature) != 64 {
		return false
	}

	group := curve.Secp256k1{}

	// Cache LiftX result — square root is 80% of verify cost
	var pkKey [32]byte
	copy(pkKey[:], publicKey)

	liftXCacheMu.RLock()
	pubPoint, cached := liftXCache[pkKey]
	liftXCacheMu.RUnlock()

	if !cached {
		var err error
		pubPoint, err = group.LiftX(publicKey)
		if err != nil {
			return false
		}
		liftXCacheMu.Lock()
		if len(liftXCache) < 1024 { // bounded cache
			liftXCache[pkKey] = pubPoint
		}
		liftXCacheMu.Unlock()
	}

	var sig sign.Signature
	if err := sig.UnmarshalBinary(group, signature); err != nil {
		return false
	}

	return sig.Verify(pubPoint, messageHash)
}
