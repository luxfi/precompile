// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graph

import (
	"github.com/luxfi/geth/common"
)

// PrecompileRegistry maps precompile addresses to their implementations
// across all Lux chains.
//
// Address Ranges:
// - 0x0001-0x00FF: Standard EVM precompiles (ECRECOVER, SHA256, etc.)
// - 0x0100-0x01FF: Warp/Teleport messaging
// - 0x0200-0x02FF: Chain-specific config (Subnet-EVM style)
// - 0x0300-0x03FF: AI/ML operations
// - 0x0400-0x04FF: DEX operations (Uniswap v4 style)
// - 0x0500-0x05FF: Graph/Query layer
// - 0x0600-0x06FF: Post-quantum cryptography
// - 0x0700-0x07FF: Privacy/Encryption (FHE, ECIES, Ring)
// - 0x0800-0x08FF: Threshold signatures (FROST, CGGMP21, Ringtail)
// - 0x0900-0x09FF: ZK proofs (KZG, Groth16)
// - 0x0A00-0x0AFF: Reserved for future use

// Precompile address constants
const (
	// Standard EVM (0x01-0x09) - already in EVM
	// 0x01 = ECRECOVER
	// 0x02 = SHA256
	// 0x03 = RIPEMD160
	// 0x04 = IDENTITY
	// 0x05 = MODEXP
	// 0x06 = ECADD (BN254)
	// 0x07 = ECMUL (BN254)
	// 0x08 = ECPAIRING (BN254)
	// 0x09 = BLAKE2F

	// BLS12-381 (0x0B-0x11) - EIP-2537
	BLS12381G1AddAddress    = "0x000b"
	BLS12381G1MulAddress    = "0x000c"
	BLS12381G1MSMAddress    = "0x000d"
	BLS12381G2AddAddress    = "0x000e"
	BLS12381G2MulAddress    = "0x000f"
	BLS12381G2MSMAddress    = "0x0010"
	BLS12381PairingAddress  = "0x0011"

	// Warp/Teleport (0x0100)
	WarpAddress = "0x0100"

	// Subnet-EVM Config (0x0200-0x02FF)
	DeployerAllowListAddress = "0x0200000000000000000000000000000000000001"
	TxAllowListAddress       = "0x0200000000000000000000000000000000000002"
	FeeManagerAddress        = "0x0200000000000000000000000000000000000003"
	NativeMinterAddress      = "0x0200000000000000000000000000000000000004"
	RewardManagerAddress     = "0x0200000000000000000000000000000000000005"

	// AI/ML (0x0300-0x03FF)
	AIMiningAddress     = "0x0300"
	NVTrustAddress      = "0x0301"
	ModelRegistryAddress = "0x0302"

	// DEX (0x0400-0x04FF) - See dex/types.go for full list
	PoolManagerAddress      = "0x0400"
	SwapRouterAddress       = "0x0401"
	HooksRegistryAddress    = "0x0402"
	FlashLoanAddress        = "0x0403"
	LendingPoolAddress      = "0x0410"
	PerpetualEngineAddress  = "0x0420"
	LiquidVaultAddress      = "0x0430"
	TeleportBridgeAddress   = "0x0440"

	// Graph/Query (0x0500-0x05FF)
	GraphQLQueryAddress     = "0x0500"
	GraphSubscribeAddress   = "0x0501"
	GraphCacheAddress       = "0x0502"

	// Post-Quantum Crypto (0x0600-0x06FF)
	MLDSAAddress        = "0x0600" // ML-DSA signatures
	MLKEMAddress        = "0x0601" // ML-KEM key encapsulation
	SLHDSAAddress       = "0x0602" // Stateless hash-based signatures
	PQCryptoAddress     = "0x0603" // Multi-PQ operations
	QuasarAddress       = "0x0604" // Quantum consensus

	// Privacy/Encryption (0x0700-0x07FF)
	FHEAddress          = "0x0700" // Fully Homomorphic Encryption
	ECIESAddress        = "0x0701" // Elliptic Curve Integrated Encryption
	RingAddress         = "0x0702" // Ring signatures
	HPKEAddress         = "0x0703" // Hybrid Public Key Encryption

	// Threshold Signatures (0x0800-0x08FF)
	FROSTAddress        = "0x0800" // Schnorr threshold signatures
	CGGMP21Address      = "0x0801" // ECDSA threshold signatures
	RingtailAddress     = "0x0802" // Threshold lattice signatures

	// ZK Proofs (0x0900-0x09FF)
	KZG4844Address      = "0x0900" // KZG commitments (EIP-4844)
	Groth16Address      = "0x0901" // Groth16 verifier
	PlonkAddress        = "0x0902" // PLONK verifier

	// secp256r1 (P-256) - EIP-7212
	P256VerifyAddress   = "0x0a00"
)

// ChainPrecompiles defines which precompiles are enabled for each chain
var ChainPrecompiles = map[string][]string{
	// A-Chain (Asset Chain) - Token standards, NFTs
	"A": {
		WarpAddress,
		GraphQLQueryAddress, // Query unified layer
	},

	// B-Chain (Bridge Chain) - Cross-chain messaging
	"B": {
		WarpAddress,
		TeleportBridgeAddress,
		GraphQLQueryAddress,
	},

	// C-Chain (Contract Chain) - Full EVM with all precompiles
	"C": {
		// All BLS12-381
		BLS12381G1AddAddress, BLS12381G1MulAddress, BLS12381G1MSMAddress,
		BLS12381G2AddAddress, BLS12381G2MulAddress, BLS12381G2MSMAddress,
		BLS12381PairingAddress,
		// Warp
		WarpAddress,
		// Subnet config
		DeployerAllowListAddress, TxAllowListAddress, FeeManagerAddress,
		NativeMinterAddress, RewardManagerAddress,
		// AI
		AIMiningAddress, NVTrustAddress,
		// DEX
		PoolManagerAddress, SwapRouterAddress, HooksRegistryAddress, FlashLoanAddress,
		LendingPoolAddress, PerpetualEngineAddress, LiquidVaultAddress, TeleportBridgeAddress,
		// Graph
		GraphQLQueryAddress, GraphSubscribeAddress,
		// PQ Crypto
		MLDSAAddress, MLKEMAddress, SLHDSAAddress, PQCryptoAddress,
		// Privacy
		FHEAddress, ECIESAddress, RingAddress, HPKEAddress,
		// Threshold
		FROSTAddress, CGGMP21Address, RingtailAddress,
		// ZK
		KZG4844Address, Groth16Address, PlonkAddress,
		// P-256
		P256VerifyAddress,
	},

	// D-Chain (DEX Chain) - Optimized for trading
	"D": {
		WarpAddress,
		// Full DEX suite
		PoolManagerAddress, SwapRouterAddress, HooksRegistryAddress, FlashLoanAddress,
		LendingPoolAddress, PerpetualEngineAddress, LiquidVaultAddress, TeleportBridgeAddress,
		// Graph for queries
		GraphQLQueryAddress,
	},

	// G-Chain (Graph Chain) - Query layer (read-only)
	"G": {
		GraphQLQueryAddress, GraphSubscribeAddress, GraphCacheAddress,
	},

	// K-Chain (Keys Chain) - Key management and cryptography
	"K": {
		WarpAddress,
		// PQ Crypto
		MLDSAAddress, MLKEMAddress, SLHDSAAddress, PQCryptoAddress, QuasarAddress,
		// Privacy
		FHEAddress, ECIESAddress, RingAddress, HPKEAddress,
		// Threshold
		FROSTAddress, CGGMP21Address, RingtailAddress,
		// P-256
		P256VerifyAddress,
		// Graph
		GraphQLQueryAddress,
	},

	// P-Chain (Platform Chain) - Validator and subnet management
	"P": {
		WarpAddress,
		RewardManagerAddress,
	},

	// Q-Chain (Quantum Chain) - Quantum-safe operations
	"Q": {
		WarpAddress,
		// Full PQ suite
		MLDSAAddress, MLKEMAddress, SLHDSAAddress, PQCryptoAddress, QuasarAddress,
		// Threshold
		RingtailAddress,
		// Graph
		GraphQLQueryAddress,
	},

	// T-Chain (Token Chain) - Token transfers and standards
	"T": {
		WarpAddress,
		TeleportBridgeAddress,
		GraphQLQueryAddress,
	},

	// X-Chain (Exchange Chain) - UTXO-based transfers
	"X": {
		WarpAddress,
	},

	// Z-Chain (Zoo Chain) - Application chain
	"Z": {
		WarpAddress,
		// DEX
		PoolManagerAddress, SwapRouterAddress,
		// AI
		AIMiningAddress,
		// Graph
		GraphQLQueryAddress,
	},
}

// PrecompileInfo contains metadata about a precompile
type PrecompileInfo struct {
	Address     string
	Name        string
	Description string
	GasBase     uint64
	Chains      []string
}

// AllPrecompiles lists all available precompiles with their metadata
var AllPrecompiles = []PrecompileInfo{
	// BLS12-381
	{BLS12381G1AddAddress, "BLS12381_G1ADD", "BLS12-381 G1 point addition", 500, []string{"C"}},
	{BLS12381G1MulAddress, "BLS12381_G1MUL", "BLS12-381 G1 scalar multiplication", 12000, []string{"C"}},
	{BLS12381PairingAddress, "BLS12381_PAIRING", "BLS12-381 pairing check", 115000, []string{"C"}},

	// Warp
	{WarpAddress, "WARP", "Cross-chain message verification", 50000, []string{"A", "B", "C", "D", "G", "K", "P", "Q", "T", "X", "Z"}},

	// AI
	{AIMiningAddress, "AI_MINING", "AI model verification and rewards", 100000, []string{"C", "Z"}},

	// DEX
	{PoolManagerAddress, "POOL_MANAGER", "Uniswap v4-style pool manager", 50000, []string{"C", "D"}},
	{SwapRouterAddress, "SWAP_ROUTER", "Optimized swap routing", 10000, []string{"C", "D", "Z"}},
	{PerpetualEngineAddress, "PERP_ENGINE", "Perpetual futures engine", 25000, []string{"C", "D"}},

	// Graph
	{GraphQLQueryAddress, "GRAPHQL_QUERY", "Unified G-Chain GraphQL queries", 5000, []string{"A", "B", "C", "D", "G", "K", "Q", "T", "Z"}},

	// PQ Crypto
	{MLDSAAddress, "ML_DSA", "NIST ML-DSA post-quantum signatures", 50000, []string{"C", "K", "Q"}},
	{MLKEMAddress, "ML_KEM", "NIST ML-KEM key encapsulation", 25000, []string{"C", "K", "Q"}},
	{QuasarAddress, "QUASAR", "Quantum consensus verification", 100000, []string{"K", "Q"}},

	// Privacy
	{FHEAddress, "FHE", "Fully Homomorphic Encryption operations", 500000, []string{"C", "K"}},
	{RingAddress, "RING", "Ring signature generation/verification", 50000, []string{"C", "K"}},

	// Threshold
	{FROSTAddress, "FROST", "Schnorr threshold signatures", 25000, []string{"C", "K"}},
	{CGGMP21Address, "CGGMP21", "ECDSA threshold signatures", 50000, []string{"C", "K"}},
	{RingtailAddress, "RINGTAIL", "Threshold lattice signatures", 75000, []string{"C", "K", "Q"}},

	// ZK
	{KZG4844Address, "KZG_4844", "EIP-4844 KZG commitment verification", 50000, []string{"C"}},
}

// GetPrecompileAddress returns the address for a precompile by name
func GetPrecompileAddress(name string) common.Address {
	for _, p := range AllPrecompiles {
		if p.Name == name {
			return common.HexToAddress(p.Address)
		}
	}
	return common.Address{}
}

// GetChainPrecompiles returns all precompile addresses for a chain
func GetChainPrecompiles(chainLetter string) []common.Address {
	addrs, ok := ChainPrecompiles[chainLetter]
	if !ok {
		return nil
	}

	result := make([]common.Address, len(addrs))
	for i, addr := range addrs {
		result[i] = common.HexToAddress(addr)
	}
	return result
}

// IsPrecompileEnabled checks if a precompile is enabled for a chain
func IsPrecompileEnabled(chainLetter string, precompileAddr common.Address) bool {
	addrs := ChainPrecompiles[chainLetter]
	addrHex := precompileAddr.Hex()

	for _, addr := range addrs {
		if common.HexToAddress(addr) == precompileAddr {
			return true
		}
		// Also check lowercase
		if addr == addrHex || addr == precompileAddr.String() {
			return true
		}
	}
	return false
}
