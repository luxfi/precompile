// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package registry

import (
	"github.com/luxfi/geth/common"
)

// ============================================================================
// PRECOMPILE ADDRESS SCHEME - Aligned with LP Numbering (LP-0099)
// ============================================================================
//
// All Lux-native precompiles live in a 64K address block starting at:
//   BASE = 0x10000
//
// Each address is BASE + selector where the 16-bit selector encodes:
//   0x P C II
//      │ │ └┴─ Item/function (8 bits, 256 items per family×chain)
//      │ └──── Chain slot    (4 bits, 16 chains max, 11 assigned)
//      └────── Family page   (4 bits, aligned with LP-Pxxx)
//
// P nibble = LP range first digit:
//   P=2 → LP-2xxx (Q-Chain, PQ Identity)
//   P=3 → LP-3xxx (C-Chain, EVM/Crypto)
//   P=4 → LP-4xxx (Z-Chain, Privacy/ZK)
//   P=5 → LP-5xxx (T-Chain, Threshold/MPC)
//   P=6 → LP-6xxx (B-Chain, Bridges)
//   P=7 → LP-7xxx (A-Chain, AI)
//   P=9 → LP-9xxx (DEX/Markets)
//
// C nibble = Chain slot:
//   C=0 → P-Chain
//   C=1 → X-Chain
//   C=2 → C-Chain (main EVM)
//   C=3 → Q-Chain
//   C=4 → A-Chain
//   C=5 → B-Chain
//   C=6 → Z-Chain
//   C=7 → M-Chain (reserved)
//   C=8 → Zoo
//   C=9 → Hanzo
//   C=A → SPC
//
// Example: FROST on C-Chain = P=5 (Threshold), C=2 (C-Chain), II=01
//          Address = 0x10000 + 0x5201 = 0x15201

const (
	// =========================================================================
	// STANDARD EVM (0x01-0x11) - Native to EVM, not in our range
	// =========================================================================
	// 0x01 = ECRECOVER
	// 0x02 = SHA256
	// 0x03 = RIPEMD160
	// 0x04 = IDENTITY
	// 0x05 = MODEXP
	// 0x06 = ECADD (BN254)
	// 0x07 = ECMUL (BN254)
	// 0x08 = ECPAIRING (BN254)
	// 0x09 = BLAKE2F
	// 0x0A = KZG Point Evaluation (EIP-4844)
	// 0x0B-0x11 = BLS12-381 (EIP-2537)

	// BLS12-381 (0x0B-0x11) - EIP-2537
	BLS12381G1AddAddress   = "0x000b"
	BLS12381G1MulAddress   = "0x000c"
	BLS12381G1MSMAddress   = "0x000d"
	BLS12381G2AddAddress   = "0x000e"
	BLS12381G2MulAddress   = "0x000f"
	BLS12381G2MSMAddress   = "0x0010"
	BLS12381PairingAddress = "0x0011"

	// secp256r1 (P-256) - EIP-7212 (passkeys/WebAuthn)
	P256VerifyAddress = "0x0100"

	// =========================================================================
	// PAGE 2: PQ IDENTITY (0x2CII) → LP-2xxx
	// =========================================================================

	// Post-Quantum Signatures (II = 0x01-0x0F)
	MLDSACChain  = "0x12201" // C-Chain ML-DSA
	MLDSAQChain  = "0x12301" // Q-Chain ML-DSA
	MLKEMCChain  = "0x12202" // C-Chain ML-KEM
	MLKEMQChain  = "0x12302" // Q-Chain ML-KEM
	SLHDSACChain = "0x12203" // C-Chain SLH-DSA
	SLHDSAQChain = "0x12303" // Q-Chain SLH-DSA
	FalconCChain = "0x12204" // C-Chain Falcon
	FalconQChain = "0x12304" // Q-Chain Falcon

	// PQ Key Exchange (II = 0x10-0x1F)
	KyberCChain = "0x12210" // C-Chain Kyber
	KyberQChain = "0x12310" // Q-Chain Kyber
	NTRUCChain  = "0x12211" // C-Chain NTRU
	NTRUQChain  = "0x12311" // Q-Chain NTRU

	// Hybrid Modes (II = 0x20-0x2F)
	HybridSignCChain = "0x12220" // C-Chain ECDSA+ML-DSA
	HybridSignQChain = "0x12320" // Q-Chain ECDSA+ML-DSA
	HybridKEMCChain  = "0x12221" // C-Chain X25519+Kyber
	HybridKEMQChain  = "0x12321" // Q-Chain X25519+Kyber

	// =========================================================================
	// PAGE 3: EVM/CRYPTO (0x3CII) → LP-3xxx
	// =========================================================================

	// Hashing (II = 0x01-0x0F)
	Poseidon2CChain    = "0x13201" // C-Chain Poseidon2
	Poseidon2ZChain    = "0x13601" // Z-Chain Poseidon2
	Poseidon2SpongeCCh = "0x13202" // C-Chain Poseidon2Sponge
	Blake3CChain       = "0x13203" // C-Chain Blake3
	Blake3ZChain       = "0x13603" // Z-Chain Blake3
	PedersenCChain     = "0x13204" // C-Chain Pedersen
	PedersenZChain     = "0x13604" // Z-Chain Pedersen
	MiMCCChain         = "0x13205" // C-Chain MiMC
	RescueCChain       = "0x13206" // C-Chain Rescue

	// Classical Signatures (II = 0x10-0x1F)
	ECDSACChain   = "0x13210" // Extended ECDSA
	Ed25519CChain = "0x13211" // Ed25519
	BLS381CChain  = "0x13212" // BLS12-381
	SchnorrCChain = "0x13213" // Schnorr (BIP-340)

	// Encryption (II = 0x20-0x2F)
	AESGCMCChain   = "0x13220" // AES-GCM
	ChaCha20CChain = "0x13221" // ChaCha20-Poly1305
	HPKECChain     = "0x13222" // HPKE
	ECIESCChain    = "0x13223" // ECIES

	// =========================================================================
	// PAGE 4: PRIVACY/ZK (0x4CII) → LP-4xxx
	// =========================================================================

	// SNARKs (II = 0x01-0x0F)
	Groth16CChain = "0x14201" // C-Chain Groth16
	Groth16ZChain = "0x14601" // Z-Chain Groth16
	PLONKCChain   = "0x14202" // C-Chain PLONK
	PLONKZChain   = "0x14602" // Z-Chain PLONK
	fflonkCChain  = "0x14203" // C-Chain fflonk
	fflonkZChain  = "0x14603" // Z-Chain fflonk
	Halo2CChain   = "0x14204" // C-Chain Halo2
	Halo2ZChain   = "0x14604" // Z-Chain Halo2
	NovaCChain    = "0x14205" // C-Chain Nova
	NovaZChain    = "0x14605" // Z-Chain Nova

	// STARKs (II = 0x10-0x1F)
	STARKCChain       = "0x14210" // C-Chain STARK
	STARKZChain       = "0x14610" // Z-Chain STARK
	STARKRecursiveCCh = "0x14211" // C-Chain STARKRecursive
	STARKRecursiveZCh = "0x14611" // Z-Chain STARKRecursive
	STARKBatchCChain  = "0x14212" // C-Chain STARKBatch
	STARKBatchZChain  = "0x14612" // Z-Chain STARKBatch
	STARKReceiptsCCh  = "0x1421F" // C-Chain STARKReceipts
	STARKReceiptsZCh  = "0x1461F" // Z-Chain STARKReceipts

	// Commitments (II = 0x20-0x2F)
	KZGCChain = "0x14220" // C-Chain KZG
	KZGZChain = "0x14620" // Z-Chain KZG
	IPACChain = "0x14221" // C-Chain IPA
	IPAZChain = "0x14621" // Z-Chain IPA
	FRICChain = "0x14222" // C-Chain FRI
	FRIZChain = "0x14622" // Z-Chain FRI

	// Privacy Primitives (II = 0x30-0x3F)
	RangeProofCChain  = "0x14230" // C-Chain Bulletproofs
	RangeProofZChain  = "0x14630" // Z-Chain Bulletproofs
	NullifierCChain   = "0x14231" // C-Chain Nullifier
	NullifierZChain   = "0x14631" // Z-Chain Nullifier
	CommitmentCChain  = "0x14232" // C-Chain Commitment
	CommitmentZChain  = "0x14632" // Z-Chain Commitment
	MerkleProofCChain = "0x14233" // C-Chain MerkleProof
	MerkleProofZChain = "0x14633" // Z-Chain MerkleProof

	// FHE (II = 0x40-0x4F)
	FHECChain         = "0x14240" // C-Chain FHE
	FHEZChain         = "0x14640" // Z-Chain FHE
	TFHECChain        = "0x14241" // C-Chain TFHE
	TFHEZChain        = "0x14641" // Z-Chain TFHE
	CKKSCChain        = "0x14242" // C-Chain CKKS
	CKKSZChain        = "0x14642" // Z-Chain CKKS
	BGVCChain         = "0x14243" // C-Chain BGV
	BGVZChain         = "0x14643" // Z-Chain BGV
	GatewayCChain     = "0x14244" // C-Chain Gateway
	GatewayZChain     = "0x14644" // Z-Chain Gateway
	TaskManagerCChain = "0x14245" // C-Chain TaskManager
	TaskManagerZChain = "0x14645" // Z-Chain TaskManager

	// =========================================================================
	// PAGE 5: THRESHOLD/MPC (0x5CII) → LP-5xxx
	// =========================================================================

	// Threshold Signatures (II = 0x01-0x0F)
	FROSTCChain     = "0x15201" // C-Chain FROST
	FROSTQChain     = "0x15301" // Q-Chain FROST
	CGGMP21CChain   = "0x15202" // C-Chain CGGMP21
	CGGMP21QChain   = "0x15302" // Q-Chain CGGMP21
	RingtailCChain  = "0x15203" // C-Chain Ringtail
	RingtailQChain  = "0x15303" // Q-Chain Ringtail
	DoernerCChain   = "0x15204" // C-Chain Doerner
	DoernerQChain   = "0x15304" // Q-Chain Doerner
	BLSThreshCChain = "0x15205" // C-Chain BLS Threshold
	BLSThreshQChain = "0x15305" // Q-Chain BLS Threshold

	// Secret Sharing (II = 0x10-0x1F)
	LSSCChain     = "0x15210" // C-Chain LSS
	LSSQChain     = "0x15310" // Q-Chain LSS
	ShamirCChain  = "0x15211" // C-Chain Shamir
	ShamirQChain  = "0x15311" // Q-Chain Shamir
	FeldmanCChain = "0x15212" // C-Chain Feldman
	FeldmanQChain = "0x15312" // Q-Chain Feldman

	// DKG/Custody (II = 0x20-0x2F)
	DKGCChain      = "0x15220" // C-Chain DKG
	DKGQChain      = "0x15320" // Q-Chain DKG
	RefreshCChain  = "0x15221" // C-Chain Key Refresh
	RefreshQChain  = "0x15321" // Q-Chain Key Refresh
	RecoveryCChain = "0x15222" // C-Chain Recovery
	RecoveryQChain = "0x15322" // Q-Chain Recovery

	// =========================================================================
	// PAGE 6: BRIDGES (0x6CII) → LP-6xxx
	// =========================================================================

	// Warp Messaging (II = 0x01-0x0F)
	WarpSendCChain     = "0x16201" // C-Chain WarpSend
	WarpSendBChain     = "0x16501" // B-Chain WarpSend
	WarpReceiveCChain  = "0x16202" // C-Chain WarpReceive
	WarpReceiveBChain  = "0x16502" // B-Chain WarpReceive
	WarpReceiptsCChain = "0x16203" // C-Chain WarpReceipts
	WarpReceiptsBChain = "0x16503" // B-Chain WarpReceipts

	// Token Bridges (II = 0x10-0x1F)
	BridgeCChain       = "0x16210" // C-Chain Bridge
	BridgeBChain       = "0x16510" // B-Chain Bridge
	TeleportCChain     = "0x16211" // C-Chain Teleport
	TeleportBChain     = "0x16511" // B-Chain Teleport
	BridgeRouterCChain = "0x16212" // C-Chain BridgeRouter
	BridgeRouterBChain = "0x16512" // B-Chain BridgeRouter

	// Fee Collection (II = 0x20-0x2F)
	FeeCollectCChain = "0x16220" // C-Chain FeeCollect
	FeeCollectBChain = "0x16520" // B-Chain FeeCollect
	FeeGovCChain     = "0x16221" // C-Chain FeeGov
	FeeGovBChain     = "0x16521" // B-Chain FeeGov

	// =========================================================================
	// PAGE 7: AI (0x7CII) → LP-7xxx
	// =========================================================================

	// Attestation (II = 0x01-0x0F)
	GPUAttestCChain = "0x17201" // C-Chain GPU Attestation
	GPUAttestAChain = "0x17401" // A-Chain GPU Attestation
	GPUAttestHanzo  = "0x17901" // Hanzo GPU Attestation
	TEEVerifyCChain = "0x17202" // C-Chain TEE Verify
	TEEVerifyAChain = "0x17402" // A-Chain TEE Verify
	NVTrustCChain   = "0x17203" // C-Chain NVTrust
	NVTrustAChain   = "0x17403" // A-Chain NVTrust
	SGXAttestCChain = "0x17204" // C-Chain SGX Attestation
	SGXAttestAChain = "0x17404" // A-Chain SGX Attestation
	TDXAttestCChain = "0x17205" // C-Chain TDX Attestation
	TDXAttestAChain = "0x17405" // A-Chain TDX Attestation

	// Inference (II = 0x10-0x1F)
	InferenceCChain  = "0x17210" // C-Chain Inference
	InferenceAChain  = "0x17410" // A-Chain Inference
	InferenceHanzo   = "0x17910" // Hanzo Inference
	ProvenanceCChain = "0x17211" // C-Chain Provenance
	ProvenanceAChain = "0x17411" // A-Chain Provenance
	ModelHashCChain  = "0x17212" // C-Chain ModelHash
	ModelHashAChain  = "0x17412" // A-Chain ModelHash

	// Mining (II = 0x20-0x2F)
	SessionCChain   = "0x17220" // C-Chain Session
	SessionAChain   = "0x17420" // A-Chain Session
	SessionHanzo    = "0x17920" // Hanzo Session
	HeartbeatCChain = "0x17221" // C-Chain Heartbeat
	HeartbeatAChain = "0x17421" // A-Chain Heartbeat
	RewardCChain    = "0x17222" // C-Chain Reward
	RewardAChain    = "0x17422" // A-Chain Reward

	// =========================================================================
	// PAGE 9: DEX/MARKETS (0x9CII) → LP-9xxx
	// =========================================================================

	// Core AMM (II = 0x01-0x0F)
	PoolManagerCChain = "0x19201" // C-Chain PoolManager
	PoolManagerZoo    = "0x19801" // Zoo PoolManager
	SwapRouterCChain  = "0x19202" // C-Chain SwapRouter
	SwapRouterZoo     = "0x19802" // Zoo SwapRouter
	HooksRegCChain    = "0x19203" // C-Chain HooksRegistry
	HooksRegZoo       = "0x19803" // Zoo HooksRegistry
	FlashLoanCChain   = "0x19204" // C-Chain FlashLoan
	FlashLoanZoo      = "0x19804" // Zoo FlashLoan

	// Orderbook (II = 0x10-0x1F)
	CLOBCChain     = "0x19210" // C-Chain CLOB
	CLOBZoo        = "0x19810" // Zoo CLOB
	OrderbookCCh   = "0x19211" // C-Chain Orderbook
	OrderbookZoo   = "0x19811" // Zoo Orderbook
	MatchingCChain = "0x19212" // C-Chain Matching
	MatchingZoo    = "0x19812" // Zoo Matching

	// Oracle (II = 0x20-0x2F)
	OracleHubCChain = "0x19220" // C-Chain OracleHub
	OracleHubZoo    = "0x19820" // Zoo OracleHub
	TWAPCChain      = "0x19221" // C-Chain TWAP
	TWAPZoo         = "0x19821" // Zoo TWAP
	FastPriceCChain = "0x19222" // C-Chain FastPrice
	FastPriceZoo    = "0x19822" // Zoo FastPrice

	// Perps (II = 0x30-0x3F)
	VaultCChain     = "0x19230" // C-Chain Vault
	VaultZoo        = "0x19830" // Zoo Vault
	PosRouterCChain = "0x19231" // C-Chain PositionRouter
	PosRouterZoo    = "0x19831" // Zoo PositionRouter
	PriceFeedCChain = "0x19232" // C-Chain PriceFeed
	PriceFeedZoo    = "0x19832" // Zoo PriceFeed
)

// PrecompileAddress calculates address from (P, C, II) nibbles
// P = Family page (aligned with LP-Pxxx), C = Chain slot, II = Item
func PrecompileAddress(p, c, ii uint8) common.Address {
	if p > 15 || c > 15 {
		return common.Address{}
	}
	selector := (uint32(p) << 12) | (uint32(c) << 8) | uint32(ii)
	addr := uint32(0x10000) + selector
	return common.HexToAddress("0x" + formatUint32AsHex(addr))
}

func formatUint32AsHex(v uint32) string {
	hex := "0123456789abcdef"
	result := make([]byte, 0, 8)
	for i := 28; i >= 0; i -= 4 {
		nibble := (v >> i) & 0xF
		result = append(result, hex[nibble])
	}
	// Trim leading zeros but keep at least one
	start := 0
	for start < len(result)-1 && result[start] == '0' {
		start++
	}
	return string(result[start:])
}

// ChainSlot returns the C-nibble for a chain name
func ChainSlot(chain string) uint8 {
	switch chain {
	case "P", "p":
		return 0
	case "X", "x":
		return 1
	case "C", "c":
		return 2
	case "Q", "q":
		return 3
	case "A", "a":
		return 4
	case "B", "b":
		return 5
	case "Z", "z":
		return 6
	case "M", "m":
		return 7
	case "Zoo", "zoo":
		return 8
	case "Hanzo", "hanzo":
		return 9
	case "SPC", "spc":
		return 0xA
	default:
		return 0xFF
	}
}

// FamilyPage returns the P-nibble for a family name (aligned with LP-Pxxx)
func FamilyPage(family string) uint8 {
	switch family {
	case "PQ", "pq":
		return 2 // LP-2xxx
	case "EVM", "evm", "Crypto", "crypto":
		return 3 // LP-3xxx
	case "Privacy", "privacy", "ZK", "zk":
		return 4 // LP-4xxx
	case "Threshold", "threshold", "MPC", "mpc":
		return 5 // LP-5xxx
	case "Bridge", "bridge":
		return 6 // LP-6xxx
	case "AI", "ai":
		return 7 // LP-7xxx
	case "DEX", "dex", "Markets", "markets":
		return 9 // LP-9xxx
	default:
		return 0xFF
	}
}

// ChainPrecompiles defines which precompiles are enabled for each chain
var ChainPrecompiles = map[string][]string{
	// C-Chain (main EVM) - all families enabled
	"C": {
		// BLS12-381 (standard EVM)
		BLS12381G1AddAddress, BLS12381G1MulAddress, BLS12381G1MSMAddress,
		BLS12381G2AddAddress, BLS12381G2MulAddress, BLS12381G2MSMAddress,
		BLS12381PairingAddress,
		// P-256
		P256VerifyAddress,
		// PQ (P=2)
		MLDSACChain, MLKEMCChain, SLHDSACChain, HybridSignCChain,
		// Crypto (P=3)
		Poseidon2CChain, Blake3CChain, PedersenCChain, SchnorrCChain, ECIESCChain,
		// Privacy/ZK (P=4)
		Groth16CChain, PLONKCChain, STARKCChain, KZGCChain, FHECChain, RangeProofCChain,
		// Threshold (P=5)
		FROSTCChain, CGGMP21CChain, RingtailCChain, LSSCChain, DKGCChain,
		// Bridges (P=6)
		WarpSendCChain, WarpReceiveCChain, BridgeCChain, TeleportCChain,
		// AI (P=7)
		GPUAttestCChain, TEEVerifyCChain, InferenceCChain, SessionCChain,
		// DEX (P=9)
		PoolManagerCChain, SwapRouterCChain, CLOBCChain, OracleHubCChain, VaultCChain,
	},

	// Q-Chain (Quantum) - PQ and Threshold focused
	"Q": {
		// PQ (P=2)
		MLDSAQChain, MLKEMQChain, SLHDSAQChain, FalconQChain, KyberQChain, HybridSignQChain,
		// Threshold (P=5)
		FROSTQChain, CGGMP21QChain, RingtailQChain, LSSQChain, DKGQChain,
	},

	// A-Chain (AI) - AI focused
	"A": {
		// AI (P=7)
		GPUAttestAChain, TEEVerifyAChain, NVTrustAChain, SGXAttestAChain, TDXAttestAChain,
		InferenceAChain, ProvenanceAChain, ModelHashAChain,
		SessionAChain, HeartbeatAChain, RewardAChain,
		// Bridges (P=6) - for cross-chain AI
		WarpSendCChain, WarpReceiveCChain,
	},

	// B-Chain (Bridge) - Bridge focused
	"B": {
		// Bridges (P=6)
		WarpSendBChain, WarpReceiveBChain, WarpReceiptsBChain,
		BridgeBChain, TeleportBChain, BridgeRouterBChain,
		FeeCollectBChain, FeeGovBChain,
	},

	// Z-Chain (Privacy) - ZK/Privacy focused
	"Z": {
		// Crypto (P=3)
		Poseidon2ZChain, Blake3ZChain, PedersenZChain,
		// Privacy/ZK (P=4)
		Groth16ZChain, PLONKZChain, fflonkZChain, Halo2ZChain, NovaZChain,
		STARKZChain, STARKRecursiveZCh, STARKBatchZChain,
		KZGZChain, IPAZChain, FRIZChain,
		RangeProofZChain, NullifierZChain, CommitmentZChain, MerkleProofZChain,
		FHEZChain, TFHEZChain, CKKSZChain, GatewayZChain,
	},

	// Zoo - DEX focused
	"Zoo": {
		// DEX (P=9)
		PoolManagerZoo, SwapRouterZoo, HooksRegZoo, FlashLoanZoo,
		CLOBZoo, OrderbookZoo, MatchingZoo,
		OracleHubZoo, TWAPZoo, FastPriceZoo,
		VaultZoo, PosRouterZoo, PriceFeedZoo,
		// Bridges for cross-chain trading
		WarpSendCChain, WarpReceiveCChain,
	},

	// Hanzo - AI focused
	"Hanzo": {
		// AI (P=7)
		GPUAttestHanzo, InferenceHanzo, SessionHanzo,
		// Bridges for cross-chain AI
		WarpSendCChain, WarpReceiveCChain,
	},

	// P-Chain (Platform) - Minimal
	"P": {
		WarpSendCChain, WarpReceiveCChain,
	},

	// X-Chain (Exchange) - UTXO
	"X": {
		WarpSendCChain, WarpReceiveCChain,
	},
}

// PrecompileInfo contains metadata about a precompile
type PrecompileInfo struct {
	Address     string
	Name        string
	Description string
	GasBase     uint64
	Chains      []string
	LPRange     string // LP-Pxxx range alignment
}

// AllPrecompiles lists all available precompiles with their metadata
var AllPrecompiles = []PrecompileInfo{
	// BLS12-381 (standard EVM)
	{BLS12381G1AddAddress, "BLS12381_G1ADD", "BLS12-381 G1 point addition", 500, []string{"C"}, "EIP-2537"},
	{BLS12381G1MulAddress, "BLS12381_G1MUL", "BLS12-381 G1 scalar multiplication", 12000, []string{"C"}, "EIP-2537"},
	{BLS12381PairingAddress, "BLS12381_PAIRING", "BLS12-381 pairing check", 115000, []string{"C"}, "EIP-2537"},

	// P-256
	{P256VerifyAddress, "P256_VERIFY", "secp256r1/P-256 signature verification", 3450, []string{"C"}, "EIP-7212"},

	// PQ Identity (P=2) → LP-2xxx
	{MLDSACChain, "ML_DSA", "NIST ML-DSA post-quantum signatures", 50000, []string{"C", "Q"}, "LP-2xxx"},
	{MLKEMCChain, "ML_KEM", "NIST ML-KEM key encapsulation", 25000, []string{"C", "Q"}, "LP-2xxx"},
	{SLHDSACChain, "SLH_DSA", "NIST SLH-DSA hash-based signatures", 75000, []string{"C", "Q"}, "LP-2xxx"},
	{HybridSignCChain, "HYBRID_SIGN", "ECDSA+ML-DSA hybrid signatures", 75000, []string{"C", "Q"}, "LP-2xxx"},

	// EVM/Crypto (P=3) → LP-3xxx
	{Poseidon2CChain, "POSEIDON2", "ZK-friendly Poseidon2 hash", 20000, []string{"C", "Z"}, "LP-3xxx"},
	{Blake3CChain, "BLAKE3", "High-performance Blake3 hash", 5000, []string{"C", "Z"}, "LP-3xxx"},
	{PedersenCChain, "PEDERSEN", "Pedersen commitment", 15000, []string{"C", "Z"}, "LP-3xxx"},
	{SchnorrCChain, "SCHNORR", "BIP-340 Schnorr signatures", 10000, []string{"C"}, "LP-3xxx"},
	{ECIESCChain, "ECIES", "Elliptic Curve Integrated Encryption", 25000, []string{"C"}, "LP-3xxx"},

	// Privacy/ZK (P=4) → LP-4xxx
	{Groth16CChain, "GROTH16", "Groth16 ZK proof verification", 150000, []string{"C", "Z"}, "LP-4xxx"},
	{PLONKCChain, "PLONK", "PLONK ZK proof verification", 175000, []string{"C", "Z"}, "LP-4xxx"},
	{STARKCChain, "STARK", "STARK proof verification", 200000, []string{"C", "Z"}, "LP-4xxx"},
	{KZGCChain, "KZG", "KZG polynomial commitments", 50000, []string{"C", "Z"}, "LP-4xxx"},
	{FHECChain, "FHE", "Fully Homomorphic Encryption", 500000, []string{"C", "Z"}, "LP-4xxx"},
	{RangeProofCChain, "RANGE_PROOF", "Bulletproof range proofs", 100000, []string{"C", "Z"}, "LP-4xxx"},

	// Threshold/MPC (P=5) → LP-5xxx
	{FROSTCChain, "FROST", "Schnorr threshold signatures", 25000, []string{"C", "Q"}, "LP-5xxx"},
	{CGGMP21CChain, "CGGMP21", "ECDSA threshold signatures", 50000, []string{"C", "Q"}, "LP-5xxx"},
	{RingtailCChain, "RINGTAIL", "Threshold lattice signatures (PQ)", 75000, []string{"C", "Q"}, "LP-5xxx"},
	{LSSCChain, "LSS", "Lux Secret Sharing", 10000, []string{"C", "Q"}, "LP-5xxx"},
	{DKGCChain, "DKG", "Distributed Key Generation", 100000, []string{"C", "Q"}, "LP-5xxx"},

	// Bridges (P=6) → LP-6xxx
	{WarpSendCChain, "WARP_SEND", "Cross-chain message send", 50000, []string{"C", "B", "A", "Zoo", "Hanzo", "P", "X"}, "LP-6xxx"},
	{WarpReceiveCChain, "WARP_RECEIVE", "Cross-chain message receive", 50000, []string{"C", "B", "A", "Zoo", "Hanzo", "P", "X"}, "LP-6xxx"},
	{BridgeCChain, "BRIDGE", "Token bridge operations", 75000, []string{"C", "B"}, "LP-6xxx"},
	{TeleportCChain, "TELEPORT", "Instant token teleport", 100000, []string{"C", "B"}, "LP-6xxx"},

	// AI (P=7) → LP-7xxx
	{GPUAttestCChain, "GPU_ATTEST", "GPU compute attestation", 100000, []string{"C", "A", "Hanzo"}, "LP-7xxx"},
	{TEEVerifyCChain, "TEE_VERIFY", "TEE attestation verification", 75000, []string{"C", "A"}, "LP-7xxx"},
	{NVTrustCChain, "NVTRUST", "NVIDIA trust attestation", 100000, []string{"C", "A"}, "LP-7xxx"},
	{InferenceCChain, "INFERENCE", "AI inference verification", 150000, []string{"C", "A", "Hanzo"}, "LP-7xxx"},
	{SessionCChain, "SESSION", "AI mining session management", 50000, []string{"C", "A", "Hanzo"}, "LP-7xxx"},

	// DEX/Markets (P=9) → LP-9xxx
	{PoolManagerCChain, "POOL_MANAGER", "Uniswap v4-style pool manager", 50000, []string{"C", "Zoo"}, "LP-9xxx"},
	{SwapRouterCChain, "SWAP_ROUTER", "Optimized swap routing", 10000, []string{"C", "Zoo"}, "LP-9xxx"},
	{CLOBCChain, "CLOB", "Central limit order book", 25000, []string{"C", "Zoo"}, "LP-9xxx"},
	{OracleHubCChain, "ORACLE_HUB", "Price oracle aggregation", 15000, []string{"C", "Zoo"}, "LP-9xxx"},
	{VaultCChain, "VAULT", "Perpetual futures vault", 50000, []string{"C", "Zoo"}, "LP-9xxx"},
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

	for _, addr := range addrs {
		if common.HexToAddress(addr) == precompileAddr {
			return true
		}
	}
	return false
}

// GetPrecompilesByFamily returns all precompiles for a family page
func GetPrecompilesByFamily(family string) []PrecompileInfo {
	page := FamilyPage(family)
	if page == 0xFF {
		return nil
	}

	lpRange := "LP-" + string('0'+page) + "xxx"
	var result []PrecompileInfo
	for _, p := range AllPrecompiles {
		if p.LPRange == lpRange {
			result = append(result, p)
		}
	}
	return result
}
