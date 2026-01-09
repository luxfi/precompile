// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package registry

import (
	"fmt"

	"github.com/luxfi/geth/common"
)

// ============================================================================
// PRECOMPILE ADDRESS SCHEME - Aligned with LP Numbering (LP-0099)
// ============================================================================
//
// All Lux-native precompiles use trailing-significant 20-byte addresses:
//   Format: 0x0000000000000000000000000000000000PCII
//
// The address ends with the 16-bit LP number (PCII) for easy identification.
// The selector encodes:
//   0x 0000...0000 P C II
//                  │ │ └┴─ Item/function (8 bits, 256 items per family×chain)
//                  │ └──── Chain slot    (4 bits, 16 chains max, 11 assigned)
//                  └────── Family page   (4 bits, aligned with LP-Pxxx)
//
// P nibble = LP range first digit:
//   P=2 → LP-2xxx (PQ Identity)
//   P=3 → LP-3xxx (EVM/Crypto)
//   P=4 → LP-4xxx (Privacy/ZK)
//   P=5 → LP-5xxx (Threshold/MPC)
//   P=6 → LP-6xxx (Bridges)
//   P=7 → LP-7xxx (AI)
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
// Example: FROST on C-Chain = P=5 (Threshold), C=2 (C-Chain), II=00
//          Address = 0x0000000000000000000000000000000000005200 (LP-5200)

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

	// BLS12-381 (0x0B-0x11) - EIP-2537 (standard EVM addresses)
	BLS12381G1AddAddress   = "0x000000000000000000000000000000000000000b"
	BLS12381G1MulAddress   = "0x000000000000000000000000000000000000000c"
	BLS12381G1MSMAddress   = "0x000000000000000000000000000000000000000d"
	BLS12381G2AddAddress   = "0x000000000000000000000000000000000000000e"
	BLS12381G2MulAddress   = "0x000000000000000000000000000000000000000f"
	BLS12381G2MSMAddress   = "0x0000000000000000000000000000000000000010"
	BLS12381PairingAddress = "0x0000000000000000000000000000000000000011"

	// secp256r1 (P-256) - EIP-7212 (passkeys/WebAuthn)
	P256VerifyAddress = "0x0000000000000000000000000000000000000100"

	// =========================================================================
	// PAGE 2: PQ IDENTITY (0x2CII) → LP-2xxx
	// =========================================================================

	// Post-Quantum Signatures (II = 0x00-0x0F)
	MLDSACChain  = "0x0000000000000000000000000000000000002200" // C-Chain ML-DSA (LP-2200)
	MLDSAQChain  = "0x0000000000000000000000000000000000002300" // Q-Chain ML-DSA (LP-2300)
	MLKEMCChain  = "0x0000000000000000000000000000000000002201" // C-Chain ML-KEM (LP-2201)
	MLKEMQChain  = "0x0000000000000000000000000000000000002301" // Q-Chain ML-KEM (LP-2301)
	SLHDSACChain = "0x0000000000000000000000000000000000002202" // C-Chain SLH-DSA (LP-2202)
	SLHDSAQChain = "0x0000000000000000000000000000000000002302" // Q-Chain SLH-DSA (LP-2302)
	FalconCChain = "0x0000000000000000000000000000000000002203" // C-Chain Falcon (LP-2203)
	FalconQChain = "0x0000000000000000000000000000000000002303" // Q-Chain Falcon (LP-2303)

	// PQ Key Exchange (II = 0x10-0x1F)
	KyberCChain = "0x0000000000000000000000000000000000002210" // C-Chain Kyber (LP-2210)
	KyberQChain = "0x0000000000000000000000000000000000002310" // Q-Chain Kyber (LP-2310)
	NTRUCChain  = "0x0000000000000000000000000000000000002211" // C-Chain NTRU (LP-2211)
	NTRUQChain  = "0x0000000000000000000000000000000000002311" // Q-Chain NTRU (LP-2311)

	// Hybrid Modes (II = 0x20-0x2F)
	HybridSignCChain = "0x0000000000000000000000000000000000002220" // C-Chain ECDSA+ML-DSA (LP-2220)
	HybridSignQChain = "0x0000000000000000000000000000000000002320" // Q-Chain ECDSA+ML-DSA (LP-2320)
	HybridKEMCChain  = "0x0000000000000000000000000000000000002221" // C-Chain X25519+Kyber (LP-2221)
	HybridKEMQChain  = "0x0000000000000000000000000000000000002321" // Q-Chain X25519+Kyber (LP-2321)

	// =========================================================================
	// PAGE 3: EVM/CRYPTO (0x3CII) → LP-3xxx
	// =========================================================================

	// Hashing (II = 0x00-0x0F)
	Poseidon2CChain    = "0x3200000000000000000000000000000000000000" // C-Chain Poseidon2
	Poseidon2ZChain    = "0x3600000000000000000000000000000000000000" // Z-Chain Poseidon2
	Poseidon2SpongeCCh = "0x3201000000000000000000000000000000000000" // C-Chain Poseidon2Sponge
	Blake3CChain       = "0x3202000000000000000000000000000000000000" // C-Chain Blake3
	Blake3ZChain       = "0x3602000000000000000000000000000000000000" // Z-Chain Blake3
	PedersenCChain     = "0x3203000000000000000000000000000000000000" // C-Chain Pedersen
	PedersenZChain     = "0x3603000000000000000000000000000000000000" // Z-Chain Pedersen
	MiMCCChain         = "0x3204000000000000000000000000000000000000" // C-Chain MiMC
	RescueCChain       = "0x3205000000000000000000000000000000000000" // C-Chain Rescue

	// Classical Signatures (II = 0x10-0x1F)
	ECDSACChain   = "0x3210000000000000000000000000000000000000" // Extended ECDSA
	Ed25519CChain = "0x3211000000000000000000000000000000000000" // Ed25519
	BLS381CChain  = "0x3212000000000000000000000000000000000000" // BLS12-381
	SchnorrCChain = "0x3213000000000000000000000000000000000000" // Schnorr (BIP-340)

	// Encryption (II = 0x20-0x2F)
	AESGCMCChain   = "0x3220000000000000000000000000000000000000" // AES-GCM
	ChaCha20CChain = "0x3221000000000000000000000000000000000000" // ChaCha20-Poly1305
	HPKECChain     = "0x3222000000000000000000000000000000000000" // HPKE
	ECIESCChain    = "0x3223000000000000000000000000000000000000" // ECIES

	// =========================================================================
	// PAGE 4: PRIVACY/ZK (0x4CII) → LP-4xxx
	// =========================================================================

	// SNARKs (II = 0x00-0x0F)
	Groth16CChain = "0x4200000000000000000000000000000000000000" // C-Chain Groth16
	Groth16ZChain = "0x4600000000000000000000000000000000000000" // Z-Chain Groth16
	PLONKCChain   = "0x4201000000000000000000000000000000000000" // C-Chain PLONK
	PLONKZChain   = "0x4601000000000000000000000000000000000000" // Z-Chain PLONK
	fflonkCChain  = "0x4202000000000000000000000000000000000000" // C-Chain fflonk
	fflonkZChain  = "0x4602000000000000000000000000000000000000" // Z-Chain fflonk
	Halo2CChain   = "0x4203000000000000000000000000000000000000" // C-Chain Halo2
	Halo2ZChain   = "0x4603000000000000000000000000000000000000" // Z-Chain Halo2
	NovaCChain    = "0x4204000000000000000000000000000000000000" // C-Chain Nova
	NovaZChain    = "0x4604000000000000000000000000000000000000" // Z-Chain Nova

	// STARKs (II = 0x10-0x1F)
	STARKCChain       = "0x4210000000000000000000000000000000000000" // C-Chain STARK
	STARKZChain       = "0x4610000000000000000000000000000000000000" // Z-Chain STARK
	STARKRecursiveCCh = "0x4211000000000000000000000000000000000000" // C-Chain STARKRecursive
	STARKRecursiveZCh = "0x4611000000000000000000000000000000000000" // Z-Chain STARKRecursive
	STARKBatchCChain  = "0x4212000000000000000000000000000000000000" // C-Chain STARKBatch
	STARKBatchZChain  = "0x4612000000000000000000000000000000000000" // Z-Chain STARKBatch
	STARKReceiptsCCh  = "0x421F000000000000000000000000000000000000" // C-Chain STARKReceipts
	STARKReceiptsZCh  = "0x461F000000000000000000000000000000000000" // Z-Chain STARKReceipts

	// Commitments (II = 0x20-0x2F)
	KZGCChain = "0x4220000000000000000000000000000000000000" // C-Chain KZG
	KZGZChain = "0x4620000000000000000000000000000000000000" // Z-Chain KZG
	IPACChain = "0x4221000000000000000000000000000000000000" // C-Chain IPA
	IPAZChain = "0x4621000000000000000000000000000000000000" // Z-Chain IPA
	FRICChain = "0x4222000000000000000000000000000000000000" // C-Chain FRI
	FRIZChain = "0x4622000000000000000000000000000000000000" // Z-Chain FRI

	// Privacy Primitives (II = 0x30-0x3F)
	RangeProofCChain  = "0x4230000000000000000000000000000000000000" // C-Chain Bulletproofs
	RangeProofZChain  = "0x4630000000000000000000000000000000000000" // Z-Chain Bulletproofs
	NullifierCChain   = "0x4231000000000000000000000000000000000000" // C-Chain Nullifier
	NullifierZChain   = "0x4631000000000000000000000000000000000000" // Z-Chain Nullifier
	CommitmentCChain  = "0x4232000000000000000000000000000000000000" // C-Chain Commitment
	CommitmentZChain  = "0x4632000000000000000000000000000000000000" // Z-Chain Commitment
	MerkleProofCChain = "0x4233000000000000000000000000000000000000" // C-Chain MerkleProof
	MerkleProofZChain = "0x4633000000000000000000000000000000000000" // Z-Chain MerkleProof

	// FHE (II = 0x40-0x4F)
	FHECChain         = "0x4240000000000000000000000000000000000000" // C-Chain FHE
	FHEZChain         = "0x4640000000000000000000000000000000000000" // Z-Chain FHE
	TFHECChain        = "0x4241000000000000000000000000000000000000" // C-Chain TFHE
	TFHEZChain        = "0x4641000000000000000000000000000000000000" // Z-Chain TFHE
	CKKSCChain        = "0x4242000000000000000000000000000000000000" // C-Chain CKKS
	CKKSZChain        = "0x4642000000000000000000000000000000000000" // Z-Chain CKKS
	BGVCChain         = "0x4243000000000000000000000000000000000000" // C-Chain BGV
	BGVZChain         = "0x4643000000000000000000000000000000000000" // Z-Chain BGV
	GatewayCChain     = "0x4244000000000000000000000000000000000000" // C-Chain Gateway
	GatewayZChain     = "0x4644000000000000000000000000000000000000" // Z-Chain Gateway
	TaskManagerCChain = "0x4245000000000000000000000000000000000000" // C-Chain TaskManager
	TaskManagerZChain = "0x4645000000000000000000000000000000000000" // Z-Chain TaskManager

	// =========================================================================
	// PAGE 5: THRESHOLD/MPC (0x5CII) → LP-5xxx
	// =========================================================================

	// Threshold Signatures (II = 0x00-0x0F)
	FROSTCChain     = "0x5200000000000000000000000000000000000000" // C-Chain FROST
	FROSTQChain     = "0x5300000000000000000000000000000000000000" // Q-Chain FROST
	CGGMP21CChain   = "0x5201000000000000000000000000000000000000" // C-Chain CGGMP21
	CGGMP21QChain   = "0x5301000000000000000000000000000000000000" // Q-Chain CGGMP21
	RingtailCChain  = "0x5202000000000000000000000000000000000000" // C-Chain Ringtail
	RingtailQChain  = "0x5302000000000000000000000000000000000000" // Q-Chain Ringtail
	DoernerCChain   = "0x5203000000000000000000000000000000000000" // C-Chain Doerner
	DoernerQChain   = "0x5303000000000000000000000000000000000000" // Q-Chain Doerner
	BLSThreshCChain = "0x5204000000000000000000000000000000000000" // C-Chain BLS Threshold
	BLSThreshQChain = "0x5304000000000000000000000000000000000000" // Q-Chain BLS Threshold

	// Secret Sharing (II = 0x10-0x1F)
	LSSCChain     = "0x5210000000000000000000000000000000000000" // C-Chain LSS
	LSSQChain     = "0x5310000000000000000000000000000000000000" // Q-Chain LSS
	ShamirCChain  = "0x5211000000000000000000000000000000000000" // C-Chain Shamir
	ShamirQChain  = "0x5311000000000000000000000000000000000000" // Q-Chain Shamir
	FeldmanCChain = "0x5212000000000000000000000000000000000000" // C-Chain Feldman
	FeldmanQChain = "0x5312000000000000000000000000000000000000" // Q-Chain Feldman

	// DKG/Custody (II = 0x20-0x2F)
	DKGCChain      = "0x5220000000000000000000000000000000000000" // C-Chain DKG
	DKGQChain      = "0x5320000000000000000000000000000000000000" // Q-Chain DKG
	RefreshCChain  = "0x5221000000000000000000000000000000000000" // C-Chain Key Refresh
	RefreshQChain  = "0x5321000000000000000000000000000000000000" // Q-Chain Key Refresh
	RecoveryCChain = "0x5222000000000000000000000000000000000000" // C-Chain Recovery
	RecoveryQChain = "0x5322000000000000000000000000000000000000" // Q-Chain Recovery

	// =========================================================================
	// PAGE 6: BRIDGES (0x6CII) → LP-6xxx
	// =========================================================================

	// Warp Messaging (II = 0x00-0x0F)
	WarpSendCChain     = "0x6200000000000000000000000000000000000000" // C-Chain WarpSend
	WarpSendBChain     = "0x6500000000000000000000000000000000000000" // B-Chain WarpSend
	WarpReceiveCChain  = "0x6201000000000000000000000000000000000000" // C-Chain WarpReceive
	WarpReceiveBChain  = "0x6501000000000000000000000000000000000000" // B-Chain WarpReceive
	WarpReceiptsCChain = "0x6202000000000000000000000000000000000000" // C-Chain WarpReceipts
	WarpReceiptsBChain = "0x6502000000000000000000000000000000000000" // B-Chain WarpReceipts

	// Token Bridges (II = 0x10-0x1F)
	BridgeCChain       = "0x6210000000000000000000000000000000000000" // C-Chain Bridge
	BridgeBChain       = "0x6510000000000000000000000000000000000000" // B-Chain Bridge
	TeleportCChain     = "0x6211000000000000000000000000000000000000" // C-Chain Teleport
	TeleportBChain     = "0x6511000000000000000000000000000000000000" // B-Chain Teleport
	BridgeRouterCChain = "0x6212000000000000000000000000000000000000" // C-Chain BridgeRouter
	BridgeRouterBChain = "0x6512000000000000000000000000000000000000" // B-Chain BridgeRouter

	// Fee Collection (II = 0x20-0x2F)
	FeeCollectCChain = "0x6220000000000000000000000000000000000000" // C-Chain FeeCollect
	FeeCollectBChain = "0x6520000000000000000000000000000000000000" // B-Chain FeeCollect
	FeeGovCChain     = "0x6221000000000000000000000000000000000000" // C-Chain FeeGov
	FeeGovBChain     = "0x6521000000000000000000000000000000000000" // B-Chain FeeGov

	// =========================================================================
	// PAGE 7: AI (0x7CII) → LP-7xxx
	// =========================================================================

	// Attestation (II = 0x00-0x0F)
	GPUAttestCChain = "0x7200000000000000000000000000000000000000" // C-Chain GPU Attestation
	GPUAttestAChain = "0x7400000000000000000000000000000000000000" // A-Chain GPU Attestation
	GPUAttestHanzo  = "0x7900000000000000000000000000000000000000" // Hanzo GPU Attestation
	TEEVerifyCChain = "0x7201000000000000000000000000000000000000" // C-Chain TEE Verify
	TEEVerifyAChain = "0x7401000000000000000000000000000000000000" // A-Chain TEE Verify
	NVTrustCChain   = "0x7202000000000000000000000000000000000000" // C-Chain NVTrust
	NVTrustAChain   = "0x7402000000000000000000000000000000000000" // A-Chain NVTrust
	SGXAttestCChain = "0x7203000000000000000000000000000000000000" // C-Chain SGX Attestation
	SGXAttestAChain = "0x7403000000000000000000000000000000000000" // A-Chain SGX Attestation
	TDXAttestCChain = "0x7204000000000000000000000000000000000000" // C-Chain TDX Attestation
	TDXAttestAChain = "0x7404000000000000000000000000000000000000" // A-Chain TDX Attestation

	// Inference (II = 0x10-0x1F)
	InferenceCChain  = "0x7210000000000000000000000000000000000000" // C-Chain Inference
	InferenceAChain  = "0x7410000000000000000000000000000000000000" // A-Chain Inference
	InferenceHanzo   = "0x7910000000000000000000000000000000000000" // Hanzo Inference
	ProvenanceCChain = "0x7211000000000000000000000000000000000000" // C-Chain Provenance
	ProvenanceAChain = "0x7411000000000000000000000000000000000000" // A-Chain Provenance
	ModelHashCChain  = "0x7212000000000000000000000000000000000000" // C-Chain ModelHash
	ModelHashAChain  = "0x7412000000000000000000000000000000000000" // A-Chain ModelHash

	// Mining (II = 0x20-0x2F)
	SessionCChain   = "0x7220000000000000000000000000000000000000" // C-Chain Session
	SessionAChain   = "0x7420000000000000000000000000000000000000" // A-Chain Session
	SessionHanzo    = "0x7920000000000000000000000000000000000000" // Hanzo Session
	HeartbeatCChain = "0x7221000000000000000000000000000000000000" // C-Chain Heartbeat
	HeartbeatAChain = "0x7421000000000000000000000000000000000000" // A-Chain Heartbeat
	RewardCChain    = "0x7222000000000000000000000000000000000000" // C-Chain Reward
	RewardAChain    = "0x7422000000000000000000000000000000000000" // A-Chain Reward

	// =========================================================================
	// PAGE 9: DEX/MARKETS → LP-9xxx (addresses match LP numbers directly)
	// =========================================================================
	// LP-9000: DEX Core Trading Protocol (spec, not precompile)
	// LP-9001: DEX Trading Engine (spec, not precompile)
	// LP-9010: DEX Precompile - Native HFT Order Book (PoolManager, Uniswap v4 style)
	// LP-9011: Oracle Precompile - Multi-Source Price Aggregation
	// LP-9015: Precompile Registry - DeFi Precompile Addresses

	// Core DEX (LP-9010 series - Uniswap v4 style singleton PoolManager)
	LXPool   = "0x0000000000000000000000000000000000009010" // LP-9010 LXPool (singleton AMM)
	LXOracle = "0x0000000000000000000000000000000000009011" // LP-9011 LXOracle (price aggregation)
	LXRouter = "0x0000000000000000000000000000000000009012" // LP-9012 LXRouter (swap routing)
	LXHooks  = "0x0000000000000000000000000000000000009013" // LP-9013 LXHooks (hook registry)
	LXFlash  = "0x0000000000000000000000000000000000009014" // LP-9014 LXFlash (flash loans)

	// Trading & DeFi Extensions (LP-90xx)
	LXBook     = "0x0000000000000000000000000000000000009020" // LP-9020 LXBook (orderbook + matching)
	LXVault    = "0x0000000000000000000000000000000000009030" // LP-9030 LXVault (custody + margin)
	LXFeed     = "0x0000000000000000000000000000000000009040" // LP-9040 LXFeed (computed prices)
	LXLend     = "0x0000000000000000000000000000000000009050" // LP-9050 LXLend (lending pool)
	LXLiquid   = "0x0000000000000000000000000000000000009060" // LP-9060 LXLiquid (self-repaying loans)
	Liquidator = "0x0000000000000000000000000000000000009070" // LP-9070 Liquidator (position liquidation)
	LiquidFX   = "0x0000000000000000000000000000000000009080" // LP-9080 LiquidFX (transmuter)
)

// PrecompileAddress calculates address from (P, C, II) nibbles
// P = Family page (aligned with LP-Pxxx), C = Chain slot, II = Item
// Returns trailing-significant format: 0x0000000000000000000000000000000000PCII
// The address ends with the LP number (e.g., 9200 for LP-9200 PoolManager)
func PrecompileAddress(p, c, ii uint8) common.Address {
	if p > 15 || c > 15 {
		return common.Address{}
	}
	// Build the 4-character selector: PCII (hex)
	selector := fmt.Sprintf("%x%x%02x", p, c, ii)
	// Pad with leading zeros to 40 hex chars (20 bytes)
	addr := "0000000000000000000000000000000000" + selector
	return common.HexToAddress("0x" + addr)
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
		// DEX (LP-9xxx)
		LXPool, LXRouter, LXHooks, LXFlash, LXOracle, LXBook, LXVault, LXFeed, LXLend, LXLiquid, Liquidator, LiquidFX,
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

	// Zoo - DEX focused (same precompile addresses)
	"Zoo": {
		// DEX (LP-9xxx) - same addresses as C-Chain
		LXPool, LXRouter, LXHooks, LXFlash, LXOracle, LXBook, LXVault, LXFeed, LXLend, LXLiquid, Liquidator, LiquidFX,
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

	// DEX/Markets → LP-9xxx (addresses end with LP number)
	{LXPool, "LX_POOL", "Uniswap v4-style singleton AMM", 50000, []string{"C", "Zoo"}, "LP-9010"},
	{LXOracle, "LX_ORACLE", "Price oracle aggregation", 15000, []string{"C", "Zoo"}, "LP-9011"},
	{LXRouter, "LX_ROUTER", "Optimized swap routing", 10000, []string{"C", "Zoo"}, "LP-9012"},
	{LXHooks, "LX_HOOKS", "Hook contract registry", 10000, []string{"C", "Zoo"}, "LP-9013"},
	{LXFlash, "LX_FLASH", "Flash loan facility", 50000, []string{"C", "Zoo"}, "LP-9014"},
	{LXBook, "LX_BOOK", "Central limit order book", 25000, []string{"C", "Zoo"}, "LP-9020"},
	{LXVault, "LX_VAULT", "Custody, margin, positions", 50000, []string{"C", "Zoo"}, "LP-9030"},
	{LXFeed, "LX_FEED", "Computed price feeds (mark/index)", 10000, []string{"C", "Zoo"}, "LP-9040"},
	{LXLend, "LX_LEND", "Lending pool (Aave-style)", 25000, []string{"C", "Zoo"}, "LP-9050"},
	{LXLiquid, "LX_LIQUID", "Self-repaying loans (Alchemix-style)", 30000, []string{"C", "Zoo"}, "LP-9060"},
	{Liquidator, "LIQUIDATOR", "Position liquidation engine", 50000, []string{"C", "Zoo"}, "LP-9070"},
	{LiquidFX, "LIQUID_FX", "Transmuter (liquid token conversion)", 25000, []string{"C", "Zoo"}, "LP-9080"},
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
