// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// Package compute implements the AI compute marketplace precompile.
// Address: 0x0310 (AI range)
//
// Operations:
//   - 0x01: RegisterProvider(gpu_info, tee_attestation) -> provider_id
//   - 0x02: SubmitJob(model_hash, input_hash, max_price) -> job_id
//   - 0x03: ClaimReward(job_id, output_hash, proof) -> $AI reward
//   - 0x04: VerifyCompute(job_id, attestation) -> bool
//   - 0x05: GetPrice(model_hash, input_size) -> price in $AI
//
// Gas: 25,000 base for register, 10,000 for submit, 50,000 for verify
// Integrates with A-Chain TEE attestation for compute verification
package compute

import "github.com/luxfi/precompile/contract"

var _ contract.StatefulPrecompiledContract = (*ComputeMarketPrecompile)(nil)

type ComputeMarketPrecompile struct{}
