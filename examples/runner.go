package examples

import (
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// maxGas is the gas budget for each demo call.
const maxGas = 10_000_000

// CallPrecompile invokes a StatefulPrecompiledContract directly (no EVM, no RPC).
// This is the fastest way to exercise a precompile in tests and demos.
func CallPrecompile(
	p contract.StatefulPrecompiledContract,
	addr common.Address,
	input []byte,
	readOnly bool,
) (output []byte, gasUsed uint64, err error) {
	gas := uint64(maxGas)
	out, remaining, err := p.Run(nil, common.Address{}, addr, input, gas, readOnly)
	return out, gas - remaining, err
}

// CallPrecompileResult is a convenience wrapper that builds a Result.
func CallPrecompileResult(
	name string,
	p contract.StatefulPrecompiledContract,
	addr common.Address,
	input []byte,
	validate func(output []byte) bool,
) Result {
	out, gasUsed, err := CallPrecompile(p, addr, input, true)
	pass := err == nil && validate(out)
	return Result{
		Name:     name,
		Address:  addr,
		Calldata: input,
		Output:   out,
		GasUsed:  gasUsed,
		Pass:     pass,
		Error:    err,
	}
}
