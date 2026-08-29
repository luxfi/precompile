// safekatverify feeds the KAT input blobs produced by safekatdump into the
// REAL precompile Run() implementations and asserts each returns the success
// word bytes32(1). This is the ground-truth check that the framed bytes the
// Solidity tests will assert against actually verify on-chain.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/luxfi/geth/common"

	cggmp21 "github.com/luxfi/precompile/cggmp21"
	corona "github.com/luxfi/precompile/corona"
	magnetar "github.com/luxfi/precompile/magnetar"
	pulsar "github.com/luxfi/precompile/pulsar"
)

type katOut struct {
	Scheme   string `json:"scheme"`
	InputHex string `json:"input"`
}

func main() {
	var kats []katOut
	if err := json.NewDecoder(os.Stdin).Decode(&kats); err != nil {
		fmt.Fprintln(os.Stderr, "decode:", err)
		os.Exit(1)
	}
	fail := false
	for _, k := range kats {
		input, err := hex.DecodeString(k.InputHex)
		if err != nil {
			fmt.Println(k.Scheme, "hex decode FAIL", err)
			fail = true
			continue
		}
		switch k.Scheme {
		case "pulsar":
			// pulsar Run returns (nil, gas, nil) on success, typed error on fail.
			_, _, err := pulsar.PulsarVerifyPrecompile.Run(nil, common.Address{}, pulsar.ContractPulsarVerifyAddress, input, 50_000_000, true)
			report("pulsar", err == nil, err, &fail)
		case "magnetar":
			out, _, err := magnetar.MagnetarVerifyPrecompile.Run(nil, common.Address{}, magnetar.ContractMagnetarVerifyAddress, input, 50_000_000, true)
			ok := err == nil && len(out) == 32 && out[31] == 1
			report("magnetar", ok, err, &fail)
		case "corona":
			out, _, err := corona.CoronaThresholdPrecompile.Run(nil, common.Address{}, corona.ContractCoronaThresholdAddress, input, 50_000_000, true)
			ok := err == nil && len(out) == 32 && out[31] == 1
			report("corona", ok, err, &fail)
		case "cggmp21":
			out, _, err := cggmp21.CGGMP21VerifyPrecompile.Run(nil, common.Address{}, cggmp21.ContractCGGMP21VerifyAddress, input, 50_000_000, true)
			ok := err == nil && len(out) == 32 && out[31] == 1
			report("cggmp21", ok, err, &fail)
		default:
			fmt.Println("unknown scheme", k.Scheme)
			fail = true
		}
	}
	if fail {
		os.Exit(1)
	}
	fmt.Println("ALL KAT INPUTS VERIFY AGAINST REAL PRECOMPILES")
}

func report(name string, ok bool, err error, fail *bool) {
	if ok {
		fmt.Printf("%-10s VERIFY=1 (real precompile accepted KAT input)\n", name)
	} else {
		fmt.Printf("%-10s VERIFY=FAIL err=%v\n", name, err)
		*fail = true
	}
}
