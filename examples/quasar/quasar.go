// Package quasar demonstrates Quasar consensus verification precompiles.
package quasar

import (
	"crypto/sha256"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/examples"
	q "github.com/luxfi/precompile/quasar"
)

type QuasarDemo struct{}

func (d QuasarDemo) Name() string { return "quasar" }

func (d QuasarDemo) Run() []examples.Result {
	// VerkleVerify: commitment(32) + proof(32) + threshold_met(1)
	commitment := sha256.Sum256([]byte("Lux Quasar Verkle commitment"))
	proof := sha256.Sum256([]byte("Lux Quasar Verkle proof"))

	verkleInput := make([]byte, 0, 65)
	verkleInput = append(verkleInput, commitment[:]...)
	verkleInput = append(verkleInput, proof[:]...)
	verkleInput = append(verkleInput, 1) // threshold_met = true

	return []examples.Result{
		examples.CallPrecompileResult(
			"Quasar VerkleVerify",
			q.VerklePrecompile,
			common.HexToAddress(q.VerkleVerifyAddress),
			verkleInput,
			func(out []byte) bool { return len(out) > 0 && out[0] == 1 },
		),
	}
}
