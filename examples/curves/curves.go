// Package curves demonstrates BLS12-381, Ed25519, secp256r1, and SR25519 precompiles.
package curves

import "github.com/luxfi/precompile/examples"

// AllCurveDemos runs all curve precompile demos.
type AllCurveDemos struct{}

func (d AllCurveDemos) Name() string { return "curves" }

func (d AllCurveDemos) Run() []examples.Result {
	var all []examples.Result
	all = append(all, BLS12381Demo()...)
	all = append(all, Ed25519Demo()...)
	all = append(all, Secp256r1Demo()...)
	all = append(all, SR25519Demo()...)
	return all
}
