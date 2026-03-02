// Package pq demonstrates post-quantum precompiles: ML-DSA, ML-KEM, SLH-DSA, Corona, X-Wing.
package pq

import "github.com/luxfi/precompile/examples"

type AllPQDemos struct{}

func (d AllPQDemos) Name() string { return "pq" }

func (d AllPQDemos) Run() []examples.Result {
	var all []examples.Result
	all = append(all, MLDSADemo()...)
	all = append(all, MLKEMDemo()...)
	all = append(all, SLHDSADemo()...)
	all = append(all, CoronaDemo()...)
	all = append(all, XWingDemo()...)
	return all
}
