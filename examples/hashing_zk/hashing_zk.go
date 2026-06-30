// Package hashing_zk demonstrates Blake3, Poseidon, Pedersen, BabyJubJub, and Pasta precompiles.
package hashing_zk

import "github.com/luxfi/precompile/examples"

type AllHashingZKDemos struct{}

func (d AllHashingZKDemos) Name() string { return "hashing_zk" }

func (d AllHashingZKDemos) Run() []examples.Result {
	var all []examples.Result
	all = append(all, Blake3Demo()...)
	all = append(all, PoseidonDemo()...)
	all = append(all, PedersenDemo()...)
	all = append(all, BabyJubJubDemo()...)
	all = append(all, PastaDemo()...)
	return all
}
