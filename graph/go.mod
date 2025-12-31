module github.com/luxfi/precompile/graph

go 1.25.5

require github.com/luxfi/geth v1.16.66

require (
	github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime v0.0.0-20251230134950-44c893854e3f // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/luxfi/cache v1.1.0 // indirect
	github.com/luxfi/crypto v1.17.30 // indirect
	github.com/luxfi/ids v1.2.5 // indirect
	github.com/luxfi/utils v1.1.0 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
)

replace github.com/luxfi/geth => ../../geth
