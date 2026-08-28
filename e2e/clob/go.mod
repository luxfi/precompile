module github.com/luxfi/precompile/e2e/clob

go 1.26.4

require (
	github.com/holiman/uint256 v1.3.2
	github.com/luxfi/dex v1.14.2
	github.com/luxfi/geth v1.17.12
	github.com/luxfi/precompile v0.5.56
	github.com/luxfi/rpc v1.1.0
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/bits-and-blooms/bitset v1.24.4 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/consensys/gnark-crypto v0.20.1 // indirect
	github.com/crate-crypto/go-eth-kzg v1.5.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/ethereum/c-kzg-4844/v2 v2.1.7 // indirect
	github.com/gorilla/rpc v1.2.1 // indirect
	github.com/gorilla/websocket v1.5.4-0.20250319132907-e064f32e3674 // indirect
	github.com/grandcat/zeroconf v1.0.0 // indirect
	github.com/klauspost/compress v1.18.6 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/luxfi/accel v1.2.4 // indirect
	github.com/luxfi/atomic v1.0.0 // indirect
	github.com/luxfi/cache v1.2.1 // indirect
	github.com/luxfi/compress v0.0.5 // indirect
	github.com/luxfi/concurrent v0.0.3 // indirect
	github.com/luxfi/consensus v1.25.29 // indirect
	github.com/luxfi/constants v1.5.8 // indirect
	github.com/luxfi/container v0.0.4 // indirect
	github.com/luxfi/crypto v1.19.26 // indirect
	github.com/luxfi/crypto/ipa v1.2.4 // indirect
	github.com/luxfi/database v1.20.4 // indirect
	github.com/luxfi/ids v1.2.15 // indirect
	github.com/luxfi/log v1.4.3 // indirect
	github.com/luxfi/math v1.4.1 // indirect
	github.com/luxfi/math/big v0.1.0 // indirect
	github.com/luxfi/mdns v0.1.1 // indirect
	github.com/luxfi/metric v1.5.9 // indirect
	github.com/luxfi/mock v0.1.1 // indirect
	github.com/luxfi/p2p v1.21.1 // indirect
	github.com/luxfi/pq v1.0.3 // indirect
	github.com/luxfi/runtime v1.1.3 // indirect
	github.com/luxfi/sampler v1.1.0 // indirect
	github.com/luxfi/utils v1.2.0 // indirect
	github.com/luxfi/validators v1.2.0 // indirect
	github.com/luxfi/version v1.0.1 // indirect
	github.com/luxfi/vm v1.2.5 // indirect
	github.com/luxfi/warp v1.23.0 // indirect
	github.com/luxfi/zap v0.8.11 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/mr-tron/base58 v1.3.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/supranational/blst v0.3.16 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	go.uber.org/mock v0.6.0 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/exp v0.0.0-20260529124908-c761662dc8c9 // indirect
	golang.org/x/mod v0.36.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/tools v0.45.0 // indirect
	gonum.org/v1/gonum v0.17.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// This standalone test module drives the LOCAL precompile working tree against
// a REAL luxfi/dex ZAP CLOB server (the d-chain gateway). Replaces to the local
// checkouts are legitimate test-harness concerns HERE; the public precompile
// module deliberately carries no such edge (it stays a pure-Go leaf). Isolating
// this in its own module keeps zero blast radius on the e2e/scenarios baseline.
replace github.com/luxfi/dex => ../../../dex

replace github.com/luxfi/precompile => ../..
