# luxprecompile-sys

FFI bindings to `libluxprecompile` — every Lux EVM precompile (PQ verify, Quasar,
Blake3, FROST, dex, AI, ZK, …) reachable via one Go-built shared library, one
stable C ABI, one Rust crate.

## System dependency

This crate links against `libluxprecompile.{dylib,so,a}` which is built from
the Go sources at <https://github.com/luxfi/precompile>. The library is *not*
vendored in this crate because it exceeds the crates.io 10 MiB tarball limit.

Install the shared library before depending on this crate:

```sh
# Clone and build the Go library
git clone https://github.com/luxfi/precompile
cd precompile
make dist          # produces dist/libluxprecompile.{dylib,a,h}

# Install into a standard system location (one of):
sudo cp dist/libluxprecompile.dylib /usr/local/lib/     # macOS
sudo cp dist/libluxprecompile.so    /usr/local/lib/     # Linux
sudo ldconfig                                            # Linux
```

The `build.rs` searches for the library in this order:

1. `$LUX_PRECOMPILE_LIB_DIR` (explicit override)
2. `~/work/lux/precompile/dist/` (in-tree dev default)
3. `/usr/local/lib` (standard install)
4. System default library path

## Usage

```rust
use luxprecompile_sys::{run, list, required_gas};

// List all registered precompiles
let precompiles = list().unwrap();
for pc in &precompiles {
    println!("{}: {}", pc.address, pc.name);
}

// Run blake3 Hash256: op = 0x01, data = b"hello"
let addr = "0x0500000000000000000000000000000000000004";
let mut input = vec![0x01u8];
input.extend_from_slice(b"hello");
let result = run(addr, &input, 1_000_000).unwrap();
assert_eq!(result.output.len(), 32);
```

## License

Lux Ecosystem License 1.2 — see the `LICENSE` file.
