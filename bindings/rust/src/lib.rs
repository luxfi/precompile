//! FFI bindings to libluxprecompile — all Lux EVM precompiles.
//!
//! One shared library, one dispatch function. Every registered precompile
//! (blake3, mldsa, mlkem, frost, dex, ai, zk, ...) is callable by address.
//!
//! # Example
//!
//! ```rust,ignore
//! use luxprecompile_sys::{run, list, required_gas};
//!
//! // List all registered precompiles
//! let precompiles = list().unwrap();
//! for pc in &precompiles {
//!     println!("{}: {}", pc.address, pc.name);
//! }
//!
//! // Run blake3 hash256: op=0x01, data=b"hello"
//! let addr = "0x0500000000000000000000000000000000000004";
//! let input = [0x01u8].iter().chain(b"hello").copied().collect::<Vec<_>>();
//! let result = run(addr, &input, 1_000_000).unwrap();
//! assert_eq!(result.output.len(), 32);
//! ```

use std::os::raw::{c_char, c_int};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PrecompileError {
    #[error("precompile not found at address {0}")]
    NotFound(String),

    #[error("precompile execution failed at address {0}")]
    ExecutionFailed(String),

    #[error("precompile at {0} requires EVM state (not callable stateless)")]
    RequiresState(String),

    #[error("buffer too small")]
    BufferTooSmall,

    #[error("failed to parse precompile list: {0}")]
    ParseError(String),
}

pub type Result<T> = std::result::Result<T, PrecompileError>;

/// Result of a precompile execution.
#[derive(Debug)]
pub struct RunResult {
    /// ABI-encoded output bytes.
    pub output: Vec<u8>,
    /// Gas remaining after execution.
    pub remaining_gas: u64,
}

/// Metadata for a registered precompile.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PrecompileInfo {
    pub address: String,
    pub name: String,
}

// ── Raw FFI ──────────────────────────────────────────────────────────

extern "C" {
    fn lux_precompile_run(
        address: *const c_char,
        addr_len: c_int,
        input: *const c_char,
        input_len: c_int,
        gas: u64,
        output: *mut c_char,
        output_len: *mut c_int,
        remaining_gas: *mut u64,
    ) -> c_int;

    fn lux_precompile_list(buf: *mut c_char, buf_len: *mut c_int) -> c_int;

    fn lux_precompile_required_gas(
        address: *const c_char,
        addr_len: c_int,
        input: *const c_char,
        input_len: c_int,
    ) -> u64;
}

// ── Safe wrappers ───────────────────────────────────────────────────

/// Maximum output buffer size for a single precompile call (1 MB).
const MAX_OUTPUT: usize = 1024 * 1024;

/// Maximum buffer size for the precompile list JSON (64 KB).
const MAX_LIST: usize = 64 * 1024;

/// Run a precompile by its hex address.
///
/// `address` is a 40-character hex string (with or without "0x" prefix).
/// `input` is the ABI-encoded input (selector + args).
/// `gas` is the supplied gas.
pub fn run(address: &str, input: &[u8], gas: u64) -> Result<RunResult> {
    let mut output = vec![0u8; MAX_OUTPUT];
    let mut output_len: c_int = 0;
    let mut remaining_gas: u64 = 0;

    let rc = unsafe {
        lux_precompile_run(
            address.as_ptr() as *const c_char,
            address.len() as c_int,
            input.as_ptr() as *const c_char,
            input.len() as c_int,
            gas,
            output.as_mut_ptr() as *mut c_char,
            &mut output_len,
            &mut remaining_gas,
        )
    };

    match rc {
        0 => {
            output.truncate(output_len as usize);
            Ok(RunResult {
                output,
                remaining_gas,
            })
        }
        -1 => Err(PrecompileError::NotFound(address.to_string())),
        -3 => Err(PrecompileError::RequiresState(address.to_string())),
        _ => Err(PrecompileError::ExecutionFailed(address.to_string())),
    }
}

/// List all registered precompiles.
pub fn list() -> Result<Vec<PrecompileInfo>> {
    let mut buf = vec![0u8; MAX_LIST];
    let mut buf_len = MAX_LIST as c_int;

    let rc = unsafe {
        lux_precompile_list(buf.as_mut_ptr() as *mut c_char, &mut buf_len)
    };

    if rc == -1 {
        // Buffer too small, retry with the size the library told us.
        let needed = buf_len as usize;
        buf = vec![0u8; needed];
        buf_len = needed as c_int;

        let rc2 = unsafe {
            lux_precompile_list(buf.as_mut_ptr() as *mut c_char, &mut buf_len)
        };
        if rc2 != 0 {
            return Err(PrecompileError::BufferTooSmall);
        }
    } else if rc != 0 {
        return Err(PrecompileError::ParseError(format!("rc={rc}")));
    }

    buf.truncate(buf_len as usize);
    serde_json::from_slice(&buf).map_err(|e| PrecompileError::ParseError(e.to_string()))
}

/// Estimate gas cost for a precompile call.
///
/// Returns 0 if the address is not found or the precompile does not implement gas estimation.
pub fn required_gas(address: &str, input: &[u8]) -> u64 {
    unsafe {
        lux_precompile_required_gas(
            address.as_ptr() as *const c_char,
            address.len() as c_int,
            input.as_ptr() as *const c_char,
            input.len() as c_int,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_precompiles() {
        let precompiles = list().unwrap();
        assert!(!precompiles.is_empty(), "should have registered precompiles");

        // Every entry should have a non-empty address and name.
        for pc in &precompiles {
            assert!(pc.address.starts_with("0x"), "address should be hex: {}", pc.address);
            assert!(!pc.name.is_empty(), "name should not be empty");
        }
    }

    #[test]
    fn test_blake3_hash256() {
        // Blake3 precompile at 0x0500000000000000000000000000000000000004
        // Op 0x01 = Hash256
        let addr = "0x0500000000000000000000000000000000000004";
        let mut input = vec![0x01u8];
        input.extend_from_slice(b"hello");

        let gas = required_gas(addr, &input);
        assert!(gas > 0, "blake3 should report non-zero gas");

        let result = run(addr, &input, 1_000_000).unwrap();
        assert_eq!(result.output.len(), 32, "blake3 hash256 should produce 32 bytes");
        assert!(result.remaining_gas < 1_000_000, "should have consumed some gas");
    }

    #[test]
    fn test_not_found() {
        // Use an address that is not registered as any precompile.
        let result = run("0x00000000000000000000000000000000FFFFFFFF", &[], 1_000_000);
        assert!(matches!(result, Err(PrecompileError::NotFound(_))));
    }
}
