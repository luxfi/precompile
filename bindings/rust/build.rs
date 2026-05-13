use std::env;
use std::path::PathBuf;

fn main() {
    // docs.rs cannot satisfy the system dependency. Skip the link entirely.
    if env::var("DOCS_RS").is_ok() {
        return;
    }

    // Search order for libluxprecompile:
    //   1. LUX_PRECOMPILE_LIB_DIR env var (explicit override)
    //   2. ~/work/lux/precompile/dist/ (in-tree dev default)
    //   3. /usr/local/lib (standard install location)
    //   4. System default library path
    //
    // The library itself (libluxprecompile.{dylib,so,a}) is built from
    // the Go sources at github.com/luxfi/precompile — it is NOT vendored
    // in this crate because it would exceed the crates.io 10 MiB limit
    // (the dylib is ~18 MiB). Consumers must install it separately; see
    // the crate README for instructions.

    let mut found_dir: Option<PathBuf> = None;

    if let Ok(lib_dir) = env::var("LUX_PRECOMPILE_LIB_DIR") {
        let p = PathBuf::from(&lib_dir);
        println!("cargo:rustc-link-search=native={}", p.display());
        found_dir = Some(p);
    } else if let Some(home) = env::var_os("HOME") {
        let dist = PathBuf::from(home).join("work/lux/precompile/dist");
        if dist.exists() {
            println!("cargo:rustc-link-search=native={}", dist.display());
            found_dir = Some(dist);
        }
    }

    // Always consult /usr/local/lib as a fallback (standard install path).
    let usrlocal = PathBuf::from("/usr/local/lib");
    if usrlocal.exists() {
        println!("cargo:rustc-link-search=native={}", usrlocal.display());
        if found_dir.is_none() {
            found_dir = Some(usrlocal.clone());
        }
    }

    println!("cargo:rustc-link-lib=dylib=luxprecompile");

    // macOS: bake rpath so consumers don't have to set DYLD_LIBRARY_PATH
    // at runtime for the common install locations.
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/local/lib");
        if let Some(dir) = found_dir {
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", dir.display());
        }
    }

    // Rerun if env knob changes.
    println!("cargo:rerun-if-env-changed=LUX_PRECOMPILE_LIB_DIR");
    println!("cargo:rerun-if-env-changed=DOCS_RS");
}
