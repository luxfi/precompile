use std::env;
use std::path::PathBuf;

fn main() {
    // Search order for libluxprecompile:
    // 1. LUX_PRECOMPILE_LIB_DIR env var
    // 2. ~/work/lux/precompile/dist/
    // 3. System library path

    if let Ok(lib_dir) = env::var("LUX_PRECOMPILE_LIB_DIR") {
        println!("cargo:rustc-link-search=native={lib_dir}");
    } else {
        // Dev default: ~/work/lux/precompile/dist/
        if let Some(home) = env::var_os("HOME") {
            let dist = PathBuf::from(home).join("work/lux/precompile/dist");
            if dist.exists() {
                println!("cargo:rustc-link-search=native={}", dist.display());
            }
        }
    }

    println!("cargo:rustc-link-lib=dylib=luxprecompile");

    // macOS: set rpath for all link targets
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/local/lib");

        if let Some(home) = env::var_os("HOME") {
            let dist = PathBuf::from(home).join("work/lux/precompile/dist");
            if dist.exists() {
                println!("cargo:rustc-link-arg=-Wl,-rpath,{}", dist.display());
            }
        }
    }
}
