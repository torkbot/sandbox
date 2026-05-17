use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(sandbox_static_kernel)");

    let Ok(kernel_c) = env::var("SANDBOX_KERNEL_BUNDLE_C") else {
        return;
    };

    let kernel_c = PathBuf::from(kernel_c);
    if !kernel_c.is_file() {
        panic!(
            "SANDBOX_KERNEL_BUNDLE_C must point to a generated libkrunfw kernel.c bundle: {}",
            kernel_c.display()
        );
    }

    cc::Build::new()
        .file(&kernel_c)
        .define("ABI_VERSION", "5")
        .compile("sandbox_kernel_bundle");

    println!("cargo:rerun-if-env-changed=SANDBOX_KERNEL_BUNDLE_C");
    println!("cargo:rerun-if-changed={}", kernel_c.display());
    println!("cargo:rustc-cfg=sandbox_static_kernel");
}
