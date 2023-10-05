use std::{
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    if cfg!(any(feature = "cargo-clippy", docsrs)) {
        return; // skip when clippy or docs is running
    }

    if option_var("CARGO_FEATURE_LIB").is_some() {
        return build_lib();
    }

    // only build if we're linking to cargo-bolero
    if option_var("CARGO_FEATURE_BIN").is_some() {
        build_bin();
    }
}

fn build_lib() {
    if let Some(runtime_dir) = option_var("CARGO_CFG_BOLERO_LIBAFL_RUNTIME_DIR") {
        println!("cargo:rustc-link-search=native={}", runtime_dir);
        println!("cargo:rustc-link-lib=bolero_libafl_runtime");
    }
}

fn build_bin() {
    println!("cargo:rerun-if-changed=runtime/src");
    println!("cargo:rerun-if-changed=runtime/Cargo.toml.template");
    println!("cargo:rerun-if-changed=runtime/build.rs");

    let runtime_out_dir = PathBuf::from(var("OUT_DIR")).join("runtime");
    let mut runtime_src_dir = PathBuf::from(var("CARGO_MANIFEST_DIR"));
    runtime_src_dir.push("runtime");

    let lib_path = build_runtime(&runtime_src_dir, &runtime_out_dir);

    // TODO hash the library

    println!(
        "cargo:rustc-env=BOLERO_LIBAFL_RUNTIME_PATH={}",
        lib_path.display()
    );
}

fn build_runtime(src_dir: &Path, out_dir: &Path) -> PathBuf {
    std::fs::copy(
        src_dir.join("Cargo.toml.template"),
        src_dir.join("Cargo.toml"),
    )
    .unwrap();

    let mut build = Command::new(var("CARGO"));
    build
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS");

    for (k, _v) in std::env::vars() {
        if k.starts_with("CARGO_PKG_") || k.starts_with("CARGO_FEATURE_") {
            build.env_remove(k);
        }
    }

    build.env("PATH", var("PATH"));

    build.current_dir(src_dir);

    let target = var("TARGET");

    build
        .arg("build")
        .arg("--release")
        .arg("--target-dir")
        .arg(out_dir)
        .arg("--target")
        .arg(&target);

    let is_ok = build.status().map_or(false, |s| s.success());
    assert!(is_ok, "build failed");

    out_dir
        .join(&target)
        .join("release")
        .join("libbolero_libafl_runtime.so")
}

fn var(name: &str) -> String {
    option_var(name).unwrap_or_else(|| panic!("missing env var: {:?}", name))
}

fn option_var(name: &str) -> Option<String> {
    println!("cargo:rerun-if-env-changed={name}");
    std::env::var(name).ok()
}
