use std::{env, process::Command};

#[cfg(not(any(
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "bitrig",
    target_os = "openbsd",
    target_os = "netbsd"
)))]
const MAKE_COMMAND: &str = "make";
#[cfg(any(
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "bitrig",
    target_os = "openbsd",
    target_os = "netbsd"
))]
const MAKE_COMMAND: &str = "gmake";

fn build(target: &str, file: &str, lib: &str) -> String {
    let out_dir = env::var("OUT_DIR").unwrap();

    let status = Command::new(MAKE_COMMAND)
        .args(["-C", "honggfuzz", target, "libhfcommon/libhfcommon.a"])
        .status()
        .unwrap();
    assert!(status.success());

    std::fs::copy(format!("honggfuzz/{target}"), format!("{out_dir}/{file}"))
        .expect("could not copy target");

    println!("cargo:rustc-link-lib=static={lib}");
    println!("cargo:rustc-link-search=native={out_dir}");

    std::fs::copy(
        "honggfuzz/libhfcommon/libhfcommon.a",
        format!("{out_dir}/libhfcommon.a"),
    )
    .expect("could not copy libhfcommon.a");

    println!("cargo:rustc-link-lib=static=hfcommon");

    // don't fail after cleaning
    Command::new(MAKE_COMMAND)
        .args(["-C", "honggfuzz", "clean"])
        .status()
        .unwrap();

    out_dir
}

fn main() {
    println!("cargo:rerun-if-env-changed=BOLERO_FUZZER");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_FUZZING_HONGGFUZZ");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_BIN");

    if std::env::var("CARGO_CFG_FUZZING_HONGGFUZZ").is_ok() {
        build("libhfuzz/libhfuzz.a", "libhfuzz.a", "hfuzz");
        return;
    }

    if std::env::var("CARGO_FEATURE_BIN").is_ok() {
        build("libhonggfuzz.a", "libhonggfuzz.a", "honggfuzz");

        if cfg!(target_os = "macos") {
            println!("cargo:rustc-link-search=framework=/System/Library/PrivateFrameworks");
            println!("cargo:rustc-link-search=framework=/System/Library/Frameworks");

            for framework in [
                "CoreSymbolication",
                "IOKit",
                "Foundation",
                "ApplicationServices",
                "Symbolication",
                "CoreServices",
                "CrashReporterSupport",
                "CoreFoundation",
                "CommerceKit",
            ]
            .iter()
            {
                println!("cargo:rustc-link-lib=framework={framework}");
            }
        }

        if cfg!(target_os = "linux") {
            for lib in [
                "unwind-ptrace",
                "unwind-generic",
                "unwind",
                "opcodes",
                "bfd",
            ]
            .iter()
            {
                println!("cargo:rustc-link-lib={lib}");
            }
        }
    }
}
