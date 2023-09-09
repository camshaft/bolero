extern crate cc;

fn main() {
    println!("cargo:rerun-if-env-changed=BOLERO_FUZZER");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_FUZZING_AFL");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_BIN");

    if std::env::var("CARGO_CFG_FUZZING_AFL").is_ok() {
        let mut build = cc::Build::new();

        build.file("afl/llvm_mode/afl-llvm-rt.o.c");
        build.flag("-fno-omit-frame-pointer");
        build.flag("-fpermissive");
        build.flag("-w");
        build.compile("afl-llvm-rt.a");
        return;
    }

    if std::env::var("CARGO_FEATURE_BIN").is_ok() {
        let mut build = cc::Build::new();

        build.include("src/bolero-afl-util.h");
        build.file("afl/afl-fuzz.c");
        build.define("BIN_PATH", "\"/\"");
        build.define("DOC_PATH", "\"/\"");
        build.flag("-fno-omit-frame-pointer");
        build.flag("-fpermissive");
        build.flag("-w");
        build.compile("afl.a");
    }
}
