use crate::{env, Result};
use xshell::{cmd, Shell};

pub fn test() -> Result {
    let rust_version = env::rustc();

    let use_stable = rust_version.map_or(false, |v| v.major > 1 && v.minor <= 65);

    Test { use_stable }.run()?;

    Ok(())
}

struct Test {
    use_stable: bool,
}

impl Test {
    fn run(&self) -> Result {
        let sh = Shell::new()?;
        sh.change_dir(env::bins());

        // make sure this is up-to-date
        let _ = sh.remove_path("Cargo.lock");

        let toolchain = &if self.use_stable {
            vec!["+stable"]
        } else {
            vec![]
        };

        let features = &vec!["--features", "honggfuzz"];

        cmd!(sh, "cargo {toolchain...} test {features...}").run()?;
        cmd!(sh, "cargo {toolchain...} build {features...}").run()?;

        // Validate failing tests don’t prevent fuzzers from being found
        sh.change_dir("cargo-bolero/test_crates/failing_tests");
        let listed_fuzzers = cmd!(
            sh,
            "cargo {toolchain...} run {features...} --manifest-path ../../Cargo.toml list"
        )
        .read()?;
        sh.change_dir("../../..");
        assert!(listed_fuzzers.contains("unit_bolero"));
        assert!(listed_fuzzers.contains("integ_bolero"));

        // Validate `cargo bolero build-clusterfuzz` runs fine
        // This runs it in $repo/bin, which is fine as cargo-bolero does have fuzz-tests
        cmd!(
            sh,
            "cargo {toolchain...} run {features...} build-clusterfuzz --rustc-bootstrap"
        )
        .run()?;

        // Validate the built fuzzers work fine
        sh.change_dir("target/fuzz");
        cmd!(sh, "tar xf clusterfuzz.tar --strip-components=1").run()?;
        cmd!(sh, "./fuzz_bytes_fuzzer -runs=10").run()?;
        cmd!(sh, "./fuzz_generator_fuzzer -runs=10").run()?;
        cmd!(sh, "./harnessed_fuzzer_fuzzer -runs=10").run()?;

        Ok(())
    }
}
