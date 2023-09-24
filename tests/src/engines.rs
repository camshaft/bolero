use crate::{env, Result};
use xshell::{cmd, Shell};

pub fn test() -> Result {
    let is_nightly = env::rustc_build().map_or(false, |b| b == "nightly");

    for engine in ["random", "libfuzzer", "afl", "honggfuzz", "kani"] {
        // TODO fix honggfuzz
        if engine == "honggfuzz" {
            continue;
        }

        let test = Test {
            engine: engine.to_string(),
            sanitizer: "NONE".to_string(),
            rustc_bootstrap: false,
            reduce: engine == "libfuzzer",
            integrations: engine != "kani",
            supports_env: engine != "kani",
            test_crashes: engine != "afl", // TODO fix this
            runs: 10_000,
            jobs: None,
        };

        test.run()?;

        if ["libfuzzer", "honggfuzz"].contains(&engine) {
            Test {
                sanitizer: "address".to_string(),
                rustc_bootstrap: !is_nightly,
                ..test.clone()
            }
            .run()?;
        }

        // libfuzzer supports multiple jobs
        if ["libfuzzer"].contains(&engine) {
            Test {
                sanitizer: "address".to_string(),
                rustc_bootstrap: !is_nightly,
                jobs: Some(2),
                ..test.clone()
            }
            .run()?;
        }
    }

    Ok(())
}

#[derive(Clone)]
struct Test {
    engine: String,
    sanitizer: String,
    rustc_bootstrap: bool,
    reduce: bool,
    integrations: bool,
    supports_env: bool,
    test_crashes: bool,
    runs: u32,
    jobs: Option<u32>,
}

impl Test {
    fn run(&self) -> Result {
        let sh = Shell::new()?;
        sh.change_dir(env::examples());
        sh.change_dir("basic");

        if self.engine == "afl" {
            sh.set_var("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1");
            sh.set_var("AFL_SKIP_CPUFREQ", "1");
        }

        env::configure_toolchain(&sh);

        let cargo_bolero = env::bins().to_string() + "/target/debug/cargo-bolero";
        let runs = self.runs.to_string();

        let mut args = vec![
            "--engine".to_string(),
            self.engine.clone(),
            "--sanitizer".to_string(),
            self.sanitizer.clone(),
        ];

        if self.rustc_bootstrap {
            args.push("--rustc-bootstrap".to_string());
        }

        let jobs = &if let Some(jobs) = self.jobs {
            vec!["--jobs".to_string(), jobs.to_string()]
        } else {
            vec![]
        };

        let args = &args;

        for test in [
            "tests::add_test",
            "tests::other_test",
            "fuzz_bytes",
            "fuzz_generator",
            "fuzz_operations",
        ] {
            let is_integration = test.starts_with("fuzz");

            if !self.integrations && is_integration {
                continue;
            }

            cmd!(
                sh,
                "{cargo_bolero} test {test} --runs {runs} {jobs...} {args...}"
            )
            .run()?;

            if self.reduce {
                cmd!(sh, "{cargo_bolero} reduce {test} {args...}").run()?;
            }

            if !self.test_crashes {
                continue;
            }

            let _env = if self.supports_env {
                sh.push_env("SHOULD_PANIC", "1")
            } else {
                sh.push_env("RUSTFLAGS", "--cfg bolero_should_panic")
            };

            // some engines will complain about panicking corpus so remove it
            if is_integration {
                let _ = sh.remove_path(format!("tests/{test}/afl_state"));
                let _ = sh.remove_path(format!("tests/{test}/corpus"));
                let _ = sh.remove_path(format!("tests/{test}/crashes"));
            } else {
                let _ = sh.remove_path(format!("src/__fuzz__/{test}"));
            }

            let res = cmd!(sh, "{cargo_bolero} test {test} {args...} {jobs...}").run();

            assert!(res.is_err(), "test {test} should catch a panic");
        }

        Ok(())
    }
}
