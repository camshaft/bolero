use crate::{exec, DEFAULT_TARGET};
use std::process::Command;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct Config {
    /// Name of the test target
    test: String,

    /// Build with the sanitizer enabled
    #[structopt(short = "s", long = "sanitizer")]
    sanitizer: Vec<String>,

    /// Build for the target triple
    #[structopt(long = "target", default_value = DEFAULT_TARGET)]
    target: String,

    /// Activate all available features
    #[structopt(long = "all-features")]
    all_features: bool,

    /// Do not activate the `default` feature
    #[structopt(long = "no-default-features")]
    no_default_features: bool,

    /// Space-separated list of features to activate
    #[structopt(long = "features")]
    features: Option<String>,

    /// Package to run tests for
    #[structopt(short = "p", long = "package")]
    package: Option<String>,

    /// Path to Cargo.toml
    #[structopt(long = "manifest-path")]
    manifest_path: Option<String>,
}

impl Config {
    pub fn workdir(&self) -> String {
        exec(self.cmd("build")).exit_on_error();

        String::from_utf8(
            self.cmd("test")
                .env("BOLERO_READ_WORKDIR", "1")
                .output()
                .expect("could not read workdir")
                .stdout,
        )
        .expect("valid workdir")
    }

    pub fn cmd(&self, call: &str) -> Command {
        let mut cmd = Command::new("cargo");

        cmd.arg(call)
            .arg("--test")
            .arg(&self.test)
            .arg("--target")
            .arg(&self.target)
            .arg("--release");

        if self.no_default_features {
            cmd.arg("--no-default-features");
        }

        if self.all_features {
            cmd.arg("--all-features");
        }

        if let Some(value) = self.features.as_ref() {
            cmd.arg("--features").arg(value);
        }

        if let Some(value) = self.package.as_ref() {
            cmd.arg("--package").arg(value);
        }

        if let Some(value) = self.manifest_path.as_ref() {
            cmd.arg("--manifest-path").arg(value);
        }

        let rustflags = [
            "--cfg fuzzing",
            "-Cpasses=sancov",
            "-Cllvm-args=-sanitizer-coverage-level=4",
            "-Cllvm-args=-sanitizer-coverage-trace-pc-guard",
            "-Cllvm-args=-sanitizer-coverage-trace-compares",
            "-Cllvm-args=-sanitizer-coverage-trace-divs",
            "-Cllvm-args=-sanitizer-coverage-trace-geps",
            "-Cllvm-args=-sanitizer-coverage-prune-blocks=0",
            "-Cdebug-assertions",
            "-g",
        ]
        .iter()
        .map(|v| v.to_string())
        .chain(
            self.sanitizer
                .iter()
                .map(|sanitizer| format!("-Zsanitizer={}", sanitizer)),
        )
        .chain(std::env::var("RUSTFLAGS").ok())
        .collect::<Vec<_>>()
        .join(" ");

        cmd.env("RUSTFLAGS", rustflags).arg("--");

        cmd
    }
}
