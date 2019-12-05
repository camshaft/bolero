use crate::{exec, manifest::TestTarget, DEFAULT_TARGET};
use failure::Error;
use std::{path::PathBuf, process::Command};
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

    /// Build artifacts in release mode, with optimizations
    #[structopt(long = "release")]
    release: bool,

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

    /// Use a rustup toolchain to execute cargo build
    #[structopt(long = "toolchain")]
    toolchain: Option<String>,
}

impl Config {
    pub fn bin_path(&self, flags: &[&str], fuzzer: &str) -> PathBuf {
        exec(self.cmd("build", flags, fuzzer)).exit_on_error();

        PathBuf::from(
            String::from_utf8(
                self.cmd("test", flags, fuzzer)
                    .env("BOLERO_INFO", "1")
                    .output()
                    .expect("could not read info")
                    .stdout,
            )
            .unwrap(),
        )
    }

    pub fn test_target(&self) -> Result<TestTarget, Error> {
        TestTarget::resolve(
            self.manifest_path.as_ref().map(AsRef::as_ref),
            self.package.as_ref().map(AsRef::as_ref),
            &self.test,
        )
    }

    fn cargo(&self) -> Command {
        match self.toolchain() {
            "default" => Command::new("cargo"),
            toolchain => {
                let mut cmd = Command::new("rustup");
                cmd.arg("run").arg(toolchain).arg("cargo");
                cmd
            }
        }
    }

    fn toolchain(&self) -> &str {
        if let Some(toolchain) = self.toolchain.as_ref() {
            toolchain
        } else if self.requires_nightly() {
            "nightly"
        } else {
            "default"
        }
    }

    pub fn cmd(&self, call: &str, flags: &[&str], fuzzer: &str) -> Command {
        let mut cmd = self.cargo();

        cmd.arg(call)
            .arg("--test")
            .arg(&self.test)
            .arg("--target")
            .arg(&self.target);

        if self.release {
            cmd.arg("--release");
        }

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
            "-Cdebug-assertions",
            "-Ctarget-cpu=native",
            "-Cdebuginfo=2",
            "-Coverflow_checks",
        ]
        .iter()
        .chain(flags.iter())
        .map(|v| (*v).to_string())
        .chain(
            self.sanitizer
                .iter()
                .map(|sanitizer| format!("-Zsanitizer={}", sanitizer)),
        )
        .chain(std::env::var("RUSTFLAGS").ok())
        .collect::<Vec<_>>()
        .join(" ");

        cmd.env("RUSTFLAGS", rustflags)
            .env("BOLERO_FUZZER", fuzzer)
            .arg("--");

        cmd
    }

    pub fn requires_nightly(&self) -> bool {
        !self.sanitizer.is_empty()
    }
}
