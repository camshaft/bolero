use crate::{exec, manifest::resolve, DEFAULT_TARGET};
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

    /// Use rustup to execute cargo build
    #[structopt(long = "toolchain")]
    toolchain: Option<String>,
}

impl Config {
    pub fn bin_path(&self, flags: &[&str]) -> PathBuf {
        exec(self.cmd("build", flags)).exit_on_error();

        PathBuf::from(
            String::from_utf8(
                self.cmd("test", flags)
                    .env("BOLERO_INFO", "1")
                    .output()
                    .expect("could not read info")
                    .stdout,
            )
            .unwrap(),
        )
    }

    pub fn workdir(&self) -> Result<PathBuf, Error> {
        let mut manifest_path = resolve(&self.manifest_path, &self.package, Some(&self.test))?;
        manifest_path.pop();
        manifest_path.push("tests");
        manifest_path.push(&self.test);
        Ok(manifest_path)
    }

    fn cargo(&self) -> Command {
        let rustup = |toolchain| {
            let mut cmd = Command::new("rustup");
            cmd.arg("run").arg(toolchain).arg("cargo");
            cmd
        };

        let cargo = || Command::new("cargo");

        let requires_nightly = self.requires_nightly();

        match (requires_nightly, self.toolchain.as_ref()) {
            (true, None) => rustup("nightly"),
            (false, None) => cargo(),
            (_, Some(toolchain)) if toolchain == "default" => cargo(),
            (_, Some(toolchain)) => rustup(toolchain),
        }
    }

    pub fn cmd(&self, call: &str, flags: &[&str]) -> Command {
        let mut cmd = self.cargo();

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
            "-Cdebug-assertions",
            "-Ctarget-cpu=native",
            "-Cdebuginfo=2",
            "-Coverflow_checks",
        ]
        .iter()
        .chain(flags.iter())
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

    pub fn requires_nightly(&self) -> bool {
        !self.sanitizer.is_empty()
    }
}
