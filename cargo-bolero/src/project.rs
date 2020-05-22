use crate::DEFAULT_TARGET;
use core::hash::{Hash, Hasher};
use std::{collections::hash_map::DefaultHasher, process::Command};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct Project {
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

    /// Directory for all generated artifacts
    #[structopt(long = "target-dir")]
    target_dir: Option<String>,

    /// Build the standard library with the provided configuration
    #[structopt(long = "build-std")]
    build_std: bool,
}

impl Project {
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

    pub fn cmd(&self, call: &str, flags: &[&str], fuzzer: Option<&str>) -> Command {
        let mut cmd = self.cargo();

        cmd.arg(call).arg("--target").arg(&self.target);

        if self.release && fuzzer.is_some() {
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

        if let Some(fuzzer) = fuzzer {
            let rustflags = self.rustflags(flags);

            if let Some(value) = self.target_dir.as_ref() {
                cmd.arg("--target-dir").arg(value);
            } else {
                let mut hasher = DefaultHasher::new();
                rustflags.hash(&mut hasher);
                cmd.arg("--target-dir")
                    .arg(format!("target/fuzz/build_{:x}", hasher.finish()));
            }

            if self.build_std {
                cmd.arg("-Zbuild-std");
            }

            cmd.env("RUSTFLAGS", rustflags).env("BOLERO_FUZZER", fuzzer);
        }

        cmd
    }

    fn rustflags(&self, flags: &[&str]) -> String {
        [
            "--cfg fuzzing",
            "-Cpasses=sancov",
            "-Cdebug-assertions",
            "-Ctarget-cpu=native",
            "-Cdebuginfo=2",
            "-Coverflow_checks",
            "-Clink-dead-code",
        ]
        .iter()
        .chain(flags.iter())
        .cloned()
        .map(String::from)
        .chain(self.sanitizer_flags())
        .chain(std::env::var("RUSTFLAGS").ok())
        // https://github.com/rust-lang/rust/issues/53945
        .chain(if cfg!(target_os = "linux") {
            Some("-Clink-arg=-fuse-ld=gold".to_string())
        } else {
            None
        })
        .collect::<Vec<_>>()
        .join(" ")
    }

    pub fn requires_nightly(&self) -> bool {
        self.sanitizers().next().is_some() || self.build_std
    }

    fn sanitizers(&self) -> impl Iterator<Item = &str> {
        self.sanitizer
            .iter()
            .map(String::as_str)
            .filter(|s| s != &"NONE")
    }

    fn sanitizer_flags(&self) -> impl Iterator<Item = String> + '_ {
        self.sanitizers()
            .map(|sanitizer| format!("-Zsanitizer={}", sanitizer))
    }
}
