use crate::DEFAULT_TARGET;
use core::hash::{Hash, Hasher};
use std::{collections::hash_map::DefaultHasher, process::Command};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct Project {
    /// Build with the sanitizer enabled
    #[structopt(short, long, default_value = "address")]
    sanitizer: Vec<String>,

    /// Build for the target triple
    #[structopt(long, default_value = DEFAULT_TARGET)]
    target: String,

    /// Activate all available features
    #[structopt(long)]
    all_features: bool,

    /// Build artifacts in release mode, with optimizations [default: true]
    #[structopt(long)]
    release: Option<Option<bool>>,

    /// Do not activate the `default` feature
    #[structopt(long)]
    no_default_features: bool,

    /// Space-separated list of features to activate
    #[structopt(long)]
    features: Option<String>,

    /// Package to run tests for
    #[structopt(short, long)]
    package: Option<String>,

    /// Path to Cargo.toml
    #[structopt(long)]
    manifest_path: Option<String>,

    /// Use a rustup toolchain to execute cargo build
    #[structopt(long)]
    toolchain: Option<String>,

    /// Directory for all generated artifacts
    #[structopt(long)]
    target_dir: Option<String>,

    /// Build the standard library with the provided configuration
    #[structopt(long)]
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

        if self.release() {
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
            let rustflags = self.rustflags("RUSTFLAGS", flags);

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

            cmd.env("RUSTFLAGS", rustflags)
                .env("RUSTDOCFLAGS", self.rustflags("RUSTDOCFLAGS", flags))
                .env("BOLERO_FUZZER", fuzzer);
        }

        cmd
    }

    fn rustflags(&self, inherits: &str, flags: &[&str]) -> String {
        [
            "--cfg fuzzing",
            "-Cdebug-assertions",
            "-Ctarget-cpu=native",
            "-Cdebuginfo=2",
            "-Coverflow_checks",
            "-Clink-dead-code",
        ]
        .iter()
        .chain({
            let toolchain = self.toolchain();
            let version_meta = if toolchain == "default" {
                rustc_version::version_meta().unwrap()
            } else {
                let mut cmd = Command::new("rustup");
                let stdout = cmd
                    .arg("run")
                    .arg(toolchain)
                    .arg("rustc")
                    .arg("-vV")
                    .output()
                    .unwrap()
                    .stdout;
                let stdout = core::str::from_utf8(&stdout).unwrap();
                rustc_version::version_meta_for(stdout).unwrap()
            };

            // New LLVM pass manager is enabled when Rust 1.57+ and LLVM 13+
            // https://github.com/rust-lang/rust/pull/88243

            let is_rust_157 = version_meta.semver.major == 1 && version_meta.semver.minor >= 57;
            let is_llvm_13 = version_meta.llvm_version.map_or(true, |v| v.major >= 13);

            Some(if is_rust_157 && is_llvm_13 {
                &"-Cpasses=sancov-module"
            } else {
                &"-Cpasses=sancov"
            })
        })
        .chain(flags.iter())
        .cloned()
        // https://github.com/rust-lang/rust/issues/53945
        .chain(if cfg!(target_os = "linux") {
            Some("-Clink-arg=-fuse-ld=gold")
        } else {
            None
        })
        // https://github.com/rust-lang/rust/issues/47071
        .chain(if self.release() {
            Some("-Ccodegen-units=1")
        } else {
            None
        })
        .map(String::from)
        .chain(self.sanitizer_flags())
        .chain(std::env::var(inherits).ok())
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

    fn release(&self) -> bool {
        match self.release {
            None => true,
            Some(None) => true,
            Some(Some(v)) => v,
        }
    }
}
