use crate::manifest::Package;
use anyhow::Result;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};
use structopt::StructOpt;

/// Create a new test target
#[derive(Debug, StructOpt)]
pub struct New {
    /// Name of the test target
    test: String,

    /// Package to run tests for
    #[structopt(short = "p", long = "package")]
    package: Option<String>,

    /// Path to Cargo.toml
    #[structopt(long = "manifest-path")]
    manifest_path: Option<String>,

    /// Generates a generator test
    #[structopt(short = "g", long = "generator")]
    generator: bool,
}

const BYTES_FILE: &str = include_str!("../tests/fuzz_bytes/fuzz_target.rs");
const GENERATOR_FILE: &str = include_str!("../tests/fuzz_generator/fuzz_target.rs");

impl New {
    pub fn exec(&self) -> Result<()> {
        let file = if self.generator {
            GENERATOR_FILE
        } else {
            BYTES_FILE
        }
        .trim_start();

        let package = Package::resolve(
            self.manifest_path.as_ref().map(AsRef::as_ref),
            self.package.as_ref().map(AsRef::as_ref),
        )?;
        let manifest_dir = package.manifest_dir();
        let target_dir = manifest_dir.join("tests").join(&self.test);

        mkdir(&target_dir);
        write(target_dir.join("fuzz_target.rs"), file);

        mkdir(target_dir.join("corpus"));
        write(target_dir.join("corpus").join(".gitkeep"), "");
        mkdir(target_dir.join("crashes"));
        write(target_dir.join("crashes").join(".gitkeep"), "");

        let mut cargo_toml = OpenOptions::new()
            .append(true)
            .open(&package.manifest_path)
            .expect("could not open Cargo.toml");

        cargo_toml
            .write_all(
                format!(
                    r#"
[[test]]
name = "{name}"
path = "tests/{name}/fuzz_target.rs"
harness = false
"#,
                    name = self.test
                )
                .as_ref(),
            )
            .expect("could not write test config");

        println!("Created {:?}", &self.test);

        Ok(())
    }
}

fn mkdir<P: AsRef<Path>>(path: P) {
    fs::create_dir_all(path).expect("could not create test directory");
}

fn write<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) {
    let path = path.as_ref();
    fs::write(path, contents).expect("could not create file");
    println!("wrote {:?}", path);
}
