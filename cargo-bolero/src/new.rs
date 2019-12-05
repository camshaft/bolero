use crate::manifest::Package;
use failure::Error;
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

const FUZZ_FILE: &str = r#"
use bolero::fuzz;

fn main() {
    fuzz!().for_each(|input| {
        if input.len() < 3 {
            return;
        }

        if input[0] == 0 && input[1] == 1 && input[2] == 2 {
            panic!("you found me!");
        }
    });
}
"#;

const GENERATOR_FILE: &str = r#"
use bolero::fuzz;

fn main() {
    fuzz!().with_type().for_each(|value: u8| {
        assert!(value * 2 > value);
    });
}
"#;

impl New {
    pub fn exec(&self) -> Result<(), Error> {
        let file = if self.generator {
            GENERATOR_FILE
        } else {
            FUZZ_FILE
        }
        .trim_start();

        let package = Package::resolve(
            self.manifest_path.as_ref().map(AsRef::as_ref),
            self.package.as_ref().map(AsRef::as_ref),
        )?;
        let manifest_dir = package.manifest_dir();
        let target_dir = manifest_dir.join("tests").join(&self.test);

        mkdir(&target_dir);
        write(target_dir.join("main.rs"), file);

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
path = "tests/{name}/main.rs"
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
