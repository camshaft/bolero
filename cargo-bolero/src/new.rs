use serde::Deserialize;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};
use structopt::StructOpt;

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

fuzz!(|input| {
    if input.len() < 3 {
        return;
    }

    if input[0] == 0 && input[1] == 1 && input[2] == 2 {
        panic!("you found me!");
    }
});
"#;

const GENERATOR_FILE: &str = r#"
use bolero::{fuzz, generator::*};

fuzz!(for value in each(u8::gen()) {
    assert!(value * 2 > value);
});
"#;

impl New {
    pub fn exec(&self) {
        let file = if self.generator {
            GENERATOR_FILE
        } else {
            FUZZ_FILE
        }
        .trim_start();

        let manifest_path = self.manifest_path();
        let project_dir = manifest_path.parent().unwrap();
        let target_dir = project_dir.join("tests").join(&self.test);

        mkdir(&target_dir);
        write(target_dir.join("main.rs"), file);

        mkdir(target_dir.join("corpus"));
        write(target_dir.join("corpus").join(".gitkeep"), "");
        mkdir(target_dir.join("crashes"));
        write(target_dir.join("crashes").join(".gitkeep"), "");

        let mut cargo_toml = OpenOptions::new()
            .append(true)
            .open(manifest_path)
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
    }

    fn manifest_path(&self) -> PathBuf {
        let mut cmd = Command::new("cargo");

        cmd.arg("metadata")
            .arg("--format-version")
            .arg("1")
            .arg("--no-deps");

        if let Some(path) = self.manifest_path.as_ref() {
            cmd.arg("--manifest-path").arg(path);
        }

        let Metadata { mut packages } =
            serde_json::from_slice(&cmd.output().expect("could not read metadata").stdout).unwrap();

        if packages.is_empty() {
            panic!("not in a cargo project");
        }

        if packages.len() == 1 {
            return PathBuf::from(packages.pop().unwrap().manifest_path);
        }

        let package_name = self
            .package
            .clone()
            .expect("package needs to be specified in a workspace");

        let package = packages
            .into_iter()
            .find(|pkg| pkg.name == package_name)
            .unwrap_or_else(|| panic!("could not find {:?} package", package_name));

        package.manifest_path.into()
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

#[derive(Debug, Deserialize)]
struct Metadata {
    packages: Vec<Project>,
}

#[derive(Debug, Deserialize)]
struct Project {
    name: String,
    manifest_path: String,
}
