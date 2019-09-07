use serde::Deserialize;
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, Deserialize)]
struct Metadata {
    packages: Vec<Project>,
}

#[derive(Debug, Deserialize)]
struct Project {
    name: String,
    manifest_path: String,
}

pub fn resolve(manifest_path: &Option<String>, package: &Option<String>) -> PathBuf {
    let mut cmd = Command::new("cargo");

    cmd.arg("metadata")
        .arg("--format-version")
        .arg("1")
        .arg("--no-deps");

    if let Some(path) = manifest_path.as_ref() {
        cmd.arg("--manifest-path").arg(path);
    }

    let result = cmd.output().expect("could not read metadata");

    if !result.status.success() {
        std::io::stderr().write_all(&result.stderr).unwrap();
        std::process::exit(result.status.code().unwrap_or(1));
    }

    let Metadata { packages } = serde_json::from_slice(&result.stdout).unwrap();

    if packages.is_empty() {
        panic!("not in a cargo project");
    }

    if packages.len() == 1 {
        return Path::new(&packages[0].manifest_path)
            .canonicalize()
            .unwrap();
    }

    if let Some(package_name) = package.as_ref() {
        return Path::new(
            &packages
                .into_iter()
                .find(|pkg| &pkg.name == package_name)
                .unwrap_or_else(|| panic!("could not find {:?} package", package_name))
                .manifest_path,
        )
        .canonicalize()
        .unwrap();
    }

    let current_dir = std::env::current_dir().unwrap();

    if packages
        .into_iter()
        .any(|pkg| current_dir.ends_with(Path::new(&pkg.manifest_path).parent().unwrap()))
    {
        return current_dir;
    }

    panic!("package name must be specified in workspace");
}
