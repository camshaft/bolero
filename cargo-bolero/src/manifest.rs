use failure::{bail, Error};
use serde::Deserialize;
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, Deserialize)]
struct Metadata {
    packages: Vec<Package>,
}

#[derive(Debug, Deserialize)]
struct Package {
    name: String,
    manifest_path: String,
    targets: Vec<Target>,
}

#[derive(Debug, Deserialize)]
struct Target {
    kind: Vec<String>,
    name: String,
}

pub fn resolve(
    manifest_path: &Option<String>,
    package: &Option<String>,
    test: Option<&str>,
) -> Result<PathBuf, Error> {
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
        bail!("not in cargo project")
    }

    if packages.len() == 1 {
        return Ok(Path::new(&packages[0].manifest_path)
            .canonicalize()
            .unwrap());
    }

    if let Some(package_name) = package.as_ref() {
        for package in packages.iter() {
            if &package.name == package_name {
                return Ok(Path::new(&package.manifest_path).canonicalize().unwrap());
            }
        }
        bail!("could not find package `{}`", package_name)
    }

    let current_dir = std::env::current_dir().unwrap();

    if packages
        .iter()
        .any(|pkg| current_dir.ends_with(Path::new(&pkg.manifest_path).parent().unwrap()))
    {
        return Ok(current_dir);
    }

    if let Some(test) = test {
        let target_matches = packages
            .iter()
            .filter_map(|package| {
                let matches = |target: &Target| target.name == test && target.kind == ["test"];

                if package.targets.iter().any(matches) {
                    Some(package.manifest_path.as_str())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        match target_matches.len() {
            0 => bail!("no test target named `{}`", test),
            1 => {
                return Ok(Path::new(&target_matches[0]).canonicalize().unwrap());
            }
            _ => bail!(
                "test target `{}` is defined in multiple packages: {}",
                test,
                target_matches.join(", ")
            ),
        }
    }

    bail!("package name must be specified in workspace")
}
