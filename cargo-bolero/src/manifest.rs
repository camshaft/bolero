use anyhow::{anyhow, bail, ensure, Result};
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

impl Metadata {
    fn from_manifest_path(manifest_path: Option<&str>) -> Result<Self> {
        let mut cmd = Command::new("cargo");

        cmd.arg("metadata")
            .arg("--format-version")
            .arg("1")
            .arg("--no-deps");

        if let Some(path) = manifest_path.as_ref() {
            cmd.arg("--manifest-path").arg(path);
        }

        let result = cmd.output()?;

        if !result.status.success() {
            std::io::stderr().write_all(&result.stderr).unwrap();
            bail!(
                "`cargo metadata` failed with code {}",
                result.status.code().unwrap_or(1)
            );
        }

        let metadata = serde_json::from_slice(&result.stdout)?;
        Ok(metadata)
    }

    fn resolve_package(&self, package_name: Option<&str>) -> Result<&Package> {
        ensure!(!self.packages.is_empty(), "Not in cargo project");

        if let Some(package_name) = package_name.as_ref() {
            self.packages
                .iter()
                .find(|package| &package.name == package_name)
                .ok_or_else(|| anyhow!("Could not resolve package {:?}", package_name))
        } else if self.packages.len() == 1 {
            Ok(&self.packages[0])
        } else {
            let current_dir = std::env::current_dir().unwrap();

            self.packages
                .iter()
                .find(|pkg| current_dir.ends_with(Path::new(&pkg.manifest_path).parent().unwrap()))
                .ok_or_else(|| anyhow!("A package name must be supplied in a workspace"))
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Package {
    pub name: String,
    pub manifest_path: String,
}

impl Package {
    pub fn resolve(manifest_path: Option<&str>, package: Option<&str>) -> Result<Self> {
        Metadata::from_manifest_path(manifest_path)?
            .resolve_package(package)
            .map(|package| package.clone())
    }

    pub fn manifest_dir(&self) -> PathBuf {
        let mut path = PathBuf::from(&self.manifest_path);
        path.pop();
        path
    }
}
