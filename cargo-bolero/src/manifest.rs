use failure::{bail, ensure, format_err, Error};
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
    fn from_manifest_path(manifest_path: Option<&str>) -> Result<Self, Error> {
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

    fn resolve_package(&self, package_name: Option<&str>) -> Result<&Package, Error> {
        ensure!(!self.packages.is_empty(), "Not in cargo project");

        if let Some(package_name) = package_name.as_ref() {
            self.packages
                .iter()
                .find(|package| &package.name == package_name)
                .ok_or_else(|| format_err!("Could not resolve package {:?}", package_name))
        } else if self.packages.len() == 1 {
            Ok(&self.packages[0])
        } else {
            let current_dir = std::env::current_dir().unwrap();

            self.packages
                .iter()
                .find(|pkg| current_dir.ends_with(Path::new(&pkg.manifest_path).parent().unwrap()))
                .ok_or_else(|| format_err!("A package name must be supplied in a workspace"))
        }
    }

    fn resolve_target(
        &self,
        package_name: Option<&str>,
        target_name: &str,
    ) -> Result<TestTarget, Error> {
        ensure!(!self.packages.is_empty(), "Not in cargo project");

        if let Ok(package) = self.resolve_package(package_name) {
            return package.resolve_target(target_name);
        }

        let mut targets = self
            .packages
            .iter()
            .filter_map(|package| package.resolve_target(target_name).ok())
            .collect::<Vec<_>>();

        ensure!(
            !targets.is_empty(),
            "Could not resolve target {:?}",
            target_name
        );
        ensure!(
            targets.len() == 1,
            "Multiple targets found named {:?} in {}. A package name needs to be supplied",
            target_name,
            targets
                .iter()
                .map(|target| target.package_name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        Ok(targets.pop().unwrap())
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Package {
    pub name: String,
    pub manifest_path: String,
    targets: Vec<Target>,
}

impl Package {
    pub fn resolve(manifest_path: Option<&str>, package: Option<&str>) -> Result<Self, Error> {
        Metadata::from_manifest_path(manifest_path)?
            .resolve_package(package)
            .map(|package| package.clone())
    }

    pub fn manifest_dir(&self) -> PathBuf {
        let mut path = PathBuf::from(&self.manifest_path);
        path.pop();
        path
    }

    fn resolve_target(&self, target_name: &str) -> Result<TestTarget, Error> {
        self.targets
            .iter()
            .find_map(|target| {
                if target.name == target_name && target.kind == ["test"] {
                    Some(target.to_test_target(&self.name, &self.manifest_path))
                } else {
                    None
                }
            })
            .ok_or_else(|| format_err!("Could not resolve target {:?}", target_name))
    }
}

#[derive(Clone, Debug, Deserialize)]
struct Target {
    kind: Vec<String>,
    name: String,
    src_path: String,
}

impl Target {
    fn to_test_target(&self, package_name: &str, manifest_path: &str) -> TestTarget {
        TestTarget {
            name: self.name.clone(),
            package_name: package_name.to_string(),
            src_path: self.src_path.clone(),
            manifest_path: manifest_path.to_string(),
        }
    }
}

#[derive(Debug)]
pub struct TestTarget {
    pub name: String,
    pub package_name: String,
    pub src_path: String,
    pub manifest_path: String,
}

impl TestTarget {
    pub fn resolve(
        manifest_path: Option<&str>,
        package: Option<&str>,
        test: &str,
    ) -> Result<TestTarget, Error> {
        Metadata::from_manifest_path(manifest_path)?.resolve_target(package, test)
    }

    pub fn workdir(&self) -> PathBuf {
        let mut path = PathBuf::from(&self.src_path);
        path.pop();
        path
    }

    pub fn corpus_dir(&self) -> PathBuf {
        let mut workdir = self.workdir();
        workdir.push("corpus");
        workdir
    }

    pub fn crashes_dir(&self) -> PathBuf {
        let mut workdir = self.workdir();
        workdir.push("crashes");
        workdir
    }
}
