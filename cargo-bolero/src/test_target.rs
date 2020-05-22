use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::{
    io::{BufRead, Cursor},
    path::PathBuf,
    process::Command,
};

#[derive(Debug, Deserialize)]
pub struct TestTarget {
    #[serde(rename = "__bolero_target")]
    pub target: String,

    pub exe: String,

    pub work_dir: String,

    pub package_name: String,

    pub is_fuzz_target: bool,
}

impl TestTarget {
    pub fn from_stdout(stdout: &[u8]) -> Result<Self> {
        let mut targets = vec![];

        for line in Cursor::new(&stdout).lines() {
            let line = line?;
            if let Ok(target) = TestTarget::parse(line) {
                if target.target != "v0.5.0" {
                    return Err(anyhow!(
                        "version mismatch between bolero and cargo-bolero. expected v0.5, got: {}",
                        target.target
                    ));
                }
                targets.push(target);
            }
        }

        match targets.len() {
            0 => Err(anyhow!("no targets matched")),
            1 => Ok(targets.pop().unwrap()),
            _ => {
                // TODO better error
                Err(anyhow!("multiple targets matched"))
            }
        }
    }

    pub fn parse(line: String) -> Result<Self> {
        let target = serde_json::from_str(&line)?;

        Ok(target)
    }

    pub fn workdir(&self) -> PathBuf {
        PathBuf::from(&self.work_dir)
    }

    pub fn corpus_dir(&self) -> PathBuf {
        let mut workdir = self.workdir();
        workdir.push("corpus");
        workdir
    }

    pub fn temp_dir(&self) -> Result<tempfile::TempDir> {
        let dir = tempfile::tempdir_in(self.workdir())?;
        Ok(dir)
    }

    pub fn crashes_dir(&self) -> PathBuf {
        let mut workdir = self.workdir();
        workdir.push("crashes");
        workdir
    }

    pub fn command(&self) -> Command {
        let mut cmd = Command::new(&self.exe);

        cmd.args(self.command_args());
        cmd.env("__BOLERO_TEST_TARGET", &self.target);

        cmd
    }

    pub fn command_args(&self) -> impl Iterator<Item = &str> {
        let needs_args = !self.is_fuzz_target;
        core::iter::empty()
            .chain(Some(self.target.as_str()))
            .chain(Some("--exact"))
            .chain(Some("--nocapture"))
            .filter(move |_| needs_args)
    }
}
