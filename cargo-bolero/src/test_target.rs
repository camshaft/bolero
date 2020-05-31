use anyhow::{anyhow, Result};
use core::fmt;
use serde::Deserialize;
use std::{
    io::{BufRead, Cursor},
    path::PathBuf,
    process::Command,
};

#[derive(Debug, Deserialize)]
pub struct TestTarget {
    #[serde(rename = "__bolero_target")]
    pub version: String,
    pub exe: String,
    pub work_dir: String,
    pub package_name: String,
    pub is_harnessed: bool,
    pub test_name: String,
}

impl TestTarget {
    pub fn from_stdout(stdout: &[u8]) -> Result<Self> {
        let mut targets = Self::all_from_stdout(stdout)?;
        match targets.len() {
            0 => Err(anyhow!("no targets matched")),
            1 => Ok(targets.pop().unwrap()),
            _ => {
                for target in targets {
                    eprintln!("{}", target);
                }
                Err(anyhow!("multiple targets matched"))
            }
        }
    }

    pub fn all_from_stdout(stdout: &[u8]) -> Result<Vec<Self>> {
        let mut targets = vec![];

        for line in Cursor::new(&stdout).lines() {
            let line = line?;
            if let Ok(target) = TestTarget::parse(line) {
                if target.version != "v0.5.0" {
                    return Err(anyhow!(
                        "version mismatch between bolero and cargo-bolero. expected v0.5, got: {}",
                        target.version
                    ));
                }
                targets.push(target);
            }
        }

        Ok(targets)
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

        cmd.args(self.command_args()).envs(self.command_env());

        cmd
    }

    pub fn command_args(&self) -> impl Iterator<Item = &str> {
        let is_harnessed = self.is_harnessed;
        core::iter::empty()
            .chain(Some(self.test_name.as_str()))
            .chain(Some("--exact"))
            .chain(Some("--nocapture"))
            .chain(Some("--quiet"))
            .chain(Some("--test-threads"))
            .chain(Some("1"))
            .filter(move |_| is_harnessed)
    }

    pub fn command_env(&self) -> impl Iterator<Item = (&str, &str)> {
        core::iter::empty().chain(Some(("BOLERO_TEST_NAME", self.test_name.as_str())))
    }
}

impl fmt::Display for TestTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            r#"{{"package":{:?},"test":{:?}}}"#,
            self.package_name, self.test_name
        )?;
        Ok(())
    }
}
