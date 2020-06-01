use anyhow::Result;
use std::{path::PathBuf, process::Command};

#[derive(Debug)]
pub struct TestTarget {
    pub exe: PathBuf,
    pub work_dir: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub package_name: String,
    pub test_name: String,
}

impl TestTarget {
    pub fn corpus_dir(&self) -> PathBuf {
        let mut workdir = self.work_dir.clone();
        workdir.push("corpus");
        workdir
    }

    pub fn temp_dir(&self) -> Result<tempfile::TempDir> {
        let dir = tempfile::tempdir_in(&self.work_dir)?;
        Ok(dir)
    }

    pub fn crashes_dir(&self) -> PathBuf {
        let mut workdir = self.work_dir.clone();
        workdir.push("crashes");
        workdir
    }

    pub fn command(&self) -> Command {
        let mut cmd = Command::new(&self.exe);

        cmd.args(&self.args)
            .envs(self.env.iter().map(|(k, v)| (k, v)));

        cmd
    }
}
