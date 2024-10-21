use crate::{exec, project::Project, test_target::TestTarget, StatusAsResult};
use anyhow::{Context, Result};
use core::ops::Deref;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct Selection {
    /// Name of the test target
    test: String,

    #[structopt(flatten)]
    project: Project,
}

impl Selection {
    pub fn new(project: Project, test: String) -> Self {
        Self { project, test }
    }

    pub fn test_target(&self, flags: &[&str], fuzzer: &str) -> Result<TestTarget> {
        let mut build_command = self.cmd("test", flags, Some(fuzzer))?;
        build_command
            .arg(&self.test)
            .arg("--no-run")
            .arg("--")
            .arg("--exact");
        exec(build_command)?;

        let mut output_command = self.cmd("test", flags, Some(fuzzer))?;
        output_command
            .arg(&self.test)
            .arg("--workspace")
            .arg("--exclude")
            .arg("neard")
            .arg("--")
            .arg("--nocapture")
            .arg("--exact")
            .env("CARGO_BOLERO_SELECT", "one");
        let output = output_command
            .output()
            .with_context(|| format!("getting output of command {:?}", output_command))?
            .status_as_result()
            .with_context(|| format!("getting status of command {:?}", output_command))?;

        TestTarget::from_stdout(&output.stdout)
    }

    pub fn test(&self) -> &str {
        &self.test
    }
}

impl Deref for Selection {
    type Target = Project;

    fn deref(&self) -> &Self::Target {
        &self.project
    }
}
