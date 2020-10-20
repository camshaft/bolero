use crate::{exec, project::Project, test_target::TestTarget, StatusAsResult};
use anyhow::Result;
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
    pub fn test_target<F: crate::fuzzer::Env>(&self, fuzzer: F) -> Result<TestTarget> {
        let mut build_command = self.cmd("test", Some(&fuzzer));
        build_command
            .arg(&self.test)
            .arg("--no-run")
            .arg("--")
            .arg("--exact");
        exec(build_command)?;

        let output = self
            .cmd("test", Some(&fuzzer))
            .arg(&self.test)
            .arg("--")
            .arg("--nocapture")
            .arg("--exact")
            .env("CARGO_BOLERO_SELECT", "one")
            .output()?
            .status_as_result()?;

        TestTarget::from_stdout(&output.stdout)
    }
}

impl Deref for Selection {
    type Target = Project;

    fn deref(&self) -> &Self::Target {
        &self.project
    }
}
