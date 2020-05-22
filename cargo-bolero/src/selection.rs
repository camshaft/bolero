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
    pub fn test_target(&self, flags: &[&str], fuzzer: &str) -> Result<TestTarget> {
        let mut target = self.select_target()?;

        if target.is_harnessed {
            target = self.build_harnessed_test_target(flags, fuzzer)?;
        } else {
            target = self.build_unharnessed_test_target(flags, fuzzer)?;
        }

        Ok(target)
    }

    fn select_target(&self) -> Result<TestTarget> {
        let mut build_command = self.cmd("test", &[], None);
        build_command
            .arg("--no-run")
            .env("CARGO_BOLERO_BOOTSTRAP", "1");
        exec(build_command)?;

        let output = self
            .cmd("test", &[], None)
            .arg(&self.test)
            .arg("--")
            .arg("--nocapture")
            .arg("--exact")
            .env("CARGO_BOLERO_SELECT", "one")
            .output()?
            .status_as_result()?;

        TestTarget::from_stdout(&output.stdout)
    }

    fn build_harnessed_test_target(&self, flags: &[&str], fuzzer: &str) -> Result<TestTarget> {
        let mut build_command = self.cmd("test", flags, Some(fuzzer));
        build_command
            .arg("--lib")
            .arg("--no-run")
            .env("CARGO_BOLERO_BOOTSTRAP", "1");
        exec(build_command)?;

        let output = self
            .cmd("test", flags, Some(fuzzer))
            .arg(&self.test)
            .arg("--lib")
            .arg("--")
            .arg("--nocapture")
            .arg("--exact")
            .env("CARGO_BOLERO_SELECT", "one")
            .output()?
            .status_as_result()?;

        let target = TestTarget::from_stdout(&output.stdout)?;

        Ok(target)
    }

    fn build_unharnessed_test_target(&self, flags: &[&str], fuzzer: &str) -> Result<TestTarget> {
        let mut build_command = self.cmd("test", flags, Some(fuzzer));
        build_command
            .arg("--test")
            .arg(&self.test)
            .env("CARGO_BOLERO_BOOTSTRAP", "1");
        exec(build_command)?;

        let output = self
            .project
            .cmd("test", flags, Some(fuzzer))
            .arg("--test")
            .arg(&self.test)
            .arg("--")
            .arg(&self.test)
            .env("CARGO_BOLERO_SELECT", "one")
            .output()?
            .status_as_result()?;

        let target = TestTarget::from_stdout(&output.stdout)?;

        Ok(target)
    }
}

impl Deref for Selection {
    type Target = Project;

    fn deref(&self) -> &Self::Target {
        &self.project
    }
}
