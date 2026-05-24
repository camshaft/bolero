use crate::{exec, project::Project, test_target::TestTarget};
use anyhow::Result;
use core::ops::Deref;
use structopt::StructOpt;

/// Lists all fuzz targets
#[derive(Debug, StructOpt)]
pub struct List {
    #[structopt(flatten)]
    project: Project,
}

impl List {
    pub fn project(&self) -> &Project {
        &self.project
    }

    pub fn list(&self) -> Result<Vec<TestTarget>> {
        let build_command = self.cmd("test", false, &["--no-run"], &[], None)?;
        exec(build_command)?;

        let mut cmd = self.cmd("test", true, &["--no-fail-fast"], &[], None)?;
        let output = cmd.env("CARGO_BOLERO_SELECT", "all").output()?;
        // ignore the status in case any tests failed

        TestTarget::all_from_stdout(&output.stdout)
    }

    pub fn exec(&self) -> Result<()> {
        for target in self.list()? {
            println!("{target}");
        }

        Ok(())
    }
}

impl Deref for List {
    type Target = Project;

    fn deref(&self) -> &Self::Target {
        &self.project
    }
}
