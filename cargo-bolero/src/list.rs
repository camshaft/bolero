use crate::{exec, project::Project, test_target::TestTarget, StatusAsResult};
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
    pub fn exec(&self) -> Result<()> {
        let mut build_command = self.cmd("test", &[], None);
        build_command
            .arg("--no-run")
            .env("CARGO_BOLERO_BOOTSTRAP", "1");
        exec(build_command)?;

        let output = self
            .cmd("test", &[], None)
            .arg("--")
            .arg("--nocapture")
            .env("CARGO_BOLERO_SELECT", "all")
            .output()?
            .status_as_result()?;

        for target in TestTarget::all_from_stdout(&output.stdout)? {
            println!("{}", target);
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
