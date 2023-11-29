use crate::{
    build_clusterfuzz::BuildClusterfuzz, list::List, new::New, reduce::Reduce,
    selection::Selection, test::Test,
};
use anyhow::{anyhow, Context, Result};
use std::io::Write;
use structopt::StructOpt;

#[cfg(feature = "afl")]
mod afl;
mod build_clusterfuzz;
mod engine;
#[cfg(feature = "honggfuzz")]
mod honggfuzz;
#[cfg(feature = "kani")]
mod kani;
mod libfuzzer;
mod list;
mod manifest;
mod new;
mod project;
mod random;
mod reduce;
mod selection;
mod test;
mod test_target;

#[derive(Debug, StructOpt)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    Test(Test),
    Reduce(Reduce),
    New(New),
    List(List),
    BuildClusterfuzz(BuildClusterfuzz),
}

impl Commands {
    fn exec(&self) -> Result<()> {
        match self {
            Self::Test(cmd) => cmd.exec(),
            Self::Reduce(cmd) => cmd.exec(),
            Self::New(cmd) => cmd.exec(),
            Self::List(cmd) => cmd.exec(),
            Self::BuildClusterfuzz(cmd) => cmd.exec(),
        }
    }
}

const DEFAULT_TARGET: &str = env!("DEFAULT_TARGET");

fn main() {
    let args = std::env::args()
        .enumerate()
        .filter_map(|(i, v)| match (i, v.as_ref()) {
            (1, "bolero") => None, // cargo passes the subcommand so filter it out
            _ => Some(v),
        });

    if let Err(err) = Commands::from_iter(args).exec() {
        // Formatting anyhow error with {:#} to print all the error causes.
        eprintln!("error: {:#}", err);
        std::process::exit(1);
    }
}

pub(crate) fn exec(mut cmd: std::process::Command) -> Result<()> {
    cmd.spawn()
        .with_context(|| format!("spawning command {:?}", cmd))?
        .wait()
        .with_context(|| format!("waiting for command {:?}", cmd))?
        .status_as_result()
        .with_context(|| format!("getting status result from command {:?}", cmd))
}

pub(crate) trait StatusAsResult {
    type Output;

    fn status_as_result(self) -> Result<Self::Output>;
}

impl StatusAsResult for std::process::ExitStatus {
    type Output = ();

    fn status_as_result(self) -> Result<()> {
        match self.code() {
            Some(0) => Ok(()),
            Some(code) => Err(anyhow!("process exited with status {}", code)),
            None => Err(anyhow!("process exited with no status code")),
        }
    }
}

impl StatusAsResult for std::process::Output {
    type Output = Self;

    fn status_as_result(self) -> Result<Self::Output> {
        if let Err(err) = self.status.status_as_result() {
            std::io::stdout().write_all(&self.stderr)?;
            return Err(err);
        }
        Ok(self)
    }
}
