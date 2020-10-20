use crate::{
    fuzz::{Fuzz, FuzzArgs},
    list::List,
    new::New,
    reduce::{Reduce, ReduceArgs},
    selection::Selection,
};
use anyhow::{anyhow, Result};
use std::io::Write;
use structopt::StructOpt;

#[cfg(feature = "afl")]
mod afl;
mod flags;
mod fuzz;
mod fuzzer;
#[cfg(feature = "honggfuzz")]
mod honggfuzz;
mod libfuzzer;
mod list;
mod manifest;
mod new;
mod project;
mod reduce;
mod selection;
mod test_target;

#[derive(Debug, StructOpt)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    Fuzz(Fuzz),
    Reduce(Reduce),
    New(New),
    List(List),
}

impl Commands {
    fn exec(&self) -> Result<()> {
        match self {
            Self::Fuzz(cmd) => cmd.exec(),
            Self::Reduce(cmd) => cmd.exec(),
            Self::New(cmd) => cmd.exec(),
            Self::List(cmd) => cmd.exec(),
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
        eprintln!("error: {}", err);
        std::process::exit(1);
    }
}

pub(crate) fn exec(mut cmd: std::process::Command) -> Result<()> {
    cmd.spawn()?.wait()?.status_as_result()
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
