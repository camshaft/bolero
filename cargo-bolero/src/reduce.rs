use crate::{engine::Engine, selection::Selection};
use anyhow::Result;
use structopt::StructOpt;

/// Reduce the corpus of a test target with an engine
#[derive(Debug, StructOpt)]
pub struct Reduce {
    /// Run the test with a specific engine
    #[structopt(short, long, default_value = "libfuzzer")]
    engine: Engine,

    #[structopt(flatten)]
    args: Args,

    #[structopt(flatten)]
    selection: Selection,
}

impl Reduce {
    pub fn exec(&self) -> Result<()> {
        self.engine.reduce(&self.selection, &self.args)
    }
}

#[derive(Debug, StructOpt)]
pub struct Args {
    /// Additional arguments to pass to the selected engine
    #[structopt(short = "E", long)]
    pub engine_args: Vec<String>,
}
