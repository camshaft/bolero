use crate::{fuzzer::Fuzzer, selection::Selection};
use anyhow::Result;
use structopt::StructOpt;

/// Reduce the corpus of a test target with a fuzzing engine
#[derive(Debug, StructOpt)]
pub struct Reduce {
    /// Run the test with a specific fuzzer
    #[structopt(short = "f", long = "fuzzer", default_value = "libfuzzer")]
    fuzzer: Fuzzer,

    #[structopt(flatten)]
    args: ReduceArgs,

    #[structopt(flatten)]
    selection: Selection,
}

impl Reduce {
    pub fn exec(&self) -> Result<()> {
        self.fuzzer.reduce(&self.selection, &self.args)
    }
}

#[derive(Debug, StructOpt)]
pub struct ReduceArgs {}
