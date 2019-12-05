use crate::{config::Config, fuzzer::Fuzzer};
use failure::Error;
use structopt::StructOpt;

/// Run a fuzzing engine for a target
#[derive(Debug, StructOpt)]
pub struct Fuzz {
    /// Run the test with a specific fuzzer
    #[structopt(short = "f", long = "fuzzer", default_value = "libfuzzer")]
    fuzzer: Fuzzer,

    #[structopt(flatten)]
    args: FuzzArgs,

    #[structopt(flatten)]
    config: Config,
}

#[derive(Debug, StructOpt)]
pub struct FuzzArgs {
    /// Run the fuzzer with an initial seed
    #[structopt(short = "S", long = "seed")]
    pub seed: Option<usize>,

    /// Run the fuzzer for a specified number of runs
    #[structopt(short = "r", long = "runs")]
    pub runs: Option<usize>,

    /// Run the fuzzer for a specified number of seconds
    #[structopt(short = "T", long = "time")]
    pub time: Option<usize>,

    /// Limit the size of inputs to a specific length
    #[structopt(short = "l", long = "max-input-length")]
    pub max_input_length: Option<usize>,

    /// Number of parallel jobs
    #[structopt(short = "j", long = "jobs")]
    pub jobs: Option<usize>,
}

impl Fuzz {
    pub fn exec(&self) -> Result<(), Error> {
        self.fuzzer.fuzz(&self.config, &self.args)
    }
}
