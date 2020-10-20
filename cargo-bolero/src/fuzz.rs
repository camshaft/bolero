use crate::{fuzzer::Fuzzer, selection::Selection};
use anyhow::Result;
use humantime::Duration;
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
    selection: Selection,
}

#[derive(Debug, StructOpt)]
pub struct FuzzArgs {
    /// Run the fuzzer with an initial seed
    #[structopt(short = "S", long = "seed")]
    pub seed: Option<usize>,

    /// Run the fuzzer for a specified number of runs. If unspecified
    /// it will continue until manually stopped.
    #[structopt(short = "r", long = "runs")]
    pub runs: Option<usize>,

    /// Run the fuzzer for a specified duration. If unspecified
    /// it will continue until manually stopped.
    #[structopt(short = "T", long = "time")]
    pub time: Option<Duration>,

    /// Limit the size of inputs to a specific length
    #[structopt(short = "l", long = "max-input-length")]
    pub max_input_length: Option<usize>,

    /// Maximum amount of time to run a fuzz target before
    /// failing
    #[structopt(short = "t", long = "timeout", default_value = "10s")]
    pub timeout: Duration,

    /// Number of parallel jobs
    #[structopt(short = "j", long = "jobs")]
    pub jobs: Option<usize>,

    /// Additional arguments to pass to the selected fuzzer engine
    #[structopt(short = "F", long = "fuzzer-args")]
    pub fuzzer_args: Vec<String>,
}

impl FuzzArgs {
    pub fn time_as_secs(&self) -> Option<u64> {
        self.time.as_ref().map(|d| d.as_secs().max(1))
    }

    pub fn timeout_as_secs(&self) -> u64 {
        self.timeout.as_secs().max(1)
    }
}

impl Fuzz {
    pub fn exec(&self) -> Result<()> {
        self.fuzzer.fuzz(&self.selection, &self.args)
    }
}
