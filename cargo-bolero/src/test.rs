use crate::{engine::Engine, selection::Selection};
use anyhow::Result;
use humantime::Duration;
use structopt::StructOpt;

/// Run an engine for a target
#[derive(Debug, StructOpt)]
pub struct Test {
    /// Run the test with a specific engine
    #[structopt(short, long, default_value = "libfuzzer")]
    engine: Engine,

    #[structopt(flatten)]
    args: Args,

    #[structopt(flatten)]
    selection: Selection,
}

#[derive(Debug, StructOpt)]
pub struct Args {
    /// Run the engine with an initial seed
    #[structopt(short = "S")]
    pub seed: Option<usize>,

    /// Run the engine for a specified number of runs. If unspecified
    /// it will continue until manually stopped.
    #[structopt(short, long)]
    pub runs: Option<usize>,

    /// Run the engine for a specified duration. If unspecified
    /// it will continue until manually stopped.
    #[structopt(short = "T")]
    pub time: Option<Duration>,

    /// Limit the size of inputs to a specific length
    #[structopt(short = "l", long)]
    pub max_input_length: Option<usize>,

    /// Maximum amount of time to run a test target before
    /// failing
    #[structopt(short, long, default_value = "10s")]
    pub timeout: Duration,

    /// Number of parallel jobs
    #[structopt(short, long)]
    pub jobs: Option<usize>,

    /// Additional arguments to pass to the selected engine
    #[structopt(short = "E", long)]
    pub engine_args: Vec<String>,
}

impl Args {
    pub fn time_as_secs(&self) -> Option<u64> {
        self.time.as_ref().map(|d| d.as_secs().max(1))
    }

    pub fn timeout_as_secs(&self) -> u64 {
        self.timeout.as_secs().max(1)
    }
}

impl Test {
    pub fn exec(&self) -> Result<()> {
        self.engine.test(&self.selection, &self.args)
    }
}
