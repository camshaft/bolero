use crate::{config::Config, fuzzer::Fuzzer};
use failure::Error;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct Shrink {
    /// Run the test with a specific fuzzer
    #[structopt(short = "f", long = "fuzzer", default_value = "libfuzzer")]
    fuzzer: Fuzzer,

    #[structopt(flatten)]
    args: ShrinkArgs,

    #[structopt(flatten)]
    config: Config,
}

impl Shrink {
    pub fn exec(&self) -> Result<(), Error> {
        self.fuzzer.shrink(&self.config, &self.args)
    }
}

#[derive(Debug, StructOpt)]
pub struct ShrinkArgs {}
