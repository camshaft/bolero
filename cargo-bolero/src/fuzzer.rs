use crate::{config::Config, fuzz::FuzzArgs, reduce::ReduceArgs};
use failure::Error;
use std::str::FromStr;

#[derive(Debug)]
pub enum Fuzzer {
    Libfuzzer,
    Afl,
    Honggfuzz,
}

impl Fuzzer {
    pub fn fuzz(&self, config: &Config, args: &FuzzArgs) -> Result<(), Error> {
        match self {
            Self::Libfuzzer => crate::libfuzzer::fuzz(config, args),
            Self::Afl => crate::afl::fuzz(config, args),
            Self::Honggfuzz => crate::honggfuzz::fuzz(config, args),
        }
    }

    pub fn reduce(&self, config: &Config, args: &ReduceArgs) -> Result<(), Error> {
        match self {
            Self::Libfuzzer => crate::libfuzzer::reduce(config, args),
            Self::Afl => crate::afl::reduce(config, args),
            Self::Honggfuzz => crate::honggfuzz::reduce(config, args),
        }
    }
}

impl FromStr for Fuzzer {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "libfuzzer" => Ok(Self::Libfuzzer),
            "afl" => Ok(Self::Afl),
            "honggfuzz" => Ok(Self::Honggfuzz),
            _ => Err(format!("invalid fuzzer {:?}", value)),
        }
    }
}
