use crate::{config::Config, fuzz::FuzzArgs, shrink::ShrinkArgs};
use std::str::FromStr;

#[derive(Debug)]
pub enum Fuzzer {
    Libfuzzer,
}

impl Fuzzer {
    pub fn fuzz(&self, config: &Config, args: &FuzzArgs) {
        match self {
            Self::Libfuzzer => crate::libfuzzer::fuzz(config, args),
        }
    }

    pub fn shrink(&self, config: &Config, args: &ShrinkArgs) {
        match self {
            Self::Libfuzzer => crate::libfuzzer::shrink(config, args),
        }
    }
}

impl FromStr for Fuzzer {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "libfuzzer" => Ok(Self::Libfuzzer),
            _ => Err(format!("invalid fuzzer {:?}", value)),
        }
    }
}
