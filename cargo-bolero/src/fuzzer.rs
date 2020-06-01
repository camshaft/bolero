use crate::{fuzz::FuzzArgs, reduce::ReduceArgs, selection::Selection};
use anyhow::Error;
use std::str::FromStr;

#[derive(Debug)]
pub enum Fuzzer {
    Libfuzzer,

    #[cfg(feature = "afl")]
    Afl,

    #[cfg(feature = "honggfuzz")]
    Honggfuzz,

    #[cfg(feature = "ravel")]
    Ravel,
}

impl Fuzzer {
    pub fn fuzz(&self, selection: &Selection, args: &FuzzArgs) -> Result<(), Error> {
        match self {
            Self::Libfuzzer => crate::libfuzzer::fuzz(selection, args),

            #[cfg(feature = "afl")]
            Self::Afl => crate::afl::fuzz(selection, args),

            #[cfg(feature = "honggfuzz")]
            Self::Honggfuzz => crate::honggfuzz::fuzz(selection, args),

            #[cfg(feature = "ravel")]
            Self::Ravel => crate::ravel::fuzz(selection, args),
        }
    }

    pub fn reduce(&self, selection: &Selection, args: &ReduceArgs) -> Result<(), Error> {
        match self {
            Self::Libfuzzer => crate::libfuzzer::reduce(selection, args),

            #[cfg(feature = "afl")]
            Self::Afl => crate::afl::reduce(selection, args),

            #[cfg(feature = "honggfuzz")]
            Self::Honggfuzz => crate::honggfuzz::reduce(selection, args),

            #[cfg(feature = "ravel")]
            Self::Ravel => crate::ravel::reduce(selection, args),
        }
    }
}

impl FromStr for Fuzzer {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "libfuzzer" => Ok(Self::Libfuzzer),

            #[cfg(feature = "afl")]
            "afl" => Ok(Self::Afl),

            #[cfg(feature = "honggfuzz")]
            "honggfuzz" => Ok(Self::Honggfuzz),

            #[cfg(feature = "ravel")]
            "ravel" => Ok(Self::Ravel),
            #[cfg(feature = "ravel")]
            "bolero-ravel" => Ok(Self::Ravel),

            _ => Err(format!("invalid fuzzer {:?}", value)),
        }
    }
}
