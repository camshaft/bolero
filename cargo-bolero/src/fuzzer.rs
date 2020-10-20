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
}

impl Fuzzer {
    pub fn fuzz(&self, selection: &Selection, args: &FuzzArgs) -> Result<(), Error> {
        match self {
            Self::Libfuzzer => crate::libfuzzer::fuzz(selection, args),

            #[cfg(feature = "afl")]
            Self::Afl => crate::afl::fuzz(selection, args),

            #[cfg(feature = "honggfuzz")]
            Self::Honggfuzz => crate::honggfuzz::fuzz(selection, args),
        }
    }

    pub fn reduce(&self, selection: &Selection, args: &ReduceArgs) -> Result<(), Error> {
        match self {
            Self::Libfuzzer => crate::libfuzzer::reduce(selection, args),

            #[cfg(feature = "afl")]
            Self::Afl => crate::afl::reduce(selection, args),

            #[cfg(feature = "honggfuzz")]
            Self::Honggfuzz => crate::honggfuzz::reduce(selection, args),
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

            _ => Err(format!("invalid fuzzer {:?}", value)),
        }
    }
}

pub trait Env {
    const NAME: &'static str;

    fn flags(&self, target: &str, args: &crate::flags::Args) -> Vec<&str> {
        let mut build_flags = self.build_flags(target);
        let mut sanitizer_flags = self.sanitizer_flags(target);

        sanitizer_flags.with_args(args);

        build_flags.extend(sanitizer_flags);

        build_flags
    }

    fn sanitizer_flags(&self, target: &str) -> crate::flags::Flags;

    fn build_flags(&self, target: &str) -> Vec<&'static str>;
}

impl Env for () {
    const NAME: &'static str = "DISABLED";

    fn sanitizer_flags(&self, _: &str) -> crate::flags::Flags {
        unreachable!("invalid environment")
    }

    fn build_flags(&self, _: &str) -> Vec<&'static str> {
        unreachable!("invalid environment")
    }
}
