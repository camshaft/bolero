use crate::{reduce, selection::Selection, test};
use anyhow::Error;
use std::str::FromStr;

#[derive(Debug)]
pub enum Engine {
    Libfuzzer,

    #[cfg(feature = "afl")]
    Afl,

    #[cfg(feature = "honggfuzz")]
    Honggfuzz,

    #[cfg(feature = "kani")]
    Kani,
}

impl Engine {
    pub fn test(&self, selection: &Selection, args: &test::Args) -> Result<(), Error> {
        match self {
            Self::Libfuzzer => crate::libfuzzer::test(selection, args),

            #[cfg(feature = "afl")]
            Self::Afl => crate::afl::test(selection, args),

            #[cfg(feature = "honggfuzz")]
            Self::Honggfuzz => crate::honggfuzz::test(selection, args),

            #[cfg(feature = "kani")]
            Self::Kani => crate::kani::test(selection, args),
        }
    }

    pub fn reduce(&self, selection: &Selection, args: &reduce::Args) -> Result<(), Error> {
        match self {
            Self::Libfuzzer => crate::libfuzzer::reduce(selection, args),

            #[cfg(feature = "afl")]
            Self::Afl => crate::afl::reduce(selection, args),

            #[cfg(feature = "honggfuzz")]
            Self::Honggfuzz => crate::honggfuzz::reduce(selection, args),

            #[cfg(feature = "kani")]
            Self::Kani => Ok(()),
        }
    }
}

impl FromStr for Engine {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "libfuzzer" => Ok(Self::Libfuzzer),

            #[cfg(feature = "afl")]
            "afl" => Ok(Self::Afl),

            #[cfg(feature = "honggfuzz")]
            "honggfuzz" => Ok(Self::Honggfuzz),

            #[cfg(feature = "kani")]
            "kani" => Ok(Self::Kani),

            _ => Err(format!("invalid fuzzer {:?}", value)),
        }
    }
}
