use crate::{reduce, selection::Selection, test};
use anyhow::Result;
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

    Random,
}

impl Engine {
    pub fn test(&self, selection: &Selection, args: &test::Args) -> Result<()> {
        match self {
            Self::Libfuzzer => crate::libfuzzer::test(selection, args),

            #[cfg(feature = "afl")]
            Self::Afl => crate::afl::test(selection, args),

            #[cfg(feature = "honggfuzz")]
            Self::Honggfuzz => crate::honggfuzz::test(selection, args),

            #[cfg(feature = "kani")]
            Self::Kani => crate::kani::test(selection, args),

            Self::Random => crate::random::test(selection, args),
        }
    }

    pub fn reduce(&self, selection: &Selection, args: &reduce::Args) -> Result<()> {
        match self {
            Self::Libfuzzer => crate::libfuzzer::reduce(selection, args),

            #[cfg(feature = "afl")]
            Self::Afl => crate::afl::reduce(selection, args),

            #[cfg(feature = "honggfuzz")]
            Self::Honggfuzz => crate::honggfuzz::reduce(selection, args),

            #[cfg(feature = "kani")]
            Self::Kani => Ok(()),

            Self::Random => Ok(()),
        }
    }
}

macro_rules! optional_engine {
    ($lower:literal, $upper:ident) => {{
        #[cfg(feature = $lower)]
        let v = Ok(Self::$upper);

        #[cfg(not(feature = $lower))]
        let v = Err(format!(
            "cargo-bolero was not built with `{}` feature",
            $lower
        ));

        v
    }};
}

impl FromStr for Engine {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "libfuzzer" => Ok(Self::Libfuzzer),

            "afl" => {
                optional_engine!("afl", Afl)
            }

            "honggfuzz" => {
                optional_engine!("honggfuzz", Honggfuzz)
            }

            "kani" => {
                optional_engine!("kani", Kani)
            }

            "random" => Ok(Self::Random),

            _ => Err(format!("invalid engine {value:?}")),
        }
    }
}
